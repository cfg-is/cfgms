// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package timemodule

import (
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	// hypervGuestKey exists (under HKLM) only inside a Hyper-V guest.
	hypervGuestKey = `SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`
	// vmicTimeProviderKey holds the Hyper-V guest time provider configuration.
	vmicTimeProviderKey = `SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider`
	// vmicEnabledValue is the DWORD that switches the provider on (1) or off (0).
	vmicEnabledValue = "Enabled"

	// announceFlagReliable is the AnnounceFlags bit (0x4) that marks the host
	// as a reliable time source.
	announceFlagReliable = 0x4

	w32timeService = "w32time"
)

// registryAccess is the narrow seam over the HKLM registry used by the
// Hyper-V time provider logic. Production uses the real registry; tests
// inject a map-backed implementation. All paths are relative to HKLM.
type registryAccess interface {
	// keyExists reports whether the key exists.
	keyExists(path string) (bool, error)
	// readDWORD reads a DWORD value. found is false when the key or value is
	// absent.
	readDWORD(path, name string) (value uint32, found bool, err error)
	// writeDWORD sets a DWORD value on an existing key.
	writeDWORD(path, name string, value uint32) error
}

// hklmRegistry is the production registryAccess over HKLM.
type hklmRegistry struct{}

func (hklmRegistry) keyExists(path string) (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	_ = k.Close()
	return true, nil
}

func (hklmRegistry) readDWORD(path, name string) (uint32, bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, err
	}
	defer func() { _ = k.Close() }()

	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return uint32(v), true, nil // #nosec G115 -- DWORD values fit in 32 bits
}

func (hklmRegistry) writeDWORD(path, name string, value uint32) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	return k.SetDWordValue(name, value)
}

// errAccessDeniedHRESULT is the exit code w32tm.exe reports when the calling
// process lacks the privilege to query the Windows Time Service configuration
// (HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED), i.e. 0x80070005). Checked as a
// numeric exit code rather than matching the printed message text, which is
// locale-dependent.
const errAccessDeniedHRESULT = 0x80070005

// isAccessDeniedExitError reports whether err is an *exec.ExitError carrying
// errAccessDeniedHRESULT. Split out from getNTPConfig so the classification
// itself is unit-testable against a synthetic exit code, independent of
// whether this session actually has an elevated token.
func isAccessDeniedExitError(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == errAccessDeniedHRESULT
}

// windowsExecutor manages host time configuration on Windows via tzutil.exe
// and w32tm.exe.
//
// Timezone is managed via tzutil /s (set) and tzutil /g (get).
// Note: Windows timezone identifiers use Windows format (e.g. "Eastern Standard Time"),
// not IANA format. The module stores and returns Windows identifiers as-is.
//
// NTP servers are managed via w32tm /config /manualpeerlist.
// NTP sync enabled/disabled and the source (manual peers or domain hierarchy)
// are managed via w32tm /config /syncfromflags; "reliable" is only set when
// ntp_reliable is true (see buildW32tmConfigArgs).
//
// The Hyper-V guest time provider (VMICTimeProvider) is managed through the
// registry and a w32time restart; it is a no-op on hosts that are not Hyper-V
// guests.
type windowsExecutor struct {
	reg            registryAccess
	restartW32Time func() error
	runW32tm       func(args ...string) ([]byte, error)
	logger         *logging.ModuleLogger
}

func newExecutor() timeExecutor {
	return &windowsExecutor{
		reg:            hklmRegistry{},
		restartW32Time: restartW32TimeService,
		runW32tm: func(args ...string) ([]byte, error) {
			return exec.Command("w32tm", args...).CombinedOutput() // #nosec G204 - arguments built from validated config by buildW32tmConfigArgs
		},
		logger: logging.ForModule("time"),
	}
}

// restartW32TimeService restarts the Windows Time service through the Service
// Control Manager (no shell-out).
func restartW32TimeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service control manager: %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(w32timeService)
	if err != nil {
		return fmt.Errorf("open service %s: %w", w32timeService, err)
	}
	defer func() { _ = s.Close() }()

	if err := stopServiceAndWait(s); err != nil {
		return err
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("start service %s: %w", w32timeService, err)
	}
	return nil
}

// stopServiceAndWait stops the service when it is running and waits up to 30
// seconds for it to reach the Stopped state. An already-stopped service is a no-op.
func stopServiceAndWait(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service %s: %w", w32timeService, err)
	}
	if status.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stop service %s: %w", w32timeService, err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("query service %s: %w", w32timeService, err)
		}
		if status.State == svc.Stopped {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for service %s to stop", w32timeService)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// getState returns the current timezone and NTP configuration from the Windows
// Time Service.
func (e *windowsExecutor) getState() (timeState, error) {
	tz, err := e.getTimezone()
	if err != nil {
		return timeState{}, err
	}

	cfg, err := e.getNTPConfig()
	if err != nil {
		return timeState{}, err
	}

	provider, err := e.getHyperVTimeProvider()
	if err != nil {
		return timeState{}, err
	}

	sort.Strings(cfg.servers)
	return timeState{
		Timezone:               tz,
		NTPServers:             cfg.servers,
		NTPSyncEnabled:         cfg.syncEnabled,
		NTPSource:              cfg.source,
		NTPReliable:            cfg.reliable,
		HyperVHostTimeProvider: provider,
	}, nil
}

// setState applies the desired timezone and NTP configuration via Windows tools.
func (e *windowsExecutor) setState(desired timeState) error {
	if out, err := exec.Command("tzutil", "/s", desired.Timezone).CombinedOutput(); err != nil { // #nosec G204 - timezone from Validate()
		return fmt.Errorf("tzutil /s %s: %w (output: %s)", desired.Timezone, err, strings.TrimSpace(string(out)))
	}

	servers := make([]string, len(desired.NTPServers))
	copy(servers, desired.NTPServers)
	sort.Strings(servers)
	desired.NTPServers = servers

	for _, args := range buildW32tmConfigArgs(desired) {
		if out, err := e.runW32tm(args...); err != nil {
			return fmt.Errorf("w32tm %s: %w (output: %s)", args[0], err, strings.TrimSpace(string(out)))
		}
	}

	return e.applyHyperVTimeProvider(desired.HyperVHostTimeProvider)
}

// isHyperVGuest reports whether this host is a Hyper-V guest.
func (e *windowsExecutor) isHyperVGuest() (bool, error) {
	ok, err := e.reg.keyExists(hypervGuestKey)
	if err != nil {
		return false, fmt.Errorf("check Hyper-V guest key: %w", err)
	}
	return ok, nil
}

// getHyperVTimeProvider reports the VMICTimeProvider state: "enabled" or
// "disabled" on a Hyper-V guest, empty elsewhere (the provider is not
// relevant). A guest without the Enabled value has no active provider and
// reports "disabled".
func (e *windowsExecutor) getHyperVTimeProvider() (string, error) {
	guest, err := e.isHyperVGuest()
	if err != nil || !guest {
		return "", err
	}
	v, found, err := e.reg.readDWORD(vmicTimeProviderKey, vmicEnabledValue)
	if err != nil {
		return "", fmt.Errorf("read VMICTimeProvider Enabled: %w", err)
	}
	if found && v != 0 {
		return hypervProviderEnabled, nil
	}
	return hypervProviderDisabled, nil
}

// vmicEnabledSatisfied reports whether the observed Enabled value already
// matches want. A missing value means the provider is not active, so disabling
// it is already satisfied.
func vmicEnabledSatisfied(current uint32, found bool, want uint32) bool {
	if !found {
		return want == 0
	}
	return current == want
}

// applyHyperVTimeProvider sets the VMICTimeProvider Enabled DWORD and restarts
// w32time only when the value changed. Empty setting means unmanaged; a host
// that is not a Hyper-V guest is a no-op.
func (e *windowsExecutor) applyHyperVTimeProvider(setting string) error {
	if setting == "" {
		return nil
	}
	guest, err := e.isHyperVGuest()
	if err != nil {
		return err
	}
	if !guest {
		e.logger.Debug("hyperv_host_time_provider ignored: host is not a Hyper-V guest",
			"hyperv_host_time_provider", logging.SanitizeLogValue(setting))
		return nil
	}

	var want uint32
	if setting == hypervProviderEnabled {
		want = 1
	}
	current, found, err := e.reg.readDWORD(vmicTimeProviderKey, vmicEnabledValue)
	if err != nil {
		return fmt.Errorf("read VMICTimeProvider Enabled: %w", err)
	}
	if vmicEnabledSatisfied(current, found, want) {
		return nil
	}

	if err := e.reg.writeDWORD(vmicTimeProviderKey, vmicEnabledValue, want); err != nil {
		return fmt.Errorf("write VMICTimeProvider Enabled=%d: %w", want, err)
	}
	if err := e.restartW32Time(); err != nil {
		return fmt.Errorf("restart %s after VMICTimeProvider change: %w", w32timeService, err)
	}
	return nil
}

// getTimezone returns the current Windows timezone identifier via tzutil /g.
func (e *windowsExecutor) getTimezone() (string, error) {
	out, err := exec.Command("tzutil", "/g").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("tzutil /g: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// w32tmConfig is the subset of "w32tm /query /configuration" the module reads.
type w32tmConfig struct {
	servers     []string
	syncEnabled bool
	source      string // "manual" or "domain"
	reliable    bool
}

// stripW32tmAnnotation drops the trailing parenthetical annotation such as
// "(Local)" and surrounding space from a w32tm value.
func stripW32tmAnnotation(val string) string {
	if idx := strings.Index(val, "("); idx >= 0 {
		val = val[:idx]
	}
	return strings.TrimSpace(val)
}

// parseNtpServerList parses "server1,0x9 server2,0x9", dropping the polling flags.
func parseNtpServerList(val string) []string {
	var servers []string
	for _, s := range strings.Fields(stripW32tmAnnotation(val)) {
		if comma := strings.Index(s, ","); comma >= 0 {
			s = s[:comma]
		}
		if s != "" {
			servers = append(servers, s)
		}
	}
	return servers
}

// parseW32tmConfiguration parses the output of "w32tm /query /configuration".
//
//	NtpServer: server1,0x9 server2,0x9 (Local)
//	Type: NT5DS (Local)          -> source "domain"; NTP -> "manual"; NoSync -> sync disabled
//	AnnounceFlags: 10 (Local)    -> reliable when bit 0x4 is set
func parseW32tmConfiguration(output string) w32tmConfig {
	cfg := w32tmConfig{source: ntpSourceManual}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "NtpServer:"):
			cfg.servers = append(cfg.servers, parseNtpServerList(strings.TrimPrefix(line, "NtpServer:"))...)
		case strings.HasPrefix(line, "Type:"):
			applyW32tmType(&cfg, stripW32tmAnnotation(strings.TrimPrefix(line, "Type:")))
		case strings.HasPrefix(line, "AnnounceFlags:"):
			val := stripW32tmAnnotation(strings.TrimPrefix(line, "AnnounceFlags:"))
			if flags, err := strconv.ParseUint(val, 0, 32); err == nil {
				cfg.reliable = flags&announceFlagReliable != 0
			}
		}
	}
	return cfg
}

// applyW32tmType records the sync mode: "NTP" or "NT5DS" means syncing
// ("NT5DS" from the domain hierarchy); "NoSync" means disabled.
func applyW32tmType(cfg *w32tmConfig, val string) {
	cfg.syncEnabled = !strings.EqualFold(val, "NoSync")
	cfg.source = ntpSourceManual
	if strings.EqualFold(val, "NT5DS") {
		cfg.source = ntpSourceDomain
	}
}

// getNTPConfig returns the NTP configuration via w32tm.
//
// "w32tm /query /configuration" requires an elevated (Administrator) token; a
// standard, non-elevated user gets HRESULT 0x80070005 (access denied). This is
// not a production concern: the steward's Windows service is installed with
// no explicit ServiceStartName (cmd/steward/service/manager_windows.go), which
// the Windows Service Control Manager defaults to LocalSystem -- a strictly
// higher-privileged account than Administrator, so the steward's own calls
// always succeed. The failure mode this guards is a developer or CI session
// running go test as a standard user, where ErrInsufficientPrivilege lets the
// caller distinguish "this environment can't answer" from a real fault instead
// of receiving an opaque access-denied error.
func (e *windowsExecutor) getNTPConfig() (w32tmConfig, error) {
	out, runErr := e.runW32tm("/query", "/configuration")
	if runErr != nil {
		if isAccessDeniedExitError(runErr) {
			return w32tmConfig{}, fmt.Errorf("w32tm /query /configuration requires an elevated (Administrator) token: %w", modules.ErrInsufficientPrivilege)
		}
		return w32tmConfig{}, fmt.Errorf("w32tm /query /configuration: %w (output: %s)", runErr, strings.TrimSpace(string(out)))
	}
	return parseW32tmConfiguration(string(out)), nil
}
