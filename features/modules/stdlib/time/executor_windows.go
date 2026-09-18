// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package timemodule

import (
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/cfgis/cfgms/features/modules"
)

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
// NTP sync enabled/disabled is managed via w32tm /config /syncfromflags.
type windowsExecutor struct{}

func newExecutor() timeExecutor {
	return &windowsExecutor{}
}

// getState returns the current timezone and NTP configuration from the Windows
// Time Service.
func (e *windowsExecutor) getState() (timeState, error) {
	tz, err := e.getTimezone()
	if err != nil {
		return timeState{}, err
	}

	servers, enabled, err := e.getNTPConfig()
	if err != nil {
		return timeState{}, err
	}

	sort.Strings(servers)
	return timeState{
		Timezone:       tz,
		NTPServers:     servers,
		NTPSyncEnabled: enabled,
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

	peerList := strings.Join(servers, " ")
	if peerList == "" {
		peerList = "time.windows.com,0x9"
	}

	if out, err := exec.Command("w32tm", "/config", "/manualpeerlist:"+peerList, "/syncfromflags:manual", "/reliable:yes", "/update").CombinedOutput(); err != nil { // #nosec G204 - peer list from config
		return fmt.Errorf("w32tm /config: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	if desired.NTPSyncEnabled {
		if out, err := exec.Command("w32tm", "/config", "/syncfromflags:manual", "/update").CombinedOutput(); err != nil { // #nosec G204 - controlled literal
			return fmt.Errorf("w32tm enable sync: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
	} else {
		if out, err := exec.Command("w32tm", "/config", "/syncfromflags:no", "/update").CombinedOutput(); err != nil { // #nosec G204 - controlled literal
			return fmt.Errorf("w32tm disable sync: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
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

// getNTPConfig returns the NTP peer list and sync-enabled state via w32tm.
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
func (e *windowsExecutor) getNTPConfig() (servers []string, enabled bool, err error) {
	out, runErr := exec.Command("w32tm", "/query", "/configuration").CombinedOutput()
	if runErr != nil {
		if isAccessDeniedExitError(runErr) {
			return nil, false, fmt.Errorf("w32tm /query /configuration requires an elevated (Administrator) token: %w", modules.ErrInsufficientPrivilege)
		}
		return nil, false, fmt.Errorf("w32tm /query /configuration: %w (output: %s)", runErr, strings.TrimSpace(string(out)))
	}

	output := string(out)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "NtpServer:") {
			// Format: "NtpServer: server1,0x9 server2,0x9 (Local)"
			val := strings.TrimPrefix(line, "NtpServer:")
			// Remove trailing parenthetical annotation.
			if idx := strings.Index(val, "("); idx >= 0 {
				val = val[:idx]
			}
			for _, s := range strings.Fields(val) {
				// Strip ,0x9 polling flags.
				if comma := strings.Index(s, ","); comma >= 0 {
					s = s[:comma]
				}
				if s != "" {
					servers = append(servers, s)
				}
			}
		}
		if strings.HasPrefix(line, "Type:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
			// "NTP" or "NT5DS" means syncing; "NoSync" means disabled.
			enabled = !strings.EqualFold(val, "NoSync")
		}
	}

	return servers, enabled, nil
}
