// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/cfgis/cfgms/pkg/security"
	"github.com/cfgis/cfgms/pkg/version"
)

// Windows SCM, service, and registry handles are released throughout this file
// with an explicit `_ =` (or a deferred closure). Every such release runs after
// the operation's outcome is already decided, and the Windows API offers no
// remedy for a failed release beyond leaking the handle until process exit — so
// the error is deliberately dropped rather than handled or logged. This mirrors
// the `_ = exec.Command(...).Run()` cleanup convention in the Linux and darwin
// siblings of this package.

const (
	// windowsInstallDir is the install root. It equals the launcher's own
	// defaultRoot() on Windows (cmd/cfgms-steward-launcher/main.go), so the
	// launcher's versioned layout (versions/, state.json) nests under it.
	windowsInstallDir = `C:\Program Files\CFGMS`
	// windowsInstallPath is the legacy bare-steward binary path. The MSI
	// payload still places cfgms-steward.exe here (it hosts the install/
	// uninstall custom actions); the service itself execs the launcher.
	windowsInstallPath = `C:\Program Files\CFGMS\cfgms-steward.exe`
	// windowsLauncherPath is where the launcher binary is installed. The
	// steward's push-upgrade handler execs "cfgms-steward-launcher.exe swap"
	// at this exact compile-time path (features/steward/client
	// launcherPath()), so a launcher-managed install is what makes a Windows
	// steward upgradeable via the control plane. It must not change.
	windowsLauncherPath = `C:\Program Files\CFGMS\cfgms-steward-launcher.exe`
	// windowsLauncherBinaryName is the launcher binary as shipped in the
	// install bundle (MSI payload), expected alongside the cfgms-steward
	// binary being installed.
	windowsLauncherBinaryName = "cfgms-steward-launcher.exe"
	windowsServiceName        = "CFGMSSteward"
	windowsDisplayName        = "CFGMS Steward"
	windowsDescription        = "CFGMS endpoint configuration management agent"
)

// platformCACertPath returns the path where the CA cert is written, respecting
// CFGMS_INSTALL_PREFIX for test isolation.
func platformCACertPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	dest := filepath.Join(programData, "cfgms", "controller-ca.crt")
	if prefix := os.Getenv("CFGMS_INSTALL_PREFIX"); prefix != "" {
		// Strip the volume name (e.g. "C:") so the path nests under the prefix.
		vol := filepath.VolumeName(dest)
		return filepath.Join(prefix, dest[len(vol):])
	}
	return dest
}

// prepareDataDir ensures the steward data directory (the parent of the pinned
// CA cert, %ProgramData%\cfgms, respecting CFGMS_INSTALL_PREFIX) exists and is
// restricted to SYSTEM and Administrators. Entries owned by a member of
// Administrators, such as the installing administrator's own account, are
// handed to Administrators (security.AdoptAdminOnlyDir), the same takeover the
// SYSTEM steward performs at start. It refuses a directory owned by any other
// principal, so the CA cert is never written into a tree a local user controls.
func prepareDataDir() error {
	dir := filepath.Dir(platformCACertPath())
	if _, err := security.AdoptAdminOnlyDir(dir); err != nil {
		return fmt.Errorf("cannot secure steward data directory %s: %w", dir, err)
	}
	return nil
}

// platformLogDir returns the platform-conventional steward log directory
// (docs/architecture/steward-operating-model.md), mirroring
// platformCACertPath's ProgramData-with-fallback resolution including the
// CFGMS_INSTALL_PREFIX test isolation.
func platformLogDir() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	dest := filepath.Join(programData, "CFGMS", "logs")
	if prefix := os.Getenv("CFGMS_INSTALL_PREFIX"); prefix != "" {
		vol := filepath.VolumeName(dest)
		return filepath.Join(prefix, dest[len(vol):])
	}
	return dest
}

// setServiceEnvironment writes the log directory and fail-closed connected
// security profile to the service's REG_MULTI_SZ Environment value — the native
// SCM mechanism for per-service environment variables (Windows has no
// systemd-style inline Environment= line; the SCM reads this value at service
// start). In-process registry access, never a reg.exe/sc.exe shell-out. root and
// keyPath are parameters so the round-trip unit test can target a scratch HKCU
// key (writing the real HKLM service key requires Administrator, which unit
// tests do not have). The access mask must include SET_VALUE — the read-only
// QUERY_VALUE mask used by read paths yields access-denied on SetStringsValue.
func setServiceEnvironment(root registry.Key, keyPath, logDir string) error {
	key, err := registry.OpenKey(root, keyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open service key %s: %w", keyPath, err)
	}
	defer func() { _ = key.Close() }()
	if err := key.SetStringsValue("Environment", []string{
		"CFGMS_LOG_DIR=" + logDir,
		"CFGMS_SECURITY_PROFILE=public-beta",
	}); err != nil {
		return fmt.Errorf("set Environment value on %s: %w", keyPath, err)
	}
	return nil
}

func newManager(binaryPath string) Manager {
	return &windowsManager{binaryPath: binaryPath}
}

type windowsManager struct {
	binaryPath string
}

// IsElevated returns true if the current process has Administrator privileges.
// It checks by attempting to open the service control manager, which requires
// Administrator — the canonical check without additional packages.
func (m *windowsManager) IsElevated() bool {
	scm, err := mgr.Connect()
	if err != nil {
		return false
	}
	_ = scm.Disconnect()
	return true
}

// Install installs the launcher to C:\Program Files\CFGMS\, stages the
// steward binary under the launcher's versioned layout, and creates a Windows
// service that runs the launcher (which supervises the steward) — mirroring
// the Linux launcher-managed model. This is what makes a Windows steward
// upgradeable via the control plane: the push-upgrade handler execs
// "cfgms-steward-launcher.exe swap" at windowsLauncherPath. If the service
// already exists it is stopped and re-registered; its definition is deleted
// only after staging succeeds, and a failed stage restarts it.
//
// Uses the native Windows Service API via golang.org/x/sys/windows/svc/mgr.
// Does NOT shell out to sc.exe.
//
// When controllerURL is non-empty, --controller-url is forwarded to the
// supervised steward via the launcher's --child-args.
// If caCertPEM is non-empty, the CA cert is written to the platform-standard
// path before the service is started. When expectedFingerprint is also non-empty,
// fingerprint verification runs first — a mismatch returns an error without any
// disk writes or service changes.
func (m *windowsManager) Install(token, controllerURL, caCertPEM, expectedFingerprint string) error {
	if err := validateToken(token); err != nil {
		return err
	}
	if tokenPath := platformTokenFilePath(); strings.ContainsAny(tokenPath, " \t\n\r\"") {
		return fmt.Errorf("registration token file path %q must not contain whitespace or quotes", tokenPath)
	}
	// Verify fingerprint before any privileged operations so the caller gets a
	// clear error without needing to undo partial changes.
	if caCertPEM != "" && expectedFingerprint != "" {
		if err := verifyCACertFingerprint(caCertPEM, expectedFingerprint); err != nil {
			return err
		}
	}

	// A launcher-managed install (steward supervised by
	// cfgms-steward-launcher.exe, staged under versions\) is what makes the
	// steward upgradeable via the control plane: the push-upgrade handler
	// execs "cfgms-steward-launcher.exe swap" and requires the launcher at
	// windowsLauncherPath. A bare direct-service steward cannot be
	// push-upgraded. The launcher binary ships alongside the steward binary
	// in the install bundle (MSI payload). Checked before the elevation gate
	// (read-only stat) so the caller gets the actionable bundle error even
	// without Administrator rights.
	launcherSrc := filepath.Join(filepath.Dir(m.binaryPath), windowsLauncherBinaryName)
	if _, err := os.Stat(launcherSrc); err != nil {
		return fmt.Errorf("launcher binary %q not found next to the steward binary: %w\n"+
			"  a launcher-managed install requires %s in the install bundle",
			launcherSrc, err, windowsLauncherBinaryName)
	}

	if !m.IsElevated() {
		return fmt.Errorf("install requires Administrator privileges: right-click the binary and select 'Run as administrator'")
	}

	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer func() { _ = scm.Disconnect() }()

	// The existing service (if any) is held open across staging: it must be
	// stopped before the launcher executable is replaced (a running executable
	// cannot be overwritten on Windows), but its definition is only deleted
	// once staging succeeds, so a failed stage can restart it (#4538).
	var existing *mgr.Service
	defer func() {
		if existing != nil {
			_ = existing.Close()
		}
	}()

	return runInstallSequence(installSteps{
		stopExisting: func() bool {
			s, err := scm.OpenService(windowsServiceName)
			if err != nil {
				return false
			}
			existing = s
			fmt.Println("Stopping existing service...")
			_, _ = existing.Control(svc.Stop)
			if err := waitForStop(existing, 30*time.Second); err != nil {
				fmt.Printf("Warning: %v — proceeding anyway\n", err)
			}
			return true
		},
		restartExisting: func() error {
			fmt.Println("Install failed — restarting existing service...")
			return existing.Start()
		},
		stage: func() error {
			return m.stageInstall(launcherSrc, caCertPEM, token)
		},
		replaceDefinition: func() error {
			if existing != nil {
				fmt.Println("Removing existing service definition...")
				err := existing.Delete()
				// Close before CreateService: an open handle keeps a
				// deleted service in the marked-for-delete state.
				_ = existing.Close()
				existing = nil
				if err != nil {
					return fmt.Errorf("failed to delete existing service: %w", err)
				}
			}
			return registerAndStartService(scm, platformTokenFilePath(), controllerURL)
		},
	})
}

// installSteps are the phases of an install that touch an existing service.
// They are parameters so the failure-path ordering in runInstallSequence is
// testable without the SCM or elevation.
type installSteps struct {
	// stopExisting stops the existing service and reports whether one was found.
	stopExisting func() bool
	// restartExisting starts the service stopped by stopExisting again.
	restartExisting func() error
	// stage installs the launcher, stages the steward binary, and writes the
	// CA cert (if any) and the registration token into the locked-down data
	// directory.
	stage func() error
	// replaceDefinition deletes the existing service definition (if any) and
	// registers and starts the new one.
	replaceDefinition func() error
}

// runInstallSequence runs stop, stage, replace-definition in that order. If
// stage fails after an existing service was stopped, the existing service is
// restarted so a failed install does not leave the host unmanaged, and the
// stage error is returned (joined with the restart error if that fails too).
func runInstallSequence(s installSteps) error {
	stopped := s.stopExisting()
	if err := s.stage(); err != nil {
		if stopped {
			if rerr := s.restartExisting(); rerr != nil {
				return errors.Join(err, fmt.Errorf("failed to restart existing service: %w", rerr))
			}
		}
		return err
	}
	return s.replaceDefinition()
}

// stageInstall installs the launcher, stages the steward binary under the
// launcher's versioned layout, then writes the CA cert and registration token
// via stageDataFiles. It runs while the existing service is stopped but still
// defined.
func (m *windowsManager) stageInstall(launcherSrc, caCertPEM, token string) error {
	// Create install directory.
	if err := os.MkdirAll(windowsInstallDir, 0755); err != nil {
		return fmt.Errorf("failed to create install directory %s: %w", windowsInstallDir, err)
	}

	ver := version.Short()

	// The MSI payload already places the launcher at windowsLauncherPath;
	// copyBinary is a same-path-safe atomic copy (temp file + rename), so this
	// also covers manual installs from an extracted bundle elsewhere on disk.
	fmt.Printf("Installing launcher to %s...\n", windowsLauncherPath)
	if err := copyBinary(launcherSrc, windowsLauncherPath); err != nil {
		return fmt.Errorf("failed to install launcher: %w", err)
	}

	// Bootstrap the launcher layout: stage the steward binary as the current
	// version under versions\<ver>\ and record it in state.json. This reuses
	// the launcher's own "swap" surface (fixed binary path + discrete argv,
	// never a composed shell string), so the on-disk layout is identical to
	// what a subsequent push-upgrade produces. windowsInstallDir equals the
	// launcher's defaultRoot() on Windows.
	fmt.Printf("Staging steward %s under %s...\n", ver, windowsInstallDir)
	if out, err := exec.Command(windowsLauncherPath, "swap", "--root", windowsInstallDir, ver, m.binaryPath).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stage steward binary via launcher: %w\n%s", err, out)
	}

	return stageDataFiles(caCertPEM, token)
}

// stageDataFiles writes the pinned CA cert (when caCertPEM is non-empty) and
// the registration token into the steward data directory, locking the
// directory down to SYSTEM and Administrators around each write. The token is
// always staged through stageRegistrationToken, so the lockdown happens with
// or without a CA cert. Both are written before the service is registered so
// the service finds them on first start.
func stageDataFiles(caCertPEM, token string) error {
	if caCertPEM != "" {
		if err := stageDataDir(caCertPEM); err != nil {
			return err
		}
	}
	return stageRegistrationToken(token)
}

// stageDataDir secures the steward data directory, writes the pinned CA cert
// into it, then secures it again: the cert file is created owned by the
// installing administrator's own account, which the SYSTEM steward's start-up
// check would refuse.
func stageDataDir(caCertPEM string) error {
	if err := prepareDataDir(); err != nil {
		return err
	}
	fmt.Printf("Writing CA cert to %s...\n", platformCACertPath())
	if err := writeCACert(caCertPEM, platformCACertPath()); err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}
	return prepareDataDir()
}

// stageRegistrationToken locks down the steward data directory, writes the
// token file into it, then locks the directory down again so the new file,
// created by the installing administrator's own account, is handed to
// Administrators (ReadTokenFile refuses any other owner). The lockdown runs
// whether or not a CA cert is staged. A token file planted by another principal
// makes the first lockdown fail, so the install aborts before the write. If the
// second lockdown fails the token file is removed rather than left unlocked.
func stageRegistrationToken(token string) error {
	if err := prepareDataDir(); err != nil {
		return err
	}
	path, err := installRegistrationToken(token)
	if err != nil {
		return err
	}
	if err := prepareDataDir(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// configureServiceRecovery sets automatic restart on failure (3 escalating
// delays, 1-day reset) and applies it to non-crash failures too. The launcher
// reports a non-zero service-specific exit code when it gives up, which the
// service manager only treats as a failure when the non-crash flag is set.
func configureServiceRecovery(svc *mgr.Service) error {
	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
	if err := svc.SetRecoveryActions(recoveryActions, 86400); err != nil {
		return err
	}
	return svc.SetRecoveryActionsOnNonCrashFailures(true)
}

// registerAndStartService creates the launcher-backed service, sets its
// environment and recovery actions, and starts it.
func registerAndStartService(scm *mgr.Mgr, tokenPath, controllerURL string) error {
	fmt.Println("Registering Windows service...")
	newSvc, err := scm.CreateService(
		windowsServiceName,
		windowsLauncherPath,
		mgr.Config{
			StartType:   mgr.StartAutomatic,
			DisplayName: windowsDisplayName,
			Description: windowsDescription,
		},
		// Arguments appended to the binary path; received as os.Args on
		// service start. The launcher supervises the steward and forwards
		// --child-args to it.
		buildLauncherServiceArgs(windowsInstallDir, tokenPath, controllerURL)...,
	)
	if err != nil {
		return fmt.Errorf("failed to create Windows service: %w", err)
	}
	defer func() { _ = newSvc.Close() }()

	// Point CFGMS_LOG_DIR at the platform-conventional log directory so an
	// installed steward never falls back to the undiscoverable /tmp/cfgms
	// (#2378). Written after CreateService (the service key must exist) and
	// before Start so the very first start picks it up.
	if err := setServiceEnvironment(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+windowsServiceName, platformLogDir()); err != nil {
		return fmt.Errorf("failed to set service environment: %w", err)
	}

	if err := configureServiceRecovery(newSvc); err != nil {
		// Non-fatal: service still works without recovery options.
		fmt.Printf("Warning: could not set service recovery options: %v\n", err)
	}

	fmt.Println("Starting service...")
	if err := newSvc.Start(); err != nil {
		return fmt.Errorf("failed to start Windows service: %w", err)
	}

	fmt.Printf("\nDone. CFGMS Steward installed and running.\n")
	fmt.Printf("  Service name: %s\n", windowsServiceName)
	fmt.Printf("  Status:  cfgms-steward status\n")
	fmt.Printf("  Remove:  cfgms-steward uninstall\n")
	return nil
}

// buildLauncherServiceArgs returns the service start arguments that make the
// SCM run the launcher's supervision loop: `run --root <root> --child-args
// "<steward args>"`. Args inside child-args are space-separated (the launcher
// splits on whitespace via strings.Fields), so the token file path must not
// contain whitespace or quotes. The registration token itself never appears:
// only the path of the SYSTEM and Administrators only token file is passed.
// Mirrors generateSystemdUnit's childArgs on Linux.
func buildLauncherServiceArgs(root, tokenPath, controllerURL string) []string {
	childArgs := fmt.Sprintf(`--regtoken-file %s`, tokenPath)
	if controllerURL != "" {
		childArgs += fmt.Sprintf(` --controller-url %s`, controllerURL)
	}
	return []string{"run", "--root", root, "--child-args", childArgs}
}

// Uninstall stops and removes the Windows service. If purge is true the
// installed launcher binary, its versioned staging layout, and the legacy
// bare-steward binary at windowsInstallPath are also deleted.
func (m *windowsManager) Uninstall(purge bool) error {
	if !m.IsElevated() {
		return fmt.Errorf("uninstall requires Administrator privileges: right-click the binary and select 'Run as administrator'")
	}

	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer func() { _ = scm.Disconnect() }()

	existing, err := scm.OpenService(windowsServiceName)
	if err != nil {
		fmt.Println("Service not registered — nothing to remove.")
	} else {
		fmt.Println("Stopping service...")
		_, _ = existing.Control(svc.Stop)
		if err := waitForStop(existing, 30*time.Second); err != nil {
			fmt.Printf("Warning: %v — proceeding anyway\n", err)
		}

		fmt.Println("Removing service definition...")
		if err := existing.Delete(); err != nil {
			_ = existing.Close()
			return fmt.Errorf("failed to delete service: %w", err)
		}
		_ = existing.Close()
	}

	if purge {
		// Launcher binary + versioned layout (versions\, state.json and the
		// legacy pointer files) for launcher-managed installs. Remove the
		// specific known paths only — windowsInstallDir also holds MSI-owned
		// files (cfgms-steward.exe, modules\), so never RemoveAll the root.
		if _, err := os.Stat(windowsLauncherPath); err == nil {
			fmt.Printf("Removing %s...\n", windowsLauncherPath)
			if err := os.Remove(windowsLauncherPath); err != nil {
				return fmt.Errorf("failed to remove launcher: %w", err)
			}
		}
		versionsDir := filepath.Join(windowsInstallDir, "versions")
		if _, err := os.Stat(versionsDir); err == nil {
			fmt.Printf("Removing %s...\n", versionsDir)
			if err := os.RemoveAll(versionsDir); err != nil {
				return fmt.Errorf("failed to remove launcher versions dir: %w", err)
			}
		}
		for _, stateFile := range []string{"state.json", "current.txt", "previous.txt"} {
			p := filepath.Join(windowsInstallDir, stateFile)
			if _, err := os.Stat(p); err == nil {
				fmt.Printf("Removing %s...\n", p)
				if err := os.Remove(p); err != nil {
					return fmt.Errorf("failed to remove launcher state file: %w", err)
				}
			}
		}
		// Legacy bare-steward binary (pre-launcher direct-service installs).
		if _, err := os.Stat(windowsInstallPath); err == nil {
			fmt.Printf("Removing %s...\n", windowsInstallPath)
			if err := os.Remove(windowsInstallPath); err != nil {
				return fmt.Errorf("failed to remove binary: %w", err)
			}
		}
	}

	fmt.Println("CFGMS Steward uninstalled.")
	return nil
}

// Stop stops the Windows service and waits for it to reach the Stopped state.
// The service definition and its automatic start type are left untouched.
func (m *windowsManager) Stop() error {
	if !m.IsElevated() {
		return fmt.Errorf("stop requires Administrator privileges: right-click the binary and select 'Run as administrator'")
	}
	scm, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer func() { _ = scm.Disconnect() }()

	existing, err := scm.OpenService(windowsServiceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed: %w", windowsServiceName, err)
	}
	defer func() { _ = existing.Close() }()

	q, err := existing.Query()
	if err != nil {
		return fmt.Errorf("failed to query service state: %w", err)
	}
	if q.State == svc.Stopped {
		return nil
	}
	if _, err := existing.Control(svc.Stop); err != nil {
		return fmt.Errorf("failed to stop service %s: %w", windowsServiceName, err)
	}
	return waitForStop(existing, 30*time.Second)
}

// RegistrationTokenConfigured reports whether the registration token file exists
// and is non-empty. The file content is never returned. The service command
// line is not consulted: it carries only the token file path.
func (m *windowsManager) RegistrationTokenConfigured() (bool, error) {
	return tokenFileConfigured(platformTokenFilePath())
}

// Status returns the current service state without requiring elevated privileges.
func (m *windowsManager) Status() (*ServiceStatus, error) {
	status := &ServiceStatus{
		ServiceName: windowsServiceName,
		// Launcher-managed: the service's exec target is the launcher
		// (mirrors linuxManager.Status reporting linuxLauncherPath).
		InstallPath: windowsLauncherPath,
	}

	scm, err := mgr.Connect()
	if err != nil {
		// Cannot connect to SCM — report not installed.
		return status, nil
	}
	defer func() { _ = scm.Disconnect() }()

	existing, err := scm.OpenService(windowsServiceName)
	if err != nil {
		// Service not registered.
		return status, nil
	}
	defer func() { _ = existing.Close() }()

	status.Installed = true

	q, err := existing.Query()
	if err != nil {
		return status, nil
	}
	status.Running = q.State == svc.Running

	return status, nil
}

// waitForStop polls the service state until it reaches Stopped or the timeout
// expires. This replaces an arbitrary time.Sleep so we proceed as soon as the
// service actually stops rather than guessing how long it takes.
func waitForStop(s *mgr.Service, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return fmt.Errorf("failed to query service state: %w", err)
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("service did not stop within %s", timeout)
}
