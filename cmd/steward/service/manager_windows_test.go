// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/cfgis/cfgms/pkg/security"
)

func TestWindowsManagerInstallPath(t *testing.T) {
	m := New("cfgms-steward.exe")
	status, err := m.Status()
	require.NoError(t, err)
	// Launcher-managed install: the service's exec target is the launcher,
	// so that is the install path Status reports (mirrors linuxLauncherPath).
	assert.Equal(t, windowsLauncherPath, status.InstallPath)
}

func TestWindowsManagerStatusNotInstalled(t *testing.T) {
	// Status must work without Administrator privileges.
	// When the service is not registered it must be reported as not installed.
	m := New("cfgms-steward.exe")
	status, err := m.Status()
	require.NoError(t, err)
	assert.Equal(t, windowsServiceName, status.ServiceName)
	assert.Equal(t, windowsLauncherPath, status.InstallPath)
}

func TestWindowsManagerInstallRequiresElevation(t *testing.T) {
	// Stage a launcher stub next to the steward path so the pre-elevation
	// bundle check passes and Install reaches the elevation gate.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, windowsLauncherBinaryName), []byte("stub"), 0o600))
	m := New(filepath.Join(dir, "cfgms-steward.exe"))
	if m.IsElevated() {
		t.Skip("skipping elevation check — running as Administrator")
	}
	err := m.Install("tok_test123", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Administrator")
}

// TestWindowsInstallFingerprintMismatch verifies that a mismatched CA fingerprint causes
// Install to return an error before writing the cert or registering the service.
// Runs without Administrator because fingerprint verification is checked before the elevation gate.
func TestWindowsInstallFingerprintMismatch(t *testing.T) {
	m := New("cfgms-steward.exe")
	if m.IsElevated() {
		t.Skip("skipping — running as Administrator would proceed past fingerprint check to service ops")
	}
	dir := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", dir)

	certPEM, _ := generateTestCACert(t)
	err := m.Install("tok_test123", "", certPEM, "deadbeefdeadbeefdeadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")

	// Cert must NOT be written on fingerprint mismatch.
	certPath := platformCACertPath()
	_, statErr := os.Stat(certPath)
	assert.True(t, os.IsNotExist(statErr), "cert file must not exist after fingerprint mismatch")
}

// TestWindowsInstallCACertWritten verifies that the CA cert is written to the prefixed
// platform path with mode 0444 when a correct fingerprint is provided (ADR-013 §3).
func TestWindowsInstallCACertWritten(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", dir)

	certPEM, fingerprint := generateTestCACert(t)

	require.NoError(t, verifyCACertFingerprint(certPEM, fingerprint))

	destPath := platformCACertPath()
	require.NoError(t, writeCACert(certPEM, destPath))

	info, err := os.Stat(destPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0444), info.Mode().Perm(), "CA cert must be written with mode 0444 per ADR-013 §3")
}

func TestWindowsManagerUninstallRequiresElevation(t *testing.T) {
	m := New("cfgms-steward.exe")
	if m.IsElevated() {
		t.Skip("skipping elevation check — running as Administrator")
	}
	err := m.Uninstall(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Administrator")
}

func TestWindowsManagerNew(t *testing.T) {
	m := New("cfgms-steward.exe")
	require.NotNil(t, m)
	_, ok := m.(*windowsManager)
	assert.True(t, ok, "New() should return a *windowsManager on Windows")
}

// TestSetServiceEnvironmentRoundTrip is the REQUIRED TEST for #2378: the
// registry-write helper round-trips the CFGMS_LOG_DIR Environment value. It
// targets a scratch HKCU key — writing the real HKLM service key requires
// Administrator, which unit tests do not have (the helper's root/keyPath
// parameters exist exactly for this).
func TestSetServiceEnvironmentRoundTrip(t *testing.T) {
	const scratch = `Software\CFGMS-test-svcenv`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, scratch, registry.ALL_ACCESS)
	require.NoError(t, err)
	require.NoError(t, key.Close())
	t.Cleanup(func() { _ = registry.DeleteKey(registry.CURRENT_USER, scratch) })

	logDir := `C:\ProgramData\CFGMS\logs`
	require.NoError(t, setServiceEnvironment(registry.CURRENT_USER, scratch, logDir))

	rk, err := registry.OpenKey(registry.CURRENT_USER, scratch, registry.QUERY_VALUE)
	require.NoError(t, err)
	defer func() { _ = rk.Close() }()
	vals, valType, err := rk.GetStringsValue("Environment")
	require.NoError(t, err)
	assert.Equal(t, uint32(registry.MULTI_SZ), valType, "Environment must be REG_MULTI_SZ — the only type the SCM accepts")
	assert.Equal(t, []string{
		"CFGMS_LOG_DIR=" + logDir,
		"CFGMS_SECURITY_PROFILE=public-beta",
	}, vals)
}

// TestWindowsLauncherPathParity is the REQUIRED path-parity TEST for #2379:
// windowsLauncherPath must equal the literal path returned by
// features/steward/client's launcherPath() on windows
// (client_transport_upgrade.go) — the compile-time contract push-upgrade
// execs. Drift between install-time and the upgrade runtime path silently
// breaks push-upgrade, so the literal is pinned here.
func TestWindowsLauncherPathParity(t *testing.T) {
	assert.Equal(t, `C:\Program Files\CFGMS\cfgms-steward-launcher.exe`, windowsLauncherPath,
		"windowsLauncherPath must match client_transport_upgrade.go launcherPath() exactly")
	assert.Equal(t, "cfgms-steward-launcher.exe", windowsLauncherBinaryName)
}

// TestWindowsInstallLauncherMissing is the REQUIRED fail-closed TEST for
// #2379: Install must return a clear, actionable error — before any service
// registration — when the launcher binary is not bundled next to the steward
// binary. The check runs before the elevation gate (like fingerprint
// verification), so this asserts an early return without touching privileged
// state.
func TestWindowsInstallLauncherMissing(t *testing.T) {
	dir := t.TempDir() // empty: no launcher next to the (hypothetical) steward binary
	m := New(filepath.Join(dir, "cfgms-steward.exe"))
	err := m.Install("tok_test123", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), windowsLauncherBinaryName,
		"error must name the missing launcher binary")
	assert.Contains(t, err.Error(), "not found next to the steward binary",
		"error must explain the bundle expectation")
	assert.NotContains(t, err.Error(), "Administrator",
		"launcher presence is checked before the elevation gate")
}

// TestRegistrationTokenConfigured_ReadsTokenFileOnly (REQUIRED, #5623):
// RegistrationTokenConfigured reports only whether the token file exists and is
// non-empty. It no longer falls back to the service command line.
func TestRegistrationTokenConfigured_ReadsTokenFileOnly(t *testing.T) {
	requireElevatedToken(t)
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	path := tokenPathInExistingDir(t)
	m := &windowsManager{}

	ok, err := m.RegistrationTokenConfigured()
	require.NoError(t, err)
	assert.False(t, ok, "a missing token file is not configured")

	require.NoError(t, os.WriteFile(path, nil, 0o600))
	ok, err = m.RegistrationTokenConfigured()
	require.NoError(t, err)
	assert.False(t, ok, "an empty token file is not configured")
	require.NoError(t, os.Remove(path))

	require.NoError(t, writeTokenFile(path, "tok_configured_check"))
	ok, err = m.RegistrationTokenConfigured()
	require.NoError(t, err)
	assert.True(t, ok, "a token file written by writeTokenFile is configured")
}

// TestBuildLauncherServiceArgs is the REQUIRED launcher-target TEST for
// #2379: the Windows service must be registered to invoke the launcher
// (`run --root ... --child-args "..."`), never the bare steward binary —
// mirrors TestGenerateSystemdUnit's assertions for Linux.
func TestBuildLauncherServiceArgs(t *testing.T) {
	tokenPath := `C:\ProgramData\cfgms\registration-token`
	token := "tok_svc_args_abc123"

	args := buildLauncherServiceArgs(windowsInstallDir, tokenPath, "")
	assert.Equal(t, []string{"run", "--root", windowsInstallDir, "--child-args", "--regtoken-file " + tokenPath}, args)

	withURL := buildLauncherServiceArgs(windowsInstallDir, tokenPath, "https://ctrl.example.com:8443")
	assert.Equal(t, []string{"run", "--root", windowsInstallDir, "--child-args",
		"--regtoken-file " + tokenPath + " --controller-url https://ctrl.example.com:8443"}, withURL)

	// The service args must never point execution at the bare steward binary.
	joined := strings.Join(withURL, " ")
	assert.NotContains(t, joined, windowsInstallPath+" --regtoken",
		"service must exec the launcher, not the bare steward binary")

	// Only the file path is passed: neither the token nor the legacy flag.
	assert.NotContains(t, joined, token)
	assert.NotContains(t, joined, "--regtoken ", "the legacy --regtoken flag must not come back")
	assert.Equal(t, 1, strings.Count(joined, "--regtoken-file"))
}

// TestWindowsLauncherUnderProgramFilesACL is the REQUIRED LPE-hardening TEST
// for #2379: the launcher — a binary a SYSTEM service execs — must be
// installed under the install dir whose default Program Files ACL restricts
// writes to Administrators/SYSTEM. No install-dir ACL is loosened by this
// package (copyBinary sets no Windows ACLs; the directory inherits Program
// Files protection), so the load-bearing guarantee is that the path never
// moves out from under it.
func TestWindowsLauncherUnderProgramFilesACL(t *testing.T) {
	assert.True(t, strings.HasPrefix(windowsLauncherPath, windowsInstallDir+`\`),
		"launcher must live inside the install dir")
	assert.True(t, strings.HasPrefix(windowsInstallDir, `C:\Program Files\`),
		"install dir must be under Program Files (Administrator-only-writable default ACL)")
}

// TestPlatformLogDir verifies the ProgramData-with-fallback resolution mirrors
// platformCACertPath, including CFGMS_INSTALL_PREFIX test isolation.
func TestPlatformLogDir(t *testing.T) {
	t.Setenv("ProgramData", `C:\ProgramData`)
	t.Setenv("CFGMS_INSTALL_PREFIX", "")
	assert.Equal(t, filepath.Join(`C:\ProgramData`, "CFGMS", "logs"), platformLogDir())

	t.Setenv("ProgramData", "")
	assert.Equal(t, filepath.Join(`C:\ProgramData`, "CFGMS", "logs"), platformLogDir(),
		`unset ProgramData falls back to C:\ProgramData`)

	t.Setenv("CFGMS_INSTALL_PREFIX", `D:\scratch`)
	assert.Equal(t, filepath.Join(`D:\scratch`, `ProgramData`, "CFGMS", "logs"), platformLogDir(),
		"CFGMS_INSTALL_PREFIX nests the path under the prefix")
}

// recordedInstallSteps returns installSteps whose closures append their name
// to calls, with stage returning stageErr and restartExisting returning
// restartErr.
func recordedInstallSteps(calls *[]string, existingFound bool, stageErr, restartErr error) installSteps {
	return installSteps{
		stopExisting: func() bool {
			*calls = append(*calls, "stop")
			return existingFound
		},
		restartExisting: func() error {
			*calls = append(*calls, "restart-existing")
			return restartErr
		},
		stage: func() error {
			*calls = append(*calls, "stage")
			return stageErr
		},
		replaceDefinition: func() error {
			*calls = append(*calls, "replace-definition")
			return nil
		},
	}
}

// TestRunInstallSequenceStageFailureRestartsExisting verifies that a failed
// stage restarts the stopped existing service and never deletes its
// definition, so a failed install leaves the host managed (#4538).
func TestRunInstallSequenceStageFailureRestartsExisting(t *testing.T) {
	var calls []string
	stageErr := errors.New("downgrade rejected")
	err := runInstallSequence(recordedInstallSteps(&calls, true, stageErr, nil))
	require.Error(t, err)
	assert.ErrorIs(t, err, stageErr)
	assert.Contains(t, err.Error(), "downgrade rejected")
	assert.Equal(t, []string{"stop", "stage", "restart-existing"}, calls)
	assert.NotContains(t, calls, "replace-definition")
}

// TestRunInstallSequenceSuccessOrder verifies the success path order: stop,
// stage, replace-definition, with no restart of the old service.
func TestRunInstallSequenceSuccessOrder(t *testing.T) {
	var calls []string
	require.NoError(t, runInstallSequence(recordedInstallSteps(&calls, true, nil, nil)))
	assert.Equal(t, []string{"stop", "stage", "replace-definition"}, calls)
}

// TestRunInstallSequenceStageFailureNoExisting verifies that with no existing
// service there is nothing to restore: the stage error is returned as-is.
func TestRunInstallSequenceStageFailureNoExisting(t *testing.T) {
	var calls []string
	stageErr := errors.New("launcher copy failed")
	err := runInstallSequence(recordedInstallSteps(&calls, false, stageErr, nil))
	require.ErrorIs(t, err, stageErr)
	assert.Equal(t, []string{"stop", "stage"}, calls)
}

// TestRunInstallSequenceRestartFailureReturnsBoth verifies that when the
// restart of the existing service also fails, both errors are returned with
// the stage error first.
func TestRunInstallSequenceRestartFailureReturnsBoth(t *testing.T) {
	var calls []string
	stageErr := errors.New("stage failed")
	restartErr := errors.New("start refused")
	err := runInstallSequence(recordedInstallSteps(&calls, true, stageErr, restartErr))
	require.Error(t, err)
	assert.ErrorIs(t, err, stageErr)
	assert.ErrorIs(t, err, restartErr)
	msg := err.Error()
	assert.Less(t, strings.Index(msg, "stage failed"), strings.Index(msg, "start refused"))
	assert.Equal(t, []string{"stop", "stage", "restart-existing"}, calls)
}

func TestPrepareDataDir_ProducesProtectedAdminOnlyDACL(t *testing.T) {
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	require.NoError(t, prepareDataDir())

	dir := filepath.Dir(platformCACertPath())
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	ctrl, _, err := sd.Control()
	require.NoError(t, err)
	assert.NotZero(t, ctrl&windows.SE_DACL_PROTECTED, "DACL must be protected")

	acl, _, err := sd.DACL()
	require.NoError(t, err)
	require.NotNil(t, acl)
	var sids []string
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(acl, i, &ace))
		sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	assert.ElementsMatch(t, []string{"S-1-5-18", "S-1-5-32-544"}, sids)
}

// treeOwners returns the owner SID of root and of every entry below it.
func treeOwners(t *testing.T, root string) map[string]string {
	t.Helper()
	owners := map[string]string{}
	require.NoError(t, filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return err
		}
		owner, _, err := sd.Owner()
		if err != nil {
			return err
		}
		owners[p] = owner.String()
		return nil
	}))
	return owners
}

// TestStageDataDir_InstalledTreePassesStewardStartCheck runs the install's
// data-directory staging as the current (elevated) user on a fresh tree, then
// the steward's start-up check. The steward runs as SYSTEM, which accepts only
// SYSTEM or Administrators as owner, so every entry must have one of those
// owners, not the installing user's own account.
func TestStageDataDir_InstalledTreePassesStewardStartCheck(t *testing.T) {
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	certPEM, _ := generateTestCACert(t)

	require.NoError(t, stageDataDir(certPEM))

	dir := filepath.Dir(platformCACertPath())
	owners := treeOwners(t, dir)
	require.Contains(t, owners, platformCACertPath(), "the CA cert must be written")
	for p, sid := range owners {
		assert.Contains(t, []string{"S-1-5-18", "S-1-5-32-544"}, sid, "%s must be owned by SYSTEM or Administrators", p)
	}
	require.NoError(t, security.EnsureAdminOnlyDir(dir), "steward start-up check must accept the installed tree")
}

// TestStageDataDir_RefusesTreePrecreatedByNonAdmin plants the data directory
// as a standard principal (BUILTIN\Users) before install. Staging must refuse
// it and write no CA cert into it.
func TestStageDataDir_RefusesTreePrecreatedByNonAdmin(t *testing.T) {
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	dir := filepath.Dir(platformCACertPath())
	require.NoError(t, os.MkdirAll(dir, 0755))
	setOwnerWithRestorePrivilege(t, dir, "S-1-5-32-545")
	certPEM, _ := generateTestCACert(t)

	assert.ErrorIs(t, stageDataDir(certPEM), security.ErrUntrustedDirOwner)
	_, err := os.Stat(platformCACertPath())
	assert.True(t, os.IsNotExist(err), "no CA cert may be written into a non-admin tree")
	assert.ErrorIs(t, security.EnsureAdminOnlyDir(dir), security.ErrUntrustedDirOwner)
}

// setOwnerWithRestorePrivilege makes the principal sidString the owner of path,
// enabling the elevated test process's SeRestorePrivilege only for this call.
func setOwnerWithRestorePrivilege(t *testing.T, path, sidString string) {
	t.Helper()
	var luid windows.LUID
	require.NoError(t, windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeRestorePrivilege"), &luid))
	var token windows.Token
	require.NoError(t, windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token))
	defer func() { _ = token.Close() }()
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	require.NoError(t, windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil))
	defer func() {
		tp.Privileges[0].Attributes = 0
		_ = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	}()
	sid, err := windows.StringToSid(sidString)
	require.NoError(t, err)
	require.NoError(t, windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil))
}

// TestConfigureServiceRecovery_AppliesToNonCrashFailures creates a throwaway
// service in the real SCM and verifies the install path's recovery policy,
// including the flag that makes the launcher's non-zero service-specific exit
// code trigger the restart actions.
func TestConfigureServiceRecovery_AppliesToNonCrashFailures(t *testing.T) {
	scm, err := mgr.Connect()
	if err != nil {
		t.Skipf("skipping - requires Administrator (SCM connect failed: %v)", err)
	}
	defer func() { _ = scm.Disconnect() }()

	name := fmt.Sprintf("CFGMSRecoveryTest_%d", os.Getpid())
	s, err := scm.CreateService(name, `C:\Windows\System32\cmd.exe`, mgr.Config{StartType: mgr.StartManual})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = s.Delete()
		_ = s.Close()
	})

	require.NoError(t, configureServiceRecovery(s))

	recovery, err := s.RecoveryActions()
	require.NoError(t, err)
	require.Len(t, recovery, 3)
	for _, a := range recovery {
		assert.Equal(t, mgr.ServiceRestart, a.Type)
	}

	nonCrash, err := s.RecoveryActionsOnNonCrashFailures()
	require.NoError(t, err)
	assert.True(t, nonCrash, "recovery must apply to non-crash failures")
}
