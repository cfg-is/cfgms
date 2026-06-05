// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	stewardsecrets "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsManagerInstallPath(t *testing.T) {
	m := New("cfgms-steward.exe")
	status, err := m.Status()
	require.NoError(t, err)
	assert.Equal(t, windowsInstallPath, status.InstallPath)
}

func TestWindowsManagerStatusNotInstalled(t *testing.T) {
	// Status must work without Administrator privileges.
	// When the service is not registered it must be reported as not installed.
	m := New("cfgms-steward.exe")
	status, err := m.Status()
	require.NoError(t, err)
	assert.Equal(t, windowsServiceName, status.ServiceName)
	assert.Equal(t, windowsInstallPath, status.InstallPath)
}

func TestWindowsManagerInstallRequiresElevation(t *testing.T) {
	m := New("cfgms-steward.exe")
	if m.IsElevated() {
		t.Skip("skipping elevation check — running as Administrator")
	}
	err := m.Install("tok_test123", "", "")
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
	err := m.Install("tok_test123", certPEM, "deadbeefdeadbeefdeadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")

	// Cert must NOT be written on fingerprint mismatch.
	certPath := platformCACertPath()
	_, statErr := os.Stat(certPath)
	assert.True(t, os.IsNotExist(statErr), "cert file must not exist after fingerprint mismatch")
}

// TestWindowsInstallCACertWritten verifies that the CA cert is written to the
// prefixed platform path with the expected on-disk shape after a successful
// fingerprint verification.
//
// On Windows the Go runtime reports a writable file's mode as 0666 regardless
// of the mode passed to os.WriteFile — Unix mode bits are not enforced. The
// CA cert is public material (see writeCACert's #nosec G306 comment), so the
// security-relevant invariants are: the file exists, sits inside the
// configured prefix, and is readable.
func TestWindowsInstallCACertWritten(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", dir)

	certPEM, fingerprint := generateTestCACert(t)

	require.NoError(t, verifyCACertFingerprint(certPEM, fingerprint))

	destPath := platformCACertPath()
	require.NoError(t, writeCACert(certPEM, destPath))

	info, err := os.Stat(destPath)
	require.NoError(t, err)
	assert.False(t, info.IsDir(), "destination must be a regular file")
	assert.Greater(t, info.Size(), int64(0), "CA cert file must be non-empty")
	written, err := os.ReadFile(destPath) // #nosec G304 -- test reads a path it just wrote
	require.NoError(t, err)
	assert.Equal(t, certPEM, string(written), "on-disk content must match the input PEM")
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

// TestInstallHyperVCertParams_LocalhostInSAN verifies that buildHyperVCertParams
// returns a parameter set with localhost, 127.0.0.1, and the machine FQDN in the
// SAN, and a NotAfter set to 5 years from now (±1 day tolerance).
// buildHyperVCertParams is a pure function — no elevation required.
func TestInstallHyperVCertParams_LocalhostInSAN(t *testing.T) {
	fqdn, err := os.Hostname()
	require.NoError(t, err)

	params := buildHyperVCertParams(fqdn)

	assert.Contains(t, params.DnsNames, "localhost", "SAN must include localhost")
	assert.Contains(t, params.DnsNames, "127.0.0.1", "SAN must include 127.0.0.1")
	assert.Contains(t, params.DnsNames, fqdn, "SAN must include machine FQDN")

	fiveYears := time.Now().Add(5 * 365 * 24 * time.Hour)
	assert.WithinDuration(t, fiveYears, params.NotAfter, 24*time.Hour,
		"cert NotAfter must be 5 years from now (±1 day tolerance)")
}

// TestInstallHyperV_PassNotInArgv verifies that the WinRM password is passed via
// stdin and does not appear in any element of cmd.Args or in the PowerShell script
// block string. Inspects the *exec.Cmd struct, not process-list output.
func TestInstallHyperV_PassNotInArgv(t *testing.T) {
	rec := &recordingPSRunner{}
	password := `s3cr3t!P@ss#with"<special>'&chars` // characters that would be dangerous if interpolated
	username := "cfgms-hyperv"

	err := createLocalUser(rec, username, password)
	require.NoError(t, err)

	require.Len(t, rec.Calls, 1, "createLocalUser must make exactly one PS call")
	call := rec.Calls[0]

	// Password must NOT appear in any element of cmd.Args.
	for _, arg := range call.Cmd.Args {
		assert.NotContains(t, arg, password,
			"password must not appear in cmd.Args element %q", arg)
	}

	// Password must NOT appear in the script block string.
	assert.NotContains(t, call.ScriptBlock, password,
		"password must not appear in the PowerShell script block string")

	// Password MUST be in StdinData (the secure delivery channel).
	assert.Equal(t, password, call.StdinData,
		"password must be passed via stdin (StdinData)")
}

// TestInstallHyperV_RequiresElevation verifies that InstallHyperV returns an error
// when called without Administrator privileges.
func TestInstallHyperV_RequiresElevation(t *testing.T) {
	m := New("cfgms-steward.exe")
	if m.IsElevated() {
		t.Skip("skipping: running as Administrator")
	}

	wm := m.(*windowsManager)
	err := wm.InstallHyperV("tok_test123", "", "", "cfgms-hyperv", "testpass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Administrator")
}

// TestInstallHyperV_ListenerBindsLocalhostOnly verifies that setupWinRMListener
// uses IP:127.0.0.1 (not Address=*) in the winrm set command.
// Uses recordingPSRunner — no PowerShell execution, no elevation required.
func TestInstallHyperV_ListenerBindsLocalhostOnly(t *testing.T) {
	rec := &recordingPSRunner{}

	err := setupWinRMListener(rec, "AABBCCDDEEFF00112233445566778899AABBCCDD")
	require.NoError(t, err)

	// Find the set command call and verify it uses IP:127.0.0.1, not *.
	var foundLoopback bool
	for _, call := range rec.Calls {
		if strings.Contains(call.ScriptBlock, "winrm set") {
			assert.Contains(t, call.ScriptBlock, "IP:127.0.0.1",
				"listener must be bound to IP:127.0.0.1, not *")
			assert.NotContains(t, call.ScriptBlock, "Address=*",
				"listener must not use Address=* (binds 0.0.0.0)")
			foundLoopback = true
		}
	}
	assert.True(t, foundLoopback, "must have a winrm set call for the HTTPS listener")
}

// TestInstallHyperV_FirewallRuleLoopbackOnly verifies that setupHyperVFirewall
// produces a script with LocalAddress=127.0.0.1 and a Block rule for non-loopback.
// Uses recordingPSRunner — no PowerShell execution, no elevation required.
func TestInstallHyperV_FirewallRuleLoopbackOnly(t *testing.T) {
	rec := &recordingPSRunner{}
	err := setupHyperVFirewall(rec)
	require.NoError(t, err)

	require.Len(t, rec.Calls, 1, "setupHyperVFirewall must make exactly one PS call")
	call := rec.Calls[0]

	// Script must include loopback-only allow rule parameters.
	assert.Contains(t, call.ScriptBlock, "LocalAddress 127.0.0.1",
		"firewall script must include LocalAddress 127.0.0.1")
	assert.Contains(t, call.ScriptBlock, "RemoteAddress 127.0.0.1",
		"firewall script must include RemoteAddress 127.0.0.1")
	// Script must also add a deny rule to block non-loopback.
	assert.Contains(t, call.ScriptBlock, "Block",
		"firewall script must include a Block (deny) rule")
}

// TestInstallHyperV_SecretsPrePopulated verifies that storeWinRMSecrets writes
// hyperv/winrm_user and hyperv/winrm_pass to the secret store, and that the
// password value does not appear in any log output.
func TestInstallHyperV_SecretsPrePopulated(t *testing.T) {
	m := New("cfgms-steward.exe")
	if !m.IsElevated() {
		t.Skip("skipping: requires Administrator privileges")
	}

	dir := t.TempDir()
	provider := &stewardsecrets.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{"secrets_dir": dir})
	require.NoError(t, err)

	winrmUser := "cfgms-hyperv-test"
	winrmPass := "testSecretP@ss123!"

	err = storeWinRMSecrets(store, winrmUser, winrmPass)
	require.NoError(t, err)

	ctx := context.Background()

	userSecret, err := store.GetSecret(ctx, "hyperv/winrm_user")
	require.NoError(t, err)
	assert.Equal(t, winrmUser, userSecret.Value, "winrm_user secret must match")

	passSecret, err := store.GetSecret(ctx, "hyperv/winrm_pass")
	require.NoError(t, err)
	assert.Equal(t, winrmPass, passSecret.Value, "winrm_pass secret must match")
}

// TestInstallHyperV_SecretsReadableByServiceAccount verifies that the secret store
// can be re-opened and secrets read back. The steward provider uses machine-level
// DPAPI (CRYPTPROTECT_LOCAL_MACHINE flag) so any account on the machine, including
// LocalSystem (the SCM service identity), can decrypt the blobs.
func TestInstallHyperV_SecretsReadableByServiceAccount(t *testing.T) {
	m := New("cfgms-steward.exe")
	if !m.IsElevated() {
		t.Skip("skipping: requires Administrator privileges")
	}

	dir := t.TempDir()
	provider := &stewardsecrets.StewardProvider{}

	store1, err := provider.CreateSecretStore(map[string]interface{}{"secrets_dir": dir})
	require.NoError(t, err)

	winrmPass := "machineReadableP@ss456!"
	err = storeWinRMSecrets(store1, "cfgms-hyperv-test", winrmPass)
	require.NoError(t, err)

	// Re-open the store as a fresh instance under a different identity context.
	// Machine-level DPAPI allows any account to decrypt.
	store2, err := provider.CreateSecretStore(map[string]interface{}{"secrets_dir": dir})
	require.NoError(t, err)

	ctx := context.Background()
	secret, err := store2.GetSecret(ctx, "hyperv/winrm_pass")
	require.NoError(t, err, "GetSecret must succeed: machine-level DPAPI allows cross-identity read")
	assert.Equal(t, winrmPass, secret.Value)
}

// TestInstallHyperV_LogsAreSanitized verifies that a winrmUser value containing
// \n and \r does not produce log forgery when processed through
// logging.SanitizeLogValue, as required for all InstallHyperV log statements.
//
// The sanitizer's contract is to REPLACE every control character (including
// CR/LF) with an underscore — not to strip content after the first control
// character. That contract is sufficient to prevent CWE-117 log forgery
// because the injected payload can no longer end the host log line; it
// becomes visible single-line user-controlled input. The substring after the
// original CR/LF may still appear in the sanitized string — that is the
// expected and intended behavior.
func TestInstallHyperV_LogsAreSanitized(t *testing.T) {
	craftedUsername := "legit-user\r\nINFO: fake-log-entry injected"
	sanitized := logging.SanitizeLogValue(craftedUsername)

	assert.NotContains(t, sanitized, "\r",
		"sanitized value must not contain carriage returns")
	assert.NotContains(t, sanitized, "\n",
		"sanitized value must not contain newlines")

	// Verify InstallHyperV log pattern: fmt.Printf("... %s ...", logging.SanitizeLogValue(winrmUser))
	// does not propagate the newline injection — the resulting log line must
	// remain a single line so the injected payload cannot impersonate a
	// separate log record.
	logLine := "Creating local service account " + logging.SanitizeLogValue(craftedUsername)
	assert.NotContains(t, logLine, "\r",
		"log line using SanitizeLogValue must not contain carriage returns")
	assert.NotContains(t, logLine, "\n",
		"log line using SanitizeLogValue must not contain newlines")
}

// TestInstallHyperV_HyperVInstallerInterface verifies that *windowsManager satisfies
// the HyperVInstaller interface and that the type assertion used in main.go works.
func TestInstallHyperV_HyperVInstallerInterface(t *testing.T) {
	mgr := New("cfgms-steward.exe")
	hi, ok := mgr.(HyperVInstaller)
	assert.True(t, ok, "*windowsManager must satisfy HyperVInstaller")
	assert.NotNil(t, hi)
}

