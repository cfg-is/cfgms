// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/cmd/controller/service"
	"github.com/cfgis/cfgms/features/controller/cutover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRestartManager is a test double for service.Manager that records
// StageBinaryAndRestart calls and uses caller-supplied paths.
type fakeRestartManager struct {
	installPathVal string
	stagedBinary   string
	stageFn        func(newBinaryPath, configPath string) error
}

func (f *fakeRestartManager) InstallPath() string { return f.installPathVal }
func (f *fakeRestartManager) IsElevated() bool    { return true }
func (f *fakeRestartManager) Install(_ string) error {
	return nil
}
func (f *fakeRestartManager) Uninstall(_ bool) error { return nil }
func (f *fakeRestartManager) Status() (*service.ServiceStatus, error) {
	return &service.ServiceStatus{}, nil
}
func (f *fakeRestartManager) StageBinaryAndRestart(newBinaryPath, configPath string) error {
	f.stagedBinary = newBinaryPath
	if f.stageFn != nil {
		return f.stageFn(newBinaryPath, configPath)
	}
	return nil
}

// saveRestartGlobals captures the upgrade-restart package-level vars that tests
// modify and restores them via t.Cleanup. Call at the top of every restart test.
func saveRestartGlobals(t *testing.T) {
	t.Helper()
	origBinary := upgradeBinaryPath
	origConfig := upgradeConfigPath
	origCandidateAPI := upgradeCandidateAPIAddr
	origCandidateTrans := upgradeCandidateTransAdr
	origCanonicalAPI := upgradeCanonicalAPIAddr
	origCanonicalTrans := upgradeCanonicalTransAdr
	origSmoketestTO := upgradeSmoketestTimeout
	origMgrFn := upgradeRestartMgrFn
	origSpawnFn := upgradeRestartSpawnFn
	t.Cleanup(func() {
		upgradeBinaryPath = origBinary
		upgradeConfigPath = origConfig
		upgradeCandidateAPIAddr = origCandidateAPI
		upgradeCandidateTransAdr = origCandidateTrans
		upgradeCanonicalAPIAddr = origCanonicalAPI
		upgradeCanonicalTransAdr = origCanonicalTrans
		upgradeSmoketestTimeout = origSmoketestTO
		upgradeRestartMgrFn = origMgrFn
		upgradeRestartSpawnFn = origSpawnFn
	})
}

// TestControllerUpgradeRunCmd_ExperimentalNotice asserts that the upgrade run
// subcommand's help text contains an experimental/unsupported notice referencing
// ADR-007, as required by Issue #2019 (freeze the port-swap orchestrator).
func TestControllerUpgradeRunCmd_ExperimentalNotice(t *testing.T) {
	longHelp := controllerUpgradeRunCmd.Long
	assert.True(t,
		strings.Contains(strings.ToLower(longHelp), "experimental") ||
			strings.Contains(strings.ToLower(longHelp), "not the supported"),
		"controllerUpgradeRunCmd.Long must contain an experimental / not-the-supported-path notice; got:\n%s", longHelp)
	assert.Contains(t, longHelp, "ADR-007",
		"controllerUpgradeRunCmd.Long must reference ADR-007")
}

// TestControllerUpgradeStatus_NoStateFile covers the fresh-install
// path: when the state file doesn't exist, status prints a friendly
// message and exits 0.
func TestControllerUpgradeStatus_NoStateFile(t *testing.T) {
	dir := t.TempDir()
	upgradeStatePath = filepath.Join(dir, "does-not-exist.json")
	upgradeStatusJSON = false

	err := runControllerUpgradeStatus(controllerUpgradeStatusCmd, nil)
	assert.NoError(t, err, "status against missing state file must not error")
}

// TestControllerUpgradeStatus_WithState verifies the status verb reads
// canonical + quarantined info from disk correctly.
func TestControllerUpgradeStatus_WithState(t *testing.T) {
	dir := t.TempDir()
	upgradeStatePath = filepath.Join(dir, "cutover.state.json")
	upgradeStatusJSON = false

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, cutover.SavePersistedState(upgradeStatePath, cutover.PersistedState{
		CanonicalBinary:      "/opt/cfgms/v0.5.11",
		CanonicalStartedAt:   now,
		QuarantinedBinary:    "/opt/cfgms/v0.5.10",
		QuarantinedStartedAt: now.Add(-time.Hour),
		QuarantineExpiresAt:  now.Add(time.Hour),
	}))

	err := runControllerUpgradeStatus(controllerUpgradeStatusCmd, nil)
	assert.NoError(t, err)
}

// TestControllerUpgradeStatus_JSONMode verifies --json flag is honoured.
func TestControllerUpgradeStatus_JSONMode(t *testing.T) {
	dir := t.TempDir()
	upgradeStatePath = filepath.Join(dir, "cutover.state.json")
	upgradeStatusJSON = true
	t.Cleanup(func() { upgradeStatusJSON = false })

	require.NoError(t, cutover.SavePersistedState(upgradeStatePath, cutover.PersistedState{
		CanonicalBinary:    "/opt/cfgms/v0.5.11",
		CanonicalStartedAt: time.Now().UTC().Truncate(time.Second),
	}))

	err := runControllerUpgradeStatus(controllerUpgradeStatusCmd, nil)
	assert.NoError(t, err)
}

// TestControllerUpgradeRun_RequiresBinary checks the binary flag
// validation.
func TestControllerUpgradeRun_RequiresBinary(t *testing.T) {
	upgradeBinaryPath = ""
	upgradeConfigPath = "/etc/cfgms/controller.cfg"

	err := runControllerUpgrade(controllerUpgradeRunCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--binary is required")
}

// TestControllerUpgradeRun_RequiresConfig checks the config flag
// validation.
func TestControllerUpgradeRun_RequiresConfig(t *testing.T) {
	upgradeBinaryPath = "/tmp/some-binary"
	upgradeConfigPath = ""

	err := runControllerUpgrade(controllerUpgradeRunCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--config is required")
}

// TestControllerUpgradeRun_BinaryNotAccessible verifies the
// validation surface — a bogus path must error BEFORE any side effects.
func TestControllerUpgradeRun_BinaryNotAccessible(t *testing.T) {
	dir := t.TempDir()
	upgradeBinaryPath = filepath.Join(dir, "ghost-binary")
	upgradeConfigPath = filepath.Join(dir, "ghost.cfg")
	upgradeStatePath = filepath.Join(dir, "state.json")

	err := runControllerUpgrade(controllerUpgradeRunCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not accessible")
}

// TestControllerUpgradeRollback_RequiresConfig matches the same flag
// validation as the run subcommand.
func TestControllerUpgradeRollback_RequiresConfig(t *testing.T) {
	upgradeConfigPath = ""

	err := runControllerUpgradeRollback(controllerUpgradeRollbackCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--config is required")
}

// TestControllerUpgradeRollback_NoQuarantineAvailable covers the
// failure case where there's no rollback target on disk.
func TestControllerUpgradeRollback_NoQuarantineAvailable(t *testing.T) {
	dir := t.TempDir()
	upgradeStatePath = filepath.Join(dir, "does-not-exist.json")
	upgradeConfigPath = "/etc/cfgms/controller.cfg"

	err := runControllerUpgradeRollback(controllerUpgradeRollbackCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no quarantined binary")
}

// TestControllerUpgradeCmd_FlagsRegistered confirms that all the
// expected flags are wired on each subcommand. Catches future
// refactors that would silently drop a flag.
func TestControllerUpgradeCmd_FlagsRegistered(t *testing.T) {
	for _, c := range []struct {
		name string
		want []string
	}{
		{"upgrade run", []string{"binary", "config", "state", "canonical-api-addr", "canonical-transport-addr", "candidate-api-addr", "candidate-transport-addr", "quarantine-window", "smoketest-timeout"}},
		{"upgrade status", []string{"state", "json"}},
		{"upgrade rollback", []string{"state", "config", "canonical-api-addr", "canonical-transport-addr", "candidate-api-addr", "candidate-transport-addr"}},
		{"upgrade restart", []string{"binary", "config", "canonical-api-addr", "canonical-transport-addr", "candidate-api-addr", "candidate-transport-addr", "smoketest-timeout"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			switch c.name {
			case "upgrade run":
				for _, f := range c.want {
					assert.NotNil(t, controllerUpgradeRunCmd.Flags().Lookup(f), "missing flag %q on run", f)
				}
			case "upgrade status":
				for _, f := range c.want {
					assert.NotNil(t, controllerUpgradeStatusCmd.Flags().Lookup(f), "missing flag %q on status", f)
				}
			case "upgrade rollback":
				for _, f := range c.want {
					assert.NotNil(t, controllerUpgradeRollbackCmd.Flags().Lookup(f), "missing flag %q on rollback", f)
				}
			case "upgrade restart":
				for _, f := range c.want {
					assert.NotNil(t, controllerUpgradeRestartCmd.Flags().Lookup(f), "missing flag %q on restart", f)
				}
			}
		})
	}
}

// TestControllerUpgradeRestartCmd_IsDocumentedSupportedPath verifies that the
// restart subcommand's help text identifies it as the supported production path
// and references Issue #2015.
func TestControllerUpgradeRestartCmd_IsDocumentedSupportedPath(t *testing.T) {
	longHelp := controllerUpgradeRestartCmd.Long
	assert.True(t,
		strings.Contains(strings.ToLower(longHelp), "supported") ||
			strings.Contains(strings.ToLower(longHelp), "production"),
		"controllerUpgradeRestartCmd.Long must identify the restart subcommand as the supported path; got:\n%s", longHelp)
	assert.Contains(t, longHelp, "#2015",
		"controllerUpgradeRestartCmd.Long must reference Issue #2015")
}

// TestControllerUpgradeRestart_RequiresBinary verifies --binary is required.
func TestControllerUpgradeRestart_RequiresBinary(t *testing.T) {
	saveRestartGlobals(t)
	upgradeBinaryPath = ""
	upgradeConfigPath = "/etc/cfgms/controller.cfg"

	err := runControllerUpgradeRestart(controllerUpgradeRestartCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--binary is required")
}

// TestControllerUpgradeRestart_RequiresConfig verifies --config is required.
func TestControllerUpgradeRestart_RequiresConfig(t *testing.T) {
	saveRestartGlobals(t)
	upgradeBinaryPath = "/tmp/some-binary"
	upgradeConfigPath = ""

	err := runControllerUpgradeRestart(controllerUpgradeRestartCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--config is required")
}

// TestControllerUpgradeRestart_BinaryNotAccessible verifies validation before
// any side effects.
func TestControllerUpgradeRestart_BinaryNotAccessible(t *testing.T) {
	saveRestartGlobals(t)
	dir := t.TempDir()
	upgradeBinaryPath = filepath.Join(dir, "ghost-binary")
	upgradeConfigPath = filepath.Join(dir, "ghost.cfg")

	err := runControllerUpgradeRestart(controllerUpgradeRestartCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not accessible")
}

// TestControllerUpgradeRestart_503AbortsAndRetainsPreviousBinary is the
// required test (Issue #2015): when the staged binary's /api/v1/ready returns
// 503, the upgrade must abort and the previous binary at the install path must
// be retained unchanged.
func TestControllerUpgradeRestart_503AbortsAndRetainsPreviousBinary(t *testing.T) {
	saveRestartGlobals(t)

	dir := t.TempDir()

	// Lay down a "previous" binary at the fake install path.
	installPath := filepath.Join(dir, "cfgms-controller")
	prevContent := []byte("previous binary content")
	require.NoError(t, os.WriteFile(installPath, prevContent, 0750))

	// A binary file for --binary (just needs to exist and not be a directory).
	newBinaryPath := filepath.Join(dir, "cfgms-controller-new")
	require.NoError(t, os.WriteFile(newBinaryPath, []byte("new binary content"), 0755))

	// Fake service manager: tracks whether StageBinaryAndRestart is called.
	fakeMgr := &fakeRestartManager{installPathVal: installPath}
	upgradeRestartMgrFn = func() (service.Manager, error) { return fakeMgr, nil }

	// Override the spawner: re-exec the test binary with a filter that matches
	// no test (exits 0 without binding to any port). The TLS test server below
	// already owns the candidate port, so waitForPortReady returns immediately.
	exe, err := os.Executable()
	require.NoError(t, err)
	upgradeRestartSpawnFn = func(binaryPath, configPath string) *cutover.ExecProcessHandle {
		h := cutover.NewExecProcessHandle(exe, configPath)
		h.ArgsOverride = []string{"-test.run=TestNonExistentHelperXXX_DoesNotMatch"}
		h.Stdout = io.Discard
		h.Stderr = io.Discard
		return h
	}

	// TLS server serving 503 on /api/v1/ready.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	// Point the candidate smoketest at the fake TLS server.
	upgradeBinaryPath = newBinaryPath
	upgradeConfigPath = filepath.Join(dir, "controller.cfg")
	upgradeCandidateAPIAddr = srv.Listener.Addr().String()
	upgradeSmoketestTimeout = 5 * time.Second

	err = runControllerUpgradeRestart(controllerUpgradeRestartCmd, nil)
	require.Error(t, err, "upgrade must fail when /api/v1/ready returns 503")
	assert.Contains(t, err.Error(), "503",
		"error must surface the 503 status so the operator knows why the gate rejected the binary")

	// The previous binary at the install path must be unchanged.
	got, readErr := os.ReadFile(installPath)
	require.NoError(t, readErr)
	assert.Equal(t, prevContent, got,
		"previous binary at install path must be retained when /api/v1/ready returns 503")

	// StageBinaryAndRestart must NOT have been called.
	assert.Empty(t, fakeMgr.stagedBinary,
		"StageBinaryAndRestart must not be called when the pre-restart readiness check fails")
}
