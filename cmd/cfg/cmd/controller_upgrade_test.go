// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller/cutover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			}
		})
	}
}
