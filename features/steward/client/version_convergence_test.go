// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests for desired_version auto-convergence in TriggerConvergence. (Issue #2260)
//
// Tests:
//   - TestTriggerConvergence_VersionConvergence_InvokesSwapWhenVersionDiffers
//   - TestTriggerConvergence_VersionConvergence_NoOpWhenVersionMatches
//   - TestTriggerConvergence_VersionConvergence_NoOpWhenDesiredVersionAbsent
//   - TestTriggerConvergence_VersionConvergence_DowngradeGuardBlocksOlderVersion
//   - TestTriggerConvergence_VersionConvergence_AllowDowngradeInCfgPermitsOlderVersion
package client

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/pkg/version"
)

// makeVersionCfgYAML marshals a StewardConfig with the given upgrade settings
// to YAML bytes for use as lastConfigYAML in convergence tests.
func makeVersionCfgYAML(t *testing.T, desiredVersion string, allowDowngrade bool) []byte {
	t.Helper()
	cfg := stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			Upgrade: stewardconfig.UpgradeConfig{
				DesiredVersion: desiredVersion,
				AllowDowngrade: allowDowngrade,
			},
		},
	}
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	return data
}

// newClientForVersionConvergenceTest returns a TransportClient wired for version
// convergence unit tests. The injected launcherSwapFunc and executor avoid any
// real binary I/O; launcherManaged=false prevents a shutdown trigger.
func newClientForVersionConvergenceTest(
	t *testing.T,
	stagedVersion, stagedPath string,
	swapFn func(ctx context.Context, lPath, ver, bin string) error,
) *TransportClient {
	t.Helper()
	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	c := &TransportClient{
		stewardID:            "test-steward",
		tenantID:             "test-tenant",
		heartbeatStop:        make(chan struct{}),
		convergenceStop:      make(chan struct{}),
		logger:               newTestLogger(t),
		configExecutor:       exec,
		launcherSwapFunc:     swapFn,
		lastStagedVersion:    stagedVersion,
		lastStagedBinaryPath: stagedPath,
		// launcherManaged=false: successful swap must not trigger a real shutdown.
		launcherManaged: false,
	}
	return c
}

// TestTriggerConvergence_VersionConvergence_InvokesSwapWhenVersionDiffers proves
// that when desired_version differs from the running version and a matching staged
// binary exists, TriggerConvergence invokes the launcher swap with the correct
// version. (AC: required unit test with injectable launcherSwapFunc)
func TestTriggerConvergence_VersionConvergence_InvokesSwapWhenVersionDiffers(t *testing.T) {
	const desiredVersion = "v99.0.0" // clearly newer than any dev build

	var swapCalled bool
	var swappedVersion string
	swapFn := func(_ context.Context, _, ver, _ string) error {
		swapCalled = true
		swappedVersion = ver
		return nil
	}

	c := newClientForVersionConvergenceTest(t, desiredVersion, filepath.Join(t.TempDir(), "fake-steward"), swapFn)
	c.lastConfigYAML = makeVersionCfgYAML(t, desiredVersion, false)
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.True(t, swapCalled, "expected launcher swap to be invoked for desired_version mismatch")
	assert.Equal(t, desiredVersion, swappedVersion, "swap must target the desired version")
}

// TestTriggerConvergence_VersionConvergence_NoOpWhenVersionMatches proves that
// TriggerConvergence does NOT invoke the swap when the running version already
// equals desired_version. (AC: matching versions → no-op)
func TestTriggerConvergence_VersionConvergence_NoOpWhenVersionMatches(t *testing.T) {
	runningVersion := version.Short()

	swapCalled := false
	swapFn := func(_ context.Context, _, _, _ string) error {
		swapCalled = true
		return nil
	}

	c := newClientForVersionConvergenceTest(t, runningVersion, filepath.Join(t.TempDir(), "fake-steward"), swapFn)
	c.lastConfigYAML = makeVersionCfgYAML(t, runningVersion, false)
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.False(t, swapCalled, "swap must NOT be called when running version equals desired_version")
}

// TestTriggerConvergence_VersionConvergence_NoOpWhenDesiredVersionAbsent proves
// back-compat: when desired_version is absent from the config, TriggerConvergence
// proceeds normally without invoking the swap path. (AC: absent desired_version → no-op)
func TestTriggerConvergence_VersionConvergence_NoOpWhenDesiredVersionAbsent(t *testing.T) {
	swapCalled := false
	swapFn := func(_ context.Context, _, _, _ string) error {
		swapCalled = true
		return nil
	}

	c := newClientForVersionConvergenceTest(t, "", "", swapFn)
	c.lastConfigYAML = makeVersionCfgYAML(t, "", false) // no desired_version
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.False(t, swapCalled, "swap must NOT be called when desired_version is absent")
}

// TestTriggerConvergence_VersionConvergence_DowngradeGuardBlocksOlderVersion
// proves that when desired_version is older than the running version and
// AllowDowngrade is false, the swap is not invoked. (AC: downgrade guard)
func TestTriggerConvergence_VersionConvergence_DowngradeGuardBlocksOlderVersion(t *testing.T) {
	const olderVersion = "v0.0.1"

	swapCalled := false
	swapFn := func(_ context.Context, _, _, _ string) error {
		swapCalled = true
		return nil
	}

	c := newClientForVersionConvergenceTest(t, olderVersion, filepath.Join(t.TempDir(), "fake-steward"), swapFn)
	c.upgradeAllowDowngrade = false
	c.lastConfigYAML = makeVersionCfgYAML(t, olderVersion, false)
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.False(t, swapCalled, "swap must NOT be called when downgrade is blocked and desired_version is older")
}

// TestTriggerConvergence_VersionConvergence_AllowDowngradeInCfgPermitsOlderVersion
// proves that when allow_downgrade is set in the controller-delivered config, the
// swap IS invoked even when desired_version is older than the running version.
func TestTriggerConvergence_VersionConvergence_AllowDowngradeInCfgPermitsOlderVersion(t *testing.T) {
	const olderVersion = "v0.0.1"

	var swapCalled bool
	var swappedVersion string
	swapFn := func(_ context.Context, _, ver, _ string) error {
		swapCalled = true
		swappedVersion = ver
		return nil
	}

	c := newClientForVersionConvergenceTest(t, olderVersion, filepath.Join(t.TempDir(), "fake-steward"), swapFn)
	c.upgradeAllowDowngrade = false
	c.lastConfigYAML = makeVersionCfgYAML(t, olderVersion, true) // allow_downgrade set in cfg
	c.lastConfigVersion = "v1"

	err := c.TriggerConvergence(context.Background())
	require.NoError(t, err)

	assert.True(t, swapCalled, "swap MUST be called when AllowDowngrade is enabled in cfg")
	assert.Equal(t, olderVersion, swappedVersion)
}
