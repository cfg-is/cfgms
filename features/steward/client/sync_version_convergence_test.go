// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Tests that config delivery (syncConfigNow) triggers desired_version convergence,
// not just the scheduled convergence loop. (Issue #2833)
//
// Before this wiring, a freshly delivered desired_version was applied to
// lastConfigYAML but not acted on until the next scheduled convergence tick
// (up to converge_interval later). syncConfigNow is the config-change entry point
// (on-connect pull + the sync_config command), so declaring a desired_version must
// converge as soon as the new config lands.
package client

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/steward/execution"
	"github.com/cfgis/cfgms/pkg/version"
)

// buildSignedConfigBytesWithVersion returns a marshalled SignedConfig whose steward
// block carries the given desired_version. The caller wraps it in the controller's
// detached transport signature before driving syncConfigNow.
func buildSignedConfigBytesWithVersion(
	t *testing.T,
	signer signature.Signer,
	stewardID,
	desiredVersion string,
) []byte {
	t.Helper()
	return marshalSignedConfig(t, signer, &controllerpb.StewardConfig{
		Steward: &controllerpb.StewardSettings{
			Id:             stewardID,
			DesiredVersion: desiredVersion,
		},
	})
}

// TestSyncConfigNow_TriggersVersionConvergence proves that when syncConfigNow
// delivers a config whose desired_version differs from the running version and a
// matching staged binary exists, the launcher swap is invoked as part of the same
// config-delivery cycle — without waiting for the scheduled convergence tick.
// (Issue #2833: declare desired_version -> steward converges on delivery.)
func TestSyncConfigNow_TriggersVersionConvergence(t *testing.T) {
	const stewardID = "steward-delivery-converge"
	const desiredVersion = "v99.0.0" // clearly newer than any dev build

	_, signer, certPEM := newSigningCA(t)
	configData := buildSignedConfigBytesWithVersion(t, signer, stewardID, desiredVersion)
	sess := &configReturnSession{
		testDataPlaneSession: *newTestSession(),
		transfer:             buildSignedConfigTransfer(t, signer, configData, "v-delivery-1"),
	}

	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	capture := newEventCapture()
	c := newMinimalClientWithCP(t, sess, exec, capture, stewardID, "tenant-delivery-converge")
	c.signingCertPEMs = []string{certPEM}

	// Wire the version-convergence preconditions: a staged binary matching the
	// desired version and an injected swap func so no real binary I/O occurs.
	// launcherManaged=false so a successful swap does not trigger a real shutdown.
	var swapCalled bool
	var swappedVersion string
	c.mu.Lock()
	c.launcherSwapFunc = func(_ context.Context, _, ver, _ string) error {
		swapCalled = true
		swappedVersion = ver
		return nil
	}
	c.lastStagedVersion = desiredVersion
	c.lastStagedBinaryPath = filepath.Join(t.TempDir(), "fake-steward")
	c.launcherManaged = false
	c.mu.Unlock()

	require.NoError(t, c.syncConfigNow(context.Background(), "on-connect", nil),
		"syncConfigNow must succeed for a valid stored config")

	assert.True(t, swapCalled,
		"launcher swap must be invoked as part of config delivery when desired_version differs from running")
	assert.Equal(t, desiredVersion, swappedVersion,
		"swap must target the delivered desired_version")
}

// TestSyncConfigNow_NoVersionConvergenceWhenVersionMatches proves back-compat: when
// the delivered desired_version equals the running version, config delivery does not
// invoke the swap. Guards against a delivery-triggered swap loop on every sync.
func TestSyncConfigNow_NoVersionConvergenceWhenVersionMatches(t *testing.T) {
	const stewardID = "steward-delivery-noop"
	runningVersion := version.Short()

	_, signer, certPEM := newSigningCA(t)
	configData := buildSignedConfigBytesWithVersion(t, signer, stewardID, runningVersion)
	sess := &configReturnSession{
		testDataPlaneSession: *newTestSession(),
		transfer:             buildSignedConfigTransfer(t, signer, configData, "v-delivery-noop-1"),
	}

	exec, err := execution.NewExecutor(&execution.ExecutorConfig{Logger: newTestLogger(t)})
	require.NoError(t, err)

	capture := newEventCapture()
	c := newMinimalClientWithCP(t, sess, exec, capture, stewardID, "tenant-delivery-noop")
	c.signingCertPEMs = []string{certPEM}

	swapCalled := false
	c.mu.Lock()
	c.launcherSwapFunc = func(_ context.Context, _, _, _ string) error {
		swapCalled = true
		return nil
	}
	c.lastStagedVersion = runningVersion
	c.lastStagedBinaryPath = filepath.Join(t.TempDir(), "fake-steward")
	c.launcherManaged = false
	c.mu.Unlock()

	require.NoError(t, c.syncConfigNow(context.Background(), "on-connect", nil))

	assert.False(t, swapCalled,
		"swap must NOT be invoked when the delivered desired_version equals the running version")
}
