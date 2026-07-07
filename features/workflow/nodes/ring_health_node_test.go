// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package nodes

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/workflow"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// makeRingTestSteward creates a StewardData record for ring health tests.
// dna must include "deployment_ring" and optionally "steward.version".
func makeRingTestSteward(id string, dna map[string]string) fleet.StewardData {
	return fleet.StewardData{
		ID:            id,
		TenantID:      "test-tenant",
		Status:        "online",
		LastHeartbeat: time.Now(),
		DNAAttributes: dna,
	}
}

// newRingHealthStep creates a minimal Step for query_ring_health.
func newRingHealthStep(name, ring, desiredVersion string) workflow.Step {
	return workflow.Step{
		Name: name,
		Type: workflow.StepTypeQueryRingHealth,
		Config: map[string]interface{}{
			"ring":            ring,
			"desired_version": desiredVersion,
			"tenant_id":       "test-tenant",
		},
	}
}

// newRingExecution creates a fresh WorkflowExecution for testing.
func newRingExecution() *workflow.WorkflowExecution {
	return &workflow.WorkflowExecution{
		ID:           "exec-test",
		WorkflowName: "test-rollout",
		Status:       workflow.StatusRunning,
		StepResults:  make(map[string]workflow.StepResult),
		Variables:    make(map[string]interface{}),
		Done:         make(chan struct{}),
	}
}

// TestRingHealthNode_OnVersionFailedPending is the required AC test:
// given a fleet with known on-version/failed/pending stewards, the step
// returns correct on_version_pct, failed_pct, pending_count.
func TestRingHealthNode_OnVersionFailedPending(t *testing.T) {
	ctx := context.Background()
	const ring = "canary"
	const desiredVersion = "v2.0.0"
	const oldVersion = "v1.9.0"

	// Set up 10 stewards in the canary ring:
	//   5 already on v2.0.0 (on-version)
	//   3 with old version and dispatched upgrade records (pending)
	//   2 with old version and failed upgrade records (failed)
	stewards := []fleet.StewardData{
		makeRingTestSteward("s-on-1", map[string]string{"deployment_ring": ring, "steward.version": desiredVersion}),
		makeRingTestSteward("s-on-2", map[string]string{"deployment_ring": ring, "steward.version": desiredVersion}),
		makeRingTestSteward("s-on-3", map[string]string{"deployment_ring": ring, "steward.version": desiredVersion}),
		makeRingTestSteward("s-on-4", map[string]string{"deployment_ring": ring, "steward.version": desiredVersion}),
		makeRingTestSteward("s-on-5", map[string]string{"deployment_ring": ring, "steward.version": desiredVersion}),
		makeRingTestSteward("s-pend-1", map[string]string{"deployment_ring": ring, "steward.version": oldVersion}),
		makeRingTestSteward("s-pend-2", map[string]string{"deployment_ring": ring, "steward.version": oldVersion}),
		makeRingTestSteward("s-pend-3", map[string]string{"deployment_ring": ring, "steward.version": oldVersion}),
		makeRingTestSteward("s-fail-1", map[string]string{"deployment_ring": ring, "steward.version": oldVersion}),
		makeRingTestSteward("s-fail-2", map[string]string{"deployment_ring": ring, "steward.version": oldVersion}),
	}

	fleetQuery := fleet.NewMemoryQuery(&testStewardProvider{stewards: stewards})

	upgradeStore := newTestUpgradeStore()

	// Populate dispatched (pending) upgrade records.
	for _, id := range []string{"s-pend-1", "s-pend-2", "s-pend-3"} {
		rec := newTestUpgradeRecordForRing("upg-"+id, id, desiredVersion)
		require.NoError(t, upgradeStore.CreateUpgrade(ctx, rec))
	}

	// Populate failed upgrade records.
	for _, id := range []string{"s-fail-1", "s-fail-2"} {
		rec := newTestUpgradeRecordForRing("upg-"+id, id, desiredVersion)
		require.NoError(t, upgradeStore.CreateUpgrade(ctx, rec))
		require.NoError(t, upgradeStore.UpdateUpgradeStatus(ctx, "upg-"+id, business.UpgradeStatusFailed, "health check failed"))
	}

	executor := NewRingHealthNodeExecutor(fleetQuery, upgradeStore)
	step := newRingHealthStep("check-canary", ring, desiredVersion)
	execution := newRingExecution()

	result, err := executor.ExecuteRingHealthStep(ctx, step, execution)
	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)

	// Verify step outputs in the StepResult.
	require.NotNil(t, result.Output)
	assert.InDelta(t, 50.0, result.Output["on_version_pct"], 0.001, "on_version_pct should be 50%%")
	assert.InDelta(t, 20.0, result.Output["failed_pct"], 0.001, "failed_pct should be 20%%")
	assert.Equal(t, 3, result.Output["pending_count"], "pending_count should be 3")

	// Verify outputs are also set as execution variables.
	onPct, ok := execution.GetVariable("check-canary_on_version_pct")
	require.True(t, ok)
	assert.InDelta(t, 50.0, onPct, 0.001)

	failPct, ok := execution.GetVariable("check-canary_failed_pct")
	require.True(t, ok)
	assert.InDelta(t, 20.0, failPct, 0.001)

	pendCount, ok := execution.GetVariable("check-canary_pending_count")
	require.True(t, ok)
	assert.Equal(t, 3, pendCount)
}

func TestRingHealthNode_AllOnVersion(t *testing.T) {
	ctx := context.Background()
	const ring = "stable"
	const desiredVersion = "v1.5.0"

	stewards := []fleet.StewardData{
		makeRingTestSteward("s-1", map[string]string{"deployment_ring": ring, "steward.version": desiredVersion}),
		makeRingTestSteward("s-2", map[string]string{"deployment_ring": ring, "steward.version": desiredVersion}),
	}

	fleetQuery := fleet.NewMemoryQuery(&testStewardProvider{stewards: stewards})
	executor := NewRingHealthNodeExecutor(fleetQuery, nil)
	step := newRingHealthStep("check-stable", ring, desiredVersion)

	result, err := executor.ExecuteRingHealthStep(ctx, step, newRingExecution())
	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)
	assert.InDelta(t, 100.0, result.Output["on_version_pct"], 0.001)
	assert.InDelta(t, 0.0, result.Output["failed_pct"], 0.001)
	assert.Equal(t, 0, result.Output["pending_count"])
}

func TestRingHealthNode_EmptyRing(t *testing.T) {
	ctx := context.Background()
	fleetQuery := fleet.NewMemoryQuery(&testStewardProvider{stewards: []fleet.StewardData{}})
	executor := NewRingHealthNodeExecutor(fleetQuery, nil)
	step := newRingHealthStep("check-empty", "no-such-ring", "v1.0.0")

	result, err := executor.ExecuteRingHealthStep(ctx, step, newRingExecution())
	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)
	assert.InDelta(t, 0.0, result.Output["on_version_pct"], 0.001)
	assert.InDelta(t, 0.0, result.Output["failed_pct"], 0.001)
	assert.Equal(t, 0, result.Output["pending_count"])
}

func TestRingHealthNode_NilUpgradeStore_AllNonOnVersionCountedAsPending(t *testing.T) {
	ctx := context.Background()
	const ring = "early"
	const desiredVersion = "v3.0.0"

	stewards := []fleet.StewardData{
		makeRingTestSteward("s-a", map[string]string{"deployment_ring": ring, "steward.version": desiredVersion}),
		makeRingTestSteward("s-b", map[string]string{"deployment_ring": ring, "steward.version": "v2.0.0"}),
		makeRingTestSteward("s-c", map[string]string{"deployment_ring": ring, "steward.version": "v2.0.0"}),
	}

	fleetQuery := fleet.NewMemoryQuery(&testStewardProvider{stewards: stewards})
	executor := NewRingHealthNodeExecutor(fleetQuery, nil)
	step := newRingHealthStep("check-early", ring, desiredVersion)

	result, err := executor.ExecuteRingHealthStep(ctx, step, newRingExecution())
	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)
	// 1 of 3 on-version = 33.33%
	assert.InDelta(t, 33.333, result.Output["on_version_pct"], 0.01)
	// No upgrade store → failed_pct always 0
	assert.InDelta(t, 0.0, result.Output["failed_pct"], 0.001)
	// All non-on-version counted as pending
	assert.Equal(t, 2, result.Output["pending_count"])
}

func TestRingHealthNode_MissingRingConfig_ReturnsError(t *testing.T) {
	ctx := context.Background()
	fleetQuery := fleet.NewMemoryQuery(&testStewardProvider{stewards: []fleet.StewardData{}})
	executor := NewRingHealthNodeExecutor(fleetQuery, nil)

	step := workflow.Step{
		Name: "bad-step",
		Type: workflow.StepTypeQueryRingHealth,
		Config: map[string]interface{}{
			// ring is missing
			"desired_version": "v1.0.0",
			"tenant_id":       "test-tenant",
		},
	}

	result, err := executor.ExecuteRingHealthStep(ctx, step, newRingExecution())
	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Contains(t, err.Error(), "ring must not be empty")
}

func TestRingHealthNode_MissingDesiredVersionConfig_ReturnsError(t *testing.T) {
	ctx := context.Background()
	fleetQuery := fleet.NewMemoryQuery(&testStewardProvider{stewards: []fleet.StewardData{}})
	executor := NewRingHealthNodeExecutor(fleetQuery, nil)

	step := workflow.Step{
		Name: "bad-step",
		Type: workflow.StepTypeQueryRingHealth,
		Config: map[string]interface{}{
			"ring":      "canary",
			"tenant_id": "test-tenant",
			// desired_version is missing
		},
	}

	result, err := executor.ExecuteRingHealthStep(ctx, step, newRingExecution())
	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Contains(t, err.Error(), "desired_version must not be empty")
}

func TestRingHealthNode_MissingTenantIDConfig_ReturnsError(t *testing.T) {
	ctx := context.Background()
	fleetQuery := fleet.NewMemoryQuery(&testStewardProvider{stewards: []fleet.StewardData{}})
	executor := NewRingHealthNodeExecutor(fleetQuery, nil)

	step := workflow.Step{
		Name: "bad-step",
		Type: workflow.StepTypeQueryRingHealth,
		Config: map[string]interface{}{
			"ring":            "canary",
			"desired_version": "v2.0.0",
			// tenant_id is missing
		},
	}

	result, err := executor.ExecuteRingHealthStep(ctx, step, newRingExecution())
	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Contains(t, err.Error(), "tenant_id must not be empty")
}

func TestRingHealthNode_FleetQueryError_ReturnsError(t *testing.T) {
	ctx := context.Background()
	executor := NewRingHealthNodeExecutor(&errorFleetQuery{err: errTestFleetError}, nil)
	step := newRingHealthStep("check-ring", "canary", "v2.0.0")

	result, err := executor.ExecuteRingHealthStep(ctx, step, newRingExecution())
	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Contains(t, err.Error(), "fleet query failed")
}

func TestRingHealthNode_RolledBackCounted_AsFailed(t *testing.T) {
	ctx := context.Background()
	const ring = "canary"
	const desiredVersion = "v2.0.0"

	stewards := []fleet.StewardData{
		makeRingTestSteward("s-rollback", map[string]string{"deployment_ring": ring, "steward.version": "v1.0.0"}),
	}

	fleetQuery := fleet.NewMemoryQuery(&testStewardProvider{stewards: stewards})
	upgradeStore := newTestUpgradeStore()

	rec := newTestUpgradeRecordForRing("upg-rollback", "s-rollback", desiredVersion)
	require.NoError(t, upgradeStore.CreateUpgrade(ctx, rec))
	require.NoError(t, upgradeStore.UpdateUpgradeStatus(ctx, "upg-rollback", business.UpgradeStatusRolledBack, "health check failed after swap"))

	executor := NewRingHealthNodeExecutor(fleetQuery, upgradeStore)
	step := newRingHealthStep("check-rb", ring, desiredVersion)

	result, err := executor.ExecuteRingHealthStep(ctx, step, newRingExecution())
	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)
	assert.InDelta(t, 0.0, result.Output["on_version_pct"], 0.001)
	assert.InDelta(t, 100.0, result.Output["failed_pct"], 0.001)
	assert.Equal(t, 0, result.Output["pending_count"])
}

// --- helpers ---

var errTestFleetError = errRingTestStr("fleet query test error")

type errRingTestStr string

func (e errRingTestStr) Error() string { return string(e) }

// newTestUpgradeRecordForRing creates an upgrade record suitable for ring health tests.
// The record's BundleSignature is non-empty (required by the upgrade store).
func newTestUpgradeRecordForRing(id, stewardID, version string) *business.UpgradeRecord {
	return &business.UpgradeRecord{
		ID:              id,
		StewardID:       stewardID,
		TenantID:        "test-tenant",
		Version:         version,
		Platform:        "linux",
		Arch:            "amd64",
		SHA256:          "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
		Status:          business.UpgradeStatusDispatched,
		Publisher:       "cfgms",
		SignatureDigest: "deadbeef",
		BundleSignature: make([]byte, 64),
		CreatedAt:       time.Now().UTC(),
		OperationNonce:  make([]byte, 32),
		DispatchedAt:    time.Now().UTC(),
	}
}
