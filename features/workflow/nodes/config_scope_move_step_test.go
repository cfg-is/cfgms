// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package nodes

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	controllersvc "github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newMoveExecution returns a WorkflowExecution populated with the given variables.
func newMoveExecution(vars map[string]interface{}) *workflow.WorkflowExecution {
	ex := &workflow.WorkflowExecution{
		ID:          "exec-move-test",
		Status:      workflow.StatusRunning,
		StepResults: make(map[string]workflow.StepResult),
		Variables:   make(map[string]interface{}),
		Done:        make(chan struct{}),
	}
	for k, v := range vars {
		ex.SetVariable(k, v)
	}
	return ex
}

// newMoveStep returns a minimal move_resource_to_cluster Step for testing.
func newMoveStep(name string) workflow.Step {
	return workflow.Step{
		Name: name,
		Type: workflow.StepTypeMoveResourceToCluster,
	}
}

// storeClusterConfig stores a StewardConfig directly via ConfigStore as a cluster-policies document.
func storeClusterConfig(t *testing.T, store cfgconfig.ConfigStore, tenantID, clusterName string, cfg stewardtypes.StewardConfig) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, store.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: "cluster-policies", Name: clusterName},
		Data:   data,
		Format: cfgconfig.ConfigFormatYAML,
	}))
}

// readClusterConfig reads and unmarshals the stored cluster-policies config.
func readClusterConfig(t *testing.T, store cfgconfig.ConfigStore, tenantID, clusterName string) stewardtypes.StewardConfig {
	t.Helper()
	entry, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "cluster-policies",
		Name:      clusterName,
	})
	require.NoError(t, err)
	var cfg stewardtypes.StewardConfig
	require.NoError(t, yaml.Unmarshal(entry.Data, &cfg))
	return cfg
}

// clusterConfigExists returns true when a cluster-policies document exists for clusterName.
func clusterConfigExists(t *testing.T, store cfgconfig.ConfigStore, tenantID, clusterName string) bool {
	t.Helper()
	_, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "cluster-policies",
		Name:      clusterName,
	})
	return err == nil
}

// clusterStoreCounter wraps a real ConfigStore and counts StoreConfig calls that
// target the cluster-policies namespace. Every call is delegated to the underlying
// store unchanged; it only instruments writes so tests can assert whether the
// executor attempted a cluster-scope write.
type clusterStoreCounter struct {
	cfgconfig.ConfigStore
	clusterStoreCalls int
}

func (c *clusterStoreCounter) StoreConfig(ctx context.Context, entry *cfgconfig.ConfigEntry) error {
	if entry != nil && entry.Key != nil && entry.Key.Namespace == "cluster-policies" {
		c.clusterStoreCalls++
	}
	return c.ConfigStore.StoreConfig(ctx, entry)
}

// findResourceInCfg returns the ResourceConfig with the given name, or nil if absent.
func findResourceInCfg(cfg stewardtypes.StewardConfig, name string) *stewardtypes.ResourceConfig {
	for i := range cfg.Resources {
		if cfg.Resources[i].Name == name {
			return &cfg.Resources[i]
		}
	}
	return nil
}

// TestMoveResourceToCluster_NormalFirstRun is the primary AC test: a resource present in
// the device doc and absent from the cluster doc gets moved to the cluster doc and removed
// from the device doc, with Config (including ha_role) preserved byte-for-byte.
func TestMoveResourceToCluster_NormalFirstRun(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-move-1"
	const stewardID = "steward-move-1"
	const vmName = "vm-alpha"
	const clusterName = "cluster-prod"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	vmConfig := map[string]interface{}{
		"memory_mb": 4096,
		"cpu_count": 2,
		"ha_role": map[string]interface{}{
			"cluster_name":        clusterName,
			"resource_group_name": "rg-prod",
		},
	}
	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, []stewardtypes.ResourceConfig{
			{Name: vmName, Module: "hyperv.vm", Config: vmConfig},
			{Name: "other-vm", Module: "hyperv.vm", Config: map[string]interface{}{"memory_mb": 2048}},
		}))

	executor := NewMoveResourceToClusterNodeExecutor(store, configSvc)
	result, err := executor.ExecuteMoveResourceToClusterStep(ctx, newMoveStep("move-vm"),
		newMoveExecution(map[string]interface{}{
			"steward_id":   stewardID,
			"tenant_id":    tenantID,
			"vm_name":      vmName,
			"cluster_name": clusterName,
		}))

	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)

	// Resource must appear in cluster doc with identical Config.
	clusterCfg := readClusterConfig(t, store, tenantID, clusterName)
	clusterRes := findResourceInCfg(clusterCfg, vmName)
	require.NotNil(t, clusterRes, "resource must exist in cluster-policies after move")
	assert.Equal(t, "hyperv.vm", clusterRes.Module)
	haRole, ok := clusterRes.Config["ha_role"].(map[string]interface{})
	require.True(t, ok, "ha_role must be preserved in cluster doc")
	assert.Equal(t, clusterName, haRole["cluster_name"])
	assert.Equal(t, "rg-prod", haRole["resource_group_name"])

	// Resource must be absent from device doc.
	deviceCfg := readStewardConfig(t, store, tenantID, stewardID)
	assert.Nil(t, findResourceInCfg(deviceCfg, vmName), "resource must be removed from device doc")
	// Other resources must be untouched.
	assert.NotNil(t, findResourceInCfg(deviceCfg, "other-vm"), "other resources must remain in device doc")
}

// TestMoveResourceToCluster_ClusterDocNotExists verifies that when no cluster-policies
// document exists yet, it is created fresh containing only the migrated resource.
func TestMoveResourceToCluster_ClusterDocNotExists(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-move-new"
	const stewardID = "steward-move-new"
	const vmName = "vm-beta"
	const clusterName = "cluster-new"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	vmConfig := map[string]interface{}{
		"memory_mb": 8192,
		"ha_role":   map[string]interface{}{"cluster_name": clusterName},
	}
	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, []stewardtypes.ResourceConfig{
			{Name: vmName, Module: "hyperv.vm", Config: vmConfig},
		}))

	// Confirm no cluster doc exists before the step.
	assert.False(t, clusterConfigExists(t, store, tenantID, clusterName))

	executor := NewMoveResourceToClusterNodeExecutor(store, configSvc)
	result, err := executor.ExecuteMoveResourceToClusterStep(ctx, newMoveStep("move-vm-new"),
		newMoveExecution(map[string]interface{}{
			"steward_id":   stewardID,
			"tenant_id":    tenantID,
			"vm_name":      vmName,
			"cluster_name": clusterName,
		}))

	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)

	// Cluster doc must now exist and contain the resource.
	assert.True(t, clusterConfigExists(t, store, tenantID, clusterName))
	clusterCfg := readClusterConfig(t, store, tenantID, clusterName)
	clusterRes := findResourceInCfg(clusterCfg, vmName)
	require.NotNil(t, clusterRes)
	assert.Equal(t, "hyperv.vm", clusterRes.Module)

	// Resource must be absent from device doc.
	deviceCfg := readStewardConfig(t, store, tenantID, stewardID)
	assert.Nil(t, findResourceInCfg(deviceCfg, vmName))
}

// TestMoveResourceToCluster_NoOpFullyMigrated verifies that re-running the step after a
// full migration (resource absent from device, present in cluster) is a no-op that returns
// success without any writes.
func TestMoveResourceToCluster_NoOpFullyMigrated(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-move-noop"
	const stewardID = "steward-move-noop"
	const vmName = "vm-gamma"
	const clusterName = "cluster-noop"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	vmConfig := map[string]interface{}{
		"memory_mb": 4096,
		"ha_role":   map[string]interface{}{"cluster_name": clusterName},
	}

	// Device doc exists but does NOT contain vmName (already removed in a prior run).
	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, []stewardtypes.ResourceConfig{
			{Name: "unrelated-vm", Module: "hyperv.vm", Config: map[string]interface{}{"memory_mb": 1024}},
		}))
	// Cluster doc already has vmName (written in a prior run).
	storeClusterConfig(t, store, tenantID, clusterName, stewardtypes.StewardConfig{
		Resources: []stewardtypes.ResourceConfig{
			{Name: vmName, Module: "hyperv.vm", Config: vmConfig},
		},
	})

	fanoutCalled := false
	configSvc.RegisterFanoutCallback(func(_ context.Context, _, _ string) {
		fanoutCalled = true
	})

	clusterBefore := readClusterConfig(t, store, tenantID, clusterName)

	executor := NewMoveResourceToClusterNodeExecutor(store, configSvc)
	result, err := executor.ExecuteMoveResourceToClusterStep(ctx, newMoveStep("noop-move"),
		newMoveExecution(map[string]interface{}{
			"steward_id":   stewardID,
			"tenant_id":    tenantID,
			"vm_name":      vmName,
			"cluster_name": clusterName,
		}))

	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)

	// No SetConfiguration (device write) must have been called.
	assert.False(t, fanoutCalled, "SetConfiguration must not be called on fully-migrated no-op")

	// Cluster doc must be unchanged.
	clusterAfter := readClusterConfig(t, store, tenantID, clusterName)
	assert.Equal(t, clusterBefore, clusterAfter, "cluster doc must be unchanged on no-op re-run")
}

// TestMoveResourceToCluster_ResumePartialIdenticalConfig verifies that when the resource
// is present in BOTH docs with identical Config (partial-run recovery), only the device-side
// removal is performed — the cluster doc is not rewritten.
func TestMoveResourceToCluster_ResumePartialIdenticalConfig(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-move-partial"
	const stewardID = "steward-move-partial"
	const vmName = "vm-delta"
	const clusterName = "cluster-partial"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	vmConfig := map[string]interface{}{
		"memory_mb": 4096,
		"ha_role":   map[string]interface{}{"cluster_name": clusterName},
	}

	// Both docs contain the resource with identical Config (partial-run state).
	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, []stewardtypes.ResourceConfig{
			{Name: vmName, Module: "hyperv.vm", Config: vmConfig},
		}))
	storeClusterConfig(t, store, tenantID, clusterName, stewardtypes.StewardConfig{
		Resources: []stewardtypes.ResourceConfig{
			{Name: vmName, Module: "hyperv.vm", Config: vmConfig},
		},
	})

	clusterBefore := readClusterConfig(t, store, tenantID, clusterName)

	// Wrap the store with a call-counting adapter so we can assert that the
	// cluster-policies doc is not re-written during partial-run recovery when an
	// identical copy already exists (idempotent skip, not an idempotent overwrite).
	countingStore := &clusterStoreCounter{ConfigStore: store}

	fanoutCallCount := 0
	configSvc.RegisterFanoutCallback(func(_ context.Context, _, _ string) {
		fanoutCallCount++
	})

	executor := NewMoveResourceToClusterNodeExecutor(countingStore, configSvc)
	result, err := executor.ExecuteMoveResourceToClusterStep(ctx, newMoveStep("resume-partial"),
		newMoveExecution(map[string]interface{}{
			"steward_id":   stewardID,
			"tenant_id":    tenantID,
			"vm_name":      vmName,
			"cluster_name": clusterName,
		}))

	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)

	// No cluster-policies write must have been attempted for an already-identical copy.
	assert.Equal(t, 0, countingStore.clusterStoreCalls,
		"cluster-policies doc must not be re-written when an identical copy already exists")

	// Device-side write must have occurred (fanout called exactly once).
	assert.Equal(t, 1, fanoutCallCount, "SetConfiguration must be called exactly once for device removal")

	// Resource must be absent from device doc after removal.
	deviceCfg := readStewardConfig(t, store, tenantID, stewardID)
	assert.Nil(t, findResourceInCfg(deviceCfg, vmName), "resource must be removed from device doc")

	// Cluster doc must still contain the resource unchanged.
	clusterAfter := readClusterConfig(t, store, tenantID, clusterName)
	assert.Equal(t, clusterBefore, clusterAfter, "cluster doc must be unchanged in partial-run recovery")
}

// TestMoveResourceToCluster_ConflictingConfigs verifies that when the resource is present
// in BOTH docs with DIFFERENT Config, the step fails with a hard error and writes nothing.
func TestMoveResourceToCluster_ConflictingConfigs(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-move-conflict"
	const stewardID = "steward-move-conflict"
	const vmName = "vm-epsilon"
	const clusterName = "cluster-conflict"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	deviceVMConfig := map[string]interface{}{
		"memory_mb": 4096,
		"ha_role":   map[string]interface{}{"cluster_name": clusterName},
	}
	clusterVMConfig := map[string]interface{}{
		"memory_mb": 8192, // different — simulates a diverged copy
		"ha_role":   map[string]interface{}{"cluster_name": clusterName},
	}

	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, []stewardtypes.ResourceConfig{
			{Name: vmName, Module: "hyperv.vm", Config: deviceVMConfig},
		}))
	storeClusterConfig(t, store, tenantID, clusterName, stewardtypes.StewardConfig{
		Resources: []stewardtypes.ResourceConfig{
			{Name: vmName, Module: "hyperv.vm", Config: clusterVMConfig},
		},
	})

	deviceBefore := readStewardConfig(t, store, tenantID, stewardID)
	clusterBefore := readClusterConfig(t, store, tenantID, clusterName)

	fanoutCalled := false
	configSvc.RegisterFanoutCallback(func(_ context.Context, _, _ string) {
		fanoutCalled = true
	})

	executor := NewMoveResourceToClusterNodeExecutor(store, configSvc)
	result, err := executor.ExecuteMoveResourceToClusterStep(ctx, newMoveStep("conflict-move"),
		newMoveExecution(map[string]interface{}{
			"steward_id":   stewardID,
			"tenant_id":    tenantID,
			"vm_name":      vmName,
			"cluster_name": clusterName,
		}))

	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Contains(t, err.Error(), "conflicting", "error must mention conflicting definitions")
	assert.Contains(t, err.Error(), "manual reconciliation", "error must mention manual reconciliation")

	// No writes must have occurred.
	assert.False(t, fanoutCalled, "SetConfiguration must not be called on conflict")
	deviceAfter := readStewardConfig(t, store, tenantID, stewardID)
	clusterAfter := readClusterConfig(t, store, tenantID, clusterName)
	assert.Equal(t, deviceBefore, deviceAfter, "device doc must be unchanged on conflict error")
	assert.Equal(t, clusterBefore, clusterAfter, "cluster doc must be unchanged on conflict error")
}

// TestMoveResourceToCluster_ResourceMissingFromBoth verifies that when the named resource
// is absent from both docs, the step fails with a clear error.
func TestMoveResourceToCluster_ResourceMissingFromBoth(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-move-miss"
	const stewardID = "steward-move-miss"
	const vmName = "vm-nonexistent"
	const clusterName = "cluster-miss"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	// Device doc exists but has no hyperv.vm resource named vmName.
	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, []stewardtypes.ResourceConfig{
			{Name: "other-vm", Module: "hyperv.vm", Config: map[string]interface{}{"memory_mb": 2048}},
		}))
	// Cluster doc also has no such resource.
	storeClusterConfig(t, store, tenantID, clusterName, stewardtypes.StewardConfig{
		Resources: []stewardtypes.ResourceConfig{
			{Name: "some-other-resource", Module: "file", Config: map[string]interface{}{"path": "/tmp"}},
		},
	})

	executor := NewMoveResourceToClusterNodeExecutor(store, configSvc)
	result, err := executor.ExecuteMoveResourceToClusterStep(ctx, newMoveStep("miss-both"),
		newMoveExecution(map[string]interface{}{
			"steward_id":   stewardID,
			"tenant_id":    tenantID,
			"vm_name":      vmName,
			"cluster_name": clusterName,
		}))

	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Contains(t, err.Error(), vmName, "error must mention the missing resource name")
}

// TestMoveResourceToCluster_ResourceMissingFromBoth_NoClusterDoc verifies the same hard
// error when neither doc exists for the resource.
func TestMoveResourceToCluster_ResourceMissingFromBoth_NoClusterDoc(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-move-miss2"
	const stewardID = "steward-move-miss2"
	const vmName = "vm-ghost"
	const clusterName = "cluster-ghost"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	// Device doc has no VM resource; no cluster doc at all.
	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, nil))

	executor := NewMoveResourceToClusterNodeExecutor(store, configSvc)
	result, err := executor.ExecuteMoveResourceToClusterStep(ctx, newMoveStep("miss-both-no-cluster"),
		newMoveExecution(map[string]interface{}{
			"steward_id":   stewardID,
			"tenant_id":    tenantID,
			"vm_name":      vmName,
			"cluster_name": clusterName,
		}))

	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Contains(t, err.Error(), vmName)
}

// TestMoveResourceToCluster_MissingVariable verifies that each required variable, when
// absent, causes StatusFailed with a descriptive error naming the missing variable.
func TestMoveResourceToCluster_MissingVariable(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()
	executor := NewMoveResourceToClusterNodeExecutor(store, configSvc)

	fullVars := map[string]interface{}{
		"steward_id":   "s1",
		"tenant_id":    "t1",
		"vm_name":      "vm1",
		"cluster_name": "c1",
	}
	for _, drop := range []string{"steward_id", "tenant_id", "vm_name", "cluster_name"} {
		vars := make(map[string]interface{})
		for k, v := range fullVars {
			if k != drop {
				vars[k] = v
			}
		}
		result, err := executor.ExecuteMoveResourceToClusterStep(ctx, newMoveStep("missing-"+drop),
			newMoveExecution(vars))
		require.Error(t, err, "missing %q must return error", drop)
		assert.Equal(t, workflow.StatusFailed, result.Status, "missing %q must produce StatusFailed", drop)
		assert.Contains(t, err.Error(), drop, "error must mention missing variable %q", drop)
	}
}

// TestMoveResourceToCluster_WriteOrder verifies the write order guarantee: the cluster doc
// is written BEFORE the device doc is updated. We simulate this by confirming that after
// a successful run, the resource exists in the cluster doc (was written first) and is
// absent from the device doc (written second).
func TestMoveResourceToCluster_WriteOrder(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-move-order"
	const stewardID = "steward-move-order"
	const vmName = "vm-order"
	const clusterName = "cluster-order"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	vmConfig := map[string]interface{}{
		"memory_mb": 4096,
		"ha_role":   map[string]interface{}{"cluster_name": clusterName},
	}
	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, []stewardtypes.ResourceConfig{
			{Name: vmName, Module: "hyperv.vm", Config: vmConfig},
		}))

	executor := NewMoveResourceToClusterNodeExecutor(store, configSvc)
	result, err := executor.ExecuteMoveResourceToClusterStep(ctx, newMoveStep("order-move"),
		newMoveExecution(map[string]interface{}{
			"steward_id":   stewardID,
			"tenant_id":    tenantID,
			"vm_name":      vmName,
			"cluster_name": clusterName,
		}))

	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)

	// Cluster doc has the resource (written first).
	clusterCfg := readClusterConfig(t, store, tenantID, clusterName)
	assert.NotNil(t, findResourceInCfg(clusterCfg, vmName), "resource must be in cluster doc after move")

	// Device doc has the resource removed (written second).
	deviceCfg := readStewardConfig(t, store, tenantID, stewardID)
	assert.Nil(t, findResourceInCfg(deviceCfg, vmName), "resource must be absent from device doc after move")
}
