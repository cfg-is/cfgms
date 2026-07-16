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

// newHARoleExecution returns a WorkflowExecution populated with the given variables.
func newHARoleExecution(vars map[string]interface{}) *workflow.WorkflowExecution {
	ex := &workflow.WorkflowExecution{
		ID:          "exec-ha-test",
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

// newHARoleStep returns a minimal set_ha_role Step for testing.
func newHARoleStep(name string) workflow.Step {
	return workflow.Step{
		Name: name,
		Type: workflow.StepTypeSetHARole,
	}
}

// storeInitialStewardConfig stores a StewardConfig directly via ConfigStore so that
// ExecuteSetHARoleStep has a pre-existing device-scope document to read.
func storeInitialStewardConfig(t *testing.T, store cfgconfig.ConfigStore, tenantID, stewardID string, cfg stewardtypes.StewardConfig) {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, store.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: "stewards", Name: stewardID},
		Data:   data,
		Format: cfgconfig.ConfigFormatYAML,
	}))
}

// minimalStewardCfg builds the smallest StewardConfig that passes validation.
func minimalStewardCfg(stewardID string, resources []stewardtypes.ResourceConfig) stewardtypes.StewardConfig {
	return stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{
			ID:   stewardID,
			Mode: stewardtypes.ModeController,
		},
		Resources: resources,
	}
}

// readStewardConfig reads and unmarshals the stored device-scope config for verification.
func readStewardConfig(t *testing.T, store cfgconfig.ConfigStore, tenantID, stewardID string) stewardtypes.StewardConfig {
	t.Helper()
	entry, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	})
	require.NoError(t, err)
	var cfg stewardtypes.StewardConfig
	require.NoError(t, yaml.Unmarshal(entry.Data, &cfg))
	return cfg
}

// findResourceByName returns the ResourceConfig with the given name, or fails the test.
func findResourceByName(t *testing.T, cfg stewardtypes.StewardConfig, name string) stewardtypes.ResourceConfig {
	t.Helper()
	for _, r := range cfg.Resources {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("resource %q not found in steward config", name)
	return stewardtypes.ResourceConfig{}
}

// TestSetHARoleNode_SetsPersistsHARole is the REQUIRED AC test:
// a hyperv.vm resource that does not yet have ha_role gets ha_role set and
// the change is persisted via ConfigurationServiceV2.SetConfiguration.
func TestSetHARoleNode_SetsPersistsHARole(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-ha"
	const stewardID = "steward-ha-1"
	const vmName = "vm-alpha"
	const clusterName = "cluster-prod"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	// Pre-populate device config with a standalone hyperv.vm resource.
	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, []stewardtypes.ResourceConfig{
			{
				Name:   vmName,
				Module: "hyperv.vm",
				Config: map[string]interface{}{
					"memory_mb": 4096,
					"cpu_count": 2,
				},
			},
		}))

	executor := NewSetHARoleNodeExecutor(store, configSvc)
	step := newHARoleStep("promote-vm")
	execution := newHARoleExecution(map[string]interface{}{
		"steward_id":   stewardID,
		"tenant_id":    tenantID,
		"vm_name":      vmName,
		"cluster_name": clusterName,
	})

	result, err := executor.ExecuteSetHARoleStep(ctx, step, execution)
	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)

	// Verify ha_role was written to the store.
	stored := readStewardConfig(t, store, tenantID, stewardID)
	vmResource := findResourceByName(t, stored, vmName)
	haRole, ok := vmResource.Config["ha_role"].(map[string]interface{})
	require.True(t, ok, "ha_role must be a map after SetHARoleStep")
	assert.Equal(t, clusterName, haRole["cluster_name"])
	_, hasRG := haRole["resource_group_name"]
	assert.False(t, hasRG, "resource_group_name must be absent when not specified")
}

// TestSetHARoleNode_WithResourceGroupName verifies that resource_group_name is
// included in ha_role when provided as an optional variable.
func TestSetHARoleNode_WithResourceGroupName(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-ha-rg"
	const stewardID = "steward-rg"
	const vmName = "vm-beta"
	const clusterName = "cluster-prod"
	const resourceGroup = "rg-prod-vms"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, []stewardtypes.ResourceConfig{
			{Name: vmName, Module: "hyperv.vm", Config: map[string]interface{}{"memory_mb": 2048}},
		}))

	executor := NewSetHARoleNodeExecutor(store, configSvc)
	result, err := executor.ExecuteSetHARoleStep(ctx, newHARoleStep("promote-with-rg"),
		newHARoleExecution(map[string]interface{}{
			"steward_id":          stewardID,
			"tenant_id":           tenantID,
			"vm_name":             vmName,
			"cluster_name":        clusterName,
			"resource_group_name": resourceGroup,
		}))
	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)

	stored := readStewardConfig(t, store, tenantID, stewardID)
	vmResource := findResourceByName(t, stored, vmName)
	haRole, ok := vmResource.Config["ha_role"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, clusterName, haRole["cluster_name"])
	assert.Equal(t, resourceGroup, haRole["resource_group_name"])
}

// TestSetHARoleNode_IdempotentWhenAlreadySet verifies that re-running the step
// when ha_role already matches is a no-op: the result is success and no additional
// SetConfiguration write occurs (verified by checking the stored config is unchanged).
func TestSetHARoleNode_IdempotentWhenAlreadySet(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-idem"
	const stewardID = "steward-idem"
	const vmName = "vm-gamma"
	const clusterName = "cluster-ha"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	// Pre-populate with ha_role already set to the desired value.
	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, []stewardtypes.ResourceConfig{
			{
				Name:   vmName,
				Module: "hyperv.vm",
				Config: map[string]interface{}{
					"memory_mb": 4096,
					"ha_role":   map[string]interface{}{"cluster_name": clusterName},
				},
			},
		}))

	// Record the stored config before the step so we can verify it didn't change.
	before := readStewardConfig(t, store, tenantID, stewardID)

	fanoutCalled := false
	configSvc.RegisterFanoutCallback(func(_ context.Context, _, _ string) {
		fanoutCalled = true
	})

	executor := NewSetHARoleNodeExecutor(store, configSvc)
	result, err := executor.ExecuteSetHARoleStep(ctx, newHARoleStep("idempotent-promote"),
		newHARoleExecution(map[string]interface{}{
			"steward_id":   stewardID,
			"tenant_id":    tenantID,
			"vm_name":      vmName,
			"cluster_name": clusterName,
		}))
	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)

	// SetConfiguration must NOT have been called (no fanout).
	assert.False(t, fanoutCalled, "SetConfiguration must not be called when ha_role already matches")

	// Stored config must be byte-identical to before the step.
	after := readStewardConfig(t, store, tenantID, stewardID)
	assert.Equal(t, before, after, "stored config must be unchanged on idempotent re-run")
}

// TestSetHARoleNode_ResourceNotFound verifies that a missing hyperv.vm resource
// fails the step with a clear error rather than auto-creating it.
func TestSetHARoleNode_ResourceNotFound(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-miss"
	const stewardID = "steward-miss"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()

	// Steward config exists, but has no hyperv.vm resource.
	storeInitialStewardConfig(t, store, tenantID, stewardID,
		minimalStewardCfg(stewardID, []stewardtypes.ResourceConfig{
			{Name: "other-resource", Module: "file", Config: map[string]interface{}{"path": "/tmp/x"}},
		}))

	executor := NewSetHARoleNodeExecutor(store, configSvc)
	result, err := executor.ExecuteSetHARoleStep(ctx, newHARoleStep("miss-vm"),
		newHARoleExecution(map[string]interface{}{
			"steward_id":   stewardID,
			"tenant_id":    tenantID,
			"vm_name":      "nonexistent-vm",
			"cluster_name": "cluster-x",
		}))
	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Contains(t, err.Error(), "not found")
}

// TestSetHARoleNode_StewardConfigNotFound verifies that a missing device config
// document fails the step with a clear error.
func TestSetHARoleNode_StewardConfigNotFound(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	const tenantID = "tenant-nodev"
	const stewardID = "steward-nodev"

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()
	// No device config stored for stewardID.

	executor := NewSetHARoleNodeExecutor(store, configSvc)
	result, err := executor.ExecuteSetHARoleStep(ctx, newHARoleStep("miss-config"),
		newHARoleExecution(map[string]interface{}{
			"steward_id":   stewardID,
			"tenant_id":    tenantID,
			"vm_name":      "vm-x",
			"cluster_name": "cluster-x",
		}))
	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Contains(t, err.Error(), "not found")
}

// TestSetHARoleNode_MissingVariable verifies that each required variable, when
// absent, causes StatusFailed with a descriptive error.
func TestSetHARoleNode_MissingVariable(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()
	executor := NewSetHARoleNodeExecutor(store, configSvc)

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
		result, err := executor.ExecuteSetHARoleStep(ctx, newHARoleStep("missing-"+drop),
			newHARoleExecution(vars))
		require.Error(t, err, "missing %q must return error", drop)
		assert.Equal(t, workflow.StatusFailed, result.Status, "missing %q must produce StatusFailed", drop)
		assert.Contains(t, err.Error(), drop, "error must mention missing variable %q", drop)
	}
}

// TestSetHARoleNode_WrongVariableType verifies that a non-string required variable
// fails with StatusFailed.
func TestSetHARoleNode_WrongVariableType(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewNoopLogger()
	sm := pkgtesting.SetupTestStorage(t)

	configSvc := controllersvc.NewConfigurationServiceV2(logger, sm, nil)
	store := sm.GetConfigStore()
	executor := NewSetHARoleNodeExecutor(store, configSvc)

	result, err := executor.ExecuteSetHARoleStep(ctx, newHARoleStep("bad-type"),
		newHARoleExecution(map[string]interface{}{
			"steward_id":   42, // wrong type
			"tenant_id":    "t1",
			"vm_name":      "vm1",
			"cluster_name": "c1",
		}))
	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Contains(t, err.Error(), "steward_id")
}
