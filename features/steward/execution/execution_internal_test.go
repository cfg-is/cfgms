// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package-private genericConfigState YAML round-trip tests (TestGenericConfigState_*)
// intentionally retained in package execution per epic #730 Story 7.
// All other tests use package execution_test via export_test.go bridges.
// Rationale: genericConfigState is package-private and its tests directly construct
// &genericConfigState{data: ...}. Moving them to package execution_test would require
// either making the type public (semantic change) or a type-alias bridge — both expose
// internal details. The clean break is a documented exemption here.
package execution

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	stewardtesting "github.com/cfgis/cfgms/features/steward/testing"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestExecutor creates an Executor with injected components for package-internal tests.
// Tests in package execution_test have their own copy of this helper using the exported API.
func newTestExecutor(t *testing.T, errorConfig config.ErrorHandlingConfig) *Executor {
	t.Helper()
	registry := discovery.ModuleRegistry{}
	moduleFactory := factory.New(registry, errorConfig, logging.NewNoopLogger())
	comparator := stewardtesting.NewStateComparator()
	logger := logging.NewLogger("info")
	executor, err := NewExecutor(&ExecutorConfig{
		Logger:        logger,
		Factory:       moduleFactory,
		Comparator:    comparator,
		ErrorHandling: errorConfig,
	})
	require.NoError(t, err)
	return executor
}

func TestGenericConfigState(t *testing.T) {
	data := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	state := &genericConfigState{data: data}

	assert.Equal(t, data, state.AsMap())

	fields := state.GetManagedFields()
	assert.Len(t, fields, 3)
	assert.Contains(t, fields, "key1")
	assert.Contains(t, fields, "key2")
	assert.Contains(t, fields, "key3")

	assert.NoError(t, state.Validate())
}

func TestGenericConfigState_ToYAMLFromYAML(t *testing.T) {
	original := &genericConfigState{data: map[string]interface{}{
		"host": "localhost",
		"port": 8080,
	}}

	// ToYAML produces valid YAML
	yamlBytes, err := original.ToYAML()
	require.NoError(t, err)
	assert.NotEmpty(t, yamlBytes)

	// FromYAML round-trips the data
	restored := &genericConfigState{data: map[string]interface{}{}}
	require.NoError(t, restored.FromYAML(yamlBytes))
	assert.Equal(t, "localhost", restored.data["host"])
}

func TestGenericConfigState_ExcludesIdentifierFields(t *testing.T) {
	state := &genericConfigState{data: map[string]interface{}{
		"path":    "/etc/hosts",
		"name":    "hosts-file",
		"content": "127.0.0.1 localhost",
	}}

	fields := state.GetManagedFields()
	assert.Len(t, fields, 1)
	assert.Contains(t, fields, "content")
	assert.NotContains(t, fields, "path")
	assert.NotContains(t, fields, "name")
}

// TestGenericConfigState_ExcludesModuleOperationalKeys verifies that the
// fields used by a module to set up its transport/identity at Configure
// time — `transport`, `tenant_id`, `audit_manager`, `steward_id`, and the
// `winrm_*` credential pointers — are not surfaced as managed fields. A
// module's Get response never includes them, so leaving them in the
// comparison set produces false-positive "added" drift on every
// convergence cycle.
//
// Regression test for the #1887 live-validation finding: the hyperv module
// was creating vSwitches successfully but the executor's verification
// reported "0 changed, 2 added, 0 removed" because `transport` and
// `tenant_id` appeared as "added" relative to the module's typed
// VSwitchConfig. Without this exclusion the executor would retry forever
// (the lab accumulated 27 duplicate vSwitches before the fix).
func TestGenericConfigState_ExcludesModuleOperationalKeys(t *testing.T) {
	state := &genericConfigState{data: map[string]interface{}{
		// Identifier — pre-existing exclusion, kept here as a control.
		"path": "vswitch:test",
		"name": "test",
		// Module-operational keys — newly excluded.
		"transport":         "ps-host",
		"tenant_id":         "tenant-x",
		"steward_id":        "steward-y",
		"audit_manager":     "ignored-pointer-shaped",
		"winrm_host":        "127.0.0.1",
		"winrm_user_secret": "secret/user",
		"winrm_pass_secret": "secret/pass",
		// Actual resource state — must remain.
		"switch_type": "internal",
		"state":       "present",
	}}

	fields := state.GetManagedFields()

	// The 7 module-operational keys + the 2 identifier keys must all be
	// excluded.
	for _, key := range []string{
		"path", "name",
		"transport", "tenant_id", "steward_id", "audit_manager",
		"winrm_host", "winrm_user_secret", "winrm_pass_secret",
	} {
		assert.NotContains(t, fields, key,
			"%q is a module-operational/identifier key and must not appear in managed fields", key)
	}

	// The 2 real resource-state keys must remain.
	assert.Contains(t, fields, "switch_type")
	assert.Contains(t, fields, "state")
	assert.Len(t, fields, 2,
		"only the genuine resource-state keys should remain after exclusion; got %v", fields)
}

// TestCompareStates_DeleteConfig_ExistenceOnly locks the convergence contract
// the hyperv DELETE bucket relied on (#2027). The contract: a config declares
// the fields it manages and ONLY those are compared; a module's Get may return
// additional values the config does not set — for an absent resource, Get still
// returns a fully-typed config whose non-state fields sit at their zero values.
// Those undeclared values must NOT register as drift.
//
// Surfaced live: hv-delete.yaml declared vhd_path/switch_type on resources being
// deleted, so the comparator diffed those create-time fields against an absent
// resource's empty values and reported permanent drift — convergence "re-deleted"
// the gone resource every cycle and never settled (status ERROR). The fix is a
// MINIMAL delete config (state:absent only), which this test pins: a delete
// config declaring only `state` converges cleanly against an absent resource
// regardless of what else Get reports.
func TestCompareStates_DeleteConfig_ExistenceOnly(t *testing.T) {
	comparator := stewardtesting.NewStateComparator()

	// A minimal delete config declares only the lifecycle state (+ identity,
	// which GetManagedFields excludes).
	deleteCfg := &genericConfigState{data: map[string]interface{}{
		"name":  "demo-vm",
		"state": "absent",
	}}

	// Get of an absent VM: a fully-typed config with state=absent and the other
	// managed fields at zero values. These are values "not set by the config"
	// and must not count as drift.
	absentCurrent := &genericConfigState{data: map[string]interface{}{
		"name":      "demo-vm",
		"state":     "absent",
		"vhd_path":  "",
		"cpu_count": 0,
		"memory_mb": 0,
	}}

	drift, diff := comparator.CompareStates(absentCurrent, deleteCfg)
	assert.False(t, drift,
		"a minimal delete config must converge cleanly against an absent resource; got %+v", diff)

	// Get of a present VM still drifts against the delete config (state
	// running -> absent) so the delete is triggered.
	presentCurrent := &genericConfigState{data: map[string]interface{}{
		"name":      "demo-vm",
		"state":     "running",
		"vhd_path":  `C:\cfgms-hvtest\demo-vm.vhdx`,
		"cpu_count": 2,
		"memory_mb": 1024,
	}}
	drift, diff = comparator.CompareStates(presentCurrent, deleteCfg)
	require.True(t, drift, "a present resource must drift against a delete config so the delete runs")
	_, stateChanged := diff.ChangedFields["state"]
	assert.True(t, stateChanged, "state (running -> absent) must be the drift that triggers deletion")
}
