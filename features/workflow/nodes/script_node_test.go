// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package nodes

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// testStewardProvider implements fleet.StewardProvider for use in fleet query tests.
type testStewardProvider struct {
	stewards []fleet.StewardData
}

func (p *testStewardProvider) GetAllStewards() []fleet.StewardData {
	return p.stewards
}

func makeSteward(id, status string, attrs map[string]string) fleet.StewardData {
	return fleet.StewardData{
		ID:            id,
		TenantID:      "test-tenant",
		Status:        status,
		LastHeartbeat: time.Now(),
		DNAAttributes: attrs,
	}
}

// wireTenantFleet wires node with a real in-memory fleet query holding the given
// device IDs under tenantID, and sets that tenant on the node. Every dispatch
// path verifies its targets against the fleet and requires a non-empty tenant
// (Issue #4338), so any test that expects devices to resolve must register them.
func wireTenantFleet(node *ScriptNode, tenantID string, deviceIDs ...string) {
	node.SetFleetQuery(tenantFleetQuery(tenantID, deviceIDs...))
	node.SetTenantID(tenantID)
}

// tenantFleetQuery builds a real in-memory fleet query holding the given device
// IDs under tenantID, in the order given.
func tenantFleetQuery(tenantID string, deviceIDs ...string) fleet.FleetQuery {
	stewards := make([]fleet.StewardData, 0, len(deviceIDs))
	for _, id := range deviceIDs {
		stewards = append(stewards, fleet.StewardData{
			ID:            id,
			TenantID:      tenantID,
			Status:        "online",
			LastHeartbeat: time.Now(),
		})
	}
	return fleet.NewMemoryQuery(&testStewardProvider{stewards: stewards})
}

// errorFleetQuery is a test-local implementation of fleet.FleetQuery that
// always returns a configured error. Used to verify error propagation.
type errorFleetQuery struct {
	err error
}

func (q *errorFleetQuery) Search(_ context.Context, _ fleet.Filter) ([]fleet.StewardResult, error) {
	return nil, q.err
}

func (q *errorFleetQuery) Count(_ context.Context, _ fleet.Filter) (int, error) {
	return 0, q.err
}

// --- Execution context tests (Issue #604) ---

// TestParseScriptStepConfig_ExecutionContext verifies that execution_context is correctly
// parsed from the raw config map and stored on ScriptStepConfig.
func TestParseScriptStepConfig_ExecutionContext(t *testing.T) {
	tests := []struct {
		name      string
		configMap map[string]interface{}
		wantCtx   script.ExecutionContext
		wantErr   bool
	}{
		{
			name: "system context",
			configMap: map[string]interface{}{
				"inline_script":     "echo hello",
				"shell":             "bash",
				"execution_context": "system",
			},
			wantCtx: script.ExecutionContextSystem,
		},
		{
			name: "logged_in_user context",
			configMap: map[string]interface{}{
				"inline_script":     "echo hello",
				"shell":             "bash",
				"execution_context": "logged_in_user",
			},
			wantCtx: script.ExecutionContextLoggedInUser,
		},
		{
			name: "missing execution_context defaults to zero value",
			configMap: map[string]interface{}{
				"inline_script": "echo hello",
				"shell":         "bash",
			},
			wantCtx: script.ExecutionContext(""), // zero value; Validate() will default it to system
		},
		{
			name:      "nil map returns empty config",
			configMap: nil,
			wantCtx:   script.ExecutionContext(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseScriptStepConfig(tt.configMap)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cfg)
			assert.Equal(t, tt.wantCtx, cfg.ExecutionContext)
		})
	}
}

// TestParseScriptStepConfig_AllFields verifies that all fields including the new
// ExecutionContext are parsed correctly from a complete config map.
func TestParseScriptStepConfig_AllFields(t *testing.T) {
	configMap := map[string]interface{}{
		"script_id":           "my-script",
		"script_version":      "1.0",
		"inline_script":       "echo hello",
		"shell":               "powershell",
		"execution_context":   "logged_in_user",
		"timeout":             "30s",
		"capture_output":      true,
		"generate_api_key":    false,
		"wait_for_completion": true,
	}

	cfg, err := parseScriptStepConfig(configMap)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "my-script", cfg.ScriptID)
	assert.Equal(t, "1.0", cfg.ScriptVersion)
	assert.Equal(t, "echo hello", cfg.InlineScript)
	assert.Equal(t, script.ShellType("powershell"), cfg.Shell)
	assert.Equal(t, script.ExecutionContextLoggedInUser, cfg.ExecutionContext)
	assert.Equal(t, 30*time.Second, cfg.Timeout)
	assert.True(t, cfg.CaptureOutput)
	assert.False(t, cfg.GenerateAPIKey)
	assert.True(t, cfg.WaitForCompletion)
}

// TestScriptStepConfig_ExecutionContextField verifies the ExecutionContext field is
// present on ScriptStepConfig with the correct type (compile-time + runtime check).
func TestScriptStepConfig_ExecutionContextField(t *testing.T) {
	cfg := &ScriptStepConfig{
		InlineScript:     "echo hello",
		Shell:            script.ShellBash,
		ExecutionContext: script.ExecutionContextLoggedInUser,
	}
	assert.Equal(t, script.ExecutionContextLoggedInUser, cfg.ExecutionContext)
}

// TestScriptNode_Execute_WiresExecutionContext verifies that the ExecutionContext from
// ScriptStepConfig flows through ScriptNode.Execute to the script executor. Exercises
// the production code path at script_node.go:218 (ExecutionContext: n.config.ExecutionContext).
func TestScriptNode_Execute_WiresExecutionContext(t *testing.T) {
	shell := script.ShellBash
	if runtime.GOOS == "windows" {
		shell = script.ShellPowerShell
	}

	monitor := script.NewExecutionMonitor()
	config := &ScriptStepConfig{
		InlineScript:      "echo hello",
		Shell:             shell,
		Timeout:           10 * time.Second,
		ExecutionContext:  script.ExecutionContextSystem,
		WaitForCompletion: false,
		Devices:           []string{"test-device"},
	}
	node := NewScriptNode("test-node", "Test Script", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "test-device")

	output, err := node.Execute(context.Background(), workflow.NodeInput{})

	require.NoError(t, err, "Execute with system execution context must succeed")
	assert.True(t, output.Success, "system execution context must produce a successful output")
	require.NotNil(t, output.Data, "output must contain result data")
	assert.Contains(t, output.Data, "execution_id", "output data must include execution_id")
}

// TestParseScriptStepConfig_ExecutionContextPassedToScriptConfig verifies that the
// ExecutionContext parsed from the step config is wired through to ScriptConfig.
// This exercises the path: parseScriptStepConfig → ScriptStepConfig.ExecutionContext
// → ScriptConfig.ExecutionContext in ScriptNode.Execute.
func TestParseScriptStepConfig_ExecutionContextPassedToScriptConfig(t *testing.T) {
	configMap := map[string]interface{}{
		"inline_script":     "echo hello",
		"shell":             "bash",
		"execution_context": "logged_in_user",
	}

	stepCfg, err := parseScriptStepConfig(configMap)
	require.NoError(t, err)

	// Simulate what ScriptNode.Execute does: build a ScriptConfig from the step config
	scriptCfg := &script.ScriptConfig{
		Content:          "echo hello",
		Shell:            stepCfg.Shell,
		ExecutionContext: stepCfg.ExecutionContext, // the field under test
	}

	assert.Equal(t, script.ExecutionContextLoggedInUser, scriptCfg.ExecutionContext,
		"ExecutionContext must flow from parseScriptStepConfig → ScriptConfig")
}

// --- Secret injection tests (Issue #601) ---

// newTestStore returns a real StewardSecretStore in a temp directory.
// Skips the test when /etc/machine-id is absent (containers without platform identity).
func newTestStore(t *testing.T) interfaces.SecretStore {
	t.Helper()
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		t.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}
	provider := &steward.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": filepath.Join(t.TempDir(), "secrets"),
	})
	require.NoError(t, err)
	return store
}

// TestScriptNode_SetSecretStore verifies that SetSecretStore wires the secret
// store field on ScriptNode so it is available during execution.
func TestScriptNode_SetSecretStore(t *testing.T) {
	store := newTestStore(t)

	node := NewScriptNode("id", "name", &ScriptStepConfig{}, nil, nil, nil)
	assert.Nil(t, node.secretStore, "secretStore must be nil before SetSecretStore")

	node.SetSecretStore(store)
	assert.Equal(t, store, node.secretStore, "SetSecretStore must assign the store to the node field")
}

// TestScriptStepExecutor_SetSecretStore verifies that SetSecretStore stores the
// reference on the executor so it is propagated to created script nodes.
func TestScriptStepExecutor_SetSecretStore(t *testing.T) {
	store := newTestStore(t)

	executor := NewScriptStepExecutor(nil, nil, nil)
	assert.Nil(t, executor.secretStore, "secretStore must be nil before SetSecretStore")

	executor.SetSecretStore(store)
	assert.Equal(t, store, executor.secretStore, "SetSecretStore must assign the store to the executor field")
}

// TestParseScriptStepConfig_SecretBindings verifies that parseScriptStepConfig
// correctly deserialises secret_bindings from a raw map.
func TestParseScriptStepConfig_SecretBindings(t *testing.T) {
	rawConfig := map[string]interface{}{
		"shell":         "bash",
		"inline_script": "echo hello",
		"secret_bindings": []interface{}{
			map[string]interface{}{
				"name": "DbPassword",
				"from": "secret-store",
				"key":  "db/password",
			},
			map[string]interface{}{
				"name":  "ApiUrl",
				"from":  "literal",
				"value": "https://example.com",
			},
		},
	}

	config, err := parseScriptStepConfig(rawConfig)
	require.NoError(t, err)
	require.Len(t, config.SecretBindings, 2)

	db := config.SecretBindings[0]
	assert.Equal(t, "DbPassword", db.Name)
	assert.Equal(t, script.ParamSourceSecretStore, db.From)
	assert.Equal(t, "db/password", db.Key)

	api := config.SecretBindings[1]
	assert.Equal(t, "ApiUrl", api.Name)
	assert.Equal(t, script.ParamSourceLiteral, api.From)
	assert.Equal(t, "https://example.com", api.Value)
}

// TestParseScriptStepConfig_MalformedBinding verifies that parseScriptStepConfig
// returns an error when a secret_bindings entry is not a map (e.g. a bare string
// in YAML), so that misconfigured bindings are never silently dropped.
func TestParseScriptStepConfig_MalformedBinding(t *testing.T) {
	rawConfig := map[string]interface{}{
		"shell": "bash",
		"secret_bindings": []interface{}{
			"not-a-map", // invalid — must be map[string]interface{}
		},
	}

	config, err := parseScriptStepConfig(rawConfig)
	require.Error(t, err, "malformed binding entry must return an error, not be silently dropped")
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "secret_bindings[0]")
}

// TestParseScriptStepConfig_EmptySecretBindings verifies that parseScriptStepConfig
// returns no bindings when the key is absent.
func TestParseScriptStepConfig_EmptySecretBindings(t *testing.T) {
	config, err := parseScriptStepConfig(map[string]interface{}{
		"shell": "bash",
	})
	require.NoError(t, err)
	assert.Empty(t, config.SecretBindings)
}

// TestParseScriptStepConfig_NilInput verifies that nil input returns an empty config.
func TestParseScriptStepConfig_NilInput(t *testing.T) {
	config, err := parseScriptStepConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Empty(t, config.SecretBindings)
}

// TestScriptStepConfig_SecretBindingsYAMLTags verifies that SecretBindings
// round-trips through YAML using the "secret_bindings" key, confirming that
// the struct tag is correct and a tag typo would be caught by this test.
func TestScriptStepConfig_SecretBindingsYAMLTags(t *testing.T) {
	original := ScriptStepConfig{
		Shell: "bash",
		SecretBindings: []script.ParamBinding{
			{Name: "Token", From: script.ParamSourceSecretStore, Key: "api/token"},
		},
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)
	assert.Contains(t, string(data), "secret_bindings:", "marshalled YAML must use the secret_bindings key")

	var roundTripped ScriptStepConfig
	require.NoError(t, yaml.Unmarshal(data, &roundTripped))
	require.Len(t, roundTripped.SecretBindings, 1)
	assert.Equal(t, "Token", roundTripped.SecretBindings[0].Name)
	assert.Equal(t, script.ParamSourceSecretStore, roundTripped.SecretBindings[0].From)
	assert.Equal(t, "api/token", roundTripped.SecretBindings[0].Key)
}

// TestScriptNode_SetFleetQuery verifies that SetFleetQuery assigns the fleet
// query to the node so it is used during device resolution.
func TestScriptNode_SetFleetQuery(t *testing.T) {
	provider := &testStewardProvider{}
	q := fleet.NewMemoryQuery(provider)

	node := NewScriptNode("id", "name", &ScriptStepConfig{}, nil, nil, nil)
	assert.Nil(t, node.fleetQuery, "fleetQuery must be nil before SetFleetQuery")

	node.SetFleetQuery(q)
	assert.Equal(t, q, node.fleetQuery, "SetFleetQuery must assign the query to the node field")
}

// TestScriptStepExecutor_SetFleetQuery verifies that SetFleetQuery stores the
// reference on the executor so it is propagated to created script nodes.
func TestScriptStepExecutor_SetFleetQuery(t *testing.T) {
	provider := &testStewardProvider{}
	q := fleet.NewMemoryQuery(provider)

	executor := NewScriptStepExecutor(nil, nil, nil)
	assert.Nil(t, executor.fleetQuery, "fleetQuery must be nil before SetFleetQuery")

	executor.SetFleetQuery(q)
	assert.Equal(t, q, executor.fleetQuery, "SetFleetQuery must assign the query to the executor field")
}

// TestResolveDeviceIDs_ExplicitDevicesWin verifies that explicit Devices take
// priority over the fleet filter, once verified against the fleet and scoped to
// the execution's authenticated tenant (Issue #4338).
func TestResolveDeviceIDs_ExplicitDevicesWin(t *testing.T) {
	provider := &testStewardProvider{
		stewards: []fleet.StewardData{
			makeSteward("explicit-device-1", "online", map[string]string{"os": "linux"}),
			makeSteward("explicit-device-2", "online", map[string]string{"os": "windows"}),
			makeSteward("fleet-device", "online", map[string]string{"os": "linux"}),
		},
	}
	q := fleet.NewMemoryQuery(provider)

	node := NewScriptNode("id", "name", &ScriptStepConfig{
		Devices:      []string{"explicit-device-1", "explicit-device-2"},
		DeviceFilter: &fleet.Filter{OS: "linux"},
	}, nil, nil, nil)
	node.SetFleetQuery(q)
	node.SetTenantID("test-tenant") // matches makeSteward's fixed TenantID

	ids, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"explicit-device-1", "explicit-device-2"}, ids,
		"explicit Devices must take priority over fleet filter, verified against the fleet")
}

// TestResolveDeviceIDs_ExplicitDevice_OutsideTenant_Filtered is the REQUIRED AC
// test (Issue #4338): a device named in an explicit list that belongs to a
// different tenant than the execution's authenticated tenant is dropped from the
// resolved targets, not dispatched to.
func TestResolveDeviceIDs_ExplicitDevice_OutsideTenant_Filtered(t *testing.T) {
	provider := &testStewardProvider{
		stewards: []fleet.StewardData{
			{ID: "tenant-a-device", TenantID: "tenant-a", Status: "online", LastHeartbeat: time.Now()},
			{ID: "tenant-b-device", TenantID: "tenant-b", Status: "online", LastHeartbeat: time.Now()},
		},
	}
	q := fleet.NewMemoryQuery(provider)

	node := NewScriptNode("id", "name", &ScriptStepConfig{
		Devices: []string{"tenant-a-device", "tenant-b-device"},
	}, nil, nil, nil)
	node.SetFleetQuery(q)
	node.SetTenantID("tenant-a")

	ids, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"tenant-a-device"}, ids,
		"a device belonging to another tenant must be filtered out, not dispatched to")
}

// TestResolveDeviceIDs_ExplicitDevicesWithoutFleetQuery_FailsClosed verifies that
// an explicit device list is never dispatched unverified: without a fleet query
// there is no way to check tenant membership, so resolution errors instead of
// returning the workflow author's raw list (Issue #4338).
func TestResolveDeviceIDs_ExplicitDevicesWithoutFleetQuery_FailsClosed(t *testing.T) {
	node := NewScriptNode("id", "name", &ScriptStepConfig{
		Devices: []string{"some-device", "other-tenant-device"},
	}, nil, nil, nil)
	node.SetTenantID("tenant-a")
	// No SetFleetQuery call.

	ids, err := node.resolveDeviceIDs(context.Background())
	require.Error(t, err, "an unverifiable explicit device list must not be dispatched")
	assert.Nil(t, ids)
	assert.Contains(t, err.Error(), "no fleet query")
}

// TestResolveDeviceIDs_EmptyTenant_FailsClosed verifies that both resolution
// branches refuse to run without an authenticated tenant. An empty
// fleet.Filter.TenantID matches every tenant, so an unset tenant would make the
// fleet query fleet-wide rather than merely unscoped (Issue #4338).
func TestResolveDeviceIDs_EmptyTenant_FailsClosed(t *testing.T) {
	provider := &testStewardProvider{
		stewards: []fleet.StewardData{
			{ID: "tenant-a-device", TenantID: "tenant-a", Status: "online", LastHeartbeat: time.Now()},
			{ID: "tenant-b-device", TenantID: "tenant-b", Status: "online", LastHeartbeat: time.Now()},
		},
	}

	tests := []struct {
		name   string
		config *ScriptStepConfig
	}{
		{
			name:   "explicit devices",
			config: &ScriptStepConfig{Devices: []string{"tenant-a-device", "tenant-b-device"}},
		},
		{
			name:   "device filter",
			config: &ScriptStepConfig{DeviceFilter: &fleet.Filter{Status: "online"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := NewScriptNode("id", "name", tt.config, nil, nil, nil)
			node.SetFleetQuery(fleet.NewMemoryQuery(provider))
			// No SetTenantID call — execution carried no authenticated tenant.

			ids, err := node.resolveDeviceIDs(context.Background())
			require.Error(t, err, "an empty tenant must fail closed, not resolve across all tenants")
			assert.Nil(t, ids, "no device may be resolved without an authenticated tenant")
			assert.Contains(t, err.Error(), "no authenticated tenant_id")
		})
	}
}

// TestResolveDeviceIDs_FilterTenantMismatch_FailsClosed verifies that an
// author-supplied device_filter naming a different tenant is refused, not
// silently rewritten to the authenticated tenant (Issue #4338).
func TestResolveDeviceIDs_FilterTenantMismatch_FailsClosed(t *testing.T) {
	provider := &testStewardProvider{
		stewards: []fleet.StewardData{
			{ID: "tenant-a-device", TenantID: "tenant-a", Status: "online", LastHeartbeat: time.Now()},
			{ID: "tenant-b-device", TenantID: "tenant-b", Status: "online", LastHeartbeat: time.Now()},
		},
	}

	node := NewScriptNode("id", "name", &ScriptStepConfig{
		DeviceFilter: &fleet.Filter{TenantID: "tenant-b"},
	}, nil, nil, nil)
	node.SetFleetQuery(fleet.NewMemoryQuery(provider))
	node.SetTenantID("tenant-a")

	ids, err := node.resolveDeviceIDs(context.Background())
	require.Error(t, err, "a filter naming another tenant must be refused")
	assert.Nil(t, ids)
	assert.Contains(t, err.Error(), "does not match the execution's authenticated tenant")
}

// TestResolveDeviceIDs_FilterTenantMatch_Honoured verifies that a device_filter
// naming the authenticated tenant is accepted and its narrowing preserved.
func TestResolveDeviceIDs_FilterTenantMatch_Honoured(t *testing.T) {
	provider := &testStewardProvider{
		stewards: []fleet.StewardData{
			{ID: "tenant-a-device", TenantID: "tenant-a", Status: "online", LastHeartbeat: time.Now()},
			{ID: "tenant-b-device", TenantID: "tenant-b", Status: "online", LastHeartbeat: time.Now()},
		},
	}

	node := NewScriptNode("id", "name", &ScriptStepConfig{
		DeviceFilter: &fleet.Filter{TenantID: "tenant-a"},
	}, nil, nil, nil)
	node.SetFleetQuery(fleet.NewMemoryQuery(provider))
	node.SetTenantID("tenant-a")

	ids, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"tenant-a-device"}, ids)
}

// TestScriptStepExecutor_ExecuteStep_NoAuthenticatedTenant_FailsClosed verifies
// that an execution carrying no authenticated tenant fails the step before any
// device is resolved or dispatched — the script executor now uses the same
// requireAuthorizedTenant guard as the set_ha_role, config_scope_move and
// ring_health executors (Issue #4338).
func TestScriptStepExecutor_ExecuteStep_NoAuthenticatedTenant_FailsClosed(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	q := script.NewExecutionQueue(monitor, nil, 0, "", script.NewInMemoryQueueStore(), nil, 0)
	defer q.Stop()

	executor := NewScriptStepExecutor(nil, monitor, nil)
	executor.SetExecutionQueue(q)
	executor.SetFleetQuery(tenantFleetQuery("tenant-a", "tenant-a-device"))

	step := workflow.Step{
		Name: "no-tenant-step",
		Config: map[string]interface{}{
			"script_id": "test-script",
			"shell":     "bash",
			"devices":   []interface{}{"tenant-a-device"},
		},
	}

	execution := &workflow.WorkflowExecution{
		ID:          "exec-no-tenant",
		Status:      workflow.StatusRunning,
		StepResults: make(map[string]workflow.StepResult),
		Variables:   make(map[string]interface{}),
		// TenantID deliberately empty: ExecuteWorkflow was called with a context
		// carrying no authenticated tenant.
		Done: make(chan struct{}),
	}

	result, err := executor.ExecuteStep(context.Background(), step, execution)
	require.Error(t, err, "a step with no authenticated tenant must fail closed")
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Contains(t, err.Error(), "no authenticated tenant_id")
	assert.Equal(t, 0, q.GetQueueDepth("tenant-a-device"),
		"nothing may be dispatched when the execution has no authenticated tenant")
	assert.Empty(t, monitor.ListExecutions(""),
		"no execution may be started when the execution has no authenticated tenant")
}

// TestScriptStepExecutor_ExecuteStep_FilterTenantMismatch_FailsClosed verifies
// that a step whose device_filter names a tenant other than the execution's
// authenticated tenant is refused outright (Issue #4338).
func TestScriptStepExecutor_ExecuteStep_FilterTenantMismatch_FailsClosed(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	q := script.NewExecutionQueue(monitor, nil, 0, "", script.NewInMemoryQueueStore(), nil, 0)
	defer q.Stop()

	executor := NewScriptStepExecutor(nil, monitor, nil)
	executor.SetExecutionQueue(q)
	executor.SetFleetQuery(tenantFleetQuery("tenant-b", "tenant-b-device"))

	step := workflow.Step{
		Name: "cross-tenant-step",
		Config: map[string]interface{}{
			"script_id":     "test-script",
			"shell":         "bash",
			"device_filter": map[string]interface{}{"tenant_id": "tenant-b"},
		},
	}

	execution := &workflow.WorkflowExecution{
		ID:          "exec-cross-tenant",
		Status:      workflow.StatusRunning,
		StepResults: make(map[string]workflow.StepResult),
		Variables:   make(map[string]interface{}),
		TenantID:    "tenant-a",
		Done:        make(chan struct{}),
	}

	result, err := executor.ExecuteStep(context.Background(), step, execution)
	require.Error(t, err, "a device_filter naming another tenant must fail the step")
	assert.Equal(t, workflow.StatusFailed, result.Status)
	assert.Equal(t, 0, q.GetQueueDepth("tenant-b-device"),
		"no device of the named foreign tenant may be dispatched to")
}

// TestResolveDeviceIDs_FleetFilter verifies that the fleet filter is used to
// resolve device IDs when no explicit devices are configured.
func TestResolveDeviceIDs_FleetFilter(t *testing.T) {
	provider := &testStewardProvider{
		stewards: []fleet.StewardData{
			makeSteward("linux-1", "online", map[string]string{"os": "linux"}),
			makeSteward("linux-2", "online", map[string]string{"os": "linux"}),
			makeSteward("win-1", "online", map[string]string{"os": "windows"}),
		},
	}
	q := fleet.NewMemoryQuery(provider)

	node := NewScriptNode("id", "name", &ScriptStepConfig{
		DeviceFilter: &fleet.Filter{OS: "linux"},
	}, nil, nil, nil)
	node.SetFleetQuery(q)
	node.SetTenantID("test-tenant")

	ids, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err)
	require.Len(t, ids, 2)
	assert.Contains(t, ids, "linux-1")
	assert.Contains(t, ids, "linux-2")
}

// TestResolveDeviceIDs_NoTargetConfigured_ReturnsError verifies that resolving
// devices fails closed — no localhost in-process fallback — when neither
// explicit devices nor a device filter are configured (Issue #4338).
func TestResolveDeviceIDs_NoTargetConfigured_ReturnsError(t *testing.T) {
	node := NewScriptNode("id", "name", &ScriptStepConfig{}, nil, nil, nil)
	node.SetTenantID("test-tenant")

	ids, err := node.resolveDeviceIDs(context.Background())
	require.Error(t, err, "no resolvable target must be a hard error, not an implicit localhost fallback")
	assert.Nil(t, ids)
	assert.Contains(t, err.Error(), "no devices or device_filter configured")
}

// TestResolveDeviceIDs_ZeroMatch verifies that a fleet filter matching no
// devices returns (nil, nil) — zero-match is success with a warning, not an error.
func TestResolveDeviceIDs_ZeroMatch(t *testing.T) {
	provider := &testStewardProvider{
		stewards: []fleet.StewardData{
			makeSteward("win-1", "online", map[string]string{"os": "windows"}),
		},
	}
	q := fleet.NewMemoryQuery(provider)

	node := NewScriptNode("id", "name", &ScriptStepConfig{
		DeviceFilter: &fleet.Filter{OS: "linux"}, // no linux devices
	}, nil, nil, nil)
	node.SetFleetQuery(q)
	node.SetTenantID("test-tenant")

	ids, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err, "zero-match must not return an error")
	assert.Empty(t, ids, "zero-match must return an empty ID list")
}

// TestResolveDeviceIDs_FilterWithoutFleetQuery verifies that when a device
// filter is set but no fleet query is injected, resolution fails closed instead
// of falling back to localhost (Issue #4338).
func TestResolveDeviceIDs_FilterWithoutFleetQuery(t *testing.T) {
	node := NewScriptNode("id", "name", &ScriptStepConfig{
		DeviceFilter: &fleet.Filter{OS: "linux"},
	}, nil, nil, nil)
	node.SetTenantID("test-tenant")
	// No SetFleetQuery call.

	ids, err := node.resolveDeviceIDs(context.Background())
	require.Error(t, err, "a device_filter that cannot be resolved must not fall back to localhost")
	assert.Nil(t, ids)
	assert.Contains(t, err.Error(), "no fleet query")
}

// TestResolveDeviceIDs_ReEvaluatedEachCall verifies that the fleet filter is
// re-evaluated on every resolveDeviceIDs call, so recurring workflows pick up
// newly registered devices without node recreation.
func TestResolveDeviceIDs_ReEvaluatedEachCall(t *testing.T) {
	provider := &testStewardProvider{
		stewards: []fleet.StewardData{
			makeSteward("device-1", "online", map[string]string{"os": "linux"}),
		},
	}
	q := fleet.NewMemoryQuery(provider)

	node := NewScriptNode("id", "name", &ScriptStepConfig{
		DeviceFilter: &fleet.Filter{OS: "linux"},
	}, nil, nil, nil)
	node.SetFleetQuery(q)
	node.SetTenantID("test-tenant")

	ids1, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err)
	assert.Len(t, ids1, 1)

	// Add a new device to the provider.
	provider.stewards = append(provider.stewards,
		makeSteward("device-2", "online", map[string]string{"os": "linux"}),
	)

	ids2, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err)
	assert.Len(t, ids2, 2, "second call must re-evaluate the filter and see the new device")
}

// TestScriptStepConfig_DeviceFilter_UsesFleetFilter verifies that
// ScriptStepConfig.DeviceFilter is typed as *fleet.Filter (not a local struct).
func TestScriptStepConfig_DeviceFilter_UsesFleetFilter(t *testing.T) {
	f := &fleet.Filter{
		OS:           "linux",
		Architecture: "amd64",
		Tags:         []string{"production"},
		Status:       "online",
	}
	cfg := ScriptStepConfig{DeviceFilter: f}
	assert.Equal(t, f, cfg.DeviceFilter)
}

// TestResolveDeviceIDs_FleetQueryError verifies that a fleet query error is
// propagated as an error from resolveDeviceIDs (not silently swallowed).
func TestResolveDeviceIDs_FleetQueryError(t *testing.T) {
	sentinel := fmt.Errorf("fleet backend unavailable")
	node := NewScriptNode("id", "name", &ScriptStepConfig{
		DeviceFilter: &fleet.Filter{OS: "linux"},
	}, nil, nil, nil)
	node.SetFleetQuery(&errorFleetQuery{err: sentinel})
	node.SetTenantID("test-tenant")

	ids, err := node.resolveDeviceIDs(context.Background())
	require.Error(t, err, "fleet query error must be returned, not swallowed")
	assert.Contains(t, err.Error(), "fleet query failed")
	assert.Contains(t, err.Error(), sentinel.Error())
	assert.Nil(t, ids)
}

// TestParseScriptStepConfig_DeviceFilter verifies that parseScriptStepConfig
// correctly deserialises all device_filter sub-fields into a *fleet.Filter.
func TestParseScriptStepConfig_DeviceFilter(t *testing.T) {
	rawConfig := map[string]interface{}{
		"shell":         "bash",
		"inline_script": "echo hello",
		"device_filter": map[string]interface{}{
			"tenant_id":    "msp-a/client-1",
			"os":           "linux",
			"platform":     "ubuntu",
			"architecture": "amd64",
			"status":       "online",
			"hostname":     "web-server",
			"tags":         []interface{}{"production", "web"},
			"dna_attributes": map[string]interface{}{
				"env":    "prod",
				"region": "us-east-1",
			},
		},
	}

	config, err := parseScriptStepConfig(rawConfig)
	require.NoError(t, err)
	require.NotNil(t, config.DeviceFilter, "DeviceFilter must be populated")

	f := config.DeviceFilter
	assert.Equal(t, "msp-a/client-1", f.TenantID)
	assert.Equal(t, "linux", f.OS)
	assert.Equal(t, "ubuntu", f.Platform)
	assert.Equal(t, "amd64", f.Architecture)
	assert.Equal(t, "online", f.Status)
	assert.Equal(t, "web-server", f.Hostname)
	assert.Equal(t, []string{"production", "web"}, f.Tags)
	assert.Equal(t, map[string]string{"env": "prod", "region": "us-east-1"}, f.DNAAttributes)
}

// TestParseScriptStepConfig_DeviceFilter_Absent verifies that a missing
// device_filter key results in a nil DeviceFilter (not an empty struct).
func TestParseScriptStepConfig_DeviceFilter_Absent(t *testing.T) {
	config, err := parseScriptStepConfig(map[string]interface{}{
		"shell": "bash",
	})
	require.NoError(t, err)
	assert.Nil(t, config.DeviceFilter, "DeviceFilter must be nil when not specified")
}

// --- ExecutionQueue wiring tests (Issue #633) ---

// newTestQueue creates a real ExecutionQueue backed by an InMemoryQueueStore for testing.
func newTestQueue(t *testing.T) *script.ExecutionQueue {
	t.Helper()
	monitor := script.NewExecutionMonitor()
	q := script.NewExecutionQueue(monitor, nil, 0, "", script.NewInMemoryQueueStore(), nil, 0)
	t.Cleanup(q.Stop)
	return q
}

// TestScriptNode_SetExecutionQueue verifies that SetExecutionQueue assigns the queue
// to the node field so it is used during Execute.
func TestScriptNode_SetExecutionQueue(t *testing.T) {
	q := newTestQueue(t)

	node := NewScriptNode("id", "name", &ScriptStepConfig{}, nil, nil, nil)
	assert.Nil(t, node.executionQueue, "executionQueue must be nil before SetExecutionQueue")

	node.SetExecutionQueue(q)
	assert.Equal(t, q, node.executionQueue, "SetExecutionQueue must assign the queue to the node field")
}

// TestScriptStepExecutor_SetExecutionQueue verifies that SetExecutionQueue stores the
// reference on the executor so it is propagated to created script nodes.
func TestScriptStepExecutor_SetExecutionQueue(t *testing.T) {
	q := newTestQueue(t)

	executor := NewScriptStepExecutor(nil, nil, nil)
	assert.Nil(t, executor.executionQueue, "executionQueue must be nil before SetExecutionQueue")

	executor.SetExecutionQueue(q)
	assert.Equal(t, q, executor.executionQueue, "SetExecutionQueue must assign the queue to the executor field")
}

// TestScriptNode_Execute_DoesNotDispatchToDeviceOutsideTenant is the REQUIRED AC
// test (Issue #4338): a script step naming a device outside the execution's
// tenant does not dispatch to it — verified end-to-end through Execute and the
// execution queue, not just resolveDeviceIDs in isolation.
func TestScriptNode_Execute_DoesNotDispatchToDeviceOutsideTenant(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	store := script.NewInMemoryQueueStore()
	q := script.NewExecutionQueue(monitor, nil, 0, "", store, nil, 0)
	defer q.Stop()

	provider := &testStewardProvider{
		stewards: []fleet.StewardData{
			{ID: "own-device", TenantID: "tenant-owner", Status: "online", LastHeartbeat: time.Now()},
			{ID: "other-tenant-device", TenantID: "tenant-attacker", Status: "online", LastHeartbeat: time.Now()},
		},
	}
	fq := fleet.NewMemoryQuery(provider)

	config := &ScriptStepConfig{
		ScriptID: "my-script",
		Shell:    script.ShellBash,
		Devices:  []string{"own-device", "other-tenant-device"},
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	node.SetFleetQuery(fq)
	node.SetTenantID("tenant-owner")
	node.SetExecutionQueue(q)

	output, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)
	assert.True(t, output.Success)
	assert.Equal(t, 1, output.Data["queued"], "only the in-tenant device must be dispatched")

	assert.Equal(t, 1, q.GetQueueDepth("own-device"), "own-device must be queued")
	assert.Equal(t, 0, q.GetQueueDepth("other-tenant-device"),
		"device outside the execution's tenant must not be dispatched to")
}

// TestScriptNode_Execute_NoResolvableTarget_FailsClosed is the REQUIRED AC test
// (Issue #4338): a script step with no fleet query and no resolvable target
// returns an error and executes nothing, in particular nothing on the controller
// host — the removed localhost in-process fallback must never run.
func TestScriptNode_Execute_NoResolvableTarget_FailsClosed(t *testing.T) {
	monitor := script.NewExecutionMonitor()

	config := &ScriptStepConfig{
		InlineScript: "echo should-never-run",
		Shell:        script.ShellBash,
		Timeout:      5 * time.Second,
		// No Devices, no DeviceFilter, no fleet query wired.
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)

	output, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.Error(t, err, "a step with no resolvable target must fail closed")
	assert.False(t, output.Success)
	assert.Empty(t, monitor.ListExecutions(""),
		"no execution must be started — nothing may run on the controller host when no target resolves")
}

// TestScriptNode_Execute_QueueDispatch verifies that when an ExecutionQueue is wired,
// ScriptNode.Execute enqueues one entry per device instead of executing inline.
func TestScriptNode_Execute_QueueDispatch(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	store := script.NewInMemoryQueueStore()
	q := script.NewExecutionQueue(monitor, nil, 0, "", store, nil, 0)
	defer q.Stop()

	config := &ScriptStepConfig{
		ScriptID: "my-script",
		Shell:    script.ShellBash,
		Devices:  []string{"device-1", "device-2"},
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "device-1", "device-2")
	node.SetExecutionQueue(q)

	output, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)
	assert.True(t, output.Success, "Execute with queue must return success")
	assert.Equal(t, 2, output.Data["queued"], "queued count must equal number of target devices")

	// Each device must have a queue entry.
	assert.Equal(t, 1, q.GetQueueDepth("device-1"), "device-1 must have one queued entry")
	assert.Equal(t, 1, q.GetQueueDepth("device-2"), "device-2 must have one queued entry")
}

// TestScriptNode_Execute_NoContentResolution_WithQueue verifies that script content is
// NOT resolved inside ScriptNode.Execute when a queue is configured — no repository required.
func TestScriptNode_Execute_NoContentResolution_WithQueue(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	q := script.NewExecutionQueue(monitor, nil, 0, "", script.NewInMemoryQueueStore(), nil, 0)
	defer q.Stop()

	// No repository wired — would panic on content resolution if attempted.
	config := &ScriptStepConfig{
		ScriptID: "repo-script",
		Shell:    script.ShellBash,
		Devices:  []string{"device-1"},
	}
	node := NewScriptNode("id", "name", config, nil /* no repository */, monitor, nil)
	wireTenantFleet(node, "test-tenant", "device-1")
	node.SetExecutionQueue(q)

	output, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err, "Execute must not attempt content resolution when queue is set")
	assert.True(t, output.Success)

	entries := q.PeekForDevice("device-1")
	require.Len(t, entries, 1)
	assert.Equal(t, "repo-script", entries[0].ScriptRef,
		"ScriptRef must be set from ScriptID without resolving content")
}

// TestScriptNode_Execute_WorkflowRunIDInQueueMetadata verifies that workflow_run_id and
// workflow_name from input.Context are stored in the queue entry Metadata.
func TestScriptNode_Execute_WorkflowRunIDInQueueMetadata(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	store := script.NewInMemoryQueueStore()
	q := script.NewExecutionQueue(monitor, nil, 0, "", store, nil, 0)
	defer q.Stop()

	config := &ScriptStepConfig{
		ScriptID: "my-script",
		Shell:    script.ShellBash,
		Devices:  []string{"device-1"},
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "device-1")
	node.SetExecutionQueue(q)

	output, err := node.Execute(context.Background(), workflow.NodeInput{
		Context: map[string]interface{}{
			"workflow_run_id": "run-abc-123",
			"workflow_name":   "deploy-workflow",
		},
	})
	require.NoError(t, err)
	assert.True(t, output.Success)

	entries := q.PeekForDevice("device-1")
	require.Len(t, entries, 1)
	assert.Equal(t, "run-abc-123", entries[0].Metadata["workflow_run_id"],
		"workflow_run_id must be stored in queue entry metadata")
	assert.Equal(t, "deploy-workflow", entries[0].Metadata["workflow_name"],
		"workflow_name must be stored in queue entry metadata")
}

// TestScriptNode_Execute_WorkflowRunID_OmittedWhenAbsent verifies that workflow_run_id
// is simply absent from metadata when not present in input.Context (ad-hoc execution).
func TestScriptNode_Execute_WorkflowRunID_OmittedWhenAbsent(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	q := script.NewExecutionQueue(monitor, nil, 0, "", script.NewInMemoryQueueStore(), nil, 0)
	defer q.Stop()

	config := &ScriptStepConfig{
		ScriptID: "my-script",
		Shell:    script.ShellBash,
		Devices:  []string{"device-1"},
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "device-1")
	node.SetExecutionQueue(q)

	// Empty context — no workflow_run_id.
	output, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)
	assert.True(t, output.Success)

	entries := q.PeekForDevice("device-1")
	require.Len(t, entries, 1)
	_, hasRunID := entries[0].Metadata["workflow_run_id"]
	assert.False(t, hasRunID, "workflow_run_id must not appear in metadata for ad-hoc executions")
}

// TestScriptNode_Execute_QueueDedup verifies that a second dispatch with identical
// script+device+params does not create a duplicate queue entry.
func TestScriptNode_Execute_QueueDedup(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	store := script.NewInMemoryQueueStore()
	q := script.NewExecutionQueue(monitor, nil, 0, "", store, nil, 0)
	defer q.Stop()

	config := &ScriptStepConfig{
		ScriptID: "my-script",
		Shell:    script.ShellBash,
		Devices:  []string{"device-1"},
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "device-1")
	node.SetExecutionQueue(q)

	// First dispatch.
	output1, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)
	assert.True(t, output1.Success)

	// Second dispatch — identical script+device+params.
	output2, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)
	assert.True(t, output2.Success, "duplicate dispatch must still return success")

	// Queue depth must remain 1 — dedup silently discards the second enqueue.
	assert.Equal(t, 1, q.GetQueueDepth("device-1"),
		"dedup must prevent a second identical entry from entering the queue")
}

// TestScriptNode_Execute_QueueDedup_NoOrphanedMonitorEntries verifies that duplicate
// dispatch does not leak orphaned entries in the execution monitor. When QueueExecution
// detects a duplicate, the monitor entry created by StartExecution must be cancelled
// so it doesn't accumulate indefinitely.
func TestScriptNode_Execute_QueueDedup_NoOrphanedMonitorEntries(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	store := script.NewInMemoryQueueStore()
	q := script.NewExecutionQueue(monitor, nil, 0, "", store, nil, 0)
	defer q.Stop()

	config := &ScriptStepConfig{
		ScriptID: "my-script",
		Shell:    script.ShellBash,
		Devices:  []string{"device-1"},
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "device-1")
	node.SetExecutionQueue(q)

	// First dispatch — creates one monitor entry (running).
	output1, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)
	assert.True(t, output1.Success)

	execsBefore := monitor.ListExecutions("")
	runningBefore := 0
	for _, e := range execsBefore {
		if e.Status == script.StatusRunning {
			runningBefore++
		}
	}
	assert.Equal(t, 1, runningBefore, "first dispatch should create exactly 1 running execution")

	// Second dispatch — duplicate. Should NOT leave an orphaned running entry.
	output2, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)
	assert.True(t, output2.Success)

	execsAfter := monitor.ListExecutions("")
	runningAfter := 0
	cancelledCount := 0
	for _, e := range execsAfter {
		if e.Status == script.StatusRunning {
			runningAfter++
		}
		if e.Status == script.StatusCancelled {
			cancelledCount++
		}
	}

	// Only the original execution should be running. The dedup entry must be cancelled.
	assert.Equal(t, 1, runningAfter,
		"duplicate dispatch must not leave orphaned running monitor entries")
	assert.Equal(t, 1, cancelledCount,
		"duplicate dispatch should produce exactly 1 cancelled monitor entry")
}

// TestScriptNode_Execute_CatchUpDequeue verifies the catch-up path: entries queued
// while a device was offline are returned by DequeueForDevice when the device reconnects.
func TestScriptNode_Execute_CatchUpDequeue(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	store := script.NewInMemoryQueueStore()
	q := script.NewExecutionQueue(monitor, nil, 0, "", store, nil, 0)
	defer q.Stop()

	config := &ScriptStepConfig{
		ScriptID: "my-script",
		Shell:    script.ShellBash,
		Devices:  []string{"offline-device"},
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "offline-device")
	node.SetExecutionQueue(q)

	// Queue execution while device is "offline".
	_, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)
	assert.Equal(t, 1, q.GetQueueDepth("offline-device"), "entry must be queued")

	// Simulate device coming online: dequeue.
	entries, err := q.DequeueForDevice("offline-device")
	require.NoError(t, err)
	require.Len(t, entries, 1, "catch-up dequeue must return the queued entry")
	assert.Equal(t, "my-script", entries[0].ScriptRef,
		"dequeued entry must carry the correct ScriptRef for repository lookup at dispatch time")
}

// TestScriptNode_Execute_ExecutionContextInQueue verifies that ExecutionContext is
// carried through to the queue entry so the steward receives the correct run-as context.
func TestScriptNode_Execute_ExecutionContextInQueue(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	q := script.NewExecutionQueue(monitor, nil, 0, "", script.NewInMemoryQueueStore(), nil, 0)
	defer q.Stop()

	config := &ScriptStepConfig{
		ScriptID:         "my-script",
		Shell:            script.ShellBash,
		Devices:          []string{"device-1"},
		ExecutionContext: script.ExecutionContextLoggedInUser,
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "device-1")
	node.SetExecutionQueue(q)

	output, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)
	assert.True(t, output.Success)

	entries := q.PeekForDevice("device-1")
	require.Len(t, entries, 1)
	assert.Equal(t, script.ExecutionContextLoggedInUser, entries[0].ExecutionContext,
		"ExecutionContext must be carried into the queue entry")
}

// TestScriptNode_Execute_NilQueue_InlineFallback verifies that when executionQueue is nil,
// the existing inline execution path is used unchanged (backward compatibility).
func TestScriptNode_Execute_NilQueue_InlineFallback(t *testing.T) {
	shell := script.ShellBash
	if runtime.GOOS == "windows" {
		shell = script.ShellPowerShell
	}

	monitor := script.NewExecutionMonitor()
	config := &ScriptStepConfig{
		InlineScript: "echo fallback",
		Shell:        shell,
		Timeout:      10 * time.Second,
		Devices:      []string{"fallback-device"},
	}
	// No queue set — executionQueue is nil.
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "fallback-device")

	output, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err, "nil queue must fall through to inline execution without error")
	assert.True(t, output.Success, "inline execution must succeed")
	assert.Contains(t, output.Data, "execution_id", "inline path must return execution_id")
}

// TestScriptStepExecutor_ExecuteStep_WorkflowRunIDPropagated verifies that
// variables["workflow_run_id"] and variables["workflow_name"] from the step variables
// map are propagated into input.Context and then into queue entry metadata.
func TestScriptStepExecutor_ExecuteStep_WorkflowRunIDPropagated(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	store := script.NewInMemoryQueueStore()
	q := script.NewExecutionQueue(monitor, nil, 0, "", store, nil, 0)
	defer q.Stop()

	executor := NewScriptStepExecutor(nil, monitor, nil)
	executor.SetExecutionQueue(q)
	executor.SetFleetQuery(tenantFleetQuery("test-tenant", "device-1"))

	step := workflow.Step{
		Name: "test-step",
		Config: map[string]interface{}{
			"script_id": "test-script",
			"shell":     "bash",
			"devices":   []interface{}{"device-1"},
		},
	}

	execution := &workflow.WorkflowExecution{
		ID:          "exec-run-id-propagated",
		Status:      workflow.StatusRunning,
		StepResults: make(map[string]workflow.StepResult),
		Variables:   make(map[string]interface{}),
		TenantID:    "test-tenant",
		Done:        make(chan struct{}),
	}
	execution.SetVariable("workflow_run_id", "wf-run-999")
	execution.SetVariable("workflow_name", "test-workflow")

	result, err := executor.ExecuteStep(context.Background(), step, execution)
	require.NoError(t, err)
	assert.Equal(t, workflow.StatusCompleted, result.Status)

	// Verify that the queue entry carries the workflow context.
	entries := q.PeekForDevice("device-1")
	require.NotEmpty(t, entries, "queue must have an entry for device-1")
	assert.Equal(t, "wf-run-999", entries[0].Metadata["workflow_run_id"],
		"workflow_run_id must flow from variables through ExecuteStep into queue metadata")
	assert.Equal(t, "test-workflow", entries[0].Metadata["workflow_name"],
		"workflow_name must flow from variables through ExecuteStep into queue metadata")
}

// --- Execution tracking tests (Issue #634) ---

// inMemoryTracker is a test-local ExecutionTracker that stores records in
// memory. It implements the script.ExecutionTracker interface without requiring
// SQLite/CGO, keeping these tests fast and dependency-free.
type inMemoryTracker struct {
	records []*script.ExecutionRecord
}

func (t *inMemoryTracker) Record(_ context.Context, r *script.ExecutionRecord) error {
	// Idempotent: replace existing record with same (execution_id, device_id).
	for i, existing := range t.records {
		if existing.ExecutionID == r.ExecutionID && existing.DeviceID == r.DeviceID {
			t.records[i] = r
			return nil
		}
	}
	t.records = append(t.records, r)
	return nil
}

func (t *inMemoryTracker) QueryByDevice(_ context.Context, deviceID string, limit int) ([]*script.ExecutionRecord, error) {
	var out []*script.ExecutionRecord
	for _, r := range t.records {
		if r.DeviceID == deviceID {
			out = append(out, r)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (t *inMemoryTracker) QueryByWorkflowRun(_ context.Context, workflowRunID string) ([]*script.ExecutionRecord, error) {
	var out []*script.ExecutionRecord
	for _, r := range t.records {
		if r.WorkflowRunID == workflowRunID {
			out = append(out, r)
		}
	}
	return out, nil
}

// TestScriptNode_Execute_InlinePath_WritesTrackingRecord verifies that the
// inline execution path writes exactly one ExecutionRecord per device when the
// execution reaches a terminal state.
func TestScriptNode_Execute_InlinePath_WritesTrackingRecord(t *testing.T) {
	shell := script.ShellBash
	if runtime.GOOS == "windows" {
		shell = script.ShellPowerShell
	}

	monitor := script.NewExecutionMonitor()
	tracker := &inMemoryTracker{}

	config := &ScriptStepConfig{
		InlineScript: "echo tracking",
		Shell:        shell,
		Devices:      []string{"device-track-1", "device-track-2"},
		Timeout:      10 * time.Second,
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "device-track-1", "device-track-2")
	node.SetExecutionTracker(tracker)

	_, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)

	assert.Len(t, tracker.records, 2, "one tracking record per device must be written")

	deviceIDs := make(map[string]bool)
	for _, r := range tracker.records {
		deviceIDs[r.DeviceID] = true
		assert.NotEmpty(t, r.ExecutionID, "ExecutionID must be set")
		assert.NotEmpty(t, r.State, "State must be set")
		assert.False(t, r.CompletedAt.IsZero(), "CompletedAt must be set")
	}
	assert.True(t, deviceIDs["device-track-1"], "record for device-track-1 must be written")
	assert.True(t, deviceIDs["device-track-2"], "record for device-track-2 must be written")
}

// TestScriptNode_Execute_InlinePath_DeviceView verifies that QueryByDevice on
// the tracker returns correct records for the requested device only.
func TestScriptNode_Execute_InlinePath_DeviceView(t *testing.T) {
	shell := script.ShellBash
	if runtime.GOOS == "windows" {
		shell = script.ShellPowerShell
	}

	monitor := script.NewExecutionMonitor()
	tracker := &inMemoryTracker{}

	config := &ScriptStepConfig{
		InlineScript: "echo device-view",
		Shell:        shell,
		Devices:      []string{"dev-a", "dev-b"},
		Timeout:      10 * time.Second,
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "dev-a", "dev-b")
	node.SetExecutionTracker(tracker)

	_, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)

	byDevA, err := tracker.QueryByDevice(context.Background(), "dev-a", 10)
	require.NoError(t, err)
	require.Len(t, byDevA, 1, "QueryByDevice must return exactly one record for dev-a")
	assert.Equal(t, "dev-a", byDevA[0].DeviceID)

	byDevB, err := tracker.QueryByDevice(context.Background(), "dev-b", 10)
	require.NoError(t, err)
	require.Len(t, byDevB, 1, "QueryByDevice must return exactly one record for dev-b")
	assert.Equal(t, "dev-b", byDevB[0].DeviceID)
}

// TestScriptNode_Execute_InlinePath_WorkflowContextPropagated verifies that
// workflow_run_id and workflow_name from input.Context flow into the tracking
// record, while ad-hoc executions have empty WorkflowRunID.
func TestScriptNode_Execute_InlinePath_WorkflowContextPropagated(t *testing.T) {
	shell := script.ShellBash
	if runtime.GOOS == "windows" {
		shell = script.ShellPowerShell
	}

	monitor := script.NewExecutionMonitor()
	tracker := &inMemoryTracker{}

	config := &ScriptStepConfig{
		InlineScript: "echo wf-ctx",
		Shell:        shell,
		Devices:      []string{"dev-wf"},
		Timeout:      10 * time.Second,
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "dev-wf")
	node.SetExecutionTracker(tracker)

	input := workflow.NodeInput{
		Context: map[string]interface{}{
			"workflow_run_id": "wf-run-ctx-1",
			"workflow_name":   "my-workflow",
		},
	}
	_, err := node.Execute(context.Background(), input)
	require.NoError(t, err)

	require.Len(t, tracker.records, 1)
	assert.Equal(t, "wf-run-ctx-1", tracker.records[0].WorkflowRunID,
		"WorkflowRunID must be populated from input.Context")
	assert.Equal(t, "my-workflow", tracker.records[0].WorkflowName,
		"WorkflowName must be populated from input.Context")
}

// TestScriptNode_Execute_InlinePath_AdHocHasEmptyWorkflowRunID verifies that
// ad-hoc (non-workflow) executions produce tracking records with empty WorkflowRunID.
func TestScriptNode_Execute_InlinePath_AdHocHasEmptyWorkflowRunID(t *testing.T) {
	shell := script.ShellBash
	if runtime.GOOS == "windows" {
		shell = script.ShellPowerShell
	}

	monitor := script.NewExecutionMonitor()
	tracker := &inMemoryTracker{}

	config := &ScriptStepConfig{
		InlineScript: "echo adhoc",
		Shell:        shell,
		Devices:      []string{"dev-adhoc"},
		Timeout:      10 * time.Second,
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "dev-adhoc")
	node.SetExecutionTracker(tracker)

	// No Context set — ad-hoc execution
	_, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)

	require.Len(t, tracker.records, 1)
	assert.Equal(t, "", tracker.records[0].WorkflowRunID,
		"ad-hoc execution must produce empty WorkflowRunID")
}

// TestScriptNode_Execute_QueuePath_WritesTrackingRecord verifies that the queue
// path writes one ExecutionRecord per device when AcknowledgeCompletion is called
// with the steward callback result.
func TestScriptNode_Execute_QueuePath_WritesTrackingRecord(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	store := script.NewInMemoryQueueStore()
	q := script.NewExecutionQueue(monitor, nil, 0, "", store, nil, 0)
	defer q.Stop()

	tracker := &inMemoryTracker{}

	config := &ScriptStepConfig{
		ScriptID: "my-script",
		Shell:    script.ShellBash,
		Devices:  []string{"dev-q1"},
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "dev-q1")
	node.SetExecutionQueue(q)
	node.SetExecutionTracker(tracker) // tracker wired into queue via SetExecutionTracker

	output, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)
	assert.True(t, output.Success)

	// Dequeue so the entry moves to dispatched state (required before AcknowledgeCompletion)
	entries, err := q.DequeueForDevice("dev-q1")
	require.NoError(t, err)
	require.Len(t, entries, 1)

	execID := entries[0].ExecutionID

	result := &script.ExecutionResult{
		ExitCode: 0,
		Stdout:   "done",
		Duration: 500 * time.Millisecond,
	}
	require.NoError(t, q.AcknowledgeCompletion(execID, "dev-q1", script.QueueStateCompleted, result))

	// Tracker must now have the record
	records, err := tracker.QueryByDevice(context.Background(), "dev-q1", 10)
	require.NoError(t, err)
	require.Len(t, records, 1, "AcknowledgeCompletion must trigger one tracking record")

	rec := records[0]
	assert.Equal(t, execID, rec.ExecutionID)
	assert.Equal(t, "dev-q1", rec.DeviceID)
	assert.Equal(t, string(script.QueueStateCompleted), rec.State)
	assert.Equal(t, 0, rec.ExitCode)
	assert.Equal(t, "done", rec.Stdout)
}

// TestScriptNode_Execute_QueuePath_WorkflowRunView verifies that
// QueryByWorkflowRun returns all device records written for a workflow run via
// the queue path.
func TestScriptNode_Execute_QueuePath_WorkflowRunView(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	store := script.NewInMemoryQueueStore()
	q := script.NewExecutionQueue(monitor, nil, 0, "", store, nil, 0)
	defer q.Stop()

	tracker := &inMemoryTracker{}
	devices := []string{"dev-r1", "dev-r2", "dev-r3"}

	config := &ScriptStepConfig{
		ScriptID: "my-script",
		Shell:    script.ShellBash,
		Devices:  devices,
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", devices...)
	node.SetExecutionQueue(q)
	node.SetExecutionTracker(tracker)

	input := workflow.NodeInput{
		Context: map[string]interface{}{
			"workflow_run_id": "wf-run-multi",
			"workflow_name":   "multi-device-workflow",
		},
	}
	_, err := node.Execute(context.Background(), input)
	require.NoError(t, err)

	// Dequeue and acknowledge each device
	for _, deviceID := range devices {
		entries, err := q.DequeueForDevice(deviceID)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		require.NoError(t, q.AcknowledgeCompletion(
			entries[0].ExecutionID, deviceID, script.QueueStateCompleted,
			&script.ExecutionResult{ExitCode: 0},
		))
	}

	// All three device records must appear in the workflow-run view
	byRun, err := tracker.QueryByWorkflowRun(context.Background(), "wf-run-multi")
	require.NoError(t, err)
	assert.Len(t, byRun, 3, "workflow-run view must return all device records for the run")

	for _, r := range byRun {
		assert.Equal(t, "wf-run-multi", r.WorkflowRunID,
			"all records must carry the workflow run ID")
	}
}

// TestScriptNode_Execute_InlinePath_ExactlyOneRecordPerDevice verifies that
// even if Execute is called multiple times for the same node (recurring workflow),
// each invocation writes exactly one record per device (no monitor duplication).
func TestScriptNode_Execute_InlinePath_ExactlyOneRecordPerDevice(t *testing.T) {
	shell := script.ShellBash
	if runtime.GOOS == "windows" {
		shell = script.ShellPowerShell
	}

	monitor := script.NewExecutionMonitor()
	tracker := &inMemoryTracker{}

	config := &ScriptStepConfig{
		InlineScript: "echo once",
		Shell:        shell,
		Devices:      []string{"dev-once"},
		Timeout:      10 * time.Second,
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "test-tenant", "dev-once")
	node.SetExecutionTracker(tracker)

	// First execution
	_, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)

	// Second execution (different ExecutionID, same device)
	_, err = node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)

	// Two records must exist — one per Execute call — not deduplicated across runs
	// because each run produces a distinct ExecutionID.
	records, err := tracker.QueryByDevice(context.Background(), "dev-once", 10)
	require.NoError(t, err)
	assert.Len(t, records, 2, "each Execute invocation must produce exactly one record per device")
}

// TestScriptNode_Execute_LibraryRunCarriesTenantID verifies a library run queued by
// the script node carries the node's authenticated tenant, so the dispatcher can
// resolve the script from that tenant's library (Issue #5422).
func TestScriptNode_Execute_LibraryRunCarriesTenantID(t *testing.T) {
	monitor := script.NewExecutionMonitor()
	q := script.NewExecutionQueue(monitor, nil, 0, "", script.NewInMemoryQueueStore(), nil, 0)
	defer q.Stop()

	config := &ScriptStepConfig{
		ScriptID: "lib-script",
		Shell:    script.ShellBash,
		Devices:  []string{"device-1"},
	}
	node := NewScriptNode("id", "name", config, nil, monitor, nil)
	wireTenantFleet(node, "tenant-lib", "device-1")
	node.SetExecutionQueue(q)

	output, err := node.Execute(context.Background(), workflow.NodeInput{})
	require.NoError(t, err)
	require.True(t, output.Success)

	entries := q.PeekForDevice("device-1")
	require.Len(t, entries, 1)
	assert.Equal(t, "tenant-lib", entries[0].Metadata["tenant_id"])
}

// --- Restricted script step (Issue #5851) -----------------------------------
//
// These tests run the real execution queue, execution monitor, tenant script
// library (over real storage), fleet query and workflow engine. The "steward" is a
// goroutine that does what a connected steward's session does on the controller:
// dequeue, prepare the payload, and acknowledge the result.

const (
	rsRunTenant   = "client-1"
	rsOwnerTenant = "msp"
	rsDevice      = "dev-1"
)

// libraryApprover is a ScriptApprover over the real tenant library: it resolves
// the owner's version and returns the pin the queue verifies. It stands in for
// the evaluator-backed adapter, which is built by its own story.
type libraryApprover struct {
	repo  *script.TenantScriptRepository
	owner string
	state workflow.ScriptApprovalState
	err   error

	mu       sync.Mutex
	asked    int
	pendings []workflow.ScriptApprovalDecision
}

func (a *libraryApprover) Approve(_ context.Context, runTenant, ceiling, id, version string) (workflow.ScriptApprovalDecision, error) {
	a.mu.Lock()
	a.asked++
	a.mu.Unlock()
	if a.err != nil {
		return workflow.ScriptApprovalDecision{}, a.err
	}
	vs, err := a.repo.GetForTenant(a.owner, id, version)
	if err != nil {
		return workflow.ScriptApprovalDecision{State: workflow.ScriptApprovalDenied, Reason: "not in library"}, nil
	}
	return workflow.ScriptApprovalDecision{
		State:        a.state,
		OwnerTenant:  a.owner,
		Version:      vs.Metadata.Version.String(),
		ApprovalHash: script.ScriptApprovalHash(a.owner, vs),
	}, nil
}

func (a *libraryApprover) RecordPending(_ context.Context, _ string, d workflow.ScriptApprovalDecision) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pendings = append(a.pendings, d)
	return nil
}

func (a *libraryApprover) askedCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.asked
}

func (a *libraryApprover) pendingCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pendings)
}

type restrictedFixture struct {
	repo     *script.TenantScriptRepository
	queue    *script.ExecutionQueue
	monitor  *script.ExecutionMonitor
	approver *libraryApprover
	revoked  atomic.Bool
}

func newRestrictedFixture(t *testing.T) *restrictedFixture {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	repo, err := script.NewTenantScriptRepository(sm.GetConfigStore())
	require.NoError(t, err)
	f := &restrictedFixture{repo: repo, monitor: script.NewExecutionMonitor()}
	f.queue = script.NewExecutionQueue(f.monitor, nil, 0, "", nil, repo, 0)
	t.Cleanup(f.queue.Stop)
	f.queue.SetGuardResolver(func(_ context.Context, runID, grantID string) error {
		if f.revoked.Load() {
			return fmt.Errorf("grant %s of run %s is revoked", grantID, runID)
		}
		return nil
	})
	f.approver = &libraryApprover{repo: repo, owner: rsOwnerTenant, state: workflow.ScriptApprovalApproved}
	return f
}

func libraryScript(id, content string, params ...script.ScriptParameter) *script.VersionedScript {
	return &script.VersionedScript{
		Metadata: &script.ScriptMetadata{
			ID: id, Name: id, Version: &script.Version{Major: 1},
			Shell: script.ShellBash, Platform: []string{"linux"}, Parameters: params,
		},
		Content:   content,
		Signature: &script.ScriptSignature{Algorithm: "rsa-sha256", Signature: "c2ln", PublicKey: "pem"},
	}
}

func (f *restrictedFixture) put(t *testing.T, tenant, id, content string, params ...script.ScriptParameter) *script.VersionedScript {
	t.Helper()
	gr, err := f.repo.ForTenant(tenant)
	require.NoError(t, err)
	require.NoError(t, gr.Create(libraryScript(id, content, params...)))
	vs, err := gr.Get(id, "1.0.0")
	require.NoError(t, err)
	return vs
}

func (f *restrictedFixture) replace(t *testing.T, tenant, id, content string) {
	t.Helper()
	gr, err := f.repo.ForTenant(tenant)
	require.NoError(t, err)
	require.NoError(t, gr.Delete(id, "1.0.0"))
	require.NoError(t, gr.Create(libraryScript(id, content)))
}

// fleetOf is a real in-memory fleet query holding the given devices, by tenant.
func fleetOf(devicesByTenant map[string]string) fleet.FleetQuery {
	var stewards []fleet.StewardData
	for id, tenant := range devicesByTenant {
		stewards = append(stewards, fleet.StewardData{ID: id, TenantID: tenant, Status: "online", LastHeartbeat: time.Now()})
	}
	return fleet.NewMemoryQuery(&testStewardProvider{stewards: stewards})
}

// unscopedFleet is a fleet source that fails to apply the tenant scope: it runs the
// real query with the filter's tenant removed. It models a backend bug the node's
// own device check must still catch.
type unscopedFleet struct{ inner fleet.FleetQuery }

func (u unscopedFleet) Search(ctx context.Context, f fleet.Filter) ([]fleet.StewardResult, error) {
	f.TenantID = ""
	return u.inner.Search(ctx, f)
}

func (u unscopedFleet) Count(ctx context.Context, f fleet.Filter) (int, error) {
	f.TenantID = ""
	return u.inner.Count(ctx, f)
}

func (f *restrictedFixture) config(version string) *ScriptStepConfig {
	return &ScriptStepConfig{ScriptID: "inventory", ScriptVersion: version, Devices: []string{rsDevice}}
}

func (f *restrictedFixture) node(cfg *ScriptStepConfig, fq fleet.FleetQuery) *ScriptNode {
	n := NewScriptNode("collect", "collect", cfg, f.repo, f.monitor, nil)
	n.SetExecutionQueue(f.queue)
	n.SetFleetQuery(fq)
	n.SetTenantID(rsRunTenant)
	n.SetRestricted(workflow.RestrictedRun{RunID: "run-1", GrantID: "grant-1", Ceiling: rsOwnerTenant})
	n.SetApprover(f.approver)
	n.SetResultWaitTimeout(10 * time.Second)
	return n
}

func (f *restrictedFixture) executor() *ScriptStepExecutor {
	e := NewScriptStepExecutor(f.repo, f.monitor, nil)
	e.SetExecutionQueue(f.queue)
	e.SetFleetQuery(fleetOf(map[string]string{rsDevice: rsRunTenant}))
	e.SetApprover(f.approver)
	e.SetResultWaitTimeout(10 * time.Second)
	return e
}

func (f *restrictedFixture) queued() int { return f.queue.GetTotalQueueDepth() }

type stewardRun struct {
	entry    *script.QueuedExecution
	prepared *script.PreparedExecution
	prepErr  error
}

// serveSteward drains the device's queue the way a steward session does: dequeue,
// prepare the payload (the second guard check and the pin verification happen
// here), and acknowledge the result. A failed prepare is acknowledged as a failure.
func (f *restrictedFixture) serveSteward(t *testing.T, device, stdout string) <-chan stewardRun {
	t.Helper()
	runs := make(chan stewardRun, 16)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	go func() {
		defer close(done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			entries, err := f.queue.DequeueForDevice(device)
			if err != nil {
				continue
			}
			for _, e := range entries {
				prep, prepErr := f.queue.PrepareExecutionForDevice(ctx, device, rsRunTenant, e)
				runs <- stewardRun{entry: e, prepared: prep, prepErr: prepErr}
				state, result := script.QueueStateCompleted, &script.ExecutionResult{ExitCode: 0, Stdout: stdout}
				if prepErr != nil {
					state, result = script.QueueStateFailed, &script.ExecutionResult{ExitCode: 1, Stderr: "refused"}
				}
				_ = f.queue.AcknowledgeCompletion(e.ExecutionID, device, state, result) //nolint:errcheck // a guard-cancelled entry is already terminal
			}
		}
	}()
	return runs
}

// waitQueued waits until the device has one queued entry and returns it.
func (f *restrictedFixture) waitQueued(t *testing.T, device string) *script.QueuedExecution {
	t.Helper()
	var got *script.QueuedExecution
	require.Eventually(t, func() bool {
		if peek := f.queue.PeekForDevice(device); len(peek) == 1 {
			got = peek[0]
			return true
		}
		return false
	}, 5*time.Second, 5*time.Millisecond, "the step never queued a command")
	return got
}

type nodeResult struct {
	out workflow.NodeOutput
	err error
}

func runNodeAsync(n *ScriptNode) <-chan nodeResult {
	ch := make(chan nodeResult, 1)
	go func() {
		out, err := n.Execute(context.Background(), workflow.NodeInput{Context: map[string]interface{}{"workflow_run_id": "run-1"}})
		ch <- nodeResult{out, err}
	}()
	return ch
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("timed out")
		panic("unreachable")
	}
}

// [REQUIRED TEST] A restricted node refuses an empty version, SecretBindings, an
// undeclared param name, a value outside AllowedValues, and an inline form, and
// queues nothing.
func TestRestrictedNode_RefusesForbiddenForms(t *testing.T) {
	mode := script.ScriptParameter{Name: "mode", Type: "string", AllowedValues: []string{"fast", "full"}}
	free := script.ScriptParameter{Name: "label", Type: "string"}
	cases := []struct {
		name    string
		mutate  func(c *ScriptStepConfig)
		wantErr string
	}{
		{"empty version", func(c *ScriptStepConfig) { c.ScriptVersion = "" }, "explicit script_version"},
		{"secret bindings", func(c *ScriptStepConfig) {
			c.SecretBindings = []script.ParamBinding{{Name: "TOKEN", From: script.ParamSourceSecretStore, Key: "k"}}
		}, "secret bindings"},
		{"inline script", func(c *ScriptStepConfig) { c.InlineScript = "echo hi" }, "inline script"},
		{"undeclared param", func(c *ScriptStepConfig) { c.Parameters = map[string]string{"extra": "x"} }, "not declared"},
		{"value outside AllowedValues", func(c *ScriptStepConfig) { c.Parameters = map[string]string{"mode": "wipe"} }, "allowed values"},
		{"template value", func(c *ScriptStepConfig) { c.Parameters = map[string]string{"label": "{{ .inputs.x }}"} }, "literal"},
		{"variable reference value", func(c *ScriptStepConfig) { c.Parameters = map[string]string{"label": "${HOME}"} }, "literal"},
		{"ephemeral API key", func(c *ScriptStepConfig) { c.GenerateAPIKey = true }, "ephemeral API key"},
		{"shell differs from the approved script", func(c *ScriptStepConfig) { c.Shell = script.ShellPowerShell }, "shell"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRestrictedFixture(t)
			f.put(t, rsOwnerTenant, "inventory", "echo ok\n", mode, free)
			cfg := f.config("1.0.0")
			tc.mutate(cfg)
			n := f.node(cfg, fleetOf(map[string]string{rsDevice: rsRunTenant}))

			out, err := n.Execute(context.Background(), workflow.NodeInput{})

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			assert.False(t, out.Success)
			assert.Zero(t, f.queued(), "a refused step queues nothing")
		})
	}
}

// [REQUIRED TEST] The path and command forms, and any key the restricted step does
// not know, are refused on the raw step config, before parsing drops them.
func TestValidateRestrictedStepConfig_RefusesPathAndCommandForms(t *testing.T) {
	good := map[string]interface{}{
		"script_id": "inventory", "script_version": "1.0.0",
		"parameters": map[string]interface{}{"mode": "fast", "n": 3, "on": true},
		"devices":    []interface{}{"d1"},
	}
	require.NoError(t, validateRestrictedStepConfig(good))

	for _, key := range []string{
		"inline_script", "script_path", "path", "file", "script_file", "command", "cmd", "args",
		"argument_list", "secret_bindings", "generate_api_key", "api_key_ttl", "on_success", "surprise",
	} {
		t.Run(key, func(t *testing.T) {
			cfg := map[string]interface{}{"script_id": "inventory", "script_version": "1.0.0", key: "x"}
			err := validateRestrictedStepConfig(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})
	}

	t.Run("non-scalar parameter", func(t *testing.T) {
		cfg := map[string]interface{}{"parameters": map[string]interface{}{"x": []interface{}{"a"}}}
		require.Error(t, validateRestrictedStepConfig(cfg))
	})
	t.Run("parameters not a mapping", func(t *testing.T) {
		require.Error(t, validateRestrictedStepConfig(map[string]interface{}{"parameters": "x"}))
	})
}

// [REQUIRED TEST] The step executor of a restricted execution refuses a command
// form before the node exists, and queues nothing.
func TestRestrictedStepExecutor_RefusesCommandForm(t *testing.T) {
	f := newRestrictedFixture(t)
	f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
	exec := &workflow.WorkflowExecution{
		ID: "x1", TenantID: rsRunTenant, Variables: map[string]interface{}{},
		Restricted: &workflow.RestrictedRun{RunID: "run-1", GrantID: "grant-1"},
	}
	step := workflow.Step{Name: "collect", Type: workflow.StepTypeScript, Config: map[string]interface{}{
		"script_id": "inventory", "script_version": "1.0.0", "command": "rm -rf /", "devices": []interface{}{rsDevice},
	}}

	res, err := f.executor().ExecuteStep(context.Background(), step, exec)

	require.Error(t, err)
	assert.Equal(t, workflow.StatusFailed, res.Status)
	assert.Contains(t, err.Error(), "command")
	assert.Zero(t, f.queued())
}

// [REQUIRED TEST] A restricted node with no approver refuses; a pending or denied
// decision, an approver error and an incomplete decision fail the step with nothing
// queued, and a pending decision is recorded.
func TestRestrictedNode_ApprovalGate(t *testing.T) {
	devices := map[string]string{rsDevice: rsRunTenant}

	t.Run("no approver", func(t *testing.T) {
		f := newRestrictedFixture(t)
		f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
		n := f.node(f.config("1.0.0"), fleetOf(devices))
		n.SetApprover(nil)

		_, err := n.Execute(context.Background(), workflow.NodeInput{})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "no script approver")
		assert.Zero(t, f.queued())
	})

	t.Run("pending is recorded and queues nothing", func(t *testing.T) {
		f := newRestrictedFixture(t)
		f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
		f.approver.state = workflow.ScriptApprovalPending
		n := f.node(f.config("1.0.0"), fleetOf(devices))

		out, err := n.Execute(context.Background(), workflow.NodeInput{})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "pending approval")
		assert.False(t, out.Success)
		assert.Equal(t, 1, f.approver.pendingCount(), "a pending decision goes to the record-and-notify hook once")
		assert.Zero(t, f.queued())
	})

	t.Run("denied queues nothing and records nothing", func(t *testing.T) {
		f := newRestrictedFixture(t)
		f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
		f.approver.state = workflow.ScriptApprovalDenied
		n := f.node(f.config("1.0.0"), fleetOf(devices))

		_, err := n.Execute(context.Background(), workflow.NodeInput{})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "not approved")
		assert.Zero(t, f.approver.pendingCount())
		assert.Zero(t, f.queued())
	})

	t.Run("approver error fails closed without leaking the cause", func(t *testing.T) {
		f := newRestrictedFixture(t)
		f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
		f.approver.err = errors.New("store at /secret/path exploded")
		n := f.node(f.config("1.0.0"), fleetOf(devices))

		_, err := n.Execute(context.Background(), workflow.NodeInput{})

		require.Error(t, err)
		assert.NotContains(t, err.Error(), "/secret/path")
		assert.Zero(t, f.queued())
	})

	t.Run("unknown script is denied", func(t *testing.T) {
		f := newRestrictedFixture(t)
		n := f.node(f.config("1.0.0"), fleetOf(devices))

		_, err := n.Execute(context.Background(), workflow.NodeInput{})

		require.Error(t, err)
		assert.Zero(t, f.queued())
	})
}

// [REQUIRED TEST] A restricted node passes the approver's owner tenant, version and
// approval hash to the queue, plus the guard reference, so an edit between approval
// and queue prepare makes the queue refuse.
func TestRestrictedNode_PinAndGuardReachTheQueue_EditBeforePrepareRefuses(t *testing.T) {
	f := newRestrictedFixture(t)
	vs := f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
	n := f.node(f.config("1.0.0"), fleetOf(map[string]string{rsDevice: rsRunTenant}))

	result := runNodeAsync(n)
	entry := f.waitQueued(t, rsDevice)

	assert.Equal(t, rsOwnerTenant, entry.Metadata[script.MetaPinOwnerTenant])
	assert.Equal(t, "1.0.0", entry.Metadata[script.MetaPinVersion])
	assert.Equal(t, script.ScriptApprovalHash(rsOwnerTenant, vs), entry.Metadata[script.MetaPinApprovalHash])
	assert.Equal(t, "run-1", entry.Metadata[script.MetaGuardRunID], "the persisted guard reference carries the run id")
	assert.Equal(t, "grant-1", entry.Metadata[script.MetaGuardGrantID], "and the grant id")
	assert.Equal(t, rsRunTenant, entry.Metadata["tenant_id"])
	assert.Equal(t, script.ShellBash, entry.Shell, "the shell comes from the approved script")

	// The script is edited after the approval and before the queue prepares it.
	f.replace(t, rsOwnerTenant, "inventory", "echo evil\n")
	steward := f.serveSteward(t, rsDevice, "")

	run := receive(t, steward)
	require.ErrorIs(t, run.prepErr, script.ErrPinMismatch)
	assert.Nil(t, run.prepared, "the edited script is never sent")

	res := receive(t, result)
	require.Error(t, res.err)
	assert.False(t, res.out.Success)
}

// [REQUIRED TEST] The persisted guard reference is set on commands the node queues,
// so revoking the grant cancels the queued commands of the workflow.
func TestRestrictedNode_RevokingCancelsQueuedCommands(t *testing.T) {
	f := newRestrictedFixture(t)
	f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
	n := f.node(f.config("1.0.0"), fleetOf(map[string]string{rsDevice: rsRunTenant}))

	result := runNodeAsync(n)
	f.waitQueued(t, rsDevice)
	f.revoked.Store(true)
	steward := f.serveSteward(t, rsDevice, "")

	// The queue evaluates the guard at dequeue: the revoked run's command is
	// cancelled and never handed to the steward.
	res := receive(t, result)
	require.Error(t, res.err)
	assert.False(t, res.out.Success)
	select {
	case run := <-steward:
		t.Fatalf("a revoked run's command reached the steward: %+v", run.prepErr)
	default:
	}
	devResults := res.out.Data["results"].(map[string]interface{})
	assert.Equal(t, string(script.StatusCancelled), devResults[rsDevice].(map[string]interface{})["status"])
	assert.Zero(t, f.queued())
}

// [REQUIRED TEST] Devices the fleet filter produces are checked against the run
// tenant: a client-2 device, or a descendant device, refuses the whole step even
// when the fleet source did not scope the query.
func TestRestrictedNode_DevicesCheckedAgainstRunTenant(t *testing.T) {
	devices := map[string]string{
		"dev-ok":      "client-1",
		"dev-client2": "client-2",
		"dev-site":    "client-1/site-a",
	}
	cases := []struct {
		name string
		cfg  func(c *ScriptStepConfig)
		fq   fleet.FleetQuery
	}{
		{"filter spanning tenants (client-2 device)", func(c *ScriptStepConfig) {
			c.Devices = nil
			c.DeviceFilter = &fleet.Filter{Status: "online"}
		}, unscopedFleet{fleetOf(devices)}},
		{"filter selecting a descendant (runTenantOnly)", func(c *ScriptStepConfig) {
			c.Devices = nil
			c.DeviceFilter = &fleet.Filter{Status: "online"}
		}, unscopedFleet{fleetOf(map[string]string{"dev-ok": "client-1", "dev-site": "client-1/site-a"})}},
		{"filter naming a tenant subtree", func(c *ScriptStepConfig) {
			c.Devices = nil
			c.DeviceFilter = &fleet.Filter{TenantSubtree: "client-1", TenantSubtreeIDs: []string{"client-1/site-a"}}
		}, fleetOf(devices)},
		{"explicit descendant device", func(c *ScriptStepConfig) { c.Devices = []string{"dev-site"} }, fleetOf(devices)},
		{"explicit other-tenant device", func(c *ScriptStepConfig) { c.Devices = []string{"dev-client2"} }, fleetOf(devices)},
		{"explicit mix refuses the whole step", func(c *ScriptStepConfig) { c.Devices = []string{"dev-ok", "dev-client2"} }, fleetOf(devices)},
		{"explicit mix against an unscoped source", func(c *ScriptStepConfig) { c.Devices = []string{"dev-ok", "dev-client2"} }, unscopedFleet{fleetOf(devices)}},
		{"filter naming another tenant", func(c *ScriptStepConfig) {
			c.Devices = nil
			c.DeviceFilter = &fleet.Filter{TenantID: "client-2"}
		}, fleetOf(devices)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRestrictedFixture(t)
			f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
			cfg := f.config("1.0.0")
			tc.cfg(cfg)
			n := f.node(cfg, tc.fq)

			out, err := n.Execute(context.Background(), workflow.NodeInput{})

			require.Error(t, err)
			assert.False(t, out.Success)
			assert.Zero(t, f.queued(), "nothing is queued, not even for the in-tenant device")
		})
	}

	t.Run("in-tenant filter still runs", func(t *testing.T) {
		f := newRestrictedFixture(t)
		f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
		cfg := f.config("1.0.0")
		cfg.Devices = nil
		cfg.DeviceFilter = &fleet.Filter{Status: "online"}
		n := f.node(cfg, fleetOf(devices))
		steward := f.serveSteward(t, "dev-ok", "fine")

		res := receive(t, runNodeAsync(n))

		require.NoError(t, res.err)
		assert.True(t, res.out.Success)
		assert.Equal(t, 1, res.out.Data["queued"])
		assert.Equal(t, rsRunTenant, receive(t, steward).entry.Metadata["tenant_id"])
	})
}

// A fleet filter matching no devices is a success with a warning and nothing queued.
func TestRestrictedNode_ZeroMatchQueuesNothing(t *testing.T) {
	f := newRestrictedFixture(t)
	f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
	cfg := f.config("1.0.0")
	cfg.Devices = nil
	cfg.DeviceFilter = &fleet.Filter{Hostname: "nothing-like-this"}
	n := f.node(cfg, fleetOf(map[string]string{rsDevice: rsRunTenant}))

	out, err := n.Execute(context.Background(), workflow.NodeInput{})

	require.NoError(t, err)
	assert.True(t, out.Success)
	assert.Contains(t, out.Data["warning"], "no devices")
	assert.Zero(t, f.queued())
}

// A restricted node with no queue or no tenant-resolved library never falls back to
// the inline path.
func TestRestrictedNode_NoQueueNeverRunsInline(t *testing.T) {
	f := newRestrictedFixture(t)
	f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
	n := f.node(f.config("1.0.0"), fleetOf(map[string]string{rsDevice: rsRunTenant}))
	n.executionQueue = nil

	_, err := n.Execute(context.Background(), workflow.NodeInput{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "execution queue")
	assert.Empty(t, f.monitor.ListExecutions(""), "nothing was started or run")
}

// A restricted step that never gets a result fails after the wait bound and
// cancels what it queued, so nothing runs after the step has failed.
func TestRestrictedNode_ResultTimeoutCancelsQueuedCommands(t *testing.T) {
	f := newRestrictedFixture(t)
	f.put(t, rsOwnerTenant, "inventory", "echo ok\n")
	n := f.node(f.config("1.0.0"), fleetOf(map[string]string{rsDevice: rsRunTenant}))
	n.SetResultWaitTimeout(300 * time.Millisecond)

	_, err := n.Execute(context.Background(), workflow.NodeInput{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.Zero(t, f.queued(), "the queued command was cancelled")
}

// --- through the real engine ---

func scriptWorkflow() workflow.Workflow {
	return workflow.Workflow{
		Name: "gather-inventory",
		Steps: []workflow.Step{
			{Name: "collect", Type: workflow.StepTypeScript, Config: map[string]interface{}{
				"script_id": "inventory", "script_version": "1.0.0", "devices": []interface{}{rsDevice},
			}},
			{
				Name: "next", Type: workflow.StepTypeConditional,
				Condition: &workflow.Condition{Type: workflow.ConditionTypeVariable, Variable: "collect_result", Operator: workflow.OperatorExists},
				Steps:     []workflow.Step{{Name: "saw-output", Type: workflow.StepTypeDelay, Delay: &workflow.DelayConfig{Duration: time.Millisecond}}},
			},
		},
	}
}

func tenantCtx() context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantID, rsRunTenant)
}

func waitExecution(t *testing.T, e *workflow.WorkflowExecution) {
	t.Helper()
	select {
	case <-e.Done:
	case <-time.After(15 * time.Second):
		t.Fatal("the workflow did not finish")
	}
}

func traceHas(e *workflow.WorkflowExecution, name string) bool {
	for _, s := range e.GetExecutionTrace() {
		if s.StepName == name {
			return true
		}
	}
	return false
}

// [REQUIRED TEST] End to end: a workflow with a script step queues a library run
// through the real execution queue, a steward result comes back, and the next step
// sees the output.
func TestEngine_ScriptStepRunsLibraryScriptAndNextStepSeesOutput(t *testing.T) {
	f := newRestrictedFixture(t)
	vs := f.put(t, rsOwnerTenant, "inventory", "echo hello\n")
	engine := workflow.NewEngine(nil, logging.NewNoopLogger(), nil, nil, nil, nil, nil, workflow.WithScriptStepExecutor(f.executor()))
	t.Cleanup(engine.Shutdown)
	steward := f.serveSteward(t, rsDevice, "hello\n")

	exec, err := engine.ExecuteRestrictedWorkflow(tenantCtx(), scriptWorkflow(), nil,
		workflow.RestrictedRun{RunID: "run-1", GrantID: "grant-1", Ceiling: rsOwnerTenant})
	require.NoError(t, err)
	waitExecution(t, exec)

	require.Equal(t, workflow.StatusCompleted, exec.GetStatus(), exec.GetError())

	run := receive(t, steward)
	require.NoError(t, run.prepErr)
	assert.Equal(t, vs.Content, run.prepared.ScriptContent, "the pinned library script is what the steward is sent")
	assert.Equal(t, "run-1", run.entry.Metadata[script.MetaGuardRunID])

	collected, ok := exec.GetVariable("collect_result")
	require.True(t, ok, "the step's output is a variable of the run")
	results := collected.(map[string]interface{})["results"].(map[string]interface{})
	dev := results[rsDevice].(map[string]interface{})
	assert.Equal(t, "hello\n", dev["stdout"])
	assert.Equal(t, 0, dev["exit_code"])
	assert.True(t, traceHas(exec, "saw-output"), "the step after the script step ran because it saw the output")
}

// [REQUIRED TEST] A workflow with a script step cannot start on an engine built
// without the executor: it fails closed with a clear error, not a nil dereference.
func TestEngine_ScriptStepWithoutExecutorFailsClosed(t *testing.T) {
	engine := workflow.NewEngine(nil, logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	t.Cleanup(engine.Shutdown)

	exec, err := engine.ExecuteRestrictedWorkflow(tenantCtx(), scriptWorkflow(), nil,
		workflow.RestrictedRun{RunID: "run-1", GrantID: "grant-1"})
	require.NoError(t, err)
	waitExecution(t, exec)

	assert.Equal(t, workflow.StatusFailed, exec.GetStatus())
	assert.Contains(t, exec.GetError(), "script executor not configured")
}

// [REQUIRED TEST] A workflow containing a script step, started through the
// unrestricted engine path, is refused with a clear error and nothing is queued.
func TestEngine_UnrestrictedPathRefusesScriptStep(t *testing.T) {
	f := newRestrictedFixture(t)
	f.put(t, rsOwnerTenant, "inventory", "echo hello\n")
	engine := workflow.NewEngine(nil, logging.NewNoopLogger(), nil, nil, nil, nil, nil, workflow.WithScriptStepExecutor(f.executor()))
	t.Cleanup(engine.Shutdown)

	nested := workflow.Workflow{Name: "nested", Steps: []workflow.Step{
		{Name: "outer", Type: workflow.StepTypeSequential, Steps: scriptWorkflow().Steps},
	}}
	for name, wf := range map[string]workflow.Workflow{"top level": scriptWorkflow(), "nested": nested} {
		t.Run(name, func(t *testing.T) {
			exec, err := engine.ExecuteWorkflow(tenantCtx(), wf, nil)

			require.ErrorIs(t, err, workflow.ErrScriptStepNotRestricted)
			assert.Contains(t, err.Error(), "restricted automation executions")
			require.NotNil(t, exec)
			assert.Equal(t, workflow.StatusFailed, exec.GetStatus())
			assert.Zero(t, f.queued())
			assert.Zero(t, f.approver.askedCount(), "the approver is never consulted")
		})
	}
}

// A restricted engine run without a run id, grant id or tenant never starts.
func TestEngine_RestrictedRunNeedsRunGrantAndTenant(t *testing.T) {
	engine := workflow.NewEngine(nil, logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	t.Cleanup(engine.Shutdown)

	_, err := engine.ExecuteRestrictedWorkflow(tenantCtx(), scriptWorkflow(), nil, workflow.RestrictedRun{GrantID: "g"})
	require.Error(t, err)
	_, err = engine.ExecuteRestrictedWorkflow(tenantCtx(), scriptWorkflow(), nil, workflow.RestrictedRun{RunID: "r"})
	require.Error(t, err)
	_, err = engine.ExecuteRestrictedWorkflow(context.Background(), scriptWorkflow(), nil, workflow.RestrictedRun{RunID: "r", GrantID: "g"})
	require.Error(t, err)
}

// A restricted run on an engine whose executor has no approver (the production
// state until the approver adapter is wired) fails the step with nothing queued.
func TestEngine_RestrictedScriptStepWithoutApproverFailsClosed(t *testing.T) {
	f := newRestrictedFixture(t)
	f.put(t, rsOwnerTenant, "inventory", "echo hello\n")
	executor := f.executor()
	executor.SetApprover(nil)
	engine := workflow.NewEngine(nil, logging.NewNoopLogger(), nil, nil, nil, nil, nil, workflow.WithScriptStepExecutor(executor))
	t.Cleanup(engine.Shutdown)

	exec, err := engine.ExecuteRestrictedWorkflow(tenantCtx(), scriptWorkflow(), nil,
		workflow.RestrictedRun{RunID: "run-1", GrantID: "grant-1"})
	require.NoError(t, err)
	waitExecution(t, exec)

	assert.Equal(t, workflow.StatusFailed, exec.GetStatus())
	assert.Contains(t, exec.GetError(), "no script approver")
	assert.Zero(t, f.queued())
}
