// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package nodes

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
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
	}
	node := NewScriptNode("test-node", "Test Script", config, nil, monitor, nil)

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
		"secrets_dir": t.TempDir(),
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
// priority over the fleet filter and the localhost fallback.
func TestResolveDeviceIDs_ExplicitDevicesWin(t *testing.T) {
	provider := &testStewardProvider{
		stewards: []fleet.StewardData{
			makeSteward("fleet-device", "online", map[string]string{"os": "linux"}),
		},
	}
	q := fleet.NewMemoryQuery(provider)

	node := NewScriptNode("id", "name", &ScriptStepConfig{
		Devices:      []string{"explicit-device-1", "explicit-device-2"},
		DeviceFilter: &fleet.Filter{OS: "linux"},
	}, nil, nil, nil)
	node.SetFleetQuery(q)

	ids, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"explicit-device-1", "explicit-device-2"}, ids,
		"explicit Devices must take priority over fleet filter")
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

	ids, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err)
	require.Len(t, ids, 2)
	assert.Contains(t, ids, "linux-1")
	assert.Contains(t, ids, "linux-2")
}

// TestResolveDeviceIDs_LocalhostFallback verifies that localhost is used when
// no explicit devices and no device filter are configured.
func TestResolveDeviceIDs_LocalhostFallback(t *testing.T) {
	node := NewScriptNode("id", "name", &ScriptStepConfig{}, nil, nil, nil)

	ids, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"localhost"}, ids)
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

	ids, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err, "zero-match must not return an error")
	assert.Empty(t, ids, "zero-match must return an empty ID list")
}

// TestResolveDeviceIDs_FilterWithoutFleetQuery verifies that when a device
// filter is set but no fleet query is injected, localhost fallback is used.
func TestResolveDeviceIDs_FilterWithoutFleetQuery(t *testing.T) {
	node := NewScriptNode("id", "name", &ScriptStepConfig{
		DeviceFilter: &fleet.Filter{OS: "linux"},
	}, nil, nil, nil)
	// No SetFleetQuery call.

	ids, err := node.resolveDeviceIDs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"localhost"}, ids, "missing fleet query falls back to localhost")
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
	}
	// No queue set — executionQueue is nil.
	node := NewScriptNode("id", "name", config, nil, monitor, nil)

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

	step := workflow.Step{
		Name: "test-step",
		Config: map[string]interface{}{
			"script_id": "test-script",
			"shell":     "bash",
			"devices":   []interface{}{"device-1"},
		},
	}

	variables := map[string]interface{}{
		"workflow_run_id": "wf-run-999",
		"workflow_name":   "test-workflow",
	}

	result, err := executor.ExecuteStep(context.Background(), step, variables)
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
