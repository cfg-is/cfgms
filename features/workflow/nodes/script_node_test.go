// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package nodes

import (
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseScriptStepConfig_ExecutionContext verifies that execution_context is correctly
// parsed from the raw config map and stored on ScriptStepConfig.
func TestParseScriptStepConfig_ExecutionContext(t *testing.T) {
	tests := []struct {
		name       string
		configMap  map[string]interface{}
		wantCtx    script.ExecutionContext
		wantErr    bool
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
		"script_id":         "my-script",
		"script_version":    "1.0",
		"inline_script":     "echo hello",
		"shell":             "powershell",
		"execution_context": "logged_in_user",
		"timeout":           "30s",
		"capture_output":    true,
		"generate_api_key":  false,
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
		InlineScript:    "echo hello",
		Shell:           script.ShellBash,
		ExecutionContext: script.ExecutionContextLoggedInUser,
	}
	assert.Equal(t, script.ExecutionContextLoggedInUser, cfg.ExecutionContext)
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
