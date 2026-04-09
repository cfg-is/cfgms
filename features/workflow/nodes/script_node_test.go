// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package nodes

import (
	"os"
	"testing"

	"github.com/cfgis/cfgms/features/modules/script"
	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

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
