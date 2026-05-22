// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package stewardtypes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateConfiguration_ValidConfig(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:   "test-steward",
			Mode: ModeStandalone,
			Logging: LoggingConfig{
				Level:  "info",
				Format: "text",
			},
		},
		Resources: []ResourceConfig{
			{
				Name:   "test-resource",
				Module: "test-module",
				Config: map[string]interface{}{"key": "value"},
			},
		},
	}
	assert.NoError(t, ValidateConfiguration(cfg))
}

func TestValidateConfiguration_MissingID(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			Mode:    ModeStandalone,
			Logging: LoggingConfig{Level: "info"},
		},
	}
	err := ValidateConfiguration(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ID")
}

func TestValidateConfiguration_InvalidLogLevel(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:      "test-steward",
			Mode:    ModeStandalone,
			Logging: LoggingConfig{Level: "verbose"},
		},
	}
	err := ValidateConfiguration(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "log level")
}

func TestValidateConfiguration_InvalidOperationMode(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:      "test-steward",
			Mode:    "distributed",
			Logging: LoggingConfig{Level: "info"},
		},
	}
	err := ValidateConfiguration(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "operation mode")
}

func TestValidateConfiguration_EmptyLogLevelValid(t *testing.T) {
	// Empty log level is valid — applyDefaults fills in "info"
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:   "test-steward",
			Mode: ModeController,
		},
	}
	assert.NoError(t, ValidateConfiguration(cfg))
}

func TestValidateConfiguration_ResourceMissingName(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:   "test-steward",
			Mode: ModeStandalone,
		},
		Resources: []ResourceConfig{
			{Module: "mod", Config: map[string]interface{}{"k": "v"}},
		},
	}
	err := ValidateConfiguration(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestValidateConfiguration_ResourceMissingModule(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:   "test-steward",
			Mode: ModeStandalone,
		},
		Resources: []ResourceConfig{
			{Name: "r1", Config: map[string]interface{}{"k": "v"}},
		},
	}
	err := ValidateConfiguration(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "module")
}

func TestValidateConfiguration_DuplicateResourceNames(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:   "test-steward",
			Mode: ModeStandalone,
		},
		Resources: []ResourceConfig{
			{Name: "dup", Module: "m1", Config: map[string]interface{}{"k": "v"}},
			{Name: "dup", Module: "m2", Config: map[string]interface{}{"k": "v"}},
		},
	}
	err := ValidateConfiguration(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestValidateConfiguration_ConvergeIntervalInvalid(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:               "test-steward",
			Mode:             ModeStandalone,
			ConvergeInterval: "not-a-duration",
		},
	}
	err := ValidateConfiguration(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "converge_interval")
}

func TestValidateConfiguration_ConvergeIntervalZero(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:               "test-steward",
			Mode:             ModeStandalone,
			ConvergeInterval: "0s",
		},
	}
	err := ValidateConfiguration(cfg)
	require.Error(t, err)
}

// --- MergeScriptSigningConfig ---

func TestMergeScriptSigningConfig_ChildInheritsParentPolicy(t *testing.T) {
	parent := ScriptSigningConfig{
		Policy:    ScriptSigningPolicyOptional,
		TrustMode: TrustModeAnyValid,
	}
	child := ScriptSigningConfig{}
	result, err := MergeScriptSigningConfig(parent, child)
	require.NoError(t, err)
	assert.Equal(t, ScriptSigningPolicyOptional, result.Policy)
	assert.Equal(t, TrustModeAnyValid, result.TrustMode)
}

func TestMergeScriptSigningConfig_ChildTighteningAllowed(t *testing.T) {
	parent := ScriptSigningConfig{
		Policy:    ScriptSigningPolicyOptional,
		TrustMode: TrustModeAnyValid,
	}
	child := ScriptSigningConfig{
		Policy:    ScriptSigningPolicyRequired,
		TrustMode: TrustModeTrustedKeys,
		TrustedKeys: []TrustedKeyRef{
			{Name: "corp-key", Thumbprint: "abc123"},
		},
	}
	result, err := MergeScriptSigningConfig(parent, child)
	require.NoError(t, err)
	assert.Equal(t, ScriptSigningPolicyRequired, result.Policy)
	assert.Equal(t, TrustModeTrustedKeys, result.TrustMode)
}

func TestMergeScriptSigningConfig_ChildLooseningFails(t *testing.T) {
	parent := ScriptSigningConfig{
		Policy:    ScriptSigningPolicyRequired,
		TrustMode: TrustModeAnyValid,
	}
	child := ScriptSigningConfig{
		Policy: ScriptSigningPolicyOptional,
	}
	_, err := MergeScriptSigningConfig(parent, child)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loosen")
}

func TestMergeScriptSigningConfig_ChildLooseningFromNoneFails(t *testing.T) {
	parent := ScriptSigningConfig{Policy: ScriptSigningPolicyRequired}
	child := ScriptSigningConfig{Policy: ScriptSigningPolicyNone}
	_, err := MergeScriptSigningConfig(parent, child)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loosen")
}

func TestMergeScriptSigningConfig_EmptyBothReturnsNone(t *testing.T) {
	result, err := MergeScriptSigningConfig(ScriptSigningConfig{}, ScriptSigningConfig{})
	require.NoError(t, err)
	assert.Equal(t, ScriptSigningPolicyNone, result.Policy)
}

func TestMergeScriptSigningConfig_InheritsRequireSignedAdhoc(t *testing.T) {
	parent := ScriptSigningConfig{
		Policy:             ScriptSigningPolicyOptional,
		RequireSignedAdhoc: true,
	}
	result, err := MergeScriptSigningConfig(parent, ScriptSigningConfig{})
	require.NoError(t, err)
	assert.True(t, result.RequireSignedAdhoc)
}

// --- GetConvergeInterval ---

func TestGetConvergeInterval_ValidInterval(t *testing.T) {
	cfg := StewardConfig{Steward: StewardSettings{ConvergeInterval: "15m"}}
	assert.Equal(t, 15*time.Minute, GetConvergeInterval(cfg))
}

func TestGetConvergeInterval_EmptyFallback(t *testing.T) {
	cfg := StewardConfig{Steward: StewardSettings{}}
	assert.Equal(t, 30*time.Minute, GetConvergeInterval(cfg))
}

// --- GetConfiguredModules ---

func TestGetConfiguredModules_DeduplicatesModules(t *testing.T) {
	cfg := StewardConfig{
		Resources: []ResourceConfig{
			{Name: "r1", Module: "directory"},
			{Name: "r2", Module: "file"},
			{Name: "r3", Module: "directory"},
		},
	}
	modules := GetConfiguredModules(cfg)
	assert.Len(t, modules, 2)
	assert.Contains(t, modules, "directory")
	assert.Contains(t, modules, "file")
}

func TestGetConfiguredModules_EmptyResources(t *testing.T) {
	cfg := StewardConfig{}
	assert.Empty(t, GetConfiguredModules(cfg))
}
