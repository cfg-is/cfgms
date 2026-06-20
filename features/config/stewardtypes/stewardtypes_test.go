// SPDX-License-Identifier: AGPL-3.0-only
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

// --- GetDNARefreshInterval ---

func TestGetDNARefreshInterval_ValidInterval(t *testing.T) {
	cfg := StewardConfig{Steward: StewardSettings{DNARefreshInterval: "15m"}}
	assert.Equal(t, 15*time.Minute, GetDNARefreshInterval(cfg))
}

func TestGetDNARefreshInterval_EmptyFallback(t *testing.T) {
	cfg := StewardConfig{Steward: StewardSettings{}}
	assert.Equal(t, 30*time.Minute, GetDNARefreshInterval(cfg))
}

func TestGetDNARefreshInterval_InvalidStringFallback(t *testing.T) {
	cfg := StewardConfig{Steward: StewardSettings{DNARefreshInterval: "notaduration"}}
	assert.Equal(t, 30*time.Minute, GetDNARefreshInterval(cfg),
		"unparseable duration must fall back to 30m default")
}

func TestGetDNARefreshInterval_ZeroFallback(t *testing.T) {
	cfg := StewardConfig{Steward: StewardSettings{DNARefreshInterval: "0s"}}
	assert.Equal(t, 30*time.Minute, GetDNARefreshInterval(cfg),
		"zero duration must fall back to 30m default")
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

// --- RequiredModules parsing ---

// [REQUIRED TEST] cfg file with required_modules parses all fields correctly.
func TestStewardConfig_RequiredModules_ParsesCorrectly(t *testing.T) {
	cfg := StewardConfig{
		RequiredModules: []RequiredModule{
			{Name: "cfgms/firewall", Version: "^1.0.0"},
		},
	}
	assert.Len(t, cfg.RequiredModules, 1)
	assert.Equal(t, "cfgms/firewall", cfg.RequiredModules[0].Name)
	assert.Equal(t, "^1.0.0", cfg.RequiredModules[0].Version)
}

func TestStewardConfig_RequiredModules_Empty(t *testing.T) {
	cfg := StewardConfig{Steward: StewardSettings{ID: "s1", Mode: ModeStandalone}}
	assert.Empty(t, cfg.RequiredModules)
	assert.NoError(t, ValidateConfiguration(cfg))
}

// --- ModuleTrustConfig parsing ---

// [REQUIRED TEST] module_trust with strict mode and additional_publishers parses correctly.
func TestStewardSettings_ModuleTrust_StrictMode_ParsesCorrectly(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:   "s1",
			Mode: ModeStandalone,
			ModuleTrust: ModuleTrustConfig{
				Mode:                 ModuleTrustModeStrict,
				AdditionalPublishers: []string{"vendor-a"},
			},
		},
	}
	assert.Equal(t, ModuleTrustModeStrict, cfg.Steward.ModuleTrust.Mode)
	assert.Equal(t, []string{"vendor-a"}, cfg.Steward.ModuleTrust.AdditionalPublishers)
	assert.NoError(t, ValidateConfiguration(cfg))
}

func TestStewardSettings_ModuleTrust_ControllerMode_Valid(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:          "s1",
			Mode:        ModeStandalone,
			ModuleTrust: ModuleTrustConfig{Mode: ModuleTrustModeController},
		},
	}
	assert.NoError(t, ValidateConfiguration(cfg))
}

func TestStewardSettings_ModuleTrust_BypassMode_Valid(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:          "s1",
			Mode:        ModeStandalone,
			ModuleTrust: ModuleTrustConfig{Mode: ModuleTrustModeBypass},
		},
	}
	assert.NoError(t, ValidateConfiguration(cfg))
}

func TestStewardSettings_ModuleTrust_EmptyMode_Valid(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:   "s1",
			Mode: ModeStandalone,
		},
	}
	assert.NoError(t, ValidateConfiguration(cfg))
}

// [REQUIRED TEST] module_trust with invalid mode returns a validation error.
func TestStewardSettings_ModuleTrust_InvalidMode_ReturnsError(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:   "s1",
			Mode: ModeStandalone,
			ModuleTrust: ModuleTrustConfig{
				Mode: ModuleTrustMode("invalid_value"),
			},
		},
	}
	err := ValidateConfiguration(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "module_trust")
	assert.Contains(t, err.Error(), "invalid_value")
}

// --- ValidateModuleTrustConfig ---

func TestValidateModuleTrustConfig_ValidModes(t *testing.T) {
	for _, mode := range []ModuleTrustMode{
		ModuleTrustModeStrict,
		ModuleTrustModeController,
		ModuleTrustModeBypass,
		"",
	} {
		t.Run(string(mode), func(t *testing.T) {
			assert.NoError(t, ValidateModuleTrustConfig(ModuleTrustConfig{Mode: mode}))
		})
	}
}

func TestValidateModuleTrustConfig_InvalidMode(t *testing.T) {
	err := ValidateModuleTrustConfig(ModuleTrustConfig{Mode: "bogus"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
}
