// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestToProtoFromProto_RoundTrip verifies that the basic StewardConfig fields
// survive a ToProto→FromProto round-trip without loss.
func TestToProtoFromProto_RoundTrip(t *testing.T) {
	original := &StewardConfig{
		Steward: StewardSettings{
			ID:          "test-steward",
			Mode:        ModeStandalone,
			ModulePaths: []string{"/opt/modules", "/usr/local/modules"},
			Logging: LoggingConfig{
				Level:  "info",
				Format: "json",
			},
			ErrorHandling: ErrorHandlingConfig{
				ModuleLoadFailure:  ActionContinue,
				ResourceFailure:    ActionWarn,
				ConfigurationError: ActionFail,
			},
		},
		Resources: []ResourceConfig{
			{
				Name:   "test-resource",
				Module: "file",
				Config: map[string]interface{}{"path": "/etc/test", "content": "hello"},
			},
		},
		Modules: map[string]string{
			"file": "/opt/modules/file",
		},
	}

	proto, err := ToProto(original)
	require.NoError(t, err)
	require.NotNil(t, proto)

	restored, err := FromProto(proto)
	require.NoError(t, err)
	require.NotNil(t, restored)

	assert.Equal(t, original.Steward.ID, restored.Steward.ID)
	assert.Equal(t, original.Steward.Mode, restored.Steward.Mode)
	assert.Equal(t, original.Steward.ModulePaths, restored.Steward.ModulePaths)
	assert.Equal(t, original.Steward.Logging.Level, restored.Steward.Logging.Level)
	assert.Equal(t, original.Steward.Logging.Format, restored.Steward.Logging.Format)
	assert.Equal(t, original.Steward.ErrorHandling.ModuleLoadFailure, restored.Steward.ErrorHandling.ModuleLoadFailure)
	assert.Equal(t, original.Steward.ErrorHandling.ResourceFailure, restored.Steward.ErrorHandling.ResourceFailure)
	assert.Equal(t, original.Steward.ErrorHandling.ConfigurationError, restored.Steward.ErrorHandling.ConfigurationError)
	assert.Equal(t, original.Modules, restored.Modules)
	require.Len(t, restored.Resources, 1)
	assert.Equal(t, "test-resource", restored.Resources[0].Name)
	assert.Equal(t, "file", restored.Resources[0].Module)
}

// TestToProtoFromProto_Secrets verifies the Secrets field survives a round-trip.
func TestToProtoFromProto_Secrets(t *testing.T) {
	original := &StewardConfig{
		Steward: StewardSettings{
			ID:   "secrets-steward",
			Mode: ModeStandalone,
			Secrets: SecretsConfig{
				SecretsDir: "/var/lib/cfgms/secrets",
				Provider:   "steward",
			},
			Logging:       LoggingConfig{Level: "info", Format: "text"},
			ErrorHandling: ErrorHandlingConfig{ModuleLoadFailure: ActionContinue, ResourceFailure: ActionWarn, ConfigurationError: ActionFail},
		},
	}

	proto, err := ToProto(original)
	require.NoError(t, err)
	require.NotNil(t, proto.Steward.Secrets)
	assert.Equal(t, "/var/lib/cfgms/secrets", proto.Steward.Secrets["secrets_dir"])
	assert.Equal(t, "steward", proto.Steward.Secrets["provider"])

	restored, err := FromProto(proto)
	require.NoError(t, err)
	assert.Equal(t, "/var/lib/cfgms/secrets", restored.Steward.Secrets.SecretsDir)
	assert.Equal(t, "steward", restored.Steward.Secrets.Provider)
}

// TestToProtoFromProto_ConvergeInterval verifies ConvergeInterval survives a round-trip.
func TestToProtoFromProto_ConvergeInterval(t *testing.T) {
	original := &StewardConfig{
		Steward: StewardSettings{
			ID:               "interval-steward",
			Mode:             ModeStandalone,
			ConvergeInterval: "45m",
			Logging:          LoggingConfig{Level: "info", Format: "text"},
			ErrorHandling:    ErrorHandlingConfig{ModuleLoadFailure: ActionContinue, ResourceFailure: ActionWarn, ConfigurationError: ActionFail},
		},
	}

	proto, err := ToProto(original)
	require.NoError(t, err)
	require.NotNil(t, proto.Steward.ConvergeInterval)
	assert.Equal(t, 45*time.Minute, proto.Steward.ConvergeInterval.AsDuration())

	restored, err := FromProto(proto)
	require.NoError(t, err)
	// The round-trip converts "45m" → Duration → String(). Go formats 45m as "45m0s".
	// Parse both and compare as durations.
	originalDur, err := time.ParseDuration(original.Steward.ConvergeInterval)
	require.NoError(t, err)
	restoredDur, err := time.ParseDuration(restored.Steward.ConvergeInterval)
	require.NoError(t, err)
	assert.Equal(t, originalDur, restoredDur)
}

// TestToProtoFromProto_ScriptSigning verifies ScriptSigning survives a round-trip.
func TestToProtoFromProto_ScriptSigning(t *testing.T) {
	original := &StewardConfig{
		Steward: StewardSettings{
			ID:   "signing-steward",
			Mode: ModeStandalone,
			ScriptSigning: ScriptSigningConfig{
				Policy:    ScriptSigningPolicyRequired,
				TrustMode: TrustModeTrustedKeys,
				TrustedKeys: []TrustedKeyRef{
					{
						Name:         "ops-key",
						Thumbprint:   "AA:BB:CC:DD",
						PublicKeyRef: "refs/keys/ops",
					},
				},
			},
			Logging:       LoggingConfig{Level: "info", Format: "text"},
			ErrorHandling: ErrorHandlingConfig{ModuleLoadFailure: ActionContinue, ResourceFailure: ActionWarn, ConfigurationError: ActionFail},
		},
	}

	proto, err := ToProto(original)
	require.NoError(t, err)
	require.NotNil(t, proto.Steward.ScriptSigning)
	assert.Equal(t, "required", proto.Steward.ScriptSigning.Policy)
	assert.Equal(t, "trusted_keys", proto.Steward.ScriptSigning.TrustMode)
	require.Len(t, proto.Steward.ScriptSigning.TrustedKeys, 1)
	assert.Equal(t, "ops-key", proto.Steward.ScriptSigning.TrustedKeys[0].Name)
	assert.Equal(t, "AA:BB:CC:DD", proto.Steward.ScriptSigning.TrustedKeys[0].Thumbprint)
	assert.Equal(t, "refs/keys/ops", proto.Steward.ScriptSigning.TrustedKeys[0].PublicKeyRef)

	restored, err := FromProto(proto)
	require.NoError(t, err)
	ss := restored.Steward.ScriptSigning
	assert.Equal(t, ScriptSigningPolicyRequired, ss.Policy)
	assert.Equal(t, TrustModeTrustedKeys, ss.TrustMode)
	require.Len(t, ss.TrustedKeys, 1)
	assert.Equal(t, "ops-key", ss.TrustedKeys[0].Name)
	assert.Equal(t, "AA:BB:CC:DD", ss.TrustedKeys[0].Thumbprint)
	assert.Equal(t, "refs/keys/ops", ss.TrustedKeys[0].PublicKeyRef)
}

// TestToProtoFromProto_AllThreeNewFields verifies Secrets, ConvergeInterval, and
// ScriptSigning all survive a single round-trip together.
func TestToProtoFromProto_AllThreeNewFields(t *testing.T) {
	original := &StewardConfig{
		Steward: StewardSettings{
			ID:   "full-steward",
			Mode: ModeStandalone,
			Secrets: SecretsConfig{
				SecretsDir: "/run/secrets",
				Provider:   "vault",
			},
			ConvergeInterval: "15m",
			ScriptSigning: ScriptSigningConfig{
				Policy:        ScriptSigningPolicyOptional,
				TrustMode:     TrustModeAnyValid,
				AllowPublicCA: true,
			},
			Logging:       LoggingConfig{Level: "debug", Format: "json"},
			ErrorHandling: ErrorHandlingConfig{ModuleLoadFailure: ActionContinue, ResourceFailure: ActionWarn, ConfigurationError: ActionFail},
		},
	}

	proto, err := ToProto(original)
	require.NoError(t, err)

	restored, err := FromProto(proto)
	require.NoError(t, err)

	// Secrets
	assert.Equal(t, "/run/secrets", restored.Steward.Secrets.SecretsDir)
	assert.Equal(t, "vault", restored.Steward.Secrets.Provider)

	// ConvergeInterval
	origDur, err := time.ParseDuration(original.Steward.ConvergeInterval)
	require.NoError(t, err)
	resDur, err := time.ParseDuration(restored.Steward.ConvergeInterval)
	require.NoError(t, err)
	assert.Equal(t, origDur, resDur)

	// ScriptSigning
	assert.Equal(t, ScriptSigningPolicyOptional, restored.Steward.ScriptSigning.Policy)
	assert.Equal(t, TrustModeAnyValid, restored.Steward.ScriptSigning.TrustMode)
	assert.True(t, restored.Steward.ScriptSigning.AllowPublicCA)
}

// TestToProto_NilConfig verifies that ToProto returns an error on nil input.
func TestToProto_NilConfig(t *testing.T) {
	proto, err := ToProto(nil)
	assert.Error(t, err)
	assert.Nil(t, proto)
	assert.Contains(t, err.Error(), "config is nil")
}

// TestFromProto_NilProto verifies that FromProto returns an error on nil input.
func TestFromProto_NilProto(t *testing.T) {
	cfg, err := FromProto(nil)
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "proto config is nil")
}

// TestToProto_InvalidConvergeInterval verifies that an unparseable converge_interval
// causes ToProto to return an error rather than silently dropping or corrupting the field.
func TestToProto_InvalidConvergeInterval(t *testing.T) {
	cfg := &StewardConfig{
		Steward: StewardSettings{
			ID:               "bad-interval-steward",
			Mode:             ModeStandalone,
			ConvergeInterval: "not-a-duration",
			Logging:          LoggingConfig{Level: "info", Format: "text"},
			ErrorHandling:    ErrorHandlingConfig{ModuleLoadFailure: ActionContinue, ResourceFailure: ActionWarn, ConfigurationError: ActionFail},
		},
	}
	proto, err := ToProto(cfg)
	assert.Error(t, err)
	assert.Nil(t, proto)
	assert.Contains(t, err.Error(), "invalid converge_interval")
}
