// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package stewardtypes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestStewardConfig_JSONKeysAreSnakeCase guards against the round-trip regression
// where StewardSettings (and its nested config structs) carried yaml tags but no
// json tags — so json.Marshal (what `cfg config show` uses) fell back to Go field
// names and leaked PascalCase (e.g. "ConvergeInterval") to the wire, while
// `cfg config upload` parses snake_case yaml ("converge_interval"). The two must
// use the same wire keys so a config round-trips: show -> edit -> upload.
func TestStewardConfig_JSONKeysAreSnakeCase(t *testing.T) {
	cfg := StewardConfig{
		Steward: StewardSettings{
			ID:                          "steward-1",
			Mode:                        ModeController,
			ModulePaths:                 []string{"/opt/cfgms/modules"},
			Logging:                     LoggingConfig{Level: "info", Format: "json"},
			ErrorHandling:               ErrorHandlingConfig{ModuleLoadFailure: ActionWarn, ResourceFailure: ActionFail, ConfigurationError: ActionFail},
			Secrets:                     SecretsConfig{SecretsDir: "/var/lib/cfgms/secrets", Provider: "sops"},
			ConvergeInterval:            "30m",
			ScriptSigning:               ScriptSigningConfig{Policy: ScriptSigningPolicyRequired, TrustMode: TrustModeTrustedKeys, TrustedKeys: []TrustedKeyRef{{Name: "k1", Thumbprint: "ab", PublicKeyRef: "ref"}}, AllowPublicCA: true, RequireSignedAdhoc: true},
			ModuleTrust:                 ModuleTrustConfig{Mode: ModuleTrustModeStrict, AdditionalPublishers: []string{"acme"}},
			SignedCommandReplayWindow:   5 * time.Minute,
			SignedCommandMaxParamsBytes: 4096,
			DriftMode:                   DriftModeApply,
			Upgrade:                     UpgradeConfig{DesiredVersion: "v0.9.7"},
			RegistrationPollTimeout:     time.Hour,
			DNARefreshInterval:          "30m",
			ObserveSweepN:               intPtr(10),
		},
		Resources: []ResourceConfig{{Name: "r1", Module: "file", Config: map[string]interface{}{"path": "/tmp/x"}}},
	}

	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)

	// Every leaf field must serialise under its snake_case key.
	wantKeys := []string{
		`"id"`, `"mode"`, `"module_paths"`, `"logging"`, `"level"`, `"format"`,
		`"error_handling"`, `"module_load_failure"`, `"resource_failure"`, `"configuration_error"`,
		`"secrets"`, `"secrets_dir"`, `"provider"`, `"converge_interval"`,
		`"script_signing"`, `"policy"`, `"trust_mode"`, `"trusted_keys"`, `"public_key_ref"`,
		`"allow_public_ca"`, `"require_signed_adhoc"`, `"module_trust"`, `"additional_publishers"`,
		`"signed_command_replay_window"`, `"signed_command_max_params_bytes"`, `"drift_mode"`,
		`"upgrade"`, `"desired_version"`, `"registration_poll_timeout"`, `"dna_refresh_interval"`,
		`"observe_sweep_n"`,
	}
	for _, k := range wantKeys {
		if !strings.Contains(got, k) {
			t.Errorf("JSON output missing snake_case key %s\ngot: %s", k, got)
		}
	}

	// No Go field name (PascalCase) may leak into the JSON keys.
	leaked := []string{
		`"ConvergeInterval"`, `"DriftMode"`, `"Mode"`, `"ModulePaths"`, `"ErrorHandling"`,
		`"ModuleLoadFailure"`, `"ResourceFailure"`, `"ConfigurationError"`, `"ScriptSigning"`,
		`"ModuleTrust"`, `"SecretsDir"`, `"DesiredVersion"`, `"RegistrationPollTimeout"`,
		`"DNARefreshInterval"`, `"AllowPublicCA"`, `"TrustMode"`, `"PublicKeyRef"`,
		`"ObserveSweepN"`,
	}
	for _, k := range leaked {
		if strings.Contains(got, k) {
			t.Errorf("JSON output leaked PascalCase Go field name %s (missing json tag)\ngot: %s", k, got)
		}
	}
}
