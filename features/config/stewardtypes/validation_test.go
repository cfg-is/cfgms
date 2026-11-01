// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package stewardtypes

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateScriptSigningConfig_PublicKeyRefAcceptsPlainName(t *testing.T) {
	cfg := ScriptSigningConfig{
		Policy:    ScriptSigningPolicyOptional,
		TrustMode: TrustModeTrustedKeys,
		TrustedKeys: []TrustedKeyRef{
			{Name: "vendor-a", PublicKeyRef: "vendor-a-key.pem"},
		},
	}
	require.NoError(t, ValidateScriptSigningConfig(cfg))
}

func TestValidateScriptSigningConfig_PublicKeyRefRejectsTraversal(t *testing.T) {
	tests := []struct {
		name string
		ref  string
	}{
		{"parent segment", "../../etc/shadow"},
		{"embedded parent segment", "keys/../../secrets/other-tenant-key.pem"},
		{"absolute path", "/etc/shadow"},
		{"windows absolute path", `\Windows\System32\config\sam`},
		{"dot segment", "./key.pem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ScriptSigningConfig{
				Policy:    ScriptSigningPolicyOptional,
				TrustMode: TrustModeTrustedKeys,
				TrustedKeys: []TrustedKeyRef{
					{Name: "malicious", PublicKeyRef: tt.ref},
				},
			}
			err := ValidateScriptSigningConfig(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "public_key_ref")
		})
	}
}

func TestValidateScriptSigningConfig_PublicKeyRefEmptyAllowedWithThumbprint(t *testing.T) {
	cfg := ScriptSigningConfig{
		Policy:    ScriptSigningPolicyOptional,
		TrustMode: TrustModeTrustedKeys,
		TrustedKeys: []TrustedKeyRef{
			{Name: "vendor-a", Thumbprint: "ABCDEF0123456789"},
		},
	}
	require.NoError(t, ValidateScriptSigningConfig(cfg))
}

func TestValidate_ModuleDriftModes_RejectsUnknownMode(t *testing.T) {
	base := func(settings StewardSettings) StewardConfig {
		settings.ID = "s1"
		return StewardConfig{Steward: settings}
	}

	if err := ValidateConfiguration(base(StewardSettings{
		DriftMode:        DriftModeApply,
		ModuleDriftModes: map[string]DriftMode{"activedirectory": DriftModeMonitor, "file": DriftModeApply},
	})); err != nil {
		t.Fatalf("valid drift modes rejected: %v", err)
	}

	cases := []struct {
		name     string
		settings StewardSettings
		wantIn   string
	}{
		{"unknown module mode", StewardSettings{ModuleDriftModes: map[string]DriftMode{"file": "enforce"}}, "module_drift_modes[file]"},
		{"empty module mode", StewardSettings{ModuleDriftModes: map[string]DriftMode{"file": ""}}, "module_drift_modes[file]"},
		{"key with dot", StewardSettings{ModuleDriftModes: map[string]DriftMode{"hyperv.vm": DriftModeMonitor}}, "module_drift_modes: malformed key"},
		{"empty key", StewardSettings{ModuleDriftModes: map[string]DriftMode{"": DriftModeMonitor}}, "module_drift_modes: malformed key"},
		{"unknown steward mode", StewardSettings{DriftMode: "enforce"}, "drift_mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConfiguration(base(tc.settings))
			if err == nil || !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantIn)
			}
		})
	}
}
