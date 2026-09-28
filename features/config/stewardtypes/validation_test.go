// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package stewardtypes

import (
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
