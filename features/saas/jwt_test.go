// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package saas

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestJWT creates a minimal three-segment JWT with the given tid claim.
// The signature segment is a placeholder — signature verification is out of scope.
func makeTestJWT(tid string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"tid":%q,"sub":"user123"}`, tid)))
	return header + "." + payload + ".fakesignature"
}

func TestExtractJWTTenantID(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantTID string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid JWT with tid",
			token:   makeTestJWT("12345678-1234-1234-1234-123456789012"),
			wantTID: "12345678-1234-1234-1234-123456789012",
		},
		{
			name:    "valid JWT with different tid value",
			token:   makeTestJWT("another-tenant-guid"),
			wantTID: "another-tenant-guid",
		},
		{
			name:    "opaque token — not a JWT",
			token:   "opaque-access-token-not-a-jwt",
			wantErr: true,
			errMsg:  "not a JWT",
		},
		{
			name:    "empty string",
			token:   "",
			wantErr: true,
			errMsg:  "not a JWT",
		},
		{
			name:    "two-segment token — still not a valid JWT",
			token:   "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0",
			wantErr: true,
			errMsg:  "not a JWT",
		},
		{
			name: "malformed base64 in payload segment",
			// Valid header, invalid base64 payload, placeholder signature.
			token:   "eyJhbGciOiJSUzI1NiJ9.!!!invalid-base64!!*.fakesignature",
			wantErr: true,
			errMsg:  "base64 decode failed",
		},
		{
			name: "missing tid field",
			token: func() string {
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
				payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user123","email":"user@example.com"}`))
				return header + "." + payload + ".fakesignature"
			}(),
			wantErr: true,
			errMsg:  "tid claim absent or empty",
		},
		{
			name: "tid field present but empty string",
			token: func() string {
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
				payload := base64.RawURLEncoding.EncodeToString([]byte(`{"tid":"","sub":"user123"}`))
				return header + "." + payload + ".fakesignature"
			}(),
			wantErr: true,
			errMsg:  "tid claim absent or empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tid, err := extractJWTTenantID(tt.token)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Empty(t, tid)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantTID, tid)
		})
	}
}
