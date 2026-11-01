// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// uuidV4Pattern matches the canonical lowercase UUID v4 form with the version
// nibble fixed at 4 and the variant nibble in [89ab].
var uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestGenerateTokenID_Format(t *testing.T) {
	id, err := GenerateTokenID()
	require.NoError(t, err)
	assert.Len(t, id, 36, "token ID must be a canonical 36-character UUID")
	assert.Regexp(t, uuidV4Pattern, id, "token ID must be a lowercase UUID v4")
}

func TestGenerateTokenID_Unique(t *testing.T) {
	const iterations = 1000
	seen := make(map[string]struct{}, iterations)
	for i := 0; i < iterations; i++ {
		id, err := GenerateTokenID()
		require.NoError(t, err)
		require.Regexp(t, uuidV4Pattern, id)
		_, dup := seen[id]
		require.False(t, dup, "GenerateTokenID must not repeat an ID (iteration %d)", i)
		seen[id] = struct{}{}
	}
	assert.Len(t, seen, iterations)
}

func TestGenerateTokenID_DiffersFromSecret(t *testing.T) {
	id, err := GenerateTokenID()
	require.NoError(t, err)
	secret, err := GenerateToken()
	require.NoError(t, err)
	assert.NotEqual(t, secret, id, "the non-secret ID must never equal the secret")
	assert.NotContains(t, secret, id)
}

func TestCreateToken_AssignsStableID(t *testing.T) {
	first, err := CreateToken(&TokenCreateRequest{
		TenantID:      "tenant-gen",
		ControllerURL: "grpc://controller:7443",
	})
	require.NoError(t, err)
	assert.Regexp(t, uuidV4Pattern, first.ID, "CreateToken must assign a UUID v4 ID")
	assert.NotEqual(t, first.Token, first.ID, "ID must not be derived from the secret")

	second, err := CreateToken(&TokenCreateRequest{
		TenantID:      "tenant-gen",
		ControllerURL: "grpc://controller:7443",
	})
	require.NoError(t, err)
	assert.NotEqual(t, first.ID, second.ID, "each created token must get a distinct ID")
}
