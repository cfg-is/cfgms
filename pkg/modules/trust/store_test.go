// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package trust_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// TestInMemoryTrustStore_AddPublisher_RejectsDuplicateName verifies Issue #4324
// item 3: a trust store must not let a second registration under an
// already-used publisher name silently overwrite the first — the exact
// behavior that let a supplied "additional publisher" displace the baked-in
// CFGMS identity in features/steward/modules/trust.verifyStrict.
func TestInMemoryTrustStore_AddPublisher_RejectsDuplicateName(t *testing.T) {
	store := trust.NewInMemoryTrustStore()

	original := trust.PublisherIdentity{Name: "cfgms", PublicKey: []byte("11111111111111111111111111111111"), Algorithm: "ed25519"}
	require.NoError(t, store.AddPublisher(original))

	colliding := trust.PublisherIdentity{Name: "cfgms", PublicKey: []byte("22222222222222222222222222222222"), Algorithm: "ed25519"}
	err := store.AddPublisher(colliding)
	require.Error(t, err)
	assert.ErrorIs(t, err, trust.ErrPublisherAlreadyRegistered)

	// The original registration must be the one that survives.
	got, ok := store.GetPublisher("cfgms")
	require.True(t, ok)
	assert.Equal(t, original.PublicKey, got.PublicKey,
		"a rejected duplicate registration must not change the stored identity")
}

// TestInMemoryTrustStore_AddPublisher_DistinctNamesBothSucceed is a control
// case: registering two different publisher names must not interfere with
// each other.
func TestInMemoryTrustStore_AddPublisher_DistinctNamesBothSucceed(t *testing.T) {
	store := trust.NewInMemoryTrustStore()

	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{Name: "cfgms", PublicKey: []byte("11111111111111111111111111111111"), Algorithm: "ed25519"}))
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{Name: "vendor-a", PublicKey: []byte("22222222222222222222222222222222"), Algorithm: "ed25519"}))

	assert.Len(t, store.ListPublishers(), 2)
}
