// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSigningMigrationSet_NotSharedYieldsNoSharedMaterial(t *testing.T) {
	c := newSigningCluster(t)
	nodes, _, _, _ := migrateThreeNodes(t, c)

	set, err := nodes[0].SigningMigrationSet(context.Background())
	require.NoError(t, err)
	assert.Nil(t, set.Shared, "no cursor: nothing to deliver")
	assert.Empty(t, set.Legacy)
	assert.Empty(t, set.LegacySerials)
}

func TestSigningMigrationSet_SharedAndLegacySigners(t *testing.T) {
	c := newSigningCluster(t)
	nodes, serials, _, _ := migrateThreeNodes(t, c)
	ctx := context.Background()
	_, created, err := nodes[1].ElectSharedSigningSerial(ctx, serials[1])
	require.NoError(t, err)
	require.True(t, created)

	for i, m := range nodes {
		set, err := m.SigningMigrationSet(ctx)
		require.NoError(t, err, "node %d", i)
		require.NotNil(t, set.Shared)
		assert.Equal(t, serials[1], set.Shared.Serial)
		assert.NotEmpty(t, set.Shared.PrivateKeyPEM)
		assert.ElementsMatch(t, []string{serials[0], serials[2]}, set.LegacySerials)
		require.Len(t, set.Legacy, 2)
		assert.Less(t, set.Legacy[0].Serial, set.Legacy[1].Serial, "sorted by serial")
	}
}

func TestSigningMigrationSet_RevokedLegacySignerIsNotASigner(t *testing.T) {
	c := newSigningCluster(t)
	nodes, serials, _, _ := migrateThreeNodes(t, c)
	ctx := context.Background()
	_, _, err := nodes[0].ElectSharedSigningSerial(ctx, serials[0])
	require.NoError(t, err)
	revokeSigningSerial(t, nodes[0], serials[2])

	set, err := nodes[0].SigningMigrationSet(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{serials[1], serials[2]}, set.LegacySerials, "a revoked serial is still retired from stewards")
	require.Len(t, set.Legacy, 1)
	assert.Equal(t, serials[1], set.Legacy[0].Serial, "a revoked key never signs")
}

func TestSigningMigrationSet_WithoutKeyStoreIsRefused(t *testing.T) {
	c := newSigningCluster(t)
	m, _ := c.node(t, c.secrets, false)
	_, err := m.SigningMigrationSet(context.Background())
	assert.ErrorIs(t, err, ErrNoSigningKeyStore)
}
