// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func storedSigningSerials(t *testing.T, c *signingCluster) []string {
	t.Helper()
	ks, err := NewSecretStoreSigningKeyStore(c.secrets, testSigningTenant, "")
	require.NoError(t, err)
	serials, err := ks.ListSigningSerials(context.Background())
	require.NoError(t, err)
	return serials
}

func TestClusterRotation_StoresKeyInSharedStoreAndObservedByOtherNode(t *testing.T) {
	c := newSigningCluster(t)
	a, dirA := c.node(t, c.secrets, true)
	b, dirB := c.node(t, c.secrets, true)
	require.NoError(t, a.EnsureSigningCertificate(fastSigningCfg))
	require.NoError(t, b.EnsureSigningCertificate(fastSigningCfg))
	original, err := a.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)

	rotated, err := a.RotateSigningCertificate(7)
	require.NoError(t, err)
	require.NotNil(t, rotated)
	assert.NotEqual(t, original.SerialNumber, rotated.SerialNumber)

	cursor, err := c.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	require.NotNil(t, cursor)
	assert.Equal(t, rotated.SerialNumber, cursor.CurrentSerial)
	assert.Equal(t, original.SerialNumber, cursor.RotatingSerial)
	assert.ElementsMatch(t, []string{original.SerialNumber, rotated.SerialNumber}, storedSigningSerials(t, c))

	// Node B resolves the new current serial and can still export the rotating key.
	gotB, err := b.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	assert.Equal(t, rotated.SerialNumber, gotB.SerialNumber)
	assert.Equal(t, rotated.PrivateKeyPEM, gotB.PrivateKeyPEM)
	_, oldKey, err := b.ExportCertificate(original.SerialNumber, true, false)
	require.NoError(t, err)
	assert.Equal(t, original.PrivateKeyPEM, oldKey)

	assert.Empty(t, signingKeyFiles(t, dirA), "no signing key on node A's disk")
	assert.Empty(t, signingKeyFiles(t, dirB), "no signing key on node B's disk")

	// The claim is released: a force rotation from B can take it again.
	_, err = b.ForceRotateSigningCertificate(7)
	require.NoError(t, err)
}

func TestClusterRotation_SecondRotationInOverlapIsInProgress(t *testing.T) {
	c := newSigningCluster(t)
	a, _ := c.node(t, c.secrets, true)
	b, _ := c.node(t, c.secrets, true)
	require.NoError(t, a.EnsureSigningCertificate(fastSigningCfg))

	_, err := a.RotateSigningCertificate(7)
	require.NoError(t, err)
	before := storedSigningSerials(t, c)

	_, err = b.RotateSigningCertificate(7)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSigningRotationInProgress))
	assert.ElementsMatch(t, before, storedSigningSerials(t, c), "no key generated for the rejected rotation")
}

func TestClusterRotation_HeldClaimBlocksBeforeKeyGeneration(t *testing.T) {
	c := newSigningCluster(t)
	a, _ := c.node(t, c.secrets, true)
	b, _ := c.node(t, c.secrets, true)
	require.NoError(t, a.EnsureSigningCertificate(fastSigningCfg))
	before := storedSigningSerials(t, c)

	ks, err := NewSecretStoreSigningKeyStore(c.secrets, testSigningTenant, "")
	require.NoError(t, err)
	won, err := ks.(interface {
		ClaimSigningRotation(context.Context) (bool, error)
	}).ClaimSigningRotation(context.Background())
	require.NoError(t, err)
	require.True(t, won)

	for _, rotate := range []func(int) (*Certificate, error){b.RotateSigningCertificate, b.ForceRotateSigningCertificate} {
		got, err := rotate(7)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.True(t, errors.Is(err, ErrSigningRotationInProgress))
	}
	assert.ElementsMatch(t, before, storedSigningSerials(t, c))
}

func TestClusterRotation_ConcurrentRotationsExactlyOneWins(t *testing.T) {
	c := newSigningCluster(t)
	const nodes = 5
	managers := make([]*Manager, nodes)
	for i := range managers {
		managers[i], _ = c.node(t, c.secrets, true)
	}
	require.NoError(t, managers[0].EnsureSigningCertificate(fastSigningCfg))
	before := storedSigningSerials(t, c)

	var wg sync.WaitGroup
	errs := make(chan error, nodes)
	for _, m := range managers {
		wg.Add(1)
		go func(m *Manager) {
			defer wg.Done()
			_, err := m.RotateSigningCertificate(7)
			errs <- err
		}(m)
	}
	wg.Wait()
	close(errs)

	var wins, inProgress int
	for err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrSigningRotationInProgress):
			inProgress++
		default:
			require.NoError(t, err, "unexpected error")
		}
	}
	assert.Equal(t, 1, wins)
	assert.Equal(t, nodes-1, inProgress)
	assert.Len(t, storedSigningSerials(t, c), len(before)+1, "exactly one new serial stored")

	cursor, err := c.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	assert.Equal(t, before[0], cursor.RotatingSerial)
}

func TestClusterRotation_LegacyLocalRefusedChangesNothing(t *testing.T) {
	c := newSigningCluster(t)
	dir := t.TempDir()
	legacy := c.nodeAt(t, dir, c.secrets, false)
	require.NoError(t, legacy.EnsureSigningCertificate(fastSigningCfg))
	upgraded := c.nodeAt(t, dir, c.secrets, true)

	for _, rotate := range []func(int) (*Certificate, error){upgraded.RotateSigningCertificate, upgraded.ForceRotateSigningCertificate} {
		got, err := rotate(7)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.True(t, errors.Is(err, ErrSigningMigrationPending))
	}
	cursor, err := c.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	assert.Nil(t, cursor)
	assert.Empty(t, storedSigningSerials(t, c))
}
