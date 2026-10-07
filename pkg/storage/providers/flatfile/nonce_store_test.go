// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestNonceStore(t *testing.T) *FlatFileNonceStore {
	t.Helper()
	store, err := NewFlatFileNonceStore(t.TempDir())
	require.NoError(t, err)
	return store
}

func TestFlatFileNonceStore_PutAndConsume(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-1", []byte("payload-1"), time.Minute))

	entry, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []byte("payload-1"), entry)
}

func TestFlatFileNonceStore_ConsumeIsSingleUse(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-2", []byte("payload-2"), time.Minute))

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-2")
	require.NoError(t, err)
	require.True(t, found)

	_, found, err = store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-2")
	require.NoError(t, err)
	assert.False(t, found, "nonce must not be consumable twice")
}

func TestFlatFileNonceStore_ConsumeNotFound(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:never-issued")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestFlatFileNonceStore_ExpiredNonceNotConsumable(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-3", []byte("payload-3"), -time.Second))

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-3")
	require.NoError(t, err)
	assert.False(t, found, "expired nonce must not be consumable")
}

func TestFlatFileNonceStore_PutOverwritesPriorEntry(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-4", []byte("first"), time.Minute))
	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-4", []byte("second"), time.Minute))

	entry, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-4")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []byte("second"), entry, "second Put must overwrite the first")
}

func TestFlatFileNonceStore_PutEmptyKeyRejected(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	err := store.PutNonce(ctx, "", []byte("payload"), time.Minute)
	assert.Error(t, err)
}

// TestFlatFileNonceStore_CrossInstanceHandoff proves a nonce PUT via one
// *FlatFileNonceStore instance is consumable via a second, independent
// instance rooted at the same directory.
func TestFlatFileNonceStore_CrossInstanceHandoff(t *testing.T) {
	root := t.TempDir()

	nodeA, err := NewFlatFileNonceStore(root)
	require.NoError(t, err)

	nodeB, err := NewFlatFileNonceStore(root)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, nodeA.PutNonce(ctx, "refresh-nonce:cross-node", []byte("issued-by-a"), time.Minute))

	entry, found, err := nodeB.GetAndConsumeNonce(ctx, "refresh-nonce:cross-node")
	require.NoError(t, err)
	require.True(t, found, "nonce issued via node A must be consumable via node B")
	assert.Equal(t, []byte("issued-by-a"), entry)

	_, found, err = nodeA.GetAndConsumeNonce(ctx, "refresh-nonce:cross-node")
	require.NoError(t, err)
	assert.False(t, found, "nonce already consumed via node B must not be consumable via node A")
}
