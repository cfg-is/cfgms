// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// inMemNonceStore is a minimal in-memory NonceStore used only for contract
// testing the interface semantics. It is NOT intended for production use.
type inMemNonceStore struct {
	mu      sync.Mutex
	entries map[string]inMemNonceEntry
}

type inMemNonceEntry struct {
	value     []byte
	expiresAt time.Time
}

func newInMemNonceStore() business.NonceStore {
	return &inMemNonceStore{entries: make(map[string]inMemNonceEntry)}
}

func (s *inMemNonceStore) PutNonce(_ context.Context, key string, entry []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = inMemNonceEntry{value: entry, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (s *inMemNonceStore) GetAndConsumeNonce(_ context.Context, key string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok {
		return nil, false, nil
	}
	delete(s.entries, key)
	if time.Now().After(e.expiresAt) {
		return nil, false, nil
	}
	return e.value, true, nil
}

// Compile-time assertion: inMemNonceStore satisfies the interface.
var _ business.NonceStore = (*inMemNonceStore)(nil)

func TestNonceStore_PutAndConsume(t *testing.T) {
	store := newInMemNonceStore()
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-1", []byte("payload"), time.Minute))

	entry, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []byte("payload"), entry)
}

func TestNonceStore_ConsumeIsSingleUse(t *testing.T) {
	store := newInMemNonceStore()
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-2", []byte("payload"), time.Minute))

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-2")
	require.NoError(t, err)
	require.True(t, found)

	_, found, err = store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-2")
	require.NoError(t, err)
	assert.False(t, found, "a nonce must not be consumable twice")
}

func TestNonceStore_ConsumeNotFound(t *testing.T) {
	store := newInMemNonceStore()
	ctx := context.Background()

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:never-issued")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestNonceStore_ExpiredNonceNotConsumable(t *testing.T) {
	store := newInMemNonceStore()
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-3", []byte("payload"), -time.Second))

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-3")
	require.NoError(t, err)
	assert.False(t, found, "an expired nonce must not be consumable")
}

func TestNonceStore_PutOverwritesPriorEntry(t *testing.T) {
	store := newInMemNonceStore()
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-4", []byte("first"), time.Minute))
	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-4", []byte("second"), time.Minute))

	entry, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-4")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []byte("second"), entry)
}
