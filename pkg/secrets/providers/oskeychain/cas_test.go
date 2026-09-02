// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package oskeychain

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCompareAndSwapSecret_Validation exercises the request rejections
// CompareAndSwapSecret performs before it ever reaches the keychain. Runs
// against the real platform backend on every host, including one with no
// usable keychain — a rejected request never touches the backend.
func TestCompareAndSwapSecret_Validation(t *testing.T) {
	store := newStore(platformBackend(t))
	ctx := context.Background()

	_, _, err := store.CompareAndSwapSecret(ctx, "k", 0, nil)
	assert.Error(t, err, "nil request")

	_, _, err = store.CompareAndSwapSecret(ctx, "", 0, &interfaces.SecretRequest{Key: "k", Value: "v"})
	assert.Error(t, err, "empty key")

	_, _, err = store.CompareAndSwapSecret(ctx, "k", 0, &interfaces.SecretRequest{Key: "", Value: "v"})
	assert.Error(t, err, "empty request key")

	_, _, err = store.CompareAndSwapSecret(ctx, "k", 0, &interfaces.SecretRequest{Key: "k", Value: ""})
	assert.Error(t, err, "empty value")
}

// TestCompareAndSwapSecret_RoundTripAndRace is the [REQUIRED TEST] contract
// proof for oskeychain: create-if-absent succeeds once, a stale expected
// version is refused with ok=false and no error, and exactly one of N
// concurrent create-if-absent calls for the same key wins. Skipped when this
// host offers no usable OS keychain backend — CFGMS forbids substituting a
// stand-in for the real backend (see platformBackend's doc comment).
func TestCompareAndSwapSecret_RoundTripAndRace(t *testing.T) {
	b := platformBackend(t)
	if !b.available() {
		t.Skip("no usable OS keychain backend on this host; CompareAndSwapSecret round-trip requires one")
	}
	store := newStore(b)
	ctx := context.Background()
	key := "cfgms/session/cas-" + randHex(t, 8)
	t.Cleanup(func() { _ = store.DeleteSecret(ctx, key) })

	newVersion, ok, err := store.CompareAndSwapSecret(ctx, key, 0, &interfaces.SecretRequest{Key: key, Value: "v1"})
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 1, newVersion)

	got, err := store.GetSecret(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)

	// Stale expected version is refused, not silently overwritten.
	_, ok, err = store.CompareAndSwapSecret(ctx, key, 0, &interfaces.SecretRequest{Key: key, Value: "attacker"})
	require.NoError(t, err)
	assert.False(t, ok)
	got, err = store.GetSecret(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)

	// Correct expected version chains.
	v2, ok, err := store.CompareAndSwapSecret(ctx, key, 1, &interfaces.SecretRequest{Key: key, Value: "v2"})
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 2, v2)

	// Concurrent race: exactly one of N create-if-absent attempts for a fresh key wins.
	raceKey := "cfgms/session/cas-race-" + randHex(t, 8)
	t.Cleanup(func() { _ = store.DeleteSecret(ctx, raceKey) })

	const attempts = 6
	var wg sync.WaitGroup
	var successes int64
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			_, ok, err := store.CompareAndSwapSecret(ctx, raceKey, 0, &interfaces.SecretRequest{Key: raceKey, Value: "value"})
			require.NoError(t, err)
			if ok {
				atomic.AddInt64(&successes, 1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int64(1), successes, "exactly one of N concurrent create-if-absent CAS calls for the same key must succeed")
}
