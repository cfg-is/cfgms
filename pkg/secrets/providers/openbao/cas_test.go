//go:build integration

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package openbao — CompareAndSwapSecret integration tests. Requires a running
// OpenBao dev instance (see store_test.go's package doc comment).
package openbao

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

func TestStore_CompareAndSwapSecret_CreateWhenAbsent(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	cleanupKey(t, store, tenantID, "cas-key")

	newVersion, ok, err := store.CompareAndSwapSecret(ctx, tenantID+"/cas-key", 0, &interfaces.SecretRequest{
		Key: "cas-key", Value: "v1", TenantID: tenantID, CreatedBy: "test",
	})
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 1, newVersion)

	got, err := store.GetSecret(ctx, tenantID+"/cas-key")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
}

func TestStore_CompareAndSwapSecret_RejectsWrongExpectedVersion(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	cleanupKey(t, store, tenantID, "cas-key")

	_, ok, err := store.CompareAndSwapSecret(ctx, tenantID+"/cas-key", 0, &interfaces.SecretRequest{
		Key: "cas-key", Value: "v1", TenantID: tenantID, CreatedBy: "test",
	})
	require.NoError(t, err)
	require.True(t, ok)

	_, ok, err = store.CompareAndSwapSecret(ctx, tenantID+"/cas-key", 0, &interfaces.SecretRequest{
		Key: "cas-key", Value: "attacker-value", TenantID: tenantID, CreatedBy: "test",
	})
	require.NoError(t, err, "a lost race is ok=false with a nil error, never an error")
	assert.False(t, ok)

	got, err := store.GetSecret(ctx, tenantID+"/cas-key")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
}

func TestStore_CompareAndSwapSecret_SucceedsWithCorrectVersionAndChains(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	cleanupKey(t, store, tenantID, "chain")

	v1, ok, err := store.CompareAndSwapSecret(ctx, tenantID+"/chain", 0, &interfaces.SecretRequest{
		Key: "chain", Value: "v1", TenantID: tenantID, CreatedBy: "test",
	})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, v1)

	v2, ok, err := store.CompareAndSwapSecret(ctx, tenantID+"/chain", v1, &interfaces.SecretRequest{
		Key: "chain", Value: "v2", TenantID: tenantID, CreatedBy: "test",
	})
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 2, v2)
}

// TestStore_CompareAndSwapSecret_CrossNodeConcurrentRace is the [REQUIRED TEST]
// contract proof: two independent OpenBaoSecretStore instances — modelling two
// separate controller nodes — talking to the same real OpenBao server race to
// create-if-absent the same key. OpenBao is this codebase's one ClusterCapable
// SecretStore provider, so this exercises genuine server-side atomicity, not a
// process-local approximation of it.
func TestStore_CompareAndSwapSecret_CrossNodeConcurrentRace(t *testing.T) {
	nodeA := testStore(t)
	nodeB := testStore(t)
	ctx := context.Background()

	tenantID := uniqueTenant(t)
	cleanupKey(t, nodeA, tenantID, "race-key")

	const attempts = 8
	var wg sync.WaitGroup
	var successes int64

	run := func(store *OpenBaoSecretStore, value string) {
		defer wg.Done()
		_, ok, err := store.CompareAndSwapSecret(ctx, tenantID+"/race-key", 0, &interfaces.SecretRequest{
			Key: "race-key", Value: value, TenantID: tenantID, CreatedBy: "test",
		})
		require.NoError(t, err)
		if ok {
			atomic.AddInt64(&successes, 1)
		}
	}

	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		if i%2 == 0 {
			go run(nodeA, "node-a-value")
		} else {
			go run(nodeB, "node-b-value")
		}
	}
	wg.Wait()

	assert.Equal(t, int64(1), successes, "exactly one of N concurrent create-if-absent CAS calls for the same key must succeed")
}
