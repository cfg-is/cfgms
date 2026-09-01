// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sops

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

func newTestSOPSStore(t *testing.T, dataRoot, keyPath string) *SOPSSecretStore {
	t.Helper()
	store, err := NewSOPSSecretStore(&SOPSSecretStoreConfig{
		StorageProvider: "flatfile",
		StorageConfig:   map[string]interface{}{"root": dataRoot},
		CacheEnabled:    false,
		KeyFile:         keyPath,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestCompareAndSwapSecret_CreateWhenAbsent proves expectedVersion 0 succeeds
// against a key that has never been written and returns version 1.
func TestCompareAndSwapSecret_CreateWhenAbsent(t *testing.T) {
	base := t.TempDir()
	dataRoot := filepath.Join(base, "data")
	store := newTestSOPSStore(t, dataRoot, writeTestKey(t, base))
	ctx := context.Background()

	newVersion, ok, err := store.CompareAndSwapSecret(ctx, "tenant-a/cas-key", 0, &secretsif.SecretRequest{
		Key: "cas-key", Value: "v1", TenantID: "tenant-a", CreatedBy: "test",
	})
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 1, newVersion)

	got, err := store.GetSecret(ctx, "tenant-a/cas-key")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
}

// TestCompareAndSwapSecret_RejectsWrongExpectedVersion proves a stale expected
// version is refused with ok=false and no error, never a silent overwrite.
func TestCompareAndSwapSecret_RejectsWrongExpectedVersion(t *testing.T) {
	base := t.TempDir()
	dataRoot := filepath.Join(base, "data")
	store := newTestSOPSStore(t, dataRoot, writeTestKey(t, base))
	ctx := context.Background()

	_, ok, err := store.CompareAndSwapSecret(ctx, "tenant-a/cas-key", 0, &secretsif.SecretRequest{
		Key: "cas-key", Value: "v1", TenantID: "tenant-a", CreatedBy: "test",
	})
	require.NoError(t, err)
	require.True(t, ok)

	// A second create-if-absent (expectedVersion 0) against the now-existing key
	// must lose — this is the exact shape of two concurrent approvals racing.
	_, ok, err = store.CompareAndSwapSecret(ctx, "tenant-a/cas-key", 0, &secretsif.SecretRequest{
		Key: "cas-key", Value: "v2-attacker", TenantID: "tenant-a", CreatedBy: "test",
	})
	require.NoError(t, err, "a lost race is ok=false with a nil error, never an error")
	assert.False(t, ok)

	// The value from the winning write must be unchanged.
	got, err := store.GetSecret(ctx, "tenant-a/cas-key")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)

	// A stale non-zero expected version is refused the same way.
	_, ok, err = store.CompareAndSwapSecret(ctx, "tenant-a/cas-key", 99, &secretsif.SecretRequest{
		Key: "cas-key", Value: "v3", TenantID: "tenant-a", CreatedBy: "test",
	})
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestCompareAndSwapSecret_SucceedsWithCorrectVersionAndChains proves the
// version returned by one successful CAS is exactly what the next CAS must
// present, forming an unbroken chain.
func TestCompareAndSwapSecret_SucceedsWithCorrectVersionAndChains(t *testing.T) {
	base := t.TempDir()
	dataRoot := filepath.Join(base, "data")
	store := newTestSOPSStore(t, dataRoot, writeTestKey(t, base))
	ctx := context.Background()

	v1, ok, err := store.CompareAndSwapSecret(ctx, "tenant-a/chain", 0, &secretsif.SecretRequest{
		Key: "chain", Value: "v1", TenantID: "tenant-a", CreatedBy: "test",
	})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, v1)

	v2, ok, err := store.CompareAndSwapSecret(ctx, "tenant-a/chain", v1, &secretsif.SecretRequest{
		Key: "chain", Value: "v2", TenantID: "tenant-a", CreatedBy: "test",
	})
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 2, v2)

	got, err := store.GetSecret(ctx, "tenant-a/chain")
	require.NoError(t, err)
	assert.Equal(t, "v2", got.Value)
}

// TestCompareAndSwapSecret_CrossInstanceConcurrentRace is the [REQUIRED TEST]
// contract proof: two independent SOPSSecretStore instances — modelling two
// separate controller nodes — pointed at the same on-disk flatfile root race
// to create-if-absent the same key. Exactly one must win; the loser must
// observe ok=false, never an error, and never a second silent write.
func TestCompareAndSwapSecret_CrossInstanceConcurrentRace(t *testing.T) {
	base := t.TempDir()
	dataRoot := filepath.Join(base, "data")
	keyPath := writeTestKey(t, base)

	nodeA := newTestSOPSStore(t, dataRoot, keyPath)
	nodeB := newTestSOPSStore(t, dataRoot, keyPath)
	ctx := context.Background()

	const attempts = 8
	var wg sync.WaitGroup
	var successes int64
	results := make([]bool, attempts*2)

	run := func(store *SOPSSecretStore, idx int, value string) {
		defer wg.Done()
		_, ok, err := store.CompareAndSwapSecret(ctx, "tenant-a/race-key", 0, &secretsif.SecretRequest{
			Key: "race-key", Value: value, TenantID: "tenant-a", CreatedBy: "test",
		})
		require.NoError(t, err)
		results[idx] = ok
		if ok {
			atomic.AddInt64(&successes, 1)
		}
	}

	wg.Add(2)
	go run(nodeA, 0, "node-a-value")
	go run(nodeB, 1, "node-b-value")
	wg.Wait()

	assert.Equal(t, int64(1), successes, "exactly one of two concurrent create-if-absent CAS calls for the same key must succeed")

	got, err := nodeA.GetSecret(ctx, "tenant-a/race-key")
	require.NoError(t, err)
	assert.Contains(t, []string{"node-a-value", "node-b-value"}, got.Value, "the stored value must be exactly the winner's, not a merge or corruption")
}

// TestCompareAndSwapSecret_ExpiredRecordIsTakenOver is the regression proof that a
// claim whose holder crashed before releasing it does not block its transition
// forever.
//
// A record past its TTL is invisible to every read path, so if it still blocked a
// create-if-absent the claim would be unrecoverable without manual store surgery —
// which for the credential-renewal claim (#3724) means every future renewal of that
// serial answering 409 forever, and a permanent lockout for a host whose only
// credential is the certificate it can no longer renew.
func TestCompareAndSwapSecret_ExpiredRecordIsTakenOver(t *testing.T) {
	base := t.TempDir()
	store := newTestSOPSStore(t, filepath.Join(base, "data"), writeTestKey(t, base))
	ctx := context.Background()

	// The claim is created with a TTL and then abandoned — exactly what a crash
	// between claim and release leaves behind.
	v1, ok, err := store.CompareAndSwapSecret(ctx, "tenant-a/claim", 0, &secretsif.SecretRequest{
		Key: "claim", Value: "", TenantID: "tenant-a", CreatedBy: "node-a", TTL: 20 * time.Millisecond,
	})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, v1)

	// While it is live it blocks a second claim, which is the whole point of it.
	_, ok, err = store.CompareAndSwapSecret(ctx, "tenant-a/claim", 0, &secretsif.SecretRequest{
		Key: "claim", Value: "", TenantID: "tenant-a", CreatedBy: "node-b",
	})
	require.NoError(t, err)
	require.False(t, ok, "a live claim must block a concurrent claim")

	require.Eventually(t, func() bool {
		_, err := store.GetSecret(ctx, "tenant-a/claim")
		return err != nil
	}, time.Second, 5*time.Millisecond, "the claim must become unreadable once its TTL elapses")

	v2, ok, err := store.CompareAndSwapSecret(ctx, "tenant-a/claim", 0, &secretsif.SecretRequest{
		Key: "claim", Value: "taken-over", TenantID: "tenant-a", CreatedBy: "node-b",
	})
	require.NoError(t, err)
	require.True(t, ok, "an expired claim must be taken over by a create-if-absent, not block it forever")

	// The version continues the record's own sequence rather than restarting at 1,
	// so a caller holding the pre-expiry version cannot resurrect it.
	assert.Equal(t, 2, v2)

	got, err := store.GetSecret(ctx, "tenant-a/claim")
	require.NoError(t, err)
	assert.Equal(t, "taken-over", got.Value)

	_, ok, err = store.CompareAndSwapSecret(ctx, "tenant-a/claim", v1, &secretsif.SecretRequest{
		Key: "claim", Value: "stale-writer", TenantID: "tenant-a", CreatedBy: "node-a",
	})
	require.NoError(t, err)
	assert.False(t, ok, "the crashed holder's stale version must not win after the takeover")
}

// TestCompareAndSwapSecret_ExpiredTakeoverHasOneWinner proves the takeover of an
// expired record is itself a compare-and-set: several callers racing to claim the
// same abandoned record must not all succeed, or the crash-recovery path would
// reintroduce the double-mint the claim exists to prevent.
func TestCompareAndSwapSecret_ExpiredTakeoverHasOneWinner(t *testing.T) {
	base := t.TempDir()
	dataRoot := filepath.Join(base, "data")
	keyPath := writeTestKey(t, base)
	store := newTestSOPSStore(t, dataRoot, keyPath)
	other := newTestSOPSStore(t, dataRoot, keyPath)
	ctx := context.Background()

	_, ok, err := store.CompareAndSwapSecret(ctx, "tenant-a/abandoned", 0, &secretsif.SecretRequest{
		Key: "abandoned", Value: "", TenantID: "tenant-a", CreatedBy: "crashed", TTL: 20 * time.Millisecond,
	})
	require.NoError(t, err)
	require.True(t, ok)

	require.Eventually(t, func() bool {
		_, err := store.GetSecret(ctx, "tenant-a/abandoned")
		return err != nil
	}, time.Second, 5*time.Millisecond)

	const attempts = 6
	var wg sync.WaitGroup
	var successes int64
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		target := store
		if i%2 == 1 {
			target = other
		}
		go func(s *SOPSSecretStore) {
			defer wg.Done()
			_, ok, err := s.CompareAndSwapSecret(ctx, "tenant-a/abandoned", 0, &secretsif.SecretRequest{
				Key: "abandoned", Value: "retry", TenantID: "tenant-a", CreatedBy: "retrier",
			})
			require.NoError(t, err)
			if ok {
				atomic.AddInt64(&successes, 1)
			}
		}(target)
	}
	wg.Wait()

	assert.Equal(t, int64(1), successes,
		"exactly one of several callers racing to take over the same expired record must win")
}

// TestCompareAndSwapIsClusterAtomic_FalseForFileLockBackend pins the honesty of the
// capability report. A flatfile-backed store coordinates via an OS file lock, which
// is correct for processes sharing one host's directory but is not a cross-node
// guarantee — O_CREAT|O_EXCL is not dependably atomic over a network filesystem — so
// it must report false and let the cluster-mode gate refuse it.
func TestCompareAndSwapIsClusterAtomic_FalseForFileLockBackend(t *testing.T) {
	base := t.TempDir()
	store := newTestSOPSStore(t, filepath.Join(base, "data"), writeTestKey(t, base))

	assert.False(t, store.CompareAndSwapIsClusterAtomic(),
		"a file-lock-coordinated store must not claim cross-node atomicity")
	assert.False(t, secretsif.CompareAndSwapIsClusterAtomic(store),
		"the interface-level helper must agree with the store's own report")

	// The strategy is resolved once at construction, so the answer cannot vary
	// between the gate's check and a later call.
	assert.Nil(t, store.conditionalStore)
	assert.NotEmpty(t, store.casLockRoot)
}

// TestCompareAndSwapSecret_FailsClosedWithoutAtomicityPrimitive proves that a store
// with neither a conditional-write backend nor a private lock root refuses to swap
// rather than performing an unprotected read-check-write. Silently degrading to "no
// mutual exclusion" is what makes two nodes both mint a certificate for one approval.
func TestCompareAndSwapSecret_FailsClosedWithoutAtomicityPrimitive(t *testing.T) {
	base := t.TempDir()
	store := newTestSOPSStore(t, filepath.Join(base, "data"), writeTestKey(t, base))

	// Reproduce the resolution outcome for a backend that offers neither primitive
	// (the database-shaped storage_config a non-conditional store would be built
	// from), without asking the test to stand up such a backend.
	store.conditionalStore = nil
	store.casLockRoot = ""
	store.casUnavailableErr = errNoCASLockRoot

	_, ok, err := store.CompareAndSwapSecret(context.Background(), "tenant-a/k", 0, &secretsif.SecretRequest{
		Key: "k", Value: "v", TenantID: "tenant-a", CreatedBy: "test",
	})
	require.Error(t, err, "an unprotected read-check-write must never be substituted for a compare-and-swap")
	assert.ErrorIs(t, err, errNoCASLockRoot)
	assert.False(t, ok)
}
