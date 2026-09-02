// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package steward

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompareAndSwapSecret_CreateWhenAbsent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	newVersion, ok, err := store.CompareAndSwapSecret(ctx, "cas-key", 0, &interfaces.SecretRequest{
		Key: "cas-key", Value: "v1", TenantID: "tenant-1", CreatedBy: "test",
	})
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 1, newVersion)

	got, err := store.GetSecret(ctx, "cas-key")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
}

func TestCompareAndSwapSecret_RejectsWrongExpectedVersion(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, ok, err := store.CompareAndSwapSecret(ctx, "cas-key", 0, &interfaces.SecretRequest{
		Key: "cas-key", Value: "v1", TenantID: "tenant-1", CreatedBy: "test",
	})
	require.NoError(t, err)
	require.True(t, ok)

	_, ok, err = store.CompareAndSwapSecret(ctx, "cas-key", 0, &interfaces.SecretRequest{
		Key: "cas-key", Value: "attacker-value", TenantID: "tenant-1", CreatedBy: "test",
	})
	require.NoError(t, err, "a lost race is ok=false with a nil error, never an error")
	assert.False(t, ok)

	got, err := store.GetSecret(ctx, "cas-key")
	require.NoError(t, err)
	assert.Equal(t, "v1", got.Value)
}

func TestCompareAndSwapSecret_SucceedsWithCorrectVersionAndChains(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	v1, ok, err := store.CompareAndSwapSecret(ctx, "chain", 0, &interfaces.SecretRequest{
		Key: "chain", Value: "v1", TenantID: "tenant-1", CreatedBy: "test",
	})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, v1)

	v2, ok, err := store.CompareAndSwapSecret(ctx, "chain", v1, &interfaces.SecretRequest{
		Key: "chain", Value: "v2", TenantID: "tenant-1", CreatedBy: "test",
	})
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 2, v2)
}

// TestCompareAndSwapSecret_ConcurrentRace proves exactly one of N concurrent
// create-if-absent CAS calls against the same key succeeds. Steward is not
// cluster-capable — exactly one StewardSecretStore ever exists per host — so
// this models the realistic race: multiple goroutines on the same steward
// process handling concurrent requests against the shared in-memory index.
func TestCompareAndSwapSecret_ConcurrentRace(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	const attempts = 8
	var wg sync.WaitGroup
	var successes int64

	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func(i int) {
			defer wg.Done()
			_, ok, err := store.CompareAndSwapSecret(ctx, "race-key", 0, &interfaces.SecretRequest{
				Key: "race-key", Value: "value", TenantID: "tenant-1", CreatedBy: "test",
			})
			require.NoError(t, err)
			if ok {
				atomic.AddInt64(&successes, 1)
			}
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int64(1), successes, "exactly one of N concurrent create-if-absent CAS calls for the same key must succeed")
}

// TestCompareAndSwapSecret_ExpiredRecordIsTakenOver proves this provider honours the
// interface's expiry rule: a record past its TTL is treated as absent, so a
// create-if-absent takes it over instead of being blocked by it forever. Nothing in
// this provider ever removes an expired entry from the index, so without the rule an
// abandoned TTL-bounded claim would strand its key permanently.
func TestCompareAndSwapSecret_ExpiredRecordIsTakenOver(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// The live-claim control uses a TTL no scheduling delay can consume. Asserting
	// "still live" against a millisecond-scale TTL races the assertion itself rather
	// than testing the expiry rule.
	v1, ok, err := store.CompareAndSwapSecret(ctx, "claim", 0, &interfaces.SecretRequest{
		Key: "claim", Value: "held", TenantID: "tenant-1", CreatedBy: "crashed-holder",
		TTL: time.Hour,
	})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, v1)

	// While live, it blocks a second claim — the property being preserved.
	_, ok, err = store.CompareAndSwapSecret(ctx, "claim", 0, &interfaces.SecretRequest{
		Key: "claim", Value: "other", TenantID: "tenant-1", CreatedBy: "other",
	})
	require.NoError(t, err)
	require.False(t, ok)

	// Replace it with the state a crash between claim and release leaves behind: the
	// same record, still indexed, with an elapsed TTL.
	v2, ok, err := store.CompareAndSwapSecret(ctx, "claim", v1, &interfaces.SecretRequest{
		Key: "claim", Value: "held", TenantID: "tenant-1", CreatedBy: "crashed-holder",
		TTL: 20 * time.Millisecond,
	})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 2, v2)

	require.Eventually(t, func() bool {
		_, err := store.GetSecret(ctx, "claim")
		return err != nil
	}, time.Second, 5*time.Millisecond, "the record must become unreadable once its TTL elapses")

	v3, ok, err := store.CompareAndSwapSecret(ctx, "claim", 0, &interfaces.SecretRequest{
		Key: "claim", Value: "taken-over", TenantID: "tenant-1", CreatedBy: "retrier",
	})
	require.NoError(t, err)
	require.True(t, ok, "an expired record must be taken over, never block a create-if-absent forever")
	assert.Equal(t, 3, v3, "the takeover continues the record's version sequence")

	got, err := store.GetSecret(ctx, "claim")
	require.NoError(t, err)
	assert.Equal(t, "taken-over", got.Value)
}

// TestCompareAndSwapSecret_ExpiredRecordRejectsNonZeroVersion is the converse: an
// expired record must also fail a non-zero expected version, since no reader can
// legitimately hold a version for a record every read path refuses.
func TestCompareAndSwapSecret_ExpiredRecordRejectsNonZeroVersion(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	v1, ok, err := store.CompareAndSwapSecret(ctx, "claim", 0, &interfaces.SecretRequest{
		Key: "claim", Value: "held", TenantID: "tenant-1", CreatedBy: "holder",
		TTL: 20 * time.Millisecond,
	})
	require.NoError(t, err)
	require.True(t, ok)

	require.Eventually(t, func() bool {
		_, err := store.GetSecret(ctx, "claim")
		return err != nil
	}, time.Second, 5*time.Millisecond)

	_, ok, err = store.CompareAndSwapSecret(ctx, "claim", v1, &interfaces.SecretRequest{
		Key: "claim", Value: "stale", TenantID: "tenant-1", CreatedBy: "holder",
	})
	require.NoError(t, err)
	assert.False(t, ok, "a non-zero expected version must not match an expired record")
}
