// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTenantQueue_ConcurrencyLimit verifies that exactly MaxConcurrentPerTenant
// acquires succeed and the next one returns ErrTenantQueueFull.
func TestTenantQueue_ConcurrencyLimit(t *testing.T) {
	q := NewTenantQueue()

	for i := 0; i < MaxConcurrentPerTenant; i++ {
		require.NoError(t, q.Acquire("tenant-a"), "acquire %d should succeed", i)
	}

	err := q.Acquire("tenant-a")
	assert.ErrorIs(t, err, ErrTenantQueueFull)
}

// TestTenantQueue_ReleaseUnblocks verifies that Release allows a subsequent
// Acquire to succeed after the queue was full.
func TestTenantQueue_ReleaseUnblocks(t *testing.T) {
	q := NewTenantQueue()

	for i := 0; i < MaxConcurrentPerTenant; i++ {
		require.NoError(t, q.Acquire("tenant-b"))
	}
	require.ErrorIs(t, q.Acquire("tenant-b"), ErrTenantQueueFull)

	q.Release("tenant-b")

	require.NoError(t, q.Acquire("tenant-b"), "acquire after release should succeed")
}

// TestTenantQueue_CrossTenantIsolation verifies that a full queue for one
// tenant does not affect another tenant.
func TestTenantQueue_CrossTenantIsolation(t *testing.T) {
	q := NewTenantQueue()

	for i := 0; i < MaxConcurrentPerTenant; i++ {
		require.NoError(t, q.Acquire("tenant-x"))
	}
	require.ErrorIs(t, q.Acquire("tenant-x"), ErrTenantQueueFull)

	// A completely separate tenant must not be affected.
	require.NoError(t, q.Acquire("tenant-y"), "different tenant must not be blocked")
}

// TestTenantQueue_ConcurrentAcquireRelease verifies correctness under
// concurrent Acquire and Release calls from multiple goroutines.
func TestTenantQueue_ConcurrentAcquireRelease(t *testing.T) {
	q := NewTenantQueue()
	const workers = MaxConcurrentPerTenant * 2
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			// Each goroutine acquires, then releases immediately.
			// With workers > MaxConcurrentPerTenant, some will see ErrTenantQueueFull —
			// that is the correct back-pressure behavior, not an error in the test.
			if err := q.Acquire("concurrent-tenant"); err == nil {
				q.Release("concurrent-tenant")
			}
		}()
	}

	wg.Wait()
	// After all goroutines finish, the semaphore must be fully drained.
	for i := 0; i < MaxConcurrentPerTenant; i++ {
		require.NoError(t, q.Acquire("concurrent-tenant"), "all slots must be available after full release")
	}
}
