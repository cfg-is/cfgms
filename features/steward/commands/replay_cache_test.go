// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package commands

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplayCache_AddNewID_ReturnsTrue(t *testing.T) {
	c := newReplayCache(5 * time.Minute)
	assert.True(t, c.Add("cmd-001"), "first Add of a new ID must return true")
}

func TestReplayCache_AddDuplicateWithinWindow_ReturnsFalse(t *testing.T) {
	c := newReplayCache(5 * time.Minute)
	require.True(t, c.Add("cmd-dup"))
	assert.False(t, c.Add("cmd-dup"), "duplicate within window must return false")
}

func TestReplayCache_AddExpiredID_ReturnsTrue(t *testing.T) {
	// Use a tiny TTL so the entry expires immediately.
	c := newReplayCache(time.Millisecond)
	require.True(t, c.Add("cmd-exp"))
	time.Sleep(10 * time.Millisecond)
	assert.True(t, c.Add("cmd-exp"), "ID added after TTL expiry must return true (not a replay)")
}

func TestReplayCache_BoundEnforcement(t *testing.T) {
	// Fill the cache to the hard cap + 1 to trigger eviction.
	c := newReplayCache(time.Hour)
	for i := range maxReplayCacheEntries + 1 {
		id := fmt.Sprintf("cmd-%d", i)
		assert.True(t, c.Add(id), "Add of unique ID %q must return true", id)
	}
	c.mu.Lock()
	size := len(c.entries)
	c.mu.Unlock()
	assert.LessOrEqual(t, size, maxReplayCacheEntries,
		"cache must not exceed %d entries", maxReplayCacheEntries)
}

func TestReplayCache_MultipleDistinctIDs_AllAccepted(t *testing.T) {
	c := newReplayCache(5 * time.Minute)
	ids := []string{"a", "b", "c", "d", "e"}
	for _, id := range ids {
		assert.True(t, c.Add(id), "unique ID %q must be accepted", id)
	}
}

func TestReplayCache_EvictExpiredOnAdd(t *testing.T) {
	c := newReplayCache(10 * time.Millisecond)
	require.True(t, c.Add("old"))
	time.Sleep(20 * time.Millisecond)

	// Adding a new entry triggers eviction of the expired "old" entry.
	require.True(t, c.Add("new"))

	c.mu.Lock()
	_, oldPresent := c.entries["old"]
	c.mu.Unlock()
	assert.False(t, oldPresent, "expired entry must be evicted on the next Add call")
}
