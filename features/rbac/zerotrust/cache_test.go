// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package zerotrust

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeCacheKey(policyID, subjectID string) string {
	return policyID + ":" + subjectID + ":tenant1:perm1:req1"
}

func makePolicyResult(policyID string) *PolicyEvaluationResult {
	return &PolicyEvaluationResult{PolicyID: policyID, Result: PolicyResultAllow}
}

// TestPolicyCache_Invalidate verifies that Invalidate removes all keys for the
// targeted policy from both L1 and L2 while leaving unrelated entries intact.
func TestPolicyCache_Invalidate(t *testing.T) {
	c := NewPolicyCache(5 * time.Minute)
	t.Cleanup(c.Close)

	targetPolicyID := "policy-target"
	otherPolicyID := "policy-other"

	targetKey := makeCacheKey(targetPolicyID, "user1")
	otherKey := makeCacheKey(otherPolicyID, "user2")

	c.Put(targetKey, makePolicyResult(targetPolicyID))
	c.Put(otherKey, makePolicyResult(otherPolicyID))

	require.NotNil(t, c.Get(targetKey), "target entry should be present before Invalidate")
	require.NotNil(t, c.Get(otherKey), "other entry should be present before Invalidate")

	c.Invalidate(targetPolicyID)

	assert.Nil(t, c.Get(targetKey), "target entry should be nil after Invalidate")
	assert.NotNil(t, c.Get(otherKey), "unrelated entry must survive Invalidate")
}

// TestPolicyCache_Invalidate_L2OnlyEntry verifies that Invalidate removes entries
// that exist only in L2 (i.e., never promoted to L1).
func TestPolicyCache_Invalidate_L2OnlyEntry(t *testing.T) {
	c := NewPolicyCache(5 * time.Minute)
	t.Cleanup(c.Close)

	policyID := "policy-l2only"
	key := makeCacheKey(policyID, "user1")

	// Put stores in L2 initially; we don't call Get so no L1 promotion occurs.
	c.Put(key, makePolicyResult(policyID))

	// Confirm L2 has the entry (direct field access within same package).
	_, inL2 := c.l2Cache.Get(key)
	require.True(t, inL2, "entry should be in L2 before Invalidate")

	c.Invalidate(policyID)

	assert.Nil(t, c.Get(key), "L2-only entry should be nil after Invalidate")
}

// TestPolicyCache_Clear verifies that Clear removes all entries from both caches.
func TestPolicyCache_Clear(t *testing.T) {
	c := NewPolicyCache(5 * time.Minute)
	t.Cleanup(c.Close)

	policyIDs := []string{"policy-a", "policy-b", "policy-c"}
	keys := make([]string, len(policyIDs))
	for i, pid := range policyIDs {
		keys[i] = makeCacheKey(pid, "user"+string(rune('1'+i)))
		c.Put(keys[i], makePolicyResult(pid))
	}

	for _, k := range keys {
		require.NotNil(t, c.Get(k), "entry %s should be present before Clear", k)
	}

	c.Clear()

	for _, k := range keys {
		assert.Nil(t, c.Get(k), "entry %s should be nil after Clear", k)
	}
}

// TestPolicyCache_Invalidate_NoMatchIsNoop confirms Invalidate with an unknown
// policy ID does not panic or corrupt existing entries.
func TestPolicyCache_Invalidate_NoMatchIsNoop(t *testing.T) {
	c := NewPolicyCache(5 * time.Minute)
	t.Cleanup(c.Close)

	key := makeCacheKey("policy-real", "user1")
	c.Put(key, makePolicyResult("policy-real"))

	assert.NotPanics(t, func() { c.Invalidate("policy-nonexistent") })
	assert.NotNil(t, c.Get(key), "existing entry must survive Invalidate for unknown policy")
}
