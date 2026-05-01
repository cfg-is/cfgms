// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package zerotrust

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestEngine() *ZeroTrustPolicyEngine {
	return NewZeroTrustPolicyEngine(&ZeroTrustConfig{
		MaxEvaluationTime: 5 * time.Second,
		CacheEnabled:      true,
		CacheTTL:          5 * time.Minute,
		MetricsInterval:   1 * time.Minute,
	})
}

// populateEvaluatorCache inserts an entry into the engine's evaluator cache
// using the same key format that PolicyEvaluator.generateCacheKey produces.
func populateEvaluatorCache(engine *ZeroTrustPolicyEngine, policyID, subjectID string) string {
	key := fmt.Sprintf("%s:%s:tenant1:perm1:req1", policyID, subjectID)
	engine.policyEvaluator.cache.Put(key, &PolicyEvaluationResult{
		PolicyID: policyID,
		Result:   PolicyResultAllow,
	})
	return key
}

// TestRetirePolicy_InvalidatesCacheEntry verifies that after RetirePolicy is called,
// a previously cached evaluation result for that policy is no longer retrievable.
func TestRetirePolicy_InvalidatesCacheEntry(t *testing.T) {
	ctx := context.Background()
	engine := newTestEngine()

	manager := engine.policyManager

	policyID := "test-retire-policy"
	policy := &ZeroTrustPolicy{
		ID:       policyID,
		Name:     "Test Retire Policy",
		Priority: PolicyPriorityNormal,
	}

	// Create → Activate → cache entry present → Deactivate → Retire
	_, err := manager.CreatePolicy(ctx, policy, "test-user")
	require.NoError(t, err)

	err = manager.ActivatePolicy(ctx, policyID, "v1.0.0", "test-user")
	require.NoError(t, err)

	cacheKey := populateEvaluatorCache(engine, policyID, "user1")
	require.NotNil(t, engine.policyEvaluator.cache.Get(cacheKey),
		"cache entry should be present before retirement")

	err = manager.DeactivatePolicy(ctx, policyID, "test-user")
	require.NoError(t, err)

	err = manager.RetirePolicy(ctx, policyID, "test-user")
	require.NoError(t, err)

	assert.Nil(t, engine.policyEvaluator.cache.Get(cacheKey),
		"cache entry should be nil after RetirePolicy")
}

// TestDeactivatePolicy_InvalidatesCacheEntry verifies that DeactivatePolicy also
// invalidates the cache synchronously.
func TestDeactivatePolicy_InvalidatesCacheEntry(t *testing.T) {
	ctx := context.Background()
	engine := newTestEngine()
	manager := engine.policyManager

	policyID := "test-deactivate-policy"
	policy := &ZeroTrustPolicy{
		ID:       policyID,
		Name:     "Test Deactivate Policy",
		Priority: PolicyPriorityNormal,
	}

	_, err := manager.CreatePolicy(ctx, policy, "test-user")
	require.NoError(t, err)

	err = manager.ActivatePolicy(ctx, policyID, "v1.0.0", "test-user")
	require.NoError(t, err)

	cacheKey := populateEvaluatorCache(engine, policyID, "user2")
	require.NotNil(t, engine.policyEvaluator.cache.Get(cacheKey))

	err = manager.DeactivatePolicy(ctx, policyID, "test-user")
	require.NoError(t, err)

	assert.Nil(t, engine.policyEvaluator.cache.Get(cacheKey),
		"cache entry should be nil after DeactivatePolicy")
}

// TestRetirePolicy_RequiresDeprecatedStatus ensures RetirePolicy rejects policies
// that have not been deactivated first.
func TestRetirePolicy_RequiresDeprecatedStatus(t *testing.T) {
	ctx := context.Background()
	engine := newTestEngine()
	manager := engine.policyManager

	policyID := "test-retire-wrong-status"
	policy := &ZeroTrustPolicy{
		ID:       policyID,
		Name:     "Test Retire Wrong Status",
		Priority: PolicyPriorityNormal,
	}

	_, err := manager.CreatePolicy(ctx, policy, "test-user")
	require.NoError(t, err)

	err = manager.ActivatePolicy(ctx, policyID, "v1.0.0", "test-user")
	require.NoError(t, err)

	// Attempt to retire an active policy (should fail)
	err = manager.RetirePolicy(ctx, policyID, "test-user")
	assert.Error(t, err, "RetirePolicy should reject an active policy")
}

// TestRetirePolicy_PolicyNotFound verifies the error when the policy does not exist.
func TestRetirePolicy_PolicyNotFound(t *testing.T) {
	ctx := context.Background()
	engine := newTestEngine()
	manager := engine.policyManager

	err := manager.RetirePolicy(ctx, "nonexistent-policy", "test-user")
	assert.Error(t, err)
}

// TestRetirePolicy_UnrelatedCacheEntriesUntouched confirms that retiring one policy
// does not remove cached evaluations for other policies.
func TestRetirePolicy_UnrelatedCacheEntriesUntouched(t *testing.T) {
	ctx := context.Background()
	engine := newTestEngine()
	manager := engine.policyManager

	targetID := "policy-to-retire"
	otherID := "policy-to-keep"

	for _, id := range []string{targetID, otherID} {
		_, err := manager.CreatePolicy(ctx, &ZeroTrustPolicy{ID: id, Name: id, Priority: PolicyPriorityNormal}, "user")
		require.NoError(t, err)
		require.NoError(t, manager.ActivatePolicy(ctx, id, "v1.0.0", "user"))
	}

	targetKey := populateEvaluatorCache(engine, targetID, "user1")
	otherKey := populateEvaluatorCache(engine, otherID, "user1")

	require.NoError(t, manager.DeactivatePolicy(ctx, targetID, "user"))
	require.NoError(t, manager.RetirePolicy(ctx, targetID, "user"))

	assert.Nil(t, engine.policyEvaluator.cache.Get(targetKey),
		"retired policy's cache entry should be gone")
	assert.NotNil(t, engine.policyEvaluator.cache.Get(otherKey),
		"unrelated policy's cache entry should remain")
}
