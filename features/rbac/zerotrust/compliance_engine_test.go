// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package zerotrust

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time { return f.t }

// TestComplianceCache_HitMissExpiry verifies that a cached compliance result is
// returned before TTL expires and absent after the clock advances past TTL.
func TestComplianceCache_HitMissExpiry(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	ttl := 10 * time.Minute

	c := cache.NewCache(cache.CacheConfig{
		Name:            "zerotrust-compliance",
		MaxRuntimeItems: 1000,
		DefaultTTL:      ttl,
		CleanupInterval: 1 * time.Minute,
		EvictionPolicy:  cache.EvictionLRU,
		Clock:           clk,
	})
	t.Cleanup(c.Close)

	key := "compliance:SOC2:user1:tenant1:req1"
	result := &ComplianceValidationResult{
		Framework:      ComplianceFrameworkSOC2,
		ComplianceRate: 1.0,
	}

	require.NoError(t, c.Set(key, result, 0)) // 0 = use DefaultTTL (10 min)

	// Hit: before TTL expires
	value, found := c.Get(key)
	require.True(t, found, "should be a cache hit before TTL expires")
	got, ok := value.(*ComplianceValidationResult)
	require.True(t, ok, "cached value should be *ComplianceValidationResult")
	assert.Equal(t, result, got)

	// Advance clock past TTL
	clk.t = clk.t.Add(ttl + time.Second)

	// Miss: after TTL expires
	_, found = c.Get(key)
	assert.False(t, found, "should be a cache miss after TTL expires")
}

func makeTestRequest(subjectID, tenantID, requestID string) *ZeroTrustAccessRequest {
	return &ZeroTrustAccessRequest{
		AccessRequest: &common.AccessRequest{
			SubjectId: subjectID,
			TenantId:  tenantID,
		},
		RequestID:       requestID,
		SecurityContext: &SecurityContext{AuthenticationMethod: "certificate"},
	}
}

// TestValidateFrameworkCompliance_CacheHitIncrementsStats verifies that a second
// call with the same key returns the cached result and increments CachedValidations.
func TestValidateFrameworkCompliance_CacheHitIncrementsStats(t *testing.T) {
	engine := NewComplianceFrameworkEngine([]ComplianceFramework{ComplianceFrameworkSOC2})
	t.Cleanup(engine.Close)

	req := makeTestRequest("user1", "tenant1", "req1")
	ctx := context.Background()

	first, err := engine.validateFrameworkCompliance(ctx, req, ComplianceFrameworkSOC2, nil)
	require.NoError(t, err)
	require.NotNil(t, first)

	statsBefore := engine.GetStats()

	second, err := engine.validateFrameworkCompliance(ctx, req, ComplianceFrameworkSOC2, nil)
	require.NoError(t, err)
	require.NotNil(t, second)

	statsAfter := engine.GetStats()
	assert.Equal(t, statsBefore.CachedValidations+1, statsAfter.CachedValidations,
		"CachedValidations should increment on cache hit")
	assert.Equal(t, first.ComplianceRate, second.ComplianceRate,
		"cached result should match original result")
}

// TestValidateFrameworkCompliance_ValidatorNotFound verifies that an unknown framework
// causes an error return from validateFrameworkCompliance.
func TestValidateFrameworkCompliance_ValidatorNotFound(t *testing.T) {
	engine := NewComplianceFrameworkEngine([]ComplianceFramework{ComplianceFrameworkSOC2})
	t.Cleanup(engine.Close)

	req := makeTestRequest("user1", "tenant1", "req-unknown")
	ctx := context.Background()

	// Use a framework that has no registered validator
	_, err := engine.validateFrameworkCompliance(ctx, req, ComplianceFramework("UNKNOWN"), nil)
	require.Error(t, err, "should return error when framework validator is not registered")
	assert.Contains(t, err.Error(), "no validator found for framework")
}

// TestValidateFrameworkCompliance_CacheDisabled verifies that when cacheEnabled is false,
// each call re-executes validation and CachedValidations stays at zero.
func TestValidateFrameworkCompliance_CacheDisabled(t *testing.T) {
	engine := NewComplianceFrameworkEngine([]ComplianceFramework{ComplianceFrameworkSOC2})
	t.Cleanup(engine.Close)
	engine.cacheEnabled = false

	req := makeTestRequest("user1", "tenant1", "req-nocache")
	ctx := context.Background()

	_, err := engine.validateFrameworkCompliance(ctx, req, ComplianceFrameworkSOC2, nil)
	require.NoError(t, err)
	_, err = engine.validateFrameworkCompliance(ctx, req, ComplianceFrameworkSOC2, nil)
	require.NoError(t, err)

	stats := engine.GetStats()
	assert.Equal(t, int64(0), stats.CachedValidations,
		"CachedValidations should remain zero when cache is disabled")
}
