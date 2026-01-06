// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package performance

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/rbac/zerotrust"
)

// TestZeroTrustPolicyEvaluationPerformance validates that zero-trust policy
// evaluation meets the <5ms performance requirement
func TestZeroTrustPolicyEvaluationPerformance(t *testing.T) {
	// Set up zero-trust policy engine with performance-optimized configuration
	config := &zerotrust.ZeroTrustConfig{
		MaxEvaluationTime:       5 * time.Millisecond, // Strict requirement
		CacheEnabled:            true,
		CacheTTL:                10 * time.Minute,
		EnableMetrics:           true,
		MetricsInterval:         1 * time.Second,
		FailSecure:              true,
		EnableRBACIntegration:   true,
		EnableJITIntegration:    false, // Disable for isolated performance test
		EnableRiskIntegration:   false, // Disable for isolated performance test
		EnableTenantIntegration: false, // Disable for isolated performance test
	}

	engine := zerotrust.NewZeroTrustPolicyEngine(config)
	ctx := context.Background()

	// Start the engine
	err := engine.Start(ctx)
	require.NoError(t, err)
	defer func() {
		stopErr := engine.Stop()
		assert.NoError(t, stopErr)
	}()

	t.Run("Single Request Performance", func(t *testing.T) {
		request := &zerotrust.ZeroTrustAccessRequest{
			RequestID:     "perf-single-001",
			RequestTime:   time.Now(),
			SubjectType:   zerotrust.SubjectTypeUser,
			ResourceType:  "api",
			SourceSystem:  "performance-test",
			RequestSource: zerotrust.RequestSourceAPI,
			Priority:      zerotrust.RequestPriorityNormal,
		}

		// Measure evaluation time
		startTime := time.Now()
		response, err := engine.EvaluateAccess(ctx, request)
		duration := time.Since(startTime)

		require.NoError(t, err)
		assert.NotNil(t, response)

		// Validate <5ms requirement
		assert.Less(t, duration, 5*time.Millisecond,
			"Single request should complete in <5ms, took %v", duration)

		// Validate reported processing time
		assert.Less(t, response.ProcessingTime, 5*time.Millisecond,
			"Reported processing time should be <5ms, was %v", response.ProcessingTime)

		t.Logf("Single request performance: %v (reported: %v)", duration, response.ProcessingTime)
	})

	t.Run("Batch Performance Testing", func(t *testing.T) {
		batchSizes := []int{10, 50, 100}

		for _, batchSize := range batchSizes {
			t.Run(fmt.Sprintf("Batch_%d", batchSize), func(t *testing.T) {
				totalDuration := time.Duration(0)
				maxDuration := time.Duration(0)
				successCount := 0

				for i := 0; i < batchSize; i++ {
					request := &zerotrust.ZeroTrustAccessRequest{
						RequestID:     fmt.Sprintf("perf-batch-%d-%03d", batchSize, i),
						RequestTime:   time.Now(),
						SubjectType:   zerotrust.SubjectTypeUser,
						ResourceType:  "api",
						SourceSystem:  "performance-test",
						RequestSource: zerotrust.RequestSourceAPI,
						Priority:      zerotrust.RequestPriorityNormal,
					}

					startTime := time.Now()
					response, err := engine.EvaluateAccess(ctx, request)
					duration := time.Since(startTime)

					if err != nil {
						t.Errorf("Request %d failed: %v", i, err)
						continue
					}

					assert.NotNil(t, response)
					successCount++

					totalDuration += duration
					if duration > maxDuration {
						maxDuration = duration
					}

					// Each request should meet <5ms requirement
					assert.Less(t, duration, 5*time.Millisecond,
						"Request %d should complete in <5ms, took %v", i, duration)
				}

				avgDuration := totalDuration / time.Duration(successCount)

				// Validate batch performance metrics
				assert.Equal(t, batchSize, successCount, "All requests should succeed")
				assert.Less(t, avgDuration, 3*time.Millisecond,
					"Average duration should be <3ms, was %v", avgDuration)
				assert.Less(t, maxDuration, 5*time.Millisecond,
					"Max duration should be <5ms, was %v", maxDuration)

				t.Logf("Batch %d performance: avg=%v, max=%v, total=%v",
					batchSize, avgDuration, maxDuration, totalDuration)
			})
		}
	})

	t.Run("Cache Performance Validation", func(t *testing.T) {
		// Create identical requests to test cache performance
		request := &zerotrust.ZeroTrustAccessRequest{
			RequestID:     "cache-perf-001",
			RequestTime:   time.Now(),
			SubjectType:   zerotrust.SubjectTypeUser,
			ResourceType:  "cached-api",
			SourceSystem:  "cache-performance-test",
			RequestSource: zerotrust.RequestSourceAPI,
			Priority:      zerotrust.RequestPriorityNormal,
		}

		// First request (potential cache miss)
		startTime := time.Now()
		response1, err := engine.EvaluateAccess(ctx, request)
		firstDuration := time.Since(startTime)

		require.NoError(t, err)
		assert.NotNil(t, response1)
		assert.Less(t, firstDuration, 5*time.Millisecond)

		// Second identical request (potential cache hit)
		startTime = time.Now()
		response2, err := engine.EvaluateAccess(ctx, request)
		secondDuration := time.Since(startTime)

		require.NoError(t, err)
		assert.NotNil(t, response2)
		assert.Less(t, secondDuration, 5*time.Millisecond)

		// Both should meet performance requirements
		t.Logf("Cache performance: first=%v, second=%v", firstDuration, secondDuration)
	})

	t.Run("Concurrent Performance Testing", func(t *testing.T) {
		// Test concurrent request handling
		concurrentRequests := 50
		results := make(chan performanceResult, concurrentRequests)

		// Launch concurrent requests
		for i := 0; i < concurrentRequests; i++ {
			go func(index int) {
				request := &zerotrust.ZeroTrustAccessRequest{
					RequestID:     fmt.Sprintf("concurrent-perf-%03d", index),
					RequestTime:   time.Now(),
					SubjectType:   zerotrust.SubjectTypeUser,
					ResourceType:  "concurrent-api",
					SourceSystem:  "concurrent-performance-test",
					RequestSource: zerotrust.RequestSourceAPI,
					Priority:      zerotrust.RequestPriorityNormal,
				}

				startTime := time.Now()
				response, err := engine.EvaluateAccess(ctx, request)
				duration := time.Since(startTime)

				results <- performanceResult{
					duration: duration,
					success:  err == nil && response != nil,
					error:    err,
				}
			}(i)
		}

		// Collect results
		var totalDuration time.Duration
		var maxDuration time.Duration
		successCount := 0

		for i := 0; i < concurrentRequests; i++ {
			result := <-results

			if result.error != nil {
				t.Logf("Concurrent request failed: %v", result.error)
				continue
			}

			if result.success {
				successCount++
				totalDuration += result.duration
				if result.duration > maxDuration {
					maxDuration = result.duration
				}

				// Each concurrent request should meet <5ms requirement
				assert.Less(t, result.duration, 5*time.Millisecond,
					"Concurrent request should complete in <5ms, took %v", result.duration)
			}
		}

		// Validate concurrent performance
		assert.GreaterOrEqual(t, successCount, int(float64(concurrentRequests)*0.95),
			"At least 95%% of concurrent requests should succeed")

		if successCount > 0 {
			avgDuration := totalDuration / time.Duration(successCount)
			assert.Less(t, avgDuration, 5*time.Millisecond,
				"Average concurrent duration should be <5ms, was %v", avgDuration)
		}

		t.Logf("Concurrent performance: %d/%d success, avg=%v, max=%v",
			successCount, concurrentRequests,
			totalDuration/time.Duration(successCount), maxDuration)
	})

	t.Run("Performance Under Load", func(t *testing.T) {
		// Sustained load testing
		loadDuration := 5 * time.Second
		requestInterval := 10 * time.Millisecond

		startTime := time.Now()
		requestCount := 0
		successCount := 0
		var totalDuration time.Duration
		maxDuration := time.Duration(0)

		for time.Since(startTime) < loadDuration {
			request := &zerotrust.ZeroTrustAccessRequest{
				RequestID:     fmt.Sprintf("load-test-%d", requestCount),
				RequestTime:   time.Now(),
				SubjectType:   zerotrust.SubjectTypeUser,
				ResourceType:  "load-test-api",
				SourceSystem:  "load-performance-test",
				RequestSource: zerotrust.RequestSourceAPI,
				Priority:      zerotrust.RequestPriorityNormal,
			}

			reqStartTime := time.Now()
			response, err := engine.EvaluateAccess(ctx, request)
			reqDuration := time.Since(reqStartTime)

			requestCount++

			if err == nil && response != nil {
				successCount++
				totalDuration += reqDuration
				if reqDuration > maxDuration {
					maxDuration = reqDuration
				}

				// Validate performance under load
				assert.Less(t, reqDuration, 5*time.Millisecond,
					"Request under load should complete in <5ms, took %v", reqDuration)
			}

			// Brief pause between requests
			time.Sleep(requestInterval)
		}

		// Validate sustained load performance
		successRate := float64(successCount) / float64(requestCount)
		assert.GreaterOrEqual(t, successRate, 0.95,
			"Should maintain 95%% success rate under load, got %.1f%%", successRate*100)

		if successCount > 0 {
			avgDuration := totalDuration / time.Duration(successCount)
			assert.Less(t, avgDuration, 4*time.Millisecond,
				"Average duration under load should be <4ms, was %v", avgDuration)
		}

		t.Logf("Load test: %d requests, %d success (%.1f%%), avg=%v, max=%v",
			requestCount, successCount, successRate*100,
			totalDuration/time.Duration(successCount), maxDuration)
	})

	t.Run("Engine Statistics Validation", func(t *testing.T) {
		// Get performance statistics from the engine
		stats := engine.GetStats()

		// Validate that statistics are being tracked
		assert.Greater(t, stats.TotalEvaluations, int64(0))
		assert.GreaterOrEqual(t, stats.SuccessfulEvaluations, int64(0))
		assert.GreaterOrEqual(t, stats.FailedEvaluations, int64(0))
		// On very fast systems, average evaluation time may be 0
		assert.GreaterOrEqual(t, stats.AverageEvaluationTime, time.Duration(0))
		assert.False(t, stats.LastUpdated.IsZero())

		// Validate performance statistics
		assert.Less(t, stats.AverageEvaluationTime, 5*time.Millisecond,
			"Average evaluation time should be <5ms, was %v", stats.AverageEvaluationTime)

		t.Logf("Engine statistics: total=%d, success=%d, failed=%d, avg=%v",
			stats.TotalEvaluations, stats.SuccessfulEvaluations,
			stats.FailedEvaluations, stats.AverageEvaluationTime)
	})
}

// TestPerformanceRequirementValidation validates that the system meets
// all documented performance requirements
func TestPerformanceRequirementValidation(t *testing.T) {
	t.Run("5ms Policy Evaluation Requirement", func(t *testing.T) {
		// This is the primary performance requirement for zero-trust policies
		// All policy evaluations must complete within 5 milliseconds

		config := &zerotrust.ZeroTrustConfig{
			MaxEvaluationTime: 5 * time.Millisecond,
			CacheEnabled:      true,
			FailSecure:        true,
			EnableMetrics:     true,
			MetricsInterval:   1 * time.Second,
		}

		engine := zerotrust.NewZeroTrustPolicyEngine(config)
		ctx := context.Background()

		err := engine.Start(ctx)
		require.NoError(t, err)
		defer func() { _ = engine.Stop() }() // Ignore error in test cleanup

		// Test various request types
		requestTypes := []struct {
			name     string
			priority zerotrust.RequestPriority
			resource string
		}{
			{"High Priority", zerotrust.RequestPriorityHigh, "critical-resource"},
			{"Normal Priority", zerotrust.RequestPriorityNormal, "standard-resource"},
			{"Low Priority", zerotrust.RequestPriorityLow, "background-resource"},
		}

		for _, rt := range requestTypes {
			t.Run(rt.name, func(t *testing.T) {
				request := &zerotrust.ZeroTrustAccessRequest{
					RequestID:     fmt.Sprintf("req-validation-%s", rt.name),
					RequestTime:   time.Now(),
					SubjectType:   zerotrust.SubjectTypeUser,
					ResourceType:  rt.resource,
					SourceSystem:  "requirement-validation-test",
					RequestSource: zerotrust.RequestSourceAPI,
					Priority:      rt.priority,
				}

				startTime := time.Now()
				response, err := engine.EvaluateAccess(ctx, request)
				duration := time.Since(startTime)

				require.NoError(t, err)
				assert.NotNil(t, response)

				// Validate <5ms requirement for all request types
				assert.Less(t, duration, 5*time.Millisecond,
					"%s request should complete in <5ms, took %v", rt.name, duration)

				t.Logf("%s performance: %v", rt.name, duration)
			})
		}
	})
}

// Performance result structure for concurrent testing
type performanceResult struct {
	duration time.Duration
	success  bool
	error    error
}
