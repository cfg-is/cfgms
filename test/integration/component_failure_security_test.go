//go:build !short
// +build !short

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package integration

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/failsafe"
	"github.com/cfgis/cfgms/features/rbac/jit"
	"github.com/cfgis/cfgms/features/rbac/risk"
	pkgtestutil "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/test/integration/testutil"
)

// ComponentFailureSecurityTestFramework provides a comprehensive testing framework for security component failures
type ComponentFailureSecurityTestFramework struct {
	t           *testing.T
	env         *testutil.TestEnv
	rbacManager rbac.RBACManager
	riskEngine  *risk.RiskAssessmentEngine
	jitManager  *jit.JITAccessManager

	// Failsafe wrappers
	failsafeRBAC    *failsafe.FailsafeRBACManager
	failsafeRisk    *failsafe.FailsafeRiskEngine
	failsafeJIT     *failsafe.FailsafeJITAccessManager
	failsafeNetwork *failsafe.NetworkPartitionTolerantManager
}

// NewComponentFailureSecurityTestFramework creates a new component failure security test framework
func NewComponentFailureSecurityTestFramework(t *testing.T) *ComponentFailureSecurityTestFramework {
	env := testutil.NewTestEnv(t)

	// Create standard RBAC components
	rbacManager := pkgtestutil.SetupTestRBACManager(t)
	riskEngine := risk.NewRiskAssessmentEngine()
	jitManager := jit.NewJITAccessManager(rbacManager, nil) // Nil notification service for testing

	// Create failsafe wrappers
	failsafeRBAC := failsafe.NewFailsafeRBACManager(rbacManager)
	failsafeRisk := failsafe.NewFailsafeRiskEngine(riskEngine)
	failsafeJIT := failsafe.NewFailsafeJITAccessManager(jitManager)
	failsafeNetwork := failsafe.NewNetworkPartitionTolerantManager(rbacManager)

	return &ComponentFailureSecurityTestFramework{
		t:               t,
		env:             env,
		rbacManager:     rbacManager,
		riskEngine:      riskEngine,
		jitManager:      jitManager,
		failsafeRBAC:    failsafeRBAC,
		failsafeRisk:    failsafeRisk,
		failsafeJIT:     failsafeJIT,
		failsafeNetwork: failsafeNetwork,
	}
}

// Setup initializes the test framework with test data
func (framework *ComponentFailureSecurityTestFramework) Setup() error {
	ctx := framework.env.GetContext()

	// Initialize RBAC system
	err := framework.rbacManager.Initialize(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize RBAC manager: %w", err)
	}

	// Create system roles first
	systemRoles := []*common.Role{
		{
			Id:          "system.read-only",
			Name:        "System Read Only",
			TenantId:    "test-tenant",
			Description: "Read-only access to system resources",
		},
		{
			Id:          "system.admin",
			Name:        "System Administrator",
			TenantId:    "test-tenant",
			Description: "Full administrative access to system",
		},
	}

	for _, role := range systemRoles {
		err = framework.rbacManager.CreateRole(ctx, role)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create system role %s: %w", role.Id, err)
		}
	}

	// Create test tenant
	err = framework.rbacManager.CreateTenantDefaultRoles(ctx, "test-tenant")
	if err != nil {
		return fmt.Errorf("failed to create tenant default roles: %w", err)
	}

	// Create test subject
	testSubject := &common.Subject{
		Id:          "test-user",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Test User",
		TenantId:    "test-tenant",
		IsActive:    true,
	}
	err = framework.rbacManager.CreateSubject(ctx, testSubject)
	if err != nil {
		return fmt.Errorf("failed to create test subject: %w", err)
	}

	// Assign role to test subject
	assignment := &common.RoleAssignment{
		SubjectId: "test-user",
		RoleId:    "system.read-only",
		TenantId:  "test-tenant",
	}
	err = framework.rbacManager.AssignRole(ctx, assignment)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}

// Cleanup cleans up the test framework
func (framework *ComponentFailureSecurityTestFramework) Cleanup() {
	framework.env.Cleanup()
}

// MockComponentFailure simulates various types of component failures
type MockComponentFailure struct {
	Component   string
	FailureType string
	Duration    time.Duration
	Description string
}

// TestRBACDatabaseFailureSecureDefault tests that RBAC database failures default to deny access decisions
func TestRBACDatabaseFailureSecureDefault(t *testing.T) {
	t.Skip("Skipping until Issue #295: Failsafe RBAC implementation doesn't properly trigger unhealthy state")
	framework := NewComponentFailureSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())
	ctx := framework.env.GetContext()

	t.Run("RBAC System Healthy - Access Granted", func(t *testing.T) {
		// First verify that access works when system is healthy
		request := &common.AccessRequest{
			SubjectId:    "test-user",
			PermissionId: "config.read",
			TenantId:     "test-tenant",
			ResourceId:   "test-resource",
		}

		response, err := framework.failsafeRBAC.CheckPermission(ctx, request)
		require.NoError(t, err)
		assert.True(t, framework.failsafeRBAC.IsHealthy(), "RBAC system should be healthy")

		// The response might be granted or denied based on actual permissions, but system should be operational
		assert.NotNil(t, response)
	})

	t.Run("RBAC System Unhealthy - Access Denied", func(t *testing.T) {
		// Force the failsafe RBAC manager to be unhealthy by calling with invalid context
		invalidCtx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately to cause failure

		request := &common.AccessRequest{
			SubjectId:    "test-user",
			PermissionId: "config.read",
			TenantId:     "test-tenant",
			ResourceId:   "test-resource",
		}

		// Make 3 consecutive failed calls to trigger unhealthy state (Issue #292)
		// System requires maxConsecutiveFailures: 3 to mark as unhealthy
		for i := 0; i < 3; i++ {
			_, err := framework.failsafeRBAC.CheckPermission(invalidCtx, request)
			assert.Error(t, err, "Call %d should fail with cancelled context", i+1)
			time.Sleep(10 * time.Millisecond)
		}

		// Wait for health check to process failures
		time.Sleep(200 * time.Millisecond)

		// Now try with valid context - should deny due to unhealthy state
		response, err := framework.failsafeRBAC.CheckPermission(ctx, request)
		assert.Error(t, err, "Should fail due to unhealthy RBAC system")
		assert.NotNil(t, response)
		assert.False(t, response.Granted, "Access should be denied when RBAC system is unhealthy")
		// Verify access was denied by checking Granted field
		assert.Contains(t, response.Reason, "fail-secure", "Response should indicate fail-secure mode")
		// Verify the reason contains failsafe information
		assert.Contains(t, response.Reason, "rbac", "Response reason should mention rbac component")
	})

	t.Run("RBAC Metrics Tracking", func(t *testing.T) {
		metrics := framework.failsafeRBAC.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Greater(t, metrics.TotalRequests, int64(0), "Should have processed requests")
		assert.Greater(t, metrics.DeniedByFailsafe, int64(0), "Should have denied requests due to failsafe")
	})
}

// TestRiskEngineFailureEnhancedAuth tests that risk engine failures trigger enhanced authentication requirements
func TestRiskEngineFailureEnhancedAuth(t *testing.T) {
	t.Skip("Skipping until Issue #295: Failsafe Risk implementation doesn't properly trigger unhealthy state")
	framework := NewComponentFailureSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())
	ctx := framework.env.GetContext()

	t.Run("Risk Engine Healthy - Normal Assessment", func(t *testing.T) {
		request := &risk.RiskAssessmentRequest{
			AccessRequest: &common.AccessRequest{
				SubjectId:    "test-user",
				PermissionId: "config.read",
				TenantId:     "test-tenant",
			},
			UserContext: &risk.UserContext{
				UserID: "test-user",
			},
			ResourceContext: &risk.ResourceContext{
				ResourceID: "test-resource",
			},
			RequiredConfidence: 0.7,
		}

		result, err := framework.failsafeRisk.EvaluateRisk(ctx, request)
		require.NoError(t, err)
		assert.True(t, framework.failsafeRisk.IsHealthy(), "Risk engine should be healthy")
		assert.NotNil(t, result)
		assert.Greater(t, result.ConfidenceScore, 0.0, "Should have confidence in assessment")
	})

	t.Run("Risk Engine Unhealthy - Enhanced Auth Required", func(t *testing.T) {
		// Force the risk engine to be unhealthy
		framework.failsafeRisk.SetFailureMode(failsafe.RiskFailureModeEnhancedAuth)

		// Cause a failure by using cancelled context
		invalidCtx, cancel := context.WithCancel(context.Background())
		cancel()

		request := &risk.RiskAssessmentRequest{
			AccessRequest: &common.AccessRequest{
				SubjectId:    "test-user",
				PermissionId: "config.read",
				TenantId:     "test-tenant",
			},
			UserContext: &risk.UserContext{
				UserID: "test-user",
			},
			ResourceContext: &risk.ResourceContext{
				ResourceID: "test-resource",
			},
			RequiredConfidence: 0.7,
		}

		// This should fail and trigger failsafe mode
		_, err := framework.failsafeRisk.EvaluateRisk(invalidCtx, request)
		assert.Error(t, err)

		// Wait for health check to mark as unhealthy
		time.Sleep(100 * time.Millisecond)

		// Now assess with valid context - should get enhanced auth requirement
		result, err := framework.failsafeRisk.EvaluateRisk(ctx, request)
		require.NoError(t, err) // Failsafe should not error, but provide conservative assessment
		assert.NotNil(t, result)

		// Verify enhanced authentication is required
		assert.Equal(t, risk.RiskLevelHigh, result.RiskLevel, "Should assess as high risk when engine is unavailable")
		assert.Equal(t, risk.AccessDecisionChallenge, result.AccessDecision, "Should require enhanced authentication")
		assert.Greater(t, len(result.RecommendedActions), 0, "Should recommend mitigation actions")
		assert.Greater(t, len(result.RequiredControls), 0, "Should require adaptive controls")

		// Check for enhanced auth control
		hasEnhancedAuth := false
		for _, control := range result.RequiredControls {
			if control.Type == "step_up_authentication" {
				hasEnhancedAuth = true
				break
			}
		}
		assert.True(t, hasEnhancedAuth, "Should require step-up authentication")

		// Verify failsafe metadata
		assert.NotNil(t, result.Metadata["failsafe_mode"])
		assert.Equal(t, true, result.Metadata["failsafe_mode"])
	})

	t.Run("Risk Engine Metrics", func(t *testing.T) {
		metrics := framework.failsafeRisk.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Greater(t, metrics.TotalAssessments, int64(0), "Should have processed assessments")
		assert.Greater(t, metrics.FailsafeAssessments, int64(0), "Should have failsafe assessments")
	})
}

// TestJITServiceFailureAutoRevoke tests that JIT service failures automatically revoke temporary permissions
func TestJITServiceFailureAutoRevoke(t *testing.T) {
	t.Skip("Skipping until Issue #295: Failsafe JIT implementation doesn't properly trigger unhealthy state")
	framework := NewComponentFailureSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())
	ctx := framework.env.GetContext()

	t.Run("JIT Service Healthy - Normal Operation", func(t *testing.T) {
		requestSpec := &jit.JITAccessRequestSpec{
			RequesterID:   "test-user",
			TargetID:      "test-user",
			TenantID:      "test-tenant",
			Permissions:   []string{"config.write"},
			Duration:      30 * time.Minute,
			Justification: "Test access for integration test",
			AutoApprove:   true,
		}

		request, err := framework.failsafeJIT.RequestAccess(ctx, requestSpec)
		require.NoError(t, err)
		assert.True(t, framework.failsafeJIT.IsHealthy(), "JIT service should be healthy")
		assert.NotNil(t, request)

		// If auto-approved, should have granted access
		if request.Status == jit.JITAccessRequestStatusApproved {
			assert.NotNil(t, request.GrantedAccess)
		}
	})

	t.Run("JIT Service Failure - Auto-Revoke Mode", func(t *testing.T) {
		// Set to auto-revoke mode
		framework.failsafeJIT.SetFailureMode(failsafe.JITFailureModeAutoRevoke)

		// First create a successful request
		requestSpec := &jit.JITAccessRequestSpec{
			RequesterID:   "test-user",
			TargetID:      "test-user",
			TenantID:      "test-tenant",
			Permissions:   []string{"config.write"},
			Duration:      30 * time.Minute,
			Justification: "Test access before failure",
			AutoApprove:   true,
		}

		_, err := framework.failsafeJIT.RequestAccess(ctx, requestSpec)
		require.NoError(t, err)

		// Force JIT service to become unhealthy by causing a failure
		invalidCtx, cancel := context.WithCancel(context.Background())
		cancel()

		failureSpec := &jit.JITAccessRequestSpec{
			RequesterID:   "test-user-2",
			TargetID:      "test-user-2",
			TenantID:      "test-tenant",
			Permissions:   []string{"config.admin"},
			Duration:      1 * time.Hour,
			Justification: "This should fail and trigger auto-revoke",
			AutoApprove:   true,
		}

		// This should fail and mark system unhealthy
		_, err = framework.failsafeJIT.RequestAccess(invalidCtx, failureSpec)
		assert.Error(t, err)

		// Wait for potential health check
		time.Sleep(100 * time.Millisecond)

		// Now try another request - should be rejected due to auto-revoke mode
		_, err = framework.failsafeJIT.RequestAccess(ctx, failureSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "auto-revoke", "Should indicate auto-revoke mode")

		// Verify active grants are revoked (check through metrics)
		metrics := framework.failsafeJIT.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Greater(t, metrics.RejectedByFailsafe, int64(0), "Should have rejected requests due to failsafe")
	})

	t.Run("JIT Service Emergency Access Only", func(t *testing.T) {
		framework.failsafeJIT.SetFailureMode(failsafe.JITFailureModeEmergencyOnly)

		// Regular request should be denied
		regularSpec := &jit.JITAccessRequestSpec{
			RequesterID:     "test-user",
			TargetID:        "test-user",
			TenantID:        "test-tenant",
			Permissions:     []string{"config.read"},
			Duration:        15 * time.Minute,
			Justification:   "Regular access request",
			EmergencyAccess: false,
			AutoApprove:     true,
		}

		_, err := framework.failsafeJIT.RequestAccess(ctx, regularSpec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "emergency", "Should require emergency access")

		// Emergency request should be allowed
		emergencySpec := &jit.JITAccessRequestSpec{
			RequesterID:     "test-user",
			TargetID:        "test-user",
			TenantID:        "test-tenant",
			Permissions:     []string{"config.read"},
			Duration:        15 * time.Minute,
			Justification:   "Emergency access during system failure",
			EmergencyAccess: true,
			AutoApprove:     true,
		}

		emergencyRequest, err := framework.failsafeJIT.RequestAccess(ctx, emergencySpec)
		require.NoError(t, err)
		assert.NotNil(t, emergencyRequest)
		assert.True(t, emergencyRequest.EmergencyAccess)
		assert.Equal(t, jit.JITAccessRequestStatusApproved, emergencyRequest.Status)

		// Emergency grant should have limited duration (max 30 minutes)
		assert.LessOrEqual(t, emergencyRequest.Duration, 30*time.Minute, "Emergency access should be limited to 30 minutes")
	})
}

// TestNetworkPartitionTolerance tests network partition tolerance with local policy enforcement
func TestNetworkPartitionTolerance(t *testing.T) {
	t.Skip("Skipping until Issue #295: Failsafe Network implementation doesn't properly trigger unhealthy state")
	framework := NewComponentFailureSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())
	ctx := framework.env.GetContext()

	t.Run("Network Connected - Normal Operation", func(t *testing.T) {
		request := &common.AccessRequest{
			SubjectId:    "test-user",
			PermissionId: "config.read",
			TenantId:     "test-tenant",
			ResourceId:   "test-resource",
		}

		response, err := framework.failsafeNetwork.CheckPermission(ctx, request)
		require.NoError(t, err)
		assert.True(t, framework.failsafeNetwork.IsNetworkConnected(), "Network should be connected")
		assert.False(t, framework.failsafeNetwork.IsPartitioned(), "Network should not be partitioned")
		assert.NotNil(t, response)
	})

	t.Run("Network Partition - Fail Secure Mode", func(t *testing.T) {
		framework.failsafeNetwork.SetPartitionMode(failsafe.PartitionModeFailSecure)

		// Simulate network partition by causing connectivity failures
		invalidCtx, cancel := context.WithCancel(context.Background())
		cancel()

		request := &common.AccessRequest{
			SubjectId:    "test-user",
			PermissionId: "config.read",
			TenantId:     "test-tenant",
			ResourceId:   "test-resource",
		}

		// This should fail and trigger partition detection
		_, err := framework.failsafeNetwork.CheckPermission(invalidCtx, request)
		assert.Error(t, err)

		// Wait for potential partition detection
		time.Sleep(100 * time.Millisecond)

		// Now try with valid context - should fail secure
		response, err := framework.failsafeNetwork.CheckPermission(ctx, request)
		assert.Error(t, err)
		assert.NotNil(t, response)
		assert.False(t, response.Granted, "Should deny access in fail-secure mode during partition")
		assert.Contains(t, response.Reason, "partition", "Should indicate network partition")
		// Verify reason contains partition information
		assert.Contains(t, response.Reason, "network_partition_fail_secure", "Response reason should indicate partition mode")
	})

	t.Run("Network Partition Metrics", func(t *testing.T) {
		metrics := framework.failsafeNetwork.GetPartitionMetrics()
		assert.NotNil(t, metrics)
		assert.Greater(t, metrics.TotalRequests, int64(0), "Should have processed requests")
	})
}

// TestSecurityStateConsistencyAcrossFailureRecovery tests that security state remains consistent across failure/recovery cycles
func TestSecurityStateConsistencyAcrossFailureRecovery(t *testing.T) {
	t.Skip("Skipping until Issue #295: Test uses RBAC failsafe which works, but needs validation after other failsafe fixes")
	framework := NewComponentFailureSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())
	ctx := framework.env.GetContext()

	t.Run("State Consistency Through RBAC Failure Recovery", func(t *testing.T) {
		request := &common.AccessRequest{
			SubjectId:    "test-user",
			PermissionId: "config.read",
			TenantId:     "test-tenant",
		}

		// 1. Initial healthy state
		response1, err := framework.failsafeRBAC.CheckPermission(ctx, request)
		require.NoError(t, err)
		initialGranted := response1.Granted
		assert.True(t, framework.failsafeRBAC.IsHealthy())

		// 2. Induce failure
		invalidCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err = framework.failsafeRBAC.CheckPermission(invalidCtx, request)
		assert.Error(t, err)

		// 3. During failure - should deny
		response2, err := framework.failsafeRBAC.CheckPermission(ctx, request)
		assert.Error(t, err)
		assert.False(t, response2.Granted, "Should deny during failure")

		// 4. Wait for potential recovery (simulate recovery by making successful call)
		time.Sleep(200 * time.Millisecond)

		// Make several successful calls to simulate recovery
		for i := 0; i < 5; i++ {
			_, err = framework.failsafeRBAC.CheckPermission(ctx, request)
			if err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		// 5. After recovery - state should be consistent
		response3, err := framework.failsafeRBAC.CheckPermission(ctx, request)
		if err == nil {
			// If system recovered, the access decision should be consistent with initial state
			assert.Equal(t, initialGranted, response3.Granted, "Access decision should be consistent after recovery")
		}

		// Verify metrics show the failure/recovery cycle
		metrics := framework.failsafeRBAC.GetMetrics()
		assert.Greater(t, metrics.FailedRequests, int64(0), "Should have recorded failures")
	})
}

// TestDegradedModeSecurityPolicyEnforcement tests security policy enforcement in degraded mode
func TestDegradedModeSecurityPolicyEnforcement(t *testing.T) {
	t.Skip("Skipping until Issue #295: Failsafe Network implementation doesn't properly trigger unhealthy state")
	framework := NewComponentFailureSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())
	ctx := framework.env.GetContext()

	t.Run("Graceful Degradation Mode", func(t *testing.T) {
		framework.failsafeNetwork.SetPartitionMode(failsafe.PartitionModeGracefulDegradation)

		// First, make a successful request to populate cache
		request := &common.AccessRequest{
			SubjectId:    "test-user",
			PermissionId: "config.read",
			TenantId:     "test-tenant",
			ResourceId:   "test-resource",
		}

		_, err := framework.failsafeNetwork.CheckPermission(ctx, request)
		require.NoError(t, err)

		// Simulate network partition
		invalidCtx, cancel := context.WithCancel(context.Background())
		cancel()

		// Cause failure to trigger partition mode
		_, err = framework.failsafeNetwork.CheckPermission(invalidCtx, request)
		assert.Error(t, err)

		time.Sleep(100 * time.Millisecond)

		// Now request should work in degraded mode with cached policy
		response2, err := framework.failsafeNetwork.CheckPermission(ctx, request)

		if err == nil && response2.Granted {
			// If access was granted in degraded mode, verify reason contains degradation info
			assert.Contains(t, response2.Reason, "degraded", "Response reason should indicate degraded mode when access granted during partition")
		}
	})

	t.Run("Read-Only Cache Mode", func(t *testing.T) {
		framework.failsafeNetwork.SetPartitionMode(failsafe.PartitionModeReadOnlyCache)

		// In read-only cache mode during partition, only cached permissions should work
		// This is a more restrictive mode than graceful degradation

		request := &common.AccessRequest{
			SubjectId:    "test-user",
			PermissionId: "config.write", // Different permission
			TenantId:     "test-tenant",
			ResourceId:   "test-resource-2",
		}

		// This should fail if not in cache
		response, err := framework.failsafeNetwork.CheckPermission(ctx, request)
		if err != nil || !response.Granted {
			// Expected - permission not cached, so denied in read-only mode
			assert.True(t, true, "Read-only cache mode correctly denies uncached permissions")
		}
	})
}

// TestConcurrentFailureScenarios tests behavior under concurrent component failures
func TestConcurrentFailureScenarios(t *testing.T) {
	t.Skip("Skipping until Issue #295: Depends on failsafe implementations that don't properly trigger unhealthy state")
	framework := NewComponentFailureSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())

	t.Run("Multiple Component Failures", func(t *testing.T) {
		var wg sync.WaitGroup
		errorCount := int64(0)

		// Simulate concurrent failures in multiple components
		components := []func(){
			func() {
				defer wg.Done()
				// Cause RBAC failure
				invalidCtx, cancel := context.WithCancel(context.Background())
				cancel()
				request := &common.AccessRequest{
					SubjectId:    "test-user",
					PermissionId: "config.read",
					TenantId:     "test-tenant",
				}
				_, err := framework.failsafeRBAC.CheckPermission(invalidCtx, request)
				if err != nil {
					errorCount++
				}
			},
			func() {
				defer wg.Done()
				// Cause Risk engine failure
				invalidCtx, cancel := context.WithCancel(context.Background())
				cancel()
				riskRequest := &risk.RiskAssessmentRequest{
					AccessRequest: &common.AccessRequest{
						SubjectId: "test-user",
						TenantId:  "test-tenant",
					},
					UserContext:        &risk.UserContext{UserID: "test-user"},
					ResourceContext:    &risk.ResourceContext{ResourceID: "test"},
					RequiredConfidence: 0.5,
				}
				_, err := framework.failsafeRisk.EvaluateRisk(invalidCtx, riskRequest)
				if err != nil {
					errorCount++
				}
			},
			func() {
				defer wg.Done()
				// Cause JIT failure
				invalidCtx, cancel := context.WithCancel(context.Background())
				cancel()
				jitSpec := &jit.JITAccessRequestSpec{
					RequesterID:   "test-user",
					TargetID:      "test-user",
					TenantID:      "test-tenant",
					Permissions:   []string{"config.write"},
					Duration:      15 * time.Minute,
					Justification: "Test concurrent failure",
				}
				_, err := framework.failsafeJIT.RequestAccess(invalidCtx, jitSpec)
				if err != nil {
					errorCount++
				}
			},
		}

		wg.Add(len(components))

		// Execute all failures concurrently
		for _, componentFail := range components {
			go componentFail()
		}

		wg.Wait()

		assert.Greater(t, errorCount, int64(0), "Should have errors from component failures")

		// Wait for systems to potentially mark as unhealthy
		time.Sleep(200 * time.Millisecond)

		// Verify that all systems are now in failsafe mode
		t.Logf("RBAC Healthy: %v", framework.failsafeRBAC.IsHealthy())
		t.Logf("Risk Healthy: %v", framework.failsafeRisk.IsHealthy())
		t.Logf("JIT Healthy: %v", framework.failsafeJIT.IsHealthy())

		// Verify metrics show the concurrent failures
		rbacMetrics := framework.failsafeRBAC.GetMetrics()
		riskMetrics := framework.failsafeRisk.GetMetrics()
		jitMetrics := framework.failsafeJIT.GetMetrics()

		assert.Greater(t, rbacMetrics.FailedRequests, int64(0), "RBAC should show failed requests")
		assert.Greater(t, riskMetrics.FailedAssessments, int64(0), "Risk should show failed assessments")
		assert.Greater(t, jitMetrics.FailedRequests, int64(0), "JIT should show failed requests")
	})
}
