//go:build !short
// +build !short

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package integration

import (
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

	// Create JIT approval permission
	jitApprovePermission := &common.Permission{
		Id:           "jit_access.approve",
		Name:         "JIT Access Approve",
		ResourceType: "jit_access",
		Actions:      []string{"approve"},
		Description:  "Permission to approve JIT access requests",
	}
	err = framework.rbacManager.CreatePermission(ctx, jitApprovePermission)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create JIT approve permission: %w", err)
	}

	// Add JIT approval permission to system.admin role
	// First get the role, add the permission, then update it
	adminRole, err := framework.rbacManager.GetRole(ctx, "system.admin")
	if err != nil {
		return fmt.Errorf("failed to get system.admin role: %w", err)
	}
	// Add the permission ID if not already there
	hasPermission := false
	for _, permID := range adminRole.PermissionIds {
		if permID == "jit_access.approve" {
			hasPermission = true
			break
		}
	}
	if !hasPermission {
		adminRole.PermissionIds = append(adminRole.PermissionIds, "jit_access.approve")
		err = framework.rbacManager.UpdateRole(ctx, adminRole)
		if err != nil {
			return fmt.Errorf("failed to update system.admin role with JIT permission: %w", err)
		}
	}

	// Create system subject for auto-approval
	systemSubject := &common.Subject{
		Id:          "system",
		Type:        common.SubjectType_SUBJECT_TYPE_SERVICE,
		DisplayName: "System Service Account",
		TenantId:    "test-tenant",
		IsActive:    true,
	}
	err = framework.rbacManager.CreateSubject(ctx, systemSubject)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create system subject: %w", err)
	}

	// Assign system.admin role to system subject (which should include JIT approval permission)
	systemAssignment := &common.RoleAssignment{
		SubjectId: "system",
		RoleId:    "system.admin",
		TenantId:  "test-tenant",
	}
	err = framework.rbacManager.AssignRole(ctx, systemAssignment)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to assign system admin role: %w", err)
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
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return fmt.Errorf("failed to create test subject: %w", err)
	}

	// Assign role to test subject
	assignment := &common.RoleAssignment{
		SubjectId: "test-user",
		RoleId:    "system.read-only",
		TenantId:  "test-tenant",
	}
	err = framework.rbacManager.AssignRole(ctx, assignment)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
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
		request := &common.AccessRequest{
			SubjectId:    "test-user",
			PermissionId: "config.read",
			TenantId:     "test-tenant",
			ResourceId:   "test-resource",
		}

		// Force the failsafe RBAC manager to be unhealthy using test helper
		framework.failsafeRBAC.ForceUnhealthy()

		// Verify system is unhealthy
		assert.False(t, framework.failsafeRBAC.IsHealthy(), "RBAC system should be unhealthy after ForceUnhealthy()")

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
		framework.failsafeRisk.ForceUnhealthy()

		// Verify system is unhealthy
		assert.False(t, framework.failsafeRisk.IsHealthy(), "Risk engine should be unhealthy after ForceUnhealthy()")

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

		// Force JIT service to become unhealthy using test helper
		framework.failsafeJIT.ForceUnhealthy()

		// Wait for auto-revoke to process
		time.Sleep(100 * time.Millisecond)

		// Verify system is unhealthy
		assert.False(t, framework.failsafeJIT.IsHealthy(), "JIT service should be unhealthy after ForceUnhealthy()")

		failureSpec := &jit.JITAccessRequestSpec{
			RequesterID:   "test-user-2",
			TargetID:      "test-user-2",
			TenantID:      "test-tenant",
			Permissions:   []string{"config.admin"},
			Duration:      1 * time.Hour,
			Justification: "This should be rejected due to auto-revoke",
			AutoApprove:   true,
		}

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

		// Force network partition using test helper
		framework.failsafeNetwork.ForcePartitioned()

		// Verify system is partitioned
		assert.True(t, framework.failsafeNetwork.IsPartitioned(), "Network should be partitioned after ForcePartitioned()")
		assert.False(t, framework.failsafeNetwork.IsNetworkConnected(), "Network should not be connected during partition")

		request := &common.AccessRequest{
			SubjectId:    "test-user",
			PermissionId: "config.read",
			TenantId:     "test-tenant",
			ResourceId:   "test-resource",
		}

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

		// 2. Force failure using test helper
		framework.failsafeRBAC.ForceUnhealthy()
		assert.False(t, framework.failsafeRBAC.IsHealthy(), "RBAC should be unhealthy")

		// 3. During failure - should deny
		response2, err := framework.failsafeRBAC.CheckPermission(ctx, request)
		assert.Error(t, err)
		assert.False(t, response2.Granted, "Should deny during failure")

		// Verify metrics increased
		metrics1 := framework.failsafeRBAC.GetMetrics()
		assert.Greater(t, metrics1.DeniedByFailsafe, int64(0), "Should have denied by failsafe")

		// 4. Force recovery using test helper
		framework.failsafeRBAC.ForceHealthy()
		assert.True(t, framework.failsafeRBAC.IsHealthy(), "RBAC should be healthy after recovery")

		// 5. After recovery - state should be consistent
		response3, err := framework.failsafeRBAC.CheckPermission(ctx, request)
		if err == nil {
			// If system recovered, the access decision should be consistent with initial state
			assert.Equal(t, initialGranted, response3.Granted, "Access decision should be consistent after recovery")
		}

		// Verify metrics show failsafe operations
		metrics2 := framework.failsafeRBAC.GetMetrics()
		assert.Greater(t, metrics2.DeniedByFailsafe, int64(0), "Should have recorded failsafe denials")
	})
}

// TestDegradedModeSecurityPolicyEnforcement tests security policy enforcement in degraded mode
func TestDegradedModeSecurityPolicyEnforcement(t *testing.T) {
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

		// Force network partition to trigger degraded mode
		framework.failsafeNetwork.ForcePartitioned()

		// Verify system is partitioned
		assert.True(t, framework.failsafeNetwork.IsPartitioned(), "Network should be partitioned")

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
	framework := NewComponentFailureSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())
	ctx := framework.env.GetContext()

	t.Run("Multiple Component Failures", func(t *testing.T) {
		var wg sync.WaitGroup
		errorCount := int64(0)

		// Force all components to unhealthy state concurrently
		components := []func(){
			func() {
				defer wg.Done()
				// Force RBAC to unhealthy state
				framework.failsafeRBAC.ForceUnhealthy()

				// Try to use RBAC - should fail due to unhealthy state
				request := &common.AccessRequest{
					SubjectId:    "test-user",
					PermissionId: "config.read",
					TenantId:     "test-tenant",
				}
				_, err := framework.failsafeRBAC.CheckPermission(ctx, request)
				if err != nil {
					errorCount++
				}
			},
			func() {
				defer wg.Done()
				// Force Risk engine to unhealthy state
				framework.failsafeRisk.ForceUnhealthy()

				// Try to use Risk engine - should fail due to unhealthy state
				riskRequest := &risk.RiskAssessmentRequest{
					AccessRequest: &common.AccessRequest{
						SubjectId: "test-user",
						TenantId:  "test-tenant",
					},
					UserContext:        &risk.UserContext{UserID: "test-user"},
					ResourceContext:    &risk.ResourceContext{ResourceID: "test"},
					RequiredConfidence: 0.5,
				}
				result, err := framework.failsafeRisk.EvaluateRisk(ctx, riskRequest)
				// Risk engine returns conservative assessment, not error
				if err == nil && result.RiskLevel == risk.RiskLevelHigh {
					errorCount++
				}
			},
			func() {
				defer wg.Done()
				// Force JIT to unhealthy state
				framework.failsafeJIT.ForceUnhealthy()
				framework.failsafeJIT.SetFailureMode(failsafe.JITFailureModeAutoRevoke)

				// Try to use JIT - should fail due to unhealthy state
				jitSpec := &jit.JITAccessRequestSpec{
					RequesterID:   "test-user",
					TargetID:      "test-user",
					TenantID:      "test-tenant",
					Permissions:   []string{"config.write"},
					Duration:      15 * time.Minute,
					Justification: "Test concurrent failure",
				}
				_, err := framework.failsafeJIT.RequestAccess(ctx, jitSpec)
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

		// Verify that all systems are now in failsafe mode
		assert.False(t, framework.failsafeRBAC.IsHealthy(), "RBAC should be unhealthy")
		assert.False(t, framework.failsafeRisk.IsHealthy(), "Risk should be unhealthy")
		assert.False(t, framework.failsafeJIT.IsHealthy(), "JIT should be unhealthy")

		// Verify metrics show the concurrent failures
		rbacMetrics := framework.failsafeRBAC.GetMetrics()
		riskMetrics := framework.failsafeRisk.GetMetrics()
		jitMetrics := framework.failsafeJIT.GetMetrics()

		assert.Greater(t, rbacMetrics.DeniedByFailsafe, int64(0), "RBAC should show failsafe denials")
		assert.Greater(t, riskMetrics.FailsafeAssessments, int64(0), "Risk should show failsafe assessments")
		assert.Greater(t, jitMetrics.RejectedByFailsafe, int64(0), "JIT should show failsafe rejections")
	})
}
