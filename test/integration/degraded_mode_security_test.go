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

// DegradedModeSecurityTestFramework tests security policy enforcement in various degraded modes
type DegradedModeSecurityTestFramework struct {
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

	// Degraded mode tracking
	degradedOperations []DegradedOperation
	operationsMutex    sync.RWMutex
}

// DegradedOperation tracks operations performed in degraded mode
type DegradedOperation struct {
	Timestamp        time.Time              `json:"timestamp"`
	Operation        string                 `json:"operation"`
	Component        string                 `json:"component"`
	DegradationLevel string                 `json:"degradation_level"`
	Subject          string                 `json:"subject"`
	Permission       string                 `json:"permission,omitempty"`
	ResourceID       string                 `json:"resource_id,omitempty"`
	Result           OperationResult        `json:"result"`
	SecurityControls []string               `json:"security_controls"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// OperationResult captures the result of a degraded mode operation
type OperationResult struct {
	Success            bool              `json:"success"`
	Granted            bool              `json:"granted"`
	Reason             string            `json:"reason"`
	ResponseTime       time.Duration     `json:"response_time"`
	SecurityMetadata   map[string]string `json:"security_metadata"`
	EnhancedMonitoring bool              `json:"enhanced_monitoring"`
}

// DegradationScenario defines a degradation testing scenario
type DegradationScenario struct {
	Name             string
	Description      string
	Components       []string // Components to degrade
	DegradationMode  string   // Type of degradation
	ExpectedBehavior string   // Expected security behavior
	Duration         time.Duration
	ValidationChecks []string // Security validation checks to perform
}

// NewDegradedModeSecurityTestFramework creates a new degraded mode security test framework
func NewDegradedModeSecurityTestFramework(t *testing.T) *DegradedModeSecurityTestFramework {
	env := testutil.NewTestEnv(t)

	// Create standard components
	rbacManager := pkgtestutil.SetupTestRBACManager(t)
	riskEngine := risk.NewRiskAssessmentEngine()
	jitManager := jit.NewJITAccessManager(rbacManager, nil)

	// Create failsafe wrappers
	failsafeRBAC := failsafe.NewFailsafeRBACManager(rbacManager)
	failsafeRisk := failsafe.NewFailsafeRiskEngine(riskEngine)
	failsafeJIT := failsafe.NewFailsafeJITAccessManager(jitManager)
	failsafeNetwork := failsafe.NewNetworkPartitionTolerantManager(rbacManager)

	return &DegradedModeSecurityTestFramework{
		t:                  t,
		env:                env,
		rbacManager:        rbacManager,
		riskEngine:         riskEngine,
		jitManager:         jitManager,
		failsafeRBAC:       failsafeRBAC,
		failsafeRisk:       failsafeRisk,
		failsafeJIT:        failsafeJIT,
		failsafeNetwork:    failsafeNetwork,
		degradedOperations: make([]DegradedOperation, 0),
		operationsMutex:    sync.RWMutex{},
	}
}

// Setup initializes the degraded mode test framework
func (framework *DegradedModeSecurityTestFramework) Setup() error {
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
			TenantId:    "degraded-tenant",
			Description: "Read-only access to system resources",
		},
		{
			Id:          "system.admin",
			Name:        "System Administrator",
			TenantId:    "degraded-tenant",
			Description: "Full administrative access to system",
		},
		{
			Id:          "service.basic",
			Name:        "Basic Service",
			TenantId:    "degraded-tenant",
			Description: "Basic service access",
		},
	}

	for _, role := range systemRoles {
		err = framework.rbacManager.CreateRole(ctx, role)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create system role %s: %w", role.Id, err)
		}
	}

	// Create test tenant and subjects
	err = framework.rbacManager.CreateTenantDefaultRoles(ctx, "degraded-tenant")
	if err != nil {
		return fmt.Errorf("failed to create tenant roles: %w", err)
	}

	// Create subjects with different privilege levels
	subjects := []struct {
		ID   string
		Role string
	}{
		{"degraded-user-low", "system.read-only"},
		{"degraded-user-high", "system.read-only"}, // Using read-only for both user levels
		{"degraded-admin", "system.admin"},
		{"degraded-service", "service.basic"},
	}

	for _, subj := range subjects {
		subject := &common.Subject{
			Id:          subj.ID,
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			DisplayName: fmt.Sprintf("Degraded Mode Test %s", subj.ID),
			TenantId:    "degraded-tenant",
			IsActive:    true,
		}
		err = framework.rbacManager.CreateSubject(ctx, subject)
		if err != nil {
			return fmt.Errorf("failed to create subject %s: %w", subj.ID, err)
		}

		assignment := &common.RoleAssignment{
			SubjectId: subj.ID,
			RoleId:    subj.Role,
			TenantId:  "degraded-tenant",
		}
		err = framework.rbacManager.AssignRole(ctx, assignment)
		if err != nil {
			return fmt.Errorf("failed to assign role to %s: %w", subj.ID, err)
		}
	}

	return nil
}

// Cleanup cleans up the degraded mode test framework
func (framework *DegradedModeSecurityTestFramework) Cleanup() {
	framework.env.Cleanup()
}

// recordDegradedOperation records an operation performed in degraded mode
func (framework *DegradedModeSecurityTestFramework) recordDegradedOperation(op DegradedOperation) {
	framework.operationsMutex.Lock()
	defer framework.operationsMutex.Unlock()

	op.Timestamp = time.Now()
	framework.degradedOperations = append(framework.degradedOperations, op)
}

// getDegradedOperations returns all recorded degraded mode operations
func (framework *DegradedModeSecurityTestFramework) getDegradedOperations() []DegradedOperation {
	framework.operationsMutex.RLock()
	defer framework.operationsMutex.RUnlock()

	operations := make([]DegradedOperation, len(framework.degradedOperations))
	copy(operations, framework.degradedOperations)
	return operations
}

// testRBACPermissionInDegradedMode tests RBAC permission checking in degraded mode
func (framework *DegradedModeSecurityTestFramework) testRBACPermissionInDegradedMode(ctx context.Context, subject, permission string) DegradedOperation {
	start := time.Now()

	request := &common.AccessRequest{
		SubjectId:    subject,
		PermissionId: permission,
		TenantId:     "degraded-tenant",
		ResourceId:   "degraded-resource",
	}

	response, err := framework.failsafeRBAC.CheckPermission(ctx, request)
	responseTime := time.Since(start)

	op := DegradedOperation{
		Operation:        "CheckPermission",
		Component:        "RBAC",
		DegradationLevel: "failsafe",
		Subject:          subject,
		Permission:       permission,
		ResourceID:       "degraded-resource",
		SecurityControls: make([]string, 0),
		Metadata:         make(map[string]interface{}),
	}

	if err != nil {
		op.Result = OperationResult{
			Success:          false,
			Granted:          false,
			Reason:           err.Error(),
			ResponseTime:     responseTime,
			SecurityMetadata: make(map[string]string),
		}

		if response != nil {
			// Parse reason to determine security controls
			if strings.Contains(response.Reason, "failsafe") {
				op.Result.SecurityMetadata["failsafe_reason"] = "rbac_failsafe"
				op.SecurityControls = append(op.SecurityControls, "failsafe_activation")
			}
		}
	} else {
		op.Result = OperationResult{
			Success:          true,
			Granted:          response.Granted,
			Reason:           response.Reason,
			ResponseTime:     responseTime,
			SecurityMetadata: make(map[string]string),
		}

		// Check for enhanced monitoring requirements based on reason
		if strings.Contains(response.Reason, "enhanced_monitoring") {
			op.Result.EnhancedMonitoring = true
			op.Result.SecurityMetadata["enhanced_monitoring"] = "required"
			op.SecurityControls = append(op.SecurityControls, "enhanced_monitoring")
		}

		if strings.Contains(response.Reason, "degraded") {
			op.Result.SecurityMetadata["degradation_active"] = "true"
			op.SecurityControls = append(op.SecurityControls, "degraded_mode")
		}
	}

	// Add health status to metadata
	op.Metadata["rbac_healthy"] = framework.failsafeRBAC.IsHealthy()

	return op
}

// testRiskAssessmentInDegradedMode tests risk assessment in degraded mode
func (framework *DegradedModeSecurityTestFramework) testRiskAssessmentInDegradedMode(ctx context.Context, subject string) DegradedOperation {
	start := time.Now()

	request := &risk.RiskAssessmentRequest{
		AccessRequest: &common.AccessRequest{
			SubjectId: subject,
			TenantId:  "degraded-tenant",
		},
		UserContext: &risk.UserContext{
			UserID: subject,
		},
		ResourceContext: &risk.ResourceContext{
			ResourceID: "degraded-resource",
		},
		RequiredConfidence: 0.7,
	}

	result, err := framework.failsafeRisk.EvaluateRisk(ctx, request)
	responseTime := time.Since(start)

	op := DegradedOperation{
		Operation:        "EvaluateRisk",
		Component:        "Risk",
		DegradationLevel: "failsafe",
		Subject:          subject,
		SecurityControls: make([]string, 0),
		Metadata:         make(map[string]interface{}),
	}

	if err != nil {
		op.Result = OperationResult{
			Success:          false,
			Granted:          false,
			Reason:           err.Error(),
			ResponseTime:     responseTime,
			SecurityMetadata: make(map[string]string),
		}
	} else {
		op.Result = OperationResult{
			Success:          true,
			Granted:          result.AccessDecision != risk.AccessDecisionDeny,
			Reason:           fmt.Sprintf("Risk level: %s, Decision: %s", result.RiskLevel, result.AccessDecision),
			ResponseTime:     responseTime,
			SecurityMetadata: make(map[string]string),
		}

		// Add risk-specific metadata
		op.Result.SecurityMetadata["risk_level"] = string(result.RiskLevel)
		op.Result.SecurityMetadata["access_decision"] = string(result.AccessDecision)
		op.Result.SecurityMetadata["confidence_score"] = fmt.Sprintf("%.2f", result.ConfidenceScore)

		// Check for failsafe mode
		if result.Metadata["failsafe_mode"] == true {
			op.SecurityControls = append(op.SecurityControls, "failsafe_risk_assessment")
			op.Result.SecurityMetadata["failsafe_mode"] = "true"
		}

		// Check for enhanced controls
		if len(result.RequiredControls) > 0 {
			op.SecurityControls = append(op.SecurityControls, "adaptive_controls")
		}

		// High risk requires enhanced monitoring
		if result.RiskLevel == risk.RiskLevelHigh || result.RiskLevel == risk.RiskLevelCritical {
			op.Result.EnhancedMonitoring = true
			op.SecurityControls = append(op.SecurityControls, "enhanced_monitoring")
		}
	}

	op.Metadata["risk_healthy"] = framework.failsafeRisk.IsHealthy()

	return op
}

// testJITAccessInDegradedMode tests JIT access in degraded mode
func (framework *DegradedModeSecurityTestFramework) testJITAccessInDegradedMode(ctx context.Context, subject string, emergency bool) DegradedOperation {
	start := time.Now()

	spec := &jit.JITAccessRequestSpec{
		RequesterID:     subject,
		TargetID:        subject,
		TenantID:        "degraded-tenant",
		Permissions:     []string{"config.write"},
		Duration:        15 * time.Minute,
		Justification:   "Degraded mode test access",
		EmergencyAccess: emergency,
		AutoApprove:     true,
	}

	request, err := framework.failsafeJIT.RequestAccess(ctx, spec)
	responseTime := time.Since(start)

	op := DegradedOperation{
		Operation:        "RequestAccess",
		Component:        "JIT",
		DegradationLevel: "failsafe",
		Subject:          subject,
		Permission:       "config.write",
		SecurityControls: make([]string, 0),
		Metadata:         make(map[string]interface{}),
	}

	if err != nil {
		op.Result = OperationResult{
			Success:          false,
			Granted:          false,
			Reason:           err.Error(),
			ResponseTime:     responseTime,
			SecurityMetadata: make(map[string]string),
		}

		// Check if this is expected failsafe behavior
		if err.Error() != "" {
			op.SecurityControls = append(op.SecurityControls, "failsafe_denial")
		}
	} else {
		granted := request.Status == jit.JITAccessRequestStatusApproved
		op.Result = OperationResult{
			Success:          true,
			Granted:          granted,
			Reason:           fmt.Sprintf("Status: %s", request.Status),
			ResponseTime:     responseTime,
			SecurityMetadata: make(map[string]string),
		}

		op.Result.SecurityMetadata["request_status"] = string(request.Status)
		op.Result.SecurityMetadata["emergency_access"] = fmt.Sprintf("%v", request.EmergencyAccess)

		if granted && request.GrantedAccess != nil {
			op.SecurityControls = append(op.SecurityControls, "jit_access_granted")

			// Check for emergency access controls
			if request.EmergencyAccess {
				op.SecurityControls = append(op.SecurityControls, "emergency_access")
				op.Result.EnhancedMonitoring = true
			}

			// Check for limited duration
			if request.Duration <= 30*time.Minute {
				op.SecurityControls = append(op.SecurityControls, "limited_duration")
			}
		}
	}

	op.Metadata["jit_healthy"] = framework.failsafeJIT.IsHealthy()
	op.Metadata["emergency_access"] = emergency

	return op
}

// testNetworkPartitionTolerance tests network partition tolerance in degraded mode
func (framework *DegradedModeSecurityTestFramework) testNetworkPartitionTolerance(ctx context.Context, subject, permission string, partitionMode failsafe.PartitionToleranceMode) DegradedOperation {
	// Set the partition mode
	framework.failsafeNetwork.SetPartitionMode(partitionMode)

	start := time.Now()

	request := &common.AccessRequest{
		SubjectId:    subject,
		PermissionId: permission,
		TenantId:     "degraded-tenant",
		ResourceId:   "partition-resource",
	}

	response, err := framework.failsafeNetwork.CheckPermission(ctx, request)
	responseTime := time.Since(start)

	op := DegradedOperation{
		Operation:        "CheckPermissionPartitioned",
		Component:        "Network",
		DegradationLevel: string(partitionMode),
		Subject:          subject,
		Permission:       permission,
		ResourceID:       "partition-resource",
		SecurityControls: make([]string, 0),
		Metadata:         make(map[string]interface{}),
	}

	if err != nil {
		op.Result = OperationResult{
			Success:          false,
			Granted:          false,
			Reason:           err.Error(),
			ResponseTime:     responseTime,
			SecurityMetadata: make(map[string]string),
		}

		if response != nil {
			// Parse reason to determine security controls
			if strings.Contains(response.Reason, "partition") {
				op.Result.SecurityMetadata["partition_reason"] = "network_partition"
				op.SecurityControls = append(op.SecurityControls, "partition_failsafe")
			}
		}
	} else {
		op.Result = OperationResult{
			Success:          true,
			Granted:          response.Granted,
			Reason:           response.Reason,
			ResponseTime:     responseTime,
			SecurityMetadata: make(map[string]string),
		}

		// Check for partition-specific controls based on reason
		if strings.Contains(response.Reason, "partition") {
			op.Result.SecurityMetadata["partition_mode"] = "active"
			op.SecurityControls = append(op.SecurityControls, "partition_tolerance")
		}

		if strings.Contains(response.Reason, "degraded") {
			op.Result.SecurityMetadata["degradation_active"] = "true"
			op.Result.EnhancedMonitoring = true
			op.SecurityControls = append(op.SecurityControls, "degraded_mode", "enhanced_monitoring")
		}

		if strings.Contains(response.Reason, "cache") || strings.Contains(response.Reason, "cached") {
			op.Result.SecurityMetadata["cache_reason"] = "policy_cached"
			op.SecurityControls = append(op.SecurityControls, "cache_based_decision")
		}
	}

	op.Metadata["network_connected"] = framework.failsafeNetwork.IsNetworkConnected()
	op.Metadata["partitioned"] = framework.failsafeNetwork.IsPartitioned()
	op.Metadata["partition_mode"] = string(partitionMode)

	return op
}

// TestRBACFailSecureDegradation tests RBAC fail-secure degradation behavior
func TestRBACFailSecureDegradation(t *testing.T) {
	framework := NewDegradedModeSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())
	ctx := context.Background()

	t.Run("RBAC Fail-Secure Mode", func(t *testing.T) {
		// Set RBAC to fail-secure mode
		framework.failsafeRBAC.SetFailureMode(failsafe.FailureModeFailSecure)

		// Induce RBAC failure
		invalidCtx, cancel := context.WithCancel(context.Background())
		cancel()

		testRequest := &common.AccessRequest{
			SubjectId:    "degraded-user-low",
			PermissionId: "test.failure",
			TenantId:     "degraded-tenant",
		}

		// This should fail and mark system unhealthy
		_, _ = framework.failsafeRBAC.CheckPermission(invalidCtx, testRequest)

		// Wait for health check to potentially mark as unhealthy
		time.Sleep(200 * time.Millisecond)

		// Test different subjects and permissions in degraded mode
		subjects := []string{"degraded-user-low", "degraded-user-high", "degraded-admin"}
		permissions := []string{"config.read", "config.write", "admin.read"}

		for _, subject := range subjects {
			for _, permission := range permissions {
				op := framework.testRBACPermissionInDegradedMode(ctx, subject, permission)
				framework.recordDegradedOperation(op)

				t.Logf("RBAC Degraded - Subject: %s, Permission: %s, Granted: %v, Reason: %s",
					subject, permission, op.Result.Granted, op.Result.Reason)

				// In fail-secure mode, access should be denied when system is unhealthy
				if !framework.failsafeRBAC.IsHealthy() {
					assert.False(t, op.Result.Granted,
						"Access should be denied in fail-secure mode when RBAC is unhealthy")
					assert.Contains(t, op.SecurityControls, "failsafe_activation",
						"Should have failsafe activation control")
				}

				assert.True(t, op.Result.ResponseTime < 5*time.Second,
					"Response time should be reasonable even in degraded mode")
			}
		}
	})
}

// TestRiskEngineEnhancedAuthDegradation tests risk engine enhanced auth degradation
func TestRiskEngineEnhancedAuthDegradation(t *testing.T) {
	framework := NewDegradedModeSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())
	ctx := context.Background()

	t.Run("Risk Engine Enhanced Auth Mode", func(t *testing.T) {
		// Set risk engine to enhanced auth mode
		framework.failsafeRisk.SetFailureMode(failsafe.RiskFailureModeEnhancedAuth)

		// Induce risk engine failure
		invalidCtx, cancel := context.WithCancel(context.Background())
		cancel()

		testRequest := &risk.RiskAssessmentRequest{
			AccessRequest: &common.AccessRequest{
				SubjectId: "degraded-user-low",
				TenantId:  "degraded-tenant",
			},
			UserContext:     &risk.UserContext{UserID: "degraded-user-low"},
			ResourceContext: &risk.ResourceContext{ResourceID: "test"},
		}

		// This should fail and trigger failsafe mode
		_, _ = framework.failsafeRisk.EvaluateRisk(invalidCtx, testRequest)

		time.Sleep(200 * time.Millisecond)

		// Test risk assessment in degraded mode
		subjects := []string{"degraded-user-low", "degraded-user-high", "degraded-admin"}

		for _, subject := range subjects {
			op := framework.testRiskAssessmentInDegradedMode(ctx, subject)
			framework.recordDegradedOperation(op)

			t.Logf("Risk Degraded - Subject: %s, Risk Level: %s, Decision: %s",
				subject, op.Result.SecurityMetadata["risk_level"], op.Result.SecurityMetadata["access_decision"])

			// In enhanced auth mode, risk assessments should require enhanced authentication
			if !framework.failsafeRisk.IsHealthy() {
				// Should have high confidence in conservative assessment
				assert.Contains(t, op.SecurityControls, "failsafe_risk_assessment",
					"Should have failsafe risk assessment control")

				if op.Result.SecurityMetadata["risk_level"] != "" {
					riskLevel := op.Result.SecurityMetadata["risk_level"]
					assert.True(t, riskLevel == "high" || riskLevel == "critical",
						"Risk level should be high or critical in failsafe mode")
				}
			}

			// Enhanced monitoring should be required for high-risk assessments
			if op.Result.SecurityMetadata["risk_level"] == "high" || op.Result.SecurityMetadata["risk_level"] == "critical" {
				assert.True(t, op.Result.EnhancedMonitoring,
					"Enhanced monitoring should be required for high-risk assessments")
			}
		}
	})
}

// TestJITAutoRevokeDegradation tests JIT auto-revoke degradation behavior
func TestJITAutoRevokeDegradation(t *testing.T) {
	framework := NewDegradedModeSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())
	ctx := context.Background()

	t.Run("JIT Auto-Revoke Mode", func(t *testing.T) {
		// Set JIT to auto-revoke mode
		framework.failsafeJIT.SetFailureMode(failsafe.JITFailureModeAutoRevoke)

		// Test normal access first
		op1 := framework.testJITAccessInDegradedMode(ctx, "degraded-user-low", false)
		framework.recordDegradedOperation(op1)

		// Induce JIT failure
		invalidCtx, cancel := context.WithCancel(context.Background())
		cancel()

		failSpec := &jit.JITAccessRequestSpec{
			RequesterID:   "degraded-user-high",
			TargetID:      "degraded-user-high",
			TenantID:      "degraded-tenant",
			Permissions:   []string{"config.admin"},
			Duration:      30 * time.Minute,
			Justification: "This should trigger failure",
		}

		_, _ = framework.failsafeJIT.RequestAccess(invalidCtx, failSpec)

		time.Sleep(200 * time.Millisecond)

		// Test JIT access in degraded mode
		subjects := []string{"degraded-user-low", "degraded-admin"}

		for _, subject := range subjects {
			// Test regular access (should be denied)
			op := framework.testJITAccessInDegradedMode(ctx, subject, false)
			framework.recordDegradedOperation(op)

			t.Logf("JIT Degraded (Regular) - Subject: %s, Granted: %v, Reason: %s",
				subject, op.Result.Granted, op.Result.Reason)

			// In auto-revoke mode, regular access should be denied
			if !framework.failsafeJIT.IsHealthy() {
				assert.False(t, op.Result.Granted,
					"Regular JIT access should be denied in auto-revoke mode")
				assert.Contains(t, op.SecurityControls, "failsafe_denial",
					"Should have failsafe denial control")
			}
		}
	})

	t.Run("JIT Emergency-Only Mode", func(t *testing.T) {
		// Set JIT to emergency-only mode
		framework.failsafeJIT.SetFailureMode(failsafe.JITFailureModeEmergencyOnly)

		// Test emergency access
		subjects := []string{"degraded-user-low", "degraded-admin"}

		for _, subject := range subjects {
			// Test regular access (should be denied)
			regOp := framework.testJITAccessInDegradedMode(ctx, subject, false)
			framework.recordDegradedOperation(regOp)

			// Test emergency access (might be allowed)
			emergOp := framework.testJITAccessInDegradedMode(ctx, subject, true)
			framework.recordDegradedOperation(emergOp)

			t.Logf("JIT Emergency Mode - Subject: %s, Regular: %v, Emergency: %v",
				subject, regOp.Result.Granted, emergOp.Result.Granted)

			// Regular access should be denied in emergency-only mode
			if !framework.failsafeJIT.IsHealthy() {
				assert.False(t, regOp.Result.Granted,
					"Regular access should be denied in emergency-only mode")
			}

			// Emergency access might be granted with strict controls
			if emergOp.Result.Granted {
				assert.Contains(t, emergOp.SecurityControls, "emergency_access",
					"Emergency access should have emergency control")
				assert.True(t, emergOp.Result.EnhancedMonitoring,
					"Emergency access should require enhanced monitoring")
				assert.Contains(t, emergOp.SecurityControls, "limited_duration",
					"Emergency access should have limited duration")
			}
		}
	})
}

// TestNetworkPartitionDegradation tests network partition degradation modes
func TestNetworkPartitionDegradation(t *testing.T) {
	framework := NewDegradedModeSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())
	ctx := context.Background()

	partitionModes := []failsafe.PartitionToleranceMode{
		failsafe.PartitionModeFailSecure,
		failsafe.PartitionModeLocalCache,
		failsafe.PartitionModeReadOnlyCache,
		failsafe.PartitionModeGracefulDegradation,
	}

	for _, mode := range partitionModes {
		t.Run(fmt.Sprintf("Partition Mode %s", mode), func(t *testing.T) {
			// Skip graceful degradation until Issue #296 implements enhanced monitoring controls
			if mode == failsafe.PartitionModeGracefulDegradation {
				t.Skip("Skipping until Issue #296: Enhanced monitoring controls not yet implemented for admin users in graceful degradation mode")
			}

			// First make a successful request to potentially populate cache
			if mode != failsafe.PartitionModeFailSecure {
				framework.failsafeNetwork.SetPartitionMode(failsafe.PartitionModeLocalCache)

				cacheRequest := &common.AccessRequest{
					SubjectId:    "degraded-user-low",
					PermissionId: "config.read",
					TenantId:     "degraded-tenant",
					ResourceId:   "cache-resource",
				}

				_, _ = framework.failsafeNetwork.CheckPermission(ctx, cacheRequest)
			}

			// Simulate network partition
			invalidCtx, cancel := context.WithCancel(context.Background())
			cancel()

			partitionRequest := &common.AccessRequest{
				SubjectId:    "degraded-user-low",
				PermissionId: "partition.test",
				TenantId:     "degraded-tenant",
			}

			_, _ = framework.failsafeNetwork.CheckPermission(invalidCtx, partitionRequest)

			time.Sleep(100 * time.Millisecond)

			// Test partition tolerance
			subjects := []string{"degraded-user-low", "degraded-admin"}
			permissions := []string{"config.read", "config.write"}

			for _, subject := range subjects {
				for _, permission := range permissions {
					op := framework.testNetworkPartitionTolerance(ctx, subject, permission, mode)
					framework.recordDegradedOperation(op)

					t.Logf("Partition %s - Subject: %s, Permission: %s, Granted: %v, Controls: %v",
						mode, subject, permission, op.Result.Granted, op.SecurityControls)

					// Validate mode-specific behavior
					switch mode {
					case failsafe.PartitionModeFailSecure:
						// Should deny all access during partition
						if op.Metadata["partitioned"] == true {
							assert.False(t, op.Result.Granted,
								"Fail-secure mode should deny access during partition")
							assert.Contains(t, op.SecurityControls, "partition_failsafe",
								"Should have partition failsafe control")
						}

					case failsafe.PartitionModeGracefulDegradation:
						// Should allow access with enhanced monitoring
						if op.Result.Granted {
							assert.True(t, op.Result.EnhancedMonitoring,
								"Graceful degradation should require enhanced monitoring")
							assert.Contains(t, op.SecurityControls, "degraded_mode",
								"Should have degraded mode control")
						}

					case failsafe.PartitionModeLocalCache:
						// Should use cache when available
						if op.Result.Granted {
							// Should indicate cache-based decision
							if op.Result.SecurityMetadata["cache_reason"] == "policy_cached" {
								assert.Contains(t, op.SecurityControls, "cache_based_decision",
									"Should have cache-based decision control")
							}
						}
					}

					// Response time should be reasonable
					assert.True(t, op.Result.ResponseTime < 3*time.Second,
						"Response time should be reasonable in partition mode")
				}
			}
		})
	}
}

// TestDegradedModeOperationalMetrics tests operational metrics during degraded mode
func TestDegradedModeOperationalMetrics(t *testing.T) {
	t.Skip("Skipping until Issue #296: Enhanced monitoring controls not yet implemented for admin users in graceful degradation mode")

	framework := NewDegradedModeSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())

	t.Run("Degraded Mode Metrics Analysis", func(t *testing.T) {
		// Run all degraded mode tests to collect operations
		ctx := context.Background()

		// Set different degradation modes and collect metrics
		testConfigs := []struct {
			Component string
			Action    func()
		}{
			{
				Component: "RBAC",
				Action: func() {
					framework.failsafeRBAC.SetFailureMode(failsafe.FailureModeFailSecure)
					op := framework.testRBACPermissionInDegradedMode(ctx, "degraded-user-low", "config.read")
					framework.recordDegradedOperation(op)
				},
			},
			{
				Component: "Risk",
				Action: func() {
					framework.failsafeRisk.SetFailureMode(failsafe.RiskFailureModeEnhancedAuth)
					op := framework.testRiskAssessmentInDegradedMode(ctx, "degraded-user-low")
					framework.recordDegradedOperation(op)
				},
			},
			{
				Component: "JIT",
				Action: func() {
					framework.failsafeJIT.SetFailureMode(failsafe.JITFailureModeAutoRevoke)
					op := framework.testJITAccessInDegradedMode(ctx, "degraded-user-low", false)
					framework.recordDegradedOperation(op)
				},
			},
		}

		for _, config := range testConfigs {
			config.Action()
		}

		// Analyze collected operations
		operations := framework.getDegradedOperations()

		t.Logf("Collected %d degraded mode operations", len(operations))

		// Analyze security controls
		controlCounts := make(map[string]int)
		responseTimes := make([]time.Duration, 0)
		enhancedMonitoringOps := 0

		for _, op := range operations {
			for _, control := range op.SecurityControls {
				controlCounts[control]++
			}

			responseTimes = append(responseTimes, op.Result.ResponseTime)

			if op.Result.EnhancedMonitoring {
				enhancedMonitoringOps++
			}
		}

		// Log analysis results
		t.Logf("Security Controls Applied:")
		for control, count := range controlCounts {
			t.Logf("  %s: %d times", control, count)
		}

		t.Logf("Enhanced Monitoring Operations: %d/%d (%.1f%%)",
			enhancedMonitoringOps, len(operations),
			float64(enhancedMonitoringOps)/float64(len(operations))*100)

		// Calculate average response time
		if len(responseTimes) > 0 {
			totalTime := time.Duration(0)
			for _, rt := range responseTimes {
				totalTime += rt
			}
			avgResponseTime := totalTime / time.Duration(len(responseTimes))
			t.Logf("Average Response Time: %v", avgResponseTime)

			// Verify reasonable performance in degraded mode
			assert.Less(t, avgResponseTime, 2*time.Second,
				"Average response time should be reasonable in degraded mode")
		}

		// Verify security properties
		assert.Greater(t, len(operations), 0, "Should have recorded operations")
		assert.Greater(t, len(controlCounts), 0, "Should have applied security controls")

		// At least some operations should have enhanced monitoring
		if len(operations) > 0 {
			assert.Greater(t, enhancedMonitoringOps, 0,
				"At least some operations should require enhanced monitoring in degraded mode")
		}

		// Verify no inappropriate access grants
		for _, op := range operations {
			if op.Result.Granted && !op.Result.Success {
				t.Errorf("Operation %s granted access but was not successful - potential security violation",
					op.Operation)
			}
		}
	})
}
