// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package continuous_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/continuous"
	"github.com/cfgis/cfgms/features/rbac/ports"
)

// Mock implementations for testing

// MockRBACManager implements RBACManager interface for testing
type MockRBACManager struct {
	checkPermissionResponse   *common.AccessResponse
	checkPermissionError      error
	effectivePermissions      []*common.Permission
	effectivePermissionsError error
	subjectPermissions        []*common.Permission
	subjectPermissionsError   error
	initializeError           error
}

func (m *MockRBACManager) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	if m.checkPermissionError != nil {
		return nil, m.checkPermissionError
	}
	if m.checkPermissionResponse != nil {
		return m.checkPermissionResponse, nil
	}

	// Default response
	return &common.AccessResponse{
		Granted:            true,
		Reason:             "RBAC check passed",
		AppliedRoles:       []string{"default-role"},
		AppliedPermissions: []string{request.PermissionId},
	}, nil
}

func (m *MockRBACManager) GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	return m.effectivePermissions, m.effectivePermissionsError
}

func (m *MockRBACManager) GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	return m.subjectPermissions, m.subjectPermissionsError
}

func (m *MockRBACManager) Initialize(ctx context.Context) error {
	return m.initializeError
}

// MockJITManager implements ports.JITManager interface for testing
type MockJITManager struct {
	validateJITAccessResponse *common.AccessResponse
	validateJITAccessError    error
}

func (m *MockJITManager) ValidateJITAccess(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	if m.validateJITAccessError != nil {
		return nil, m.validateJITAccessError
	}
	if m.validateJITAccessResponse != nil {
		return m.validateJITAccessResponse, nil
	}

	// Default no JIT access
	return &common.AccessResponse{
		Granted: false,
		Reason:  "No active JIT access",
	}, nil
}

// MockRiskManager implements RiskManager interface for testing
type MockRiskManager struct {
	enhancedRiskResponse *continuous.RiskAccessResult
	enhancedRiskError    error
}

func (m *MockRiskManager) EnhancedRiskAccessCheck(ctx context.Context, request *common.AccessRequest) (*continuous.RiskAccessResult, error) {
	if m.enhancedRiskError != nil {
		return nil, m.enhancedRiskError
	}
	if m.enhancedRiskResponse != nil {
		return m.enhancedRiskResponse, nil
	}

	// Default low risk response
	return &continuous.RiskAccessResult{
		StandardResponse: &common.AccessResponse{
			Granted:            true,
			Reason:             "Low risk assessment",
			AppliedPermissions: []string{request.PermissionId},
		},
	}, nil
}

// MockTenantSecurityPolicyEngine for testing
type MockTenantSecurityPolicyEngine struct{}

func (m *MockTenantSecurityPolicyEngine) EvaluateSecurityPolicy(ctx context.Context, request *continuous.SecurityEvaluationRequest) (*continuous.SecurityPolicyResult, error) {
	return &continuous.SecurityPolicyResult{
		ComplianceStatus:   true,
		RecommendedActions: []string{},
		Violations:         []continuous.PolicyViolation{},
		AppliedRules:       []string{"default-rule"},
		Allowed:            true,
	}, nil
}

// MockTenantSecurityMiddleware implements TenantSecurityMiddleware for testing
type MockTenantSecurityMiddleware struct {
	policyEngine continuous.TenantSecurityPolicyEngine
}

func (m *MockTenantSecurityMiddleware) GetPolicyEngine() continuous.TenantSecurityPolicyEngine {
	if m.policyEngine != nil {
		return m.policyEngine
	}
	return &MockTenantSecurityPolicyEngine{}
}

// Test helper functions

func defaultTestConfig() *continuous.ContinuousAuthConfig {
	return &continuous.ContinuousAuthConfig{
		MaxAuthLatencyMs:       10,
		PermissionCacheTTL:     5 * time.Minute,
		SessionUpdateInterval:  60 * time.Second,
		PropagationTimeoutMs:   1000,
		MaxRetryAttempts:       3,
		EnableRiskReassessment: true,
		RiskCheckInterval:      30 * time.Second,
		EnableAutoTermination:  false,
	}
}

// newTestContinuousEngine creates a ContinuousAuthorizationEngine via the public constructor.
// Nil arguments default to the standard mock implementations.
func newTestContinuousEngine(
	rbacMgr ports.RBACManager,
	jitMgr ports.JITManager,
	riskMgr continuous.ContinuousRiskManager,
	ts continuous.TenantSecurityMiddleware,
) *continuous.ContinuousAuthorizationEngine {
	if rbacMgr == nil {
		rbacMgr = &MockRBACManager{}
	}
	if jitMgr == nil {
		jitMgr = &MockJITManager{}
	}
	if riskMgr == nil {
		riskMgr = &MockRiskManager{}
	}
	if ts == nil {
		ts = &MockTenantSecurityMiddleware{}
	}
	return continuous.NewContinuousAuthorizationEngine(rbacMgr, jitMgr, riskMgr, ts, defaultTestConfig())
}

func createTestContinuousAuthEngine() *continuous.ContinuousAuthorizationEngine {
	return newTestContinuousEngine(nil, nil, nil, nil)
}

func createTestContinuousAuthRequest(subjectID, resourceID, permissionID, tenantID, sessionID string) *continuous.ContinuousAuthRequest {
	return &continuous.ContinuousAuthRequest{
		AccessRequest: &common.AccessRequest{
			SubjectId:    subjectID,
			ResourceId:   resourceID,
			PermissionId: permissionID,
			TenantId:     tenantID,
			Context: map[string]string{
				"request_type": "continuous_auth",
			},
		},
		SessionID:     sessionID,
		OperationType: continuous.OperationTypeStandard,
		ResourceContext: map[string]string{
			"resource_type": "database",
			"sensitivity":   "high",
		},
	}
}

// Test functions

func TestNewContinuousAuthorizationEngine(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	// Prove all 9 internal dependencies were correctly wired:
	// Start() initialises each component and returns an error if any are nil or fail.
	err := engine.Start(ctx)
	require.NoError(t, err)

	err = engine.Stop()
	require.NoError(t, err)
}

func TestContinuousAuthorizationEngine_Start_Success(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	err := engine.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() { _ = engine.Stop() })
}

func TestContinuousAuthorizationEngine_Start_InitializationError(t *testing.T) {
	engine := newTestContinuousEngine(
		&MockRBACManager{initializeError: fmt.Errorf("initialization failed")},
		nil, nil, nil,
	)
	ctx := context.Background()

	err := engine.Start(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "initialization failed")
}

func TestContinuousAuthorizationEngine_Stop_Success(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	// Start the engine first
	err := engine.Start(ctx)
	require.NoError(t, err)

	// Now stop it
	err = engine.Stop()
	require.NoError(t, err)
}

func TestContinuousAuthorizationEngine_AuthorizeAction_Success(t *testing.T) {
	rbacMgr := &MockRBACManager{
		checkPermissionResponse: &common.AccessResponse{
			Granted:            true,
			Reason:             "Access granted by RBAC",
			AppliedPermissions: []string{"read"},
		},
	}
	engine := newTestContinuousEngine(rbacMgr, nil, nil, nil)
	ctx := context.Background()

	// Register session first
	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	request := createTestContinuousAuthRequest("user1", "resource1", "read", "tenant1", "session1")

	response, err := engine.AuthorizeAction(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.True(t, response.AccessResponse.Granted)
	assert.NotEmpty(t, response.DecisionID)
}

func TestContinuousAuthorizationEngine_AuthorizeAction_RBACDenied(t *testing.T) {
	rbacMgr := &MockRBACManager{
		checkPermissionResponse: &common.AccessResponse{
			Granted: false,
			Reason:  "Access denied by RBAC",
		},
	}
	engine := newTestContinuousEngine(rbacMgr, nil, nil, nil)
	ctx := context.Background()

	// Register session first
	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	request := createTestContinuousAuthRequest("user1", "resource1", "admin", "tenant1", "session1")

	response, err := engine.AuthorizeAction(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.False(t, response.AccessResponse.Granted)
	assert.NotEmpty(t, response.DecisionID)
	assert.Contains(t, response.AccessResponse.Reason, "Access denied by RBAC")
}

func TestContinuousAuthorizationEngine_AuthorizeAction_WithJITAccess(t *testing.T) {
	engine := newTestContinuousEngine(
		&MockRBACManager{
			checkPermissionResponse: &common.AccessResponse{
				Granted: false,
				Reason:  "No standard permission",
			},
		},
		&MockJITManager{
			validateJITAccessResponse: &common.AccessResponse{
				Granted:            true,
				Reason:             "JIT access active",
				AppliedPermissions: []string{"admin"},
			},
		},
		&MockRiskManager{
			enhancedRiskResponse: &continuous.RiskAccessResult{
				StandardResponse: &common.AccessResponse{
					Granted:            true,
					Reason:             "JIT access active",
					AppliedPermissions: []string{"admin"},
				},
			},
		},
		nil,
	)
	ctx := context.Background()

	// Register session first
	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	request := createTestContinuousAuthRequest("user1", "resource1", "admin", "tenant1", "session1")

	response, err := engine.AuthorizeAction(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.True(t, response.AccessResponse.Granted)
	assert.Contains(t, response.AccessResponse.Reason, "JIT access active")
}

func TestContinuousAuthorizationEngine_AuthorizeAction_RiskBasedDenial(t *testing.T) {
	engine := newTestContinuousEngine(
		&MockRBACManager{
			checkPermissionResponse: &common.AccessResponse{
				Granted:            true,
				Reason:             "RBAC permission granted",
				AppliedPermissions: []string{"read"},
			},
		},
		nil,
		&MockRiskManager{
			enhancedRiskResponse: &continuous.RiskAccessResult{
				StandardResponse: &common.AccessResponse{
					Granted: false,
					Reason:  "High risk detected - access denied",
				},
			},
		},
		nil,
	)
	ctx := context.Background()

	// Register session first
	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	request := createTestContinuousAuthRequest("user1", "resource1", "read", "tenant1", "session1")

	response, err := engine.AuthorizeAction(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.False(t, response.AccessResponse.Granted)
	assert.Contains(t, response.AccessResponse.Reason, "High risk detected")
}

func TestContinuousAuthorizationEngine_AuthorizeAction_ValidationErrors(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	tests := []struct {
		name    string
		request *continuous.ContinuousAuthRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			request: nil,
			wantErr: true,
		},
		{
			name: "missing access request",
			request: &continuous.ContinuousAuthRequest{
				SessionID: "session1",
			},
			wantErr: true,
		},
		{
			name: "missing subject ID",
			request: &continuous.ContinuousAuthRequest{
				AccessRequest: &common.AccessRequest{
					ResourceId:   "resource1",
					PermissionId: "read",
					TenantId:     "tenant1",
				},
				SessionID: "session1",
			},
			wantErr: true,
		},
		{
			name: "missing session ID",
			request: &continuous.ContinuousAuthRequest{
				AccessRequest: &common.AccessRequest{
					SubjectId:    "user1",
					ResourceId:   "resource1",
					PermissionId: "read",
					TenantId:     "tenant1",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := engine.AuthorizeAction(ctx, tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
			}
		})
	}
}

func TestContinuousAuthorizationEngine_RegisterSession_Success(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	metadata := map[string]string{
		"client_id":  "web-app",
		"user_agent": "Mozilla/5.0",
		"ip_address": "192.168.1.100",
	}

	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", metadata)

	require.NoError(t, err)

	// Verify session is registered by checking status
	status, err := engine.GetSessionStatus(ctx, "session1")
	require.NoError(t, err)
	assert.NotNil(t, status)
	assert.Equal(t, "session1", status.SessionID)
	assert.NotEmpty(t, status.Status)
}

func TestContinuousAuthorizationEngine_UnregisterSession_Success(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	// First register a session
	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	// Then unregister it
	err = engine.UnregisterSession(ctx, "session1")
	require.NoError(t, err)

	// Verify session is no longer found
	status, err := engine.GetSessionStatus(ctx, "session1")
	assert.Error(t, err)
	assert.Nil(t, status)
}

func TestContinuousAuthorizationEngine_RevokePermissions_Success(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	permissions := []string{"read", "write"}

	err := engine.RevokePermissions(ctx, "user1", "tenant1", permissions)

	require.NoError(t, err)
}

func TestContinuousAuthorizationEngine_GetSessionStatus_SessionNotFound(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	status, err := engine.GetSessionStatus(ctx, "nonexistent-session")

	assert.Error(t, err)
	assert.Nil(t, status)
	assert.Contains(t, err.Error(), "session not found")
}

func TestContinuousAuthorizationEngine_GetAuthorizationStats(t *testing.T) {
	engine := createTestContinuousAuthEngine()

	stats := engine.GetAuthorizationStats()

	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.TotalAuthChecks, int64(0))
	assert.GreaterOrEqual(t, stats.AuthorizedRequests, int64(0))
	assert.GreaterOrEqual(t, stats.DeniedRequests, int64(0))
	assert.GreaterOrEqual(t, stats.ActiveSessions, 0)
}

func TestContinuousAuthorizationEngine_AuthorizeAction_SystemIntegrationFailure(t *testing.T) {
	engine := newTestContinuousEngine(
		&MockRBACManager{checkPermissionError: fmt.Errorf("RBAC system unavailable")},
		nil, nil, nil,
	)
	ctx := context.Background()

	// Register session first
	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	request := createTestContinuousAuthRequest("user1", "resource1", "read", "tenant1", "session1")

	response, err := engine.AuthorizeAction(ctx, request)

	require.NoError(t, err) // Should not error, but should return denied response
	assert.NotNil(t, response)
	assert.False(t, response.AccessResponse.Granted)
	assert.Contains(t, response.AccessResponse.Reason, "system error")
}

func TestContinuousAuthorizationEngine_AuthorizeAction_SecurityEdgeCases(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	tests := []struct {
		name        string
		request     *continuous.ContinuousAuthRequest
		expectError bool
	}{
		{
			name: "malformed session ID",
			request: &continuous.ContinuousAuthRequest{
				AccessRequest: &common.AccessRequest{
					SubjectId:    "user1",
					ResourceId:   "resource1",
					PermissionId: "read",
					TenantId:     "tenant1",
				},
				SessionID: "../../../etc/passwd",
			},
			expectError: false, // Should handle gracefully, not error
		},
		{
			name: "injection attempt in subject ID",
			request: &continuous.ContinuousAuthRequest{
				AccessRequest: &common.AccessRequest{
					SubjectId:    "user1'; DROP TABLE users; --",
					ResourceId:   "resource1",
					PermissionId: "read",
					TenantId:     "tenant1",
				},
				SessionID: "session1",
			},
			expectError: false,
		},
		{
			name: "cross-tenant access attempt",
			request: &continuous.ContinuousAuthRequest{
				AccessRequest: &common.AccessRequest{
					SubjectId:    "user1",
					ResourceId:   "tenant2/sensitive-resource",
					PermissionId: "admin",
					TenantId:     "tenant1",
				},
				SessionID: "session1",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := engine.AuthorizeAction(ctx, tt.request)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				// Security edge cases should be denied, not cause errors
				assert.False(t, response.AccessResponse.Granted)
			}
		})
	}
}

func TestContinuousAuthorizationEngine_AuthorizeAction_ConcurrentRequests(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	const numConcurrent = 10
	results := make(chan *continuous.ContinuousAuthResponse, numConcurrent)
	errors := make(chan error, numConcurrent)

	// Run multiple concurrent authorization requests
	for i := 0; i < numConcurrent; i++ {
		go func(requestNum int) {
			request := createTestContinuousAuthRequest(
				fmt.Sprintf("user%d", requestNum),
				"resource1",
				"read",
				"tenant1",
				fmt.Sprintf("session%d", requestNum),
			)

			response, err := engine.AuthorizeAction(ctx, request)
			if err != nil {
				errors <- err
			} else {
				results <- response
			}
		}(i)
	}

	// Collect results
	successCount := 0
	errorCount := 0

	for i := 0; i < numConcurrent; i++ {
		select {
		case response := <-results:
			assert.NotNil(t, response)
			assert.NotEmpty(t, response.DecisionID)
			successCount++
		case err := <-errors:
			t.Errorf("Unexpected error in concurrent test: %v", err)
			errorCount++
		case <-time.After(5 * time.Second):
			t.Fatal("Test timed out waiting for concurrent authorizations")
		}
	}

	assert.Equal(t, numConcurrent, successCount)
	assert.Equal(t, 0, errorCount)
}

func TestContinuousAuthorizationEngine_AuthorizeAction_PerformanceTesting(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	request := createTestContinuousAuthRequest("user1", "resource1", "read", "tenant1", "session1")

	// Measure authorization time for performance validation
	startTime := time.Now()

	response, err := engine.AuthorizeAction(ctx, request)

	elapsedTime := time.Since(startTime)

	require.NoError(t, err)
	assert.NotNil(t, response)

	// Should complete within reasonable time (adjust threshold as needed)
	assert.Less(t, elapsedTime, 100*time.Millisecond,
		"Authorization should complete quickly for performance")
}
