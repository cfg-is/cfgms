// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package continuous

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
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

// MockJITManager implements JITManager interface for testing
type MockJITManager struct {
	checkJITAccessResponse *common.AccessResponse
	checkJITAccessError    error
}

func (m *MockJITManager) CheckJITAccess(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	if m.checkJITAccessError != nil {
		return nil, m.checkJITAccessError
	}
	if m.checkJITAccessResponse != nil {
		return m.checkJITAccessResponse, nil
	}

	// Default no JIT access
	return &common.AccessResponse{
		Granted: false,
		Reason:  "No active JIT access",
	}, nil
}

// MockRiskManager implements RiskManager interface for testing
type MockRiskManager struct {
	enhancedRiskResponse *RiskAccessResult
	enhancedRiskError    error
}

func (m *MockRiskManager) EnhancedRiskAccessCheck(ctx context.Context, request *common.AccessRequest) (*RiskAccessResult, error) {
	if m.enhancedRiskError != nil {
		return nil, m.enhancedRiskError
	}
	if m.enhancedRiskResponse != nil {
		return m.enhancedRiskResponse, nil
	}

	// Default low risk response
	return &RiskAccessResult{
		StandardResponse: &common.AccessResponse{
			Granted:            true,
			Reason:             "Low risk assessment",
			AppliedPermissions: []string{request.PermissionId},
		},
	}, nil
}

// MockTenantSecurityPolicyEngine for testing
type MockTenantSecurityPolicyEngine struct{}

func (m *MockTenantSecurityPolicyEngine) EvaluateSecurityPolicy(ctx context.Context, request *SecurityEvaluationRequest) (*SecurityPolicyResult, error) {
	return &SecurityPolicyResult{
		ComplianceStatus:   true,
		RecommendedActions: []string{},
		Violations:         []PolicyViolation{},
		AppliedRules:       []string{"default-rule"},
		Allowed:            true,
	}, nil
}

// MockTenantSecurityMiddleware implements TenantSecurityMiddleware for testing
type MockTenantSecurityMiddleware struct {
	policyEngine TenantSecurityPolicyEngine
}

func (m *MockTenantSecurityMiddleware) GetPolicyEngine() TenantSecurityPolicyEngine {
	if m.policyEngine != nil {
		return m.policyEngine
	}
	return &MockTenantSecurityPolicyEngine{}
}

// Test helper functions

func createTestContinuousAuthEngine() *ContinuousAuthorizationEngine {
	config := &ContinuousAuthConfig{
		MaxAuthLatencyMs:       10,
		PermissionCacheTTL:     5 * time.Minute,
		SessionUpdateInterval:  60 * time.Second,
		PropagationTimeoutMs:   1000,
		MaxRetryAttempts:       3,
		EnableRiskReassessment: true,
		RiskCheckInterval:      30 * time.Second,
		EnableAutoTermination:  false,
	}

	return &ContinuousAuthorizationEngine{
		rbacManager:     &MockRBACManager{},
		jitManager:      &MockJITManager{},
		riskManager:     &MockRiskManager{},
		tenantSecurity:  &MockTenantSecurityMiddleware{},
		sessionRegistry: NewSessionRegistry(),
		permissionCache: NewCacheManager(config.PermissionCacheTTL, config.MaxAuthLatencyMs),
		eventBus:        NewPermissionEventBus(100),                           // buffer size
		contextMonitor:  NewContextMonitor(nil, config.SessionUpdateInterval), // nil risk manager for test
		policyEnforcer:  NewPolicyEnforcer(nil, false),                        // nil tenant security, no auto termination
		config:          config,
		stats:           &AuthorizationStats{mutex: sync.RWMutex{}}, // Initialize stats for tests
		stopChannel:     make(chan struct{}),                        // Initialize stop channel
	}
}

func createTestContinuousAuthRequest(subjectID, resourceID, permissionID, tenantID, sessionID string) *ContinuousAuthRequest {
	return &ContinuousAuthRequest{
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
		OperationType: OperationTypeStandard,
		ResourceContext: map[string]string{
			"resource_type": "database",
			"sensitivity":   "high",
		},
	}
}

// Test functions

func TestNewContinuousAuthorizationEngine(t *testing.T) {
	engine := createTestContinuousAuthEngine()

	assert.NotNil(t, engine)
	assert.NotNil(t, engine.rbacManager)
	assert.NotNil(t, engine.jitManager)
	assert.NotNil(t, engine.riskManager)
	assert.NotNil(t, engine.tenantSecurity)
	assert.NotNil(t, engine.sessionRegistry)
	assert.NotNil(t, engine.permissionCache)
	assert.NotNil(t, engine.eventBus)
	assert.NotNil(t, engine.contextMonitor)
	assert.NotNil(t, engine.policyEnforcer)
	assert.NotNil(t, engine.config)
}

func TestContinuousAuthorizationEngine_Start_Success(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	err := engine.Start(ctx)

	require.NoError(t, err)

	// Verify that monitoring loops are started (we can't easily test this without exposing internal state)
	// The important thing is that Start doesn't return an error
}

func TestContinuousAuthorizationEngine_Start_InitializationError(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	engine.rbacManager = &MockRBACManager{
		initializeError: fmt.Errorf("initialization failed"),
	}
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
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	// Register session first
	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	// Setup successful RBAC response
	engine.rbacManager = &MockRBACManager{
		checkPermissionResponse: &common.AccessResponse{
			Granted:            true,
			Reason:             "Access granted by RBAC",
			AppliedPermissions: []string{"read"},
		},
	}

	request := createTestContinuousAuthRequest("user1", "resource1", "read", "tenant1", "session1")

	response, err := engine.AuthorizeAction(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.True(t, response.AccessResponse.Granted)
	assert.NotEmpty(t, response.DecisionID)
}

func TestContinuousAuthorizationEngine_AuthorizeAction_RBACDenied(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	// Register session first
	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	// Setup RBAC denial
	engine.rbacManager = &MockRBACManager{
		checkPermissionResponse: &common.AccessResponse{
			Granted: false,
			Reason:  "Access denied by RBAC",
		},
	}

	request := createTestContinuousAuthRequest("user1", "resource1", "admin", "tenant1", "session1")

	response, err := engine.AuthorizeAction(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.False(t, response.AccessResponse.Granted)
	assert.NotEmpty(t, response.DecisionID)
	assert.Contains(t, response.AccessResponse.Reason, "Access denied by RBAC")
}

func TestContinuousAuthorizationEngine_AuthorizeAction_WithJITAccess(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	// Register session first
	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	// Setup RBAC denial but JIT access granted
	engine.rbacManager = &MockRBACManager{
		checkPermissionResponse: &common.AccessResponse{
			Granted: false,
			Reason:  "No standard permission",
		},
	}

	engine.jitManager = &MockJITManager{
		checkJITAccessResponse: &common.AccessResponse{
			Granted:            true,
			Reason:             "JIT access active",
			AppliedPermissions: []string{"admin"},
		},
	}

	// Setup risk manager to preserve JIT access decision
	engine.riskManager = &MockRiskManager{
		enhancedRiskResponse: &RiskAccessResult{
			StandardResponse: &common.AccessResponse{
				Granted:            true,
				Reason:             "JIT access active",
				AppliedPermissions: []string{"admin"},
			},
		},
	}

	request := createTestContinuousAuthRequest("user1", "resource1", "admin", "tenant1", "session1")

	response, err := engine.AuthorizeAction(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.True(t, response.AccessResponse.Granted)
	assert.Contains(t, response.AccessResponse.Reason, "JIT access active")
}

func TestContinuousAuthorizationEngine_AuthorizeAction_RiskBasedDenial(t *testing.T) {
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	// Register session first
	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	// Setup RBAC success but high risk denial
	engine.rbacManager = &MockRBACManager{
		checkPermissionResponse: &common.AccessResponse{
			Granted:            true,
			Reason:             "RBAC permission granted",
			AppliedPermissions: []string{"read"},
		},
	}

	engine.riskManager = &MockRiskManager{
		enhancedRiskResponse: &RiskAccessResult{
			StandardResponse: &common.AccessResponse{
				Granted: false,
				Reason:  "High risk detected - access denied",
			},
		},
	}

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
		request *ContinuousAuthRequest
		wantErr bool
	}{
		{
			name:    "nil request",
			request: nil,
			wantErr: true,
		},
		{
			name: "missing access request",
			request: &ContinuousAuthRequest{
				SessionID: "session1",
			},
			wantErr: true,
		},
		{
			name: "missing subject ID",
			request: &ContinuousAuthRequest{
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
			request: &ContinuousAuthRequest{
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
	engine := createTestContinuousAuthEngine()
	ctx := context.Background()

	// Register session first
	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	// Setup RBAC system failure
	engine.rbacManager = &MockRBACManager{
		checkPermissionError: fmt.Errorf("RBAC system unavailable"),
	}

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
		request     *ContinuousAuthRequest
		expectError bool
	}{
		{
			name: "malformed session ID",
			request: &ContinuousAuthRequest{
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
			request: &ContinuousAuthRequest{
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
			request: &ContinuousAuthRequest{
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
	results := make(chan *ContinuousAuthResponse, numConcurrent)
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
