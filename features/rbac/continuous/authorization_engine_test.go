// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package continuous_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/continuous"
	"github.com/cfgis/cfgms/features/rbac/ports"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// Mock implementations for testing
//
// MockRBACManager is retained only for the two tests that need to simulate RBAC-layer
// errors (Start_InitializationError, SystemIntegrationFailure) — scenarios that cannot
// be triggered through a real rbac.Manager.  All other tests use newTestRBACManager(t)
// which returns a real rbac.Manager backed by an in-process SQLite store.
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

// The three test doubles below remain because no real CFGMS type satisfies their
// respective interfaces.  This is documented architectural debt in the continuous
// package — resolving it requires redesigning these production interfaces in a
// dedicated story.
//
//   - ports.JITManager.ValidateJITAccess has a different signature than
//     jit.JITAccessManager.CheckJITAccess.
//   - continuous.ContinuousRiskManager.EnhancedRiskAccessCheck returns a local
//     wrapper type that no real risk package type satisfies.
//   - continuous.TenantSecurityMiddleware.GetPolicyEngine() has no real CFGMS
//     implementation.

// MockJITManager implements ports.JITManager for testing.
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

	return &common.AccessResponse{
		Granted: false,
		Reason:  "No active JIT access",
	}, nil
}

// MockRiskManager implements continuous.ContinuousRiskManager for testing.
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

	return &continuous.RiskAccessResult{
		StandardResponse: &common.AccessResponse{
			Granted:            true,
			Reason:             "Low risk assessment",
			AppliedPermissions: []string{request.PermissionId},
		},
	}, nil
}

// MockTenantSecurityPolicyEngine for testing.
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

// MockTenantSecurityMiddleware implements continuous.TenantSecurityMiddleware for testing.
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

// newTestRBACManager returns a real rbac.Manager backed by an in-process OSS store
// rooted in t.TempDir().  Cleanup is registered automatically.
func newTestRBACManager(t *testing.T) *rbac.Manager {
	t.Helper()
	tmpDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, sm.Close()) })

	mgr := rbac.NewManagerWithStorage(sm.GetAuditStore(), sm.GetClientTenantStore(), sm.GetRBACStore())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, mgr.Close(ctx))
	})

	ctx := rbac.WithSensitiveOperationJustification(context.Background(), "test rbac manager initialization")
	require.NoError(t, mgr.Initialize(ctx))
	return mgr
}

// grantPermission creates a permission + role + subject + assignment in mgr.
func grantPermission(t *testing.T, mgr *rbac.Manager, subjectID, permissionID, tenantID string) {
	t.Helper()
	ctx := rbac.WithSensitiveOperationJustification(context.Background(), "test setup: grant permission")

	perm := &common.Permission{
		Id:           permissionID,
		Name:         permissionID,
		ResourceType: "test",
		Actions:      []string{"execute"},
	}
	if err := mgr.CreatePermission(ctx, perm); err != nil && !strings.Contains(err.Error(), "already exists") {
		require.NoError(t, err)
	}

	roleID := subjectID + "-" + permissionID + "-" + tenantID
	role := &common.Role{
		Id:            roleID,
		Name:          roleID,
		PermissionIds: []string{permissionID},
		TenantId:      tenantID,
	}
	if err := mgr.CreateRole(ctx, role); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return
		}
		require.NoError(t, err)
	}

	subject := &common.Subject{
		Id:          subjectID,
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: subjectID,
		TenantId:    tenantID,
		IsActive:    true,
	}
	if err := mgr.CreateSubject(ctx, subject); err != nil && !strings.Contains(err.Error(), "already exists") {
		require.NoError(t, err)
	}

	assignment := &common.RoleAssignment{
		SubjectId: subjectID,
		RoleId:    roleID,
		TenantId:  tenantID,
	}
	require.NoError(t, mgr.AssignRole(ctx, assignment))
}

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

// newTestContinuousEngine creates a ContinuousAuthorizationEngine via the public
// constructor.  A nil rbacMgr uses a real rbac.Manager; nil jitMgr, riskMgr, and ts
// use test doubles (no real CFGMS implementation satisfies those interfaces — see
// comment above the mock type definitions).
func newTestContinuousEngine(
	t *testing.T,
	rbacMgr ports.RBACManager,
	jitMgr ports.JITManager,
	riskMgr continuous.ContinuousRiskManager,
	ts continuous.TenantSecurityMiddleware,
) *continuous.ContinuousAuthorizationEngine {
	t.Helper()
	if rbacMgr == nil {
		rbacMgr = newTestRBACManager(t)
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

func createTestContinuousAuthEngine(t *testing.T) *continuous.ContinuousAuthorizationEngine {
	t.Helper()
	return newTestContinuousEngine(t, nil, nil, nil, nil)
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
	engine := createTestContinuousAuthEngine(t)
	ctx := context.Background()

	// Prove all 9 internal dependencies were correctly wired:
	// Start() initialises each component and returns an error if any are nil or fail.
	err := engine.Start(ctx)
	require.NoError(t, err)

	err = engine.Stop()
	require.NoError(t, err)
}

func TestContinuousAuthorizationEngine_Start_Success(t *testing.T) {
	engine := createTestContinuousAuthEngine(t)
	ctx := context.Background()

	err := engine.Start(ctx)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, engine.Stop()) })
}

func TestContinuousAuthorizationEngine_Start_InitializationError(t *testing.T) {
	engine := newTestContinuousEngine(
		t,
		&MockRBACManager{initializeError: fmt.Errorf("initialization failed")},
		nil, nil, nil,
	)
	ctx := context.Background()

	err := engine.Start(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "initialization failed")
}

func TestContinuousAuthorizationEngine_Stop_Success(t *testing.T) {
	engine := createTestContinuousAuthEngine(t)
	ctx := context.Background()

	err := engine.Start(ctx)
	require.NoError(t, err)

	err = engine.Stop()
	require.NoError(t, err)
}

func TestContinuousAuthorizationEngine_AuthorizeAction_Success(t *testing.T) {
	rbacMgr := newTestRBACManager(t)
	grantPermission(t, rbacMgr, "user1", "read", "tenant1")
	engine := newTestContinuousEngine(t, rbacMgr, nil, nil, nil)
	ctx := context.Background()

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
	// Real manager with no permissions granted — RBAC denies by default.
	engine := createTestContinuousAuthEngine(t)
	ctx := context.Background()

	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	request := createTestContinuousAuthRequest("user1", "resource1", "admin", "tenant1", "session1")

	response, err := engine.AuthorizeAction(ctx, request)

	require.NoError(t, err)
	assert.NotNil(t, response)
	assert.False(t, response.AccessResponse.Granted)
	assert.NotEmpty(t, response.DecisionID)
	assert.NotEmpty(t, response.AccessResponse.Reason)
}

func TestContinuousAuthorizationEngine_AuthorizeAction_WithJITAccess(t *testing.T) {
	// Real manager with no permissions — RBAC denies, JIT grants.
	engine := newTestContinuousEngine(
		t,
		nil, // real rbac.Manager, no permissions → RBAC denies
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
	rbacMgr := newTestRBACManager(t)
	grantPermission(t, rbacMgr, "user1", "read", "tenant1")
	engine := newTestContinuousEngine(
		t,
		rbacMgr,
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
	engine := createTestContinuousAuthEngine(t)
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
	engine := createTestContinuousAuthEngine(t)
	ctx := context.Background()

	metadata := map[string]string{
		"client_id":  "web-app",
		"user_agent": "Mozilla/5.0",
		"ip_address": "192.168.1.100",
	}

	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", metadata)

	require.NoError(t, err)

	status, err := engine.GetSessionStatus(ctx, "session1")
	require.NoError(t, err)
	assert.NotNil(t, status)
	assert.Equal(t, "session1", status.SessionID)
	assert.NotEmpty(t, status.Status)
}

func TestContinuousAuthorizationEngine_UnregisterSession_Success(t *testing.T) {
	engine := createTestContinuousAuthEngine(t)
	ctx := context.Background()

	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	err = engine.UnregisterSession(ctx, "session1")
	require.NoError(t, err)

	status, err := engine.GetSessionStatus(ctx, "session1")
	assert.Error(t, err)
	assert.Nil(t, status)
}

func TestContinuousAuthorizationEngine_RevokePermissions_Success(t *testing.T) {
	engine := createTestContinuousAuthEngine(t)
	ctx := context.Background()

	permissions := []string{"read", "write"}

	err := engine.RevokePermissions(ctx, "user1", "tenant1", permissions)

	require.NoError(t, err)
}

func TestContinuousAuthorizationEngine_GetSessionStatus_SessionNotFound(t *testing.T) {
	engine := createTestContinuousAuthEngine(t)
	ctx := context.Background()

	status, err := engine.GetSessionStatus(ctx, "nonexistent-session")

	assert.Error(t, err)
	assert.Nil(t, status)
	assert.Contains(t, err.Error(), "session not found")
}

func TestContinuousAuthorizationEngine_GetAuthorizationStats(t *testing.T) {
	engine := createTestContinuousAuthEngine(t)

	stats := engine.GetAuthorizationStats()

	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.TotalAuthChecks, int64(0))
	assert.GreaterOrEqual(t, stats.AuthorizedRequests, int64(0))
	assert.GreaterOrEqual(t, stats.DeniedRequests, int64(0))
	assert.GreaterOrEqual(t, stats.ActiveSessions, 0)
}

func TestContinuousAuthorizationEngine_AuthorizeAction_SystemIntegrationFailure(t *testing.T) {
	engine := newTestContinuousEngine(
		t,
		&MockRBACManager{checkPermissionError: fmt.Errorf("RBAC system unavailable")},
		nil, nil, nil,
	)
	ctx := context.Background()

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
	// Each subtest gets its own engine so sessions don't conflict between cases.
	// Sessions are registered with the exact IDs from the request so the engine
	// exercises RBAC rather than short-circuiting at "session not found".
	// No permissions are granted, so RBAC denies all requests — this proves the
	// engine handles unusual/malicious inputs without panicking and correctly
	// propagates the denial.
	ctx := context.Background()

	tests := []struct {
		name       string
		sessionID  string
		subjectID  string
		resourceID string
		permID     string
		tenantID   string
	}{
		{
			name:       "malformed session ID",
			sessionID:  "../../../etc/passwd",
			subjectID:  "user1",
			resourceID: "resource1",
			permID:     "read",
			tenantID:   "tenant1",
		},
		{
			name:       "injection attempt in subject ID",
			sessionID:  "session-injection",
			subjectID:  "user1'; DROP TABLE users; --",
			resourceID: "resource1",
			permID:     "read",
			tenantID:   "tenant1",
		},
		{
			name:       "cross-tenant access attempt",
			sessionID:  "session-crosstenant",
			subjectID:  "user1",
			resourceID: "tenant2/sensitive-resource",
			permID:     "admin",
			tenantID:   "tenant1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := createTestContinuousAuthEngine(t)

			err := engine.RegisterSession(ctx, tt.sessionID, tt.subjectID, tt.tenantID, nil)
			require.NoError(t, err, "registering a session must succeed regardless of ID content")

			request := &continuous.ContinuousAuthRequest{
				AccessRequest: &common.AccessRequest{
					SubjectId:    tt.subjectID,
					ResourceId:   tt.resourceID,
					PermissionId: tt.permID,
					TenantId:     tt.tenantID,
				},
				SessionID: tt.sessionID,
			}

			response, err := engine.AuthorizeAction(ctx, request)

			// Engine must handle unusual inputs gracefully: no panic, no error.
			require.NoError(t, err)
			assert.NotNil(t, response)
			// No permissions are granted in the test RBAC store.
			assert.False(t, response.AccessResponse.Granted)
		})
	}
}

func TestContinuousAuthorizationEngine_AuthorizeAction_ConcurrentRequests(t *testing.T) {
	engine := createTestContinuousAuthEngine(t)
	ctx := context.Background()

	const numConcurrent = 10

	// Pre-register all sessions so AuthorizeAction exercises the full RBAC pipeline
	// rather than short-circuiting at session validation.
	for i := 0; i < numConcurrent; i++ {
		err := engine.RegisterSession(ctx, fmt.Sprintf("session%d", i), fmt.Sprintf("user%d", i), "tenant1", nil)
		require.NoError(t, err)
	}

	results := make(chan *continuous.ContinuousAuthResponse, numConcurrent)
	errors := make(chan error, numConcurrent)

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
	engine := createTestContinuousAuthEngine(t)
	ctx := context.Background()

	err := engine.RegisterSession(ctx, "session1", "user1", "tenant1", nil)
	require.NoError(t, err)

	request := createTestContinuousAuthRequest("user1", "resource1", "read", "tenant1", "session1")

	startTime := time.Now()

	response, err := engine.AuthorizeAction(ctx, request)

	elapsedTime := time.Since(startTime)

	require.NoError(t, err)
	assert.NotNil(t, response)

	assert.Less(t, elapsedTime, 100*time.Millisecond,
		"Authorization should complete quickly for performance")
}
