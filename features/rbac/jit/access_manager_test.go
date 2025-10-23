// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package jit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/zerotrust"
)

func TestNewJITAccessManager(t *testing.T) {
	rbacManager := &MockRBACManager{}
	notificationService := &MockNotificationService{}

	jam := NewJITAccessManager(rbacManager, notificationService)

	assert.NotNil(t, jam)
	assert.Equal(t, rbacManager, jam.rbacManager)
	assert.Equal(t, notificationService, jam.notificationService)
	assert.NotNil(t, jam.requests)
	assert.NotNil(t, jam.activeGrants)
	assert.NotNil(t, jam.approvalWorkflows)
	assert.NotNil(t, jam.auditLogger)
	assert.False(t, jam.zeroTrustEnabled)
	assert.Equal(t, ZeroTrustJITModeDisabled, jam.zeroTrustMode)
	assert.Nil(t, jam.zeroTrustEngine)
}

func TestJITAccessManager_EnableZeroTrustPolicies(t *testing.T) {
	tests := []struct {
		name            string
		engine          *zerotrust.ZeroTrustPolicyEngine
		mode            ZeroTrustJITMode
		expectedEnabled bool
	}{
		{
			name:            "Enable with valid engine and mode",
			engine:          createMockZeroTrustEngine(),
			mode:            ZeroTrustJITModeComprehensive,
			expectedEnabled: true,
		},
		{
			name:            "Disable with disabled mode",
			engine:          createMockZeroTrustEngine(),
			mode:            ZeroTrustJITModeDisabled,
			expectedEnabled: false,
		},
		{
			name:            "Disable with nil engine",
			engine:          nil,
			mode:            ZeroTrustJITModeComprehensive,
			expectedEnabled: false,
		},
		{
			name:            "Enable request validation mode",
			engine:          createMockZeroTrustEngine(),
			mode:            ZeroTrustJITModeRequestValidation,
			expectedEnabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jam := NewJITAccessManager(&MockRBACManager{}, &MockNotificationService{})

			jam.EnableZeroTrustPolicies(tt.engine, tt.mode)

			assert.Equal(t, tt.expectedEnabled, jam.zeroTrustEnabled)
			assert.Equal(t, tt.mode, jam.zeroTrustMode)
			assert.Equal(t, tt.engine, jam.zeroTrustEngine)
		})
	}
}

func TestJITAccessManager_SetZeroTrustMode(t *testing.T) {
	jam := NewJITAccessManager(&MockRBACManager{}, &MockNotificationService{})
	engine := createMockZeroTrustEngine()

	// First enable with an engine
	jam.EnableZeroTrustPolicies(engine, ZeroTrustJITModeComprehensive)
	assert.True(t, jam.zeroTrustEnabled)

	// Change mode to disabled
	jam.SetZeroTrustMode(ZeroTrustJITModeDisabled)
	assert.False(t, jam.zeroTrustEnabled)
	assert.Equal(t, ZeroTrustJITModeDisabled, jam.GetZeroTrustMode())

	// Change mode back to enabled
	jam.SetZeroTrustMode(ZeroTrustJITModeApprovalGating)
	assert.True(t, jam.zeroTrustEnabled)
	assert.Equal(t, ZeroTrustJITModeApprovalGating, jam.GetZeroTrustMode())
}

func TestJITAccessManager_RequestAccess_Success(t *testing.T) {
	tests := []struct {
		name        string
		requestSpec *JITAccessRequestSpec
		setupMocks  func(*MockRBACManager, *MockNotificationService)
	}{
		{
			name: "Valid access request with immediate approval",
			requestSpec: &JITAccessRequestSpec{
				RequesterID:     "user1",
				TenantID:        "tenant1",
				Permissions:     []string{"read"},
				Duration:        time.Hour,
				Justification:   "Need access for troubleshooting",
				AutoApprove:     true,
				EmergencyAccess: false,
				Priority:        AccessPriorityMedium,
			},
			setupMocks: func(rbac *MockRBACManager, notif *MockNotificationService) {
				// Current access check - should return false (user doesn't have access)
				rbac.SetCheckPermissionResponse("user1", "read", "tenant1", false, "No access")
				// System approval check - should return true (system can auto-approve)
				rbac.SetCheckPermissionResponse("system", "jit_access.approve", "tenant1", true, "System approved")
			},
		},
		{
			name: "Valid access request with workflow approval",
			requestSpec: &JITAccessRequestSpec{
				RequesterID:   "user2",
				TenantID:      "tenant1",
				Permissions:   []string{"write", "delete"},
				Duration:      2 * time.Hour,
				Justification: "Urgent production fix required",
				AutoApprove:   false,
				Priority:      AccessPriorityHigh,
			},
			setupMocks: func(rbac *MockRBACManager, notif *MockNotificationService) {
				// Current access check - should return false
				rbac.SetCheckPermissionResponse("user2", "write", "tenant1", false, "No access")
				rbac.SetCheckPermissionResponse("user2", "delete", "tenant1", false, "No access")
			},
		},
		{
			name: "Emergency access request",
			requestSpec: &JITAccessRequestSpec{
				RequesterID:     "user3",
				TenantID:        "tenant1",
				Permissions:     []string{"admin"},
				Duration:        30 * time.Minute,
				Justification:   "Critical system failure - emergency access required",
				EmergencyAccess: true,
				Priority:        AccessPriorityEmergency,
			},
			setupMocks: func(rbac *MockRBACManager, notif *MockNotificationService) {
				rbac.SetCheckPermissionResponse("user3", "admin", "tenant1", false, "No access")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbacManager := &MockRBACManager{}
			notificationService := &MockNotificationService{}
			jam := NewJITAccessManager(rbacManager, notificationService)

			if tt.setupMocks != nil {
				tt.setupMocks(rbacManager, notificationService)
			}

			ctx := context.Background()
			request, err := jam.RequestAccess(ctx, tt.requestSpec)

			require.NoError(t, err)
			assert.NotNil(t, request)
			assert.NotEmpty(t, request.ID)
			assert.Equal(t, tt.requestSpec.RequesterID, request.RequesterID)
			assert.Equal(t, tt.requestSpec.TenantID, request.TenantID)
			assert.Equal(t, tt.requestSpec.Permissions, request.Permissions)
			assert.Equal(t, tt.requestSpec.Duration, request.Duration)
			assert.Equal(t, tt.requestSpec.Justification, request.Justification)
			assert.Equal(t, tt.requestSpec.EmergencyAccess, request.EmergencyAccess)
			assert.Equal(t, tt.requestSpec.Priority, request.Priority)
			assert.NotZero(t, request.CreatedAt)
			assert.NotZero(t, request.ExpiresAt)
			assert.NotZero(t, request.RequestTTL)

			// If auto-approve is enabled, should have granted access
			if tt.requestSpec.AutoApprove {
				assert.Equal(t, JITAccessRequestStatusApproved, request.Status)
				assert.NotNil(t, request.GrantedAccess)
			} else {
				assert.Equal(t, JITAccessRequestStatusPending, request.Status)
			}
		})
	}
}

func TestJITAccessManager_RequestAccess_ValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		requestSpec *JITAccessRequestSpec
		expectedErr string
	}{
		{
			name: "Missing requester ID",
			requestSpec: &JITAccessRequestSpec{
				TenantID:      "tenant1",
				Permissions:   []string{"read"},
				Duration:      time.Hour,
				Justification: "Test",
			},
			expectedErr: "requester ID is required",
		},
		{
			name: "Missing tenant ID",
			requestSpec: &JITAccessRequestSpec{
				RequesterID:   "user1",
				Permissions:   []string{"read"},
				Duration:      time.Hour,
				Justification: "Test",
			},
			expectedErr: "tenant ID is required",
		},
		{
			name: "Missing permissions and roles",
			requestSpec: &JITAccessRequestSpec{
				RequesterID:   "user1",
				TenantID:      "tenant1",
				Duration:      time.Hour,
				Justification: "Test",
			},
			expectedErr: "at least one permission or role is required",
		},
		{
			name: "Invalid duration (zero)",
			requestSpec: &JITAccessRequestSpec{
				RequesterID:   "user1",
				TenantID:      "tenant1",
				Permissions:   []string{"read"},
				Duration:      0,
				Justification: "Test",
			},
			expectedErr: "duration must be positive",
		},
		{
			name: "Duration exceeds maximum",
			requestSpec: &JITAccessRequestSpec{
				RequesterID:   "user1",
				TenantID:      "tenant1",
				Permissions:   []string{"read"},
				Duration:      25 * time.Hour,
				Justification: "Test",
			},
			expectedErr: "duration cannot exceed 24 hours",
		},
		{
			name: "Missing justification",
			requestSpec: &JITAccessRequestSpec{
				RequesterID: "user1",
				TenantID:    "tenant1",
				Permissions: []string{"read"},
				Duration:    time.Hour,
			},
			expectedErr: "justification is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jam := NewJITAccessManager(&MockRBACManager{}, &MockNotificationService{})

			ctx := context.Background()
			request, err := jam.RequestAccess(ctx, tt.requestSpec)

			assert.Error(t, err)
			assert.Nil(t, request)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestJITAccessManager_RequestAccess_AlreadyHasAccess(t *testing.T) {
	rbacManager := &MockRBACManager{}
	jam := NewJITAccessManager(rbacManager, &MockNotificationService{})

	// Setup mock to return that user already has access
	rbacManager.SetCheckPermissionResponse("user1", "read", "tenant1", true, "Already has access")

	requestSpec := &JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"read"},
		Duration:      time.Hour,
		Justification: "Test access",
	}

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, requestSpec)

	assert.Error(t, err)
	assert.Nil(t, request)
	assert.Contains(t, err.Error(), "already has the requested permissions")
}

func TestJITAccessManager_ApproveRequest(t *testing.T) {
	rbacManager := &MockRBACManager{}
	jam := NewJITAccessManager(rbacManager, &MockNotificationService{})

	// Create a pending request
	rbacManager.SetCheckPermissionResponse("user1", "admin", "tenant1", false, "No access")
	rbacManager.SetCheckPermissionResponse("approver1", "jit_access.approve", "tenant1", true, "Can approve")
	rbacManager.SetCheckPermissionResponse("system", "jit_access.approve", "tenant1", true, "System can approve")

	requestSpec := &JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"}, // High privilege to prevent auto-approval
		Duration:      2 * time.Hour,     // Longer duration to prevent auto-approval
		Justification: "Need access for testing",
		AutoApprove:   false,
	}

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, requestSpec)
	require.NoError(t, err)
	assert.Equal(t, JITAccessRequestStatusPending, request.Status)

	// Now approve the request
	grant, err := jam.ApproveRequest(ctx, request.ID, "approver1", "Approved for testing")

	require.NoError(t, err)
	assert.NotNil(t, grant)
	assert.Equal(t, request.ID, grant.RequestID)
	assert.Equal(t, "approver1", grant.ApprovedBy)
	assert.Equal(t, "Approved for testing", grant.ApprovalReason)
	assert.Equal(t, JITAccessGrantStatusActive, grant.Status)
	assert.NotZero(t, grant.GrantedAt)
	assert.Equal(t, request.ExpiresAt, grant.ExpiresAt)

	// Check request was updated
	updatedRequest, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, JITAccessRequestStatusApproved, updatedRequest.Status)
	assert.Equal(t, "approver1", updatedRequest.ApprovedBy)
	assert.NotNil(t, updatedRequest.ApprovedAt)
	assert.Equal(t, grant, updatedRequest.GrantedAccess)
}

func TestJITAccessManager_ApproveRequest_Errors(t *testing.T) {
	tests := []struct {
		name          string
		setupRequest  func(*JITAccessManager, context.Context) *JITAccessRequest
		approverID    string
		setupApprover func(*MockRBACManager, string, string)
		expectedErr   string
	}{
		{
			name: "Request not found",
			setupRequest: func(jam *JITAccessManager, ctx context.Context) *JITAccessRequest {
				return nil // Don't create a request
			},
			approverID:  "approver1",
			expectedErr: "not found",
		},
		{
			name: "Request not in pending status",
			setupRequest: func(jam *JITAccessManager, ctx context.Context) *JITAccessRequest {
				// Create and immediately deny a request
				rbacManager := jam.rbacManager.(*MockRBACManager)
				rbacManager.SetCheckPermissionResponse("user1", "read", "tenant1", false, "No access")

				req := &JITAccessRequestSpec{
					RequesterID:   "user1",
					TenantID:      "tenant1",
					Permissions:   []string{"read"},
					Duration:      time.Hour,
					Justification: "Test",
				}

				request, _ := jam.RequestAccess(ctx, req)
				_ = jam.DenyRequest(ctx, request.ID, "reviewer1", "Denied for testing")
				return request
			},
			approverID:  "approver1",
			expectedErr: "not in pending status",
		},
		{
			name: "Approver lacks permission",
			setupRequest: func(jam *JITAccessManager, ctx context.Context) *JITAccessRequest {
				rbacManager := jam.rbacManager.(*MockRBACManager)
				rbacManager.SetCheckPermissionResponse("user1", "read", "tenant1", false, "No access")

				req := &JITAccessRequestSpec{
					RequesterID:   "user1",
					TenantID:      "tenant1",
					Permissions:   []string{"read"},
					Duration:      time.Hour,
					Justification: "Test",
					AutoApprove:   false,
				}

				request, _ := jam.RequestAccess(ctx, req)
				return request
			},
			approverID: "unauthorized_approver",
			setupApprover: func(rbac *MockRBACManager, approverID, tenantID string) {
				rbac.SetCheckPermissionResponse(approverID, "jit_access.approve", tenantID, false, "No permission")
			},
			expectedErr: "does not have permission to approve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbacManager := &MockRBACManager{}
			jam := NewJITAccessManager(rbacManager, &MockNotificationService{})

			ctx := context.Background()
			var requestID string

			if tt.setupRequest != nil {
				if request := tt.setupRequest(jam, ctx); request != nil {
					requestID = request.ID
				} else {
					requestID = "non-existent-request"
				}
			}

			if tt.setupApprover != nil {
				tt.setupApprover(rbacManager, tt.approverID, "tenant1")
			}

			grant, err := jam.ApproveRequest(ctx, requestID, tt.approverID, "Test approval")

			assert.Error(t, err)
			assert.Nil(t, grant)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestJITAccessManager_DenyRequest(t *testing.T) {
	rbacManager := &MockRBACManager{}
	jam := NewJITAccessManager(rbacManager, &MockNotificationService{})

	// Create a pending request
	rbacManager.SetCheckPermissionResponse("user1", "admin", "tenant1", false, "No access")

	requestSpec := &JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"}, // High privilege to prevent auto-approval
		Duration:      2 * time.Hour,     // Longer duration to prevent auto-approval
		Justification: "Need access for testing",
		AutoApprove:   false,
	}

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, requestSpec)
	require.NoError(t, err)
	assert.Equal(t, JITAccessRequestStatusPending, request.Status)

	// Deny the request
	err = jam.DenyRequest(ctx, request.ID, "reviewer1", "Access not justified")

	require.NoError(t, err)

	// Check request was updated
	updatedRequest, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, JITAccessRequestStatusDenied, updatedRequest.Status)
	assert.Equal(t, "reviewer1", updatedRequest.ReviewedBy)
	assert.NotNil(t, updatedRequest.ReviewedAt)
	assert.Equal(t, "Access not justified", updatedRequest.DenialReason)
}

func TestJITAccessManager_ExtendAccess(t *testing.T) {
	rbacManager := &MockRBACManager{}
	jam := NewJITAccessManager(rbacManager, &MockNotificationService{})

	// Create and approve a request
	rbacManager.SetCheckPermissionResponse("user1", "admin", "tenant1", false, "No access")
	rbacManager.SetCheckPermissionResponse("approver1", "jit_access.approve", "tenant1", true, "Can approve")
	rbacManager.SetCheckPermissionResponse("system", "jit_access.approve", "tenant1", true, "System can approve")

	requestSpec := &JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"}, // High privilege to prevent auto-approval
		Duration:      2 * time.Hour,     // Longer duration to prevent auto-approval
		MaxDuration:   4 * time.Hour,
		Justification: "Testing access",
		AutoApprove:   false,
	}

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, requestSpec)
	require.NoError(t, err)

	grant, err := jam.ApproveRequest(ctx, request.ID, "approver1", "Approved")
	require.NoError(t, err)

	originalExpiry := grant.ExpiresAt

	// Extend the access
	extensionDuration := 30 * time.Minute
	err = jam.ExtendAccess(ctx, grant.ID, extensionDuration, "user1", "Need more time")

	require.NoError(t, err)

	// Verify extension
	extendedGrant := jam.activeGrants[grant.ID]
	assert.Equal(t, originalExpiry.Add(extensionDuration), extendedGrant.ExpiresAt)
	assert.Equal(t, 1, extendedGrant.ExtensionsUsed)
	assert.NotNil(t, extendedGrant.LastExtensionAt)
	assert.Equal(t, "user1", extendedGrant.LastExtensionBy)
	assert.Len(t, extendedGrant.ExtensionReasons, 1)
	assert.Equal(t, "Need more time", extendedGrant.ExtensionReasons[0].Reason)
	assert.Equal(t, extensionDuration, extendedGrant.ExtensionReasons[0].Duration)
}

func TestJITAccessManager_ExtendAccess_Errors(t *testing.T) {
	tests := []struct {
		name           string
		setupGrant     func(*JITAccessManager, context.Context) *JITAccessGrant
		extensionDur   time.Duration
		requesterID    string
		setupRequester func(*MockRBACManager, string, string)
		expectedErr    string
	}{
		{
			name: "Grant not found",
			setupGrant: func(jam *JITAccessManager, ctx context.Context) *JITAccessGrant {
				return nil // Don't create a grant
			},
			extensionDur: 30 * time.Minute,
			requesterID:  "user1",
			expectedErr:  "not found",
		},
		{
			name: "Maximum extensions reached",
			setupGrant: func(jam *JITAccessManager, ctx context.Context) *JITAccessGrant {
				// Create a grant and max out extensions
				rbacManager := jam.rbacManager.(*MockRBACManager)
				rbacManager.SetCheckPermissionResponse("user1", "read", "tenant1", false, "No access")
				rbacManager.SetCheckPermissionResponse("approver1", "jit_access.approve", "tenant1", true, "Can approve")

				req := &JITAccessRequestSpec{
					RequesterID:   "user1",
					TenantID:      "tenant1",
					Permissions:   []string{"read"},
					Duration:      time.Hour,
					Justification: "Test",
				}

				request, _ := jam.RequestAccess(ctx, req)
				grant, _ := jam.ApproveRequest(ctx, request.ID, "approver1", "Approved")
				grant.ExtensionsUsed = grant.MaxExtensions // Max out extensions
				return grant
			},
			extensionDur: 30 * time.Minute,
			requesterID:  "user1",
			expectedErr:  "maximum extensions",
		},
		{
			name: "Would exceed maximum duration",
			setupGrant: func(jam *JITAccessManager, ctx context.Context) *JITAccessGrant {
				rbacManager := jam.rbacManager.(*MockRBACManager)
				rbacManager.SetCheckPermissionResponse("user1", "read", "tenant1", false, "No access")
				rbacManager.SetCheckPermissionResponse("approver1", "jit_access.approve", "tenant1", true, "Can approve")

				req := &JITAccessRequestSpec{
					RequesterID:   "user1",
					TenantID:      "tenant1",
					Permissions:   []string{"read"},
					Duration:      time.Hour,
					MaxDuration:   2 * time.Hour, // Short max duration
					Justification: "Test",
				}

				request, _ := jam.RequestAccess(ctx, req)
				grant, _ := jam.ApproveRequest(ctx, request.ID, "approver1", "Approved")
				return grant
			},
			extensionDur: 2 * time.Hour, // Would exceed max duration
			requesterID:  "user1",
			expectedErr:  "exceed maximum duration",
		},
		{
			name: "Unauthorized extender",
			setupGrant: func(jam *JITAccessManager, ctx context.Context) *JITAccessGrant {
				rbacManager := jam.rbacManager.(*MockRBACManager)
				rbacManager.SetCheckPermissionResponse("user1", "read", "tenant1", false, "No access")
				rbacManager.SetCheckPermissionResponse("approver1", "jit_access.approve", "tenant1", true, "Can approve")

				req := &JITAccessRequestSpec{
					RequesterID:   "user1",
					TenantID:      "tenant1",
					Permissions:   []string{"read"},
					Duration:      time.Hour,
					Justification: "Test",
				}

				request, _ := jam.RequestAccess(ctx, req)
				grant, _ := jam.ApproveRequest(ctx, request.ID, "approver1", "Approved")
				return grant
			},
			extensionDur: 30 * time.Minute,
			requesterID:  "other_user",
			setupRequester: func(rbac *MockRBACManager, requesterID, tenantID string) {
				rbac.SetCheckPermissionResponse(requesterID, "jit_access.extend", tenantID, false, "No permission")
			},
			expectedErr: "not authorized to extend",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbacManager := &MockRBACManager{}
			jam := NewJITAccessManager(rbacManager, &MockNotificationService{})

			ctx := context.Background()
			var grantID string

			if tt.setupGrant != nil {
				if grant := tt.setupGrant(jam, ctx); grant != nil {
					grantID = grant.ID
				} else {
					grantID = "non-existent-grant"
				}
			}

			if tt.setupRequester != nil {
				tt.setupRequester(rbacManager, tt.requesterID, "tenant1")
			}

			err := jam.ExtendAccess(ctx, grantID, tt.extensionDur, tt.requesterID, "Test extension")

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestJITAccessManager_RevokeAccess(t *testing.T) {
	rbacManager := &MockRBACManager{}
	jam := NewJITAccessManager(rbacManager, &MockNotificationService{})

	// Create and approve a request
	rbacManager.SetCheckPermissionResponse("user1", "admin", "tenant1", false, "No access")
	rbacManager.SetCheckPermissionResponse("approver1", "jit_access.approve", "tenant1", true, "Can approve")
	rbacManager.SetCheckPermissionResponse("revoker1", "jit_access.revoke", "tenant1", true, "Can revoke")

	requestSpec := &JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"}, // High privilege to prevent auto-approval
		Duration:      2 * time.Hour,     // Longer duration to prevent auto-approval
		Justification: "Testing access",
		AutoApprove:   false,
	}

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, requestSpec)
	require.NoError(t, err)

	grant, err := jam.ApproveRequest(ctx, request.ID, "approver1", "Approved")
	require.NoError(t, err)
	assert.Equal(t, JITAccessGrantStatusActive, grant.Status)

	// Revoke the access
	err = jam.RevokeAccess(ctx, grant.ID, "revoker1", "Security concern")

	require.NoError(t, err)

	// Verify revocation
	revokedGrant := jam.activeGrants[grant.ID]
	assert.Equal(t, JITAccessGrantStatusRevoked, revokedGrant.Status)
	assert.NotNil(t, revokedGrant.RevokedAt)
	assert.Equal(t, "revoker1", revokedGrant.RevokedBy)
	assert.Equal(t, "Security concern", revokedGrant.RevocationReason)
}

func TestJITAccessManager_GetActiveGrants(t *testing.T) {
	rbacManager := &MockRBACManager{}
	jam := NewJITAccessManager(rbacManager, &MockNotificationService{})

	// Create multiple grants for different users
	setupGrant := func(requesterID, permission string) *JITAccessGrant {
		rbacManager.SetCheckPermissionResponse(requesterID, permission, "tenant1", false, "No access")
		rbacManager.SetCheckPermissionResponse("system", "jit_access.approve", "tenant1", true, "System can approve")

		req := &JITAccessRequestSpec{
			RequesterID:   requesterID,
			TenantID:      "tenant1",
			Permissions:   []string{permission},
			Duration:      time.Hour,
			Justification: "Testing",
			AutoApprove:   true,
		}

		request, _ := jam.RequestAccess(context.Background(), req)
		return request.GrantedAccess
	}

	grant1 := setupGrant("user1", "read")
	grant2 := setupGrant("user1", "write")
	grant3 := setupGrant("user2", "admin")

	ctx := context.Background()

	// Get grants for user1
	grants, err := jam.GetActiveGrants(ctx, "user1", "tenant1")
	require.NoError(t, err)
	assert.Len(t, grants, 2)

	// Verify correct grants returned
	grantIDs := []string{grants[0].ID, grants[1].ID}
	assert.Contains(t, grantIDs, grant1.ID)
	assert.Contains(t, grantIDs, grant2.ID)
	assert.NotContains(t, grantIDs, grant3.ID)

	// Get grants for user2
	grants2, err := jam.GetActiveGrants(ctx, "user2", "tenant1")
	require.NoError(t, err)
	assert.Len(t, grants2, 1)
	assert.Equal(t, grant3.ID, grants2[0].ID)
}

// Note: Zero-trust integration tests would require more complex setup
// For now, we test the zero-trust mode configuration separately
func TestJITAccessManager_ZeroTrustModeConfiguration(t *testing.T) {
	jam := NewJITAccessManager(&MockRBACManager{}, &MockNotificationService{})

	// Test that zero-trust evaluation checks work correctly
	assert.False(t, jam.shouldEvaluateZeroTrustForRequest())
	assert.False(t, jam.shouldEvaluateZeroTrustForApproval())
	assert.False(t, jam.shouldEvaluateZeroTrustForGrant())

	// Enable zero-trust with comprehensive mode
	engine := createMockZeroTrustEngine()
	jam.EnableZeroTrustPolicies(engine, ZeroTrustJITModeComprehensive)

	assert.True(t, jam.shouldEvaluateZeroTrustForRequest())
	assert.True(t, jam.shouldEvaluateZeroTrustForApproval())
	assert.True(t, jam.shouldEvaluateZeroTrustForGrant())

	// Test specific modes
	jam.SetZeroTrustMode(ZeroTrustJITModeRequestValidation)
	assert.True(t, jam.shouldEvaluateZeroTrustForRequest())
	assert.False(t, jam.shouldEvaluateZeroTrustForApproval())
	assert.False(t, jam.shouldEvaluateZeroTrustForGrant())

	jam.SetZeroTrustMode(ZeroTrustJITModeApprovalGating)
	assert.False(t, jam.shouldEvaluateZeroTrustForRequest())
	assert.True(t, jam.shouldEvaluateZeroTrustForApproval())
	assert.False(t, jam.shouldEvaluateZeroTrustForGrant())

	jam.SetZeroTrustMode(ZeroTrustJITModeGrantValidation)
	assert.False(t, jam.shouldEvaluateZeroTrustForRequest())
	assert.False(t, jam.shouldEvaluateZeroTrustForApproval())
	assert.True(t, jam.shouldEvaluateZeroTrustForGrant())
}

func TestJITAccessManager_ConcurrentAccess(t *testing.T) {
	rbacManager := &MockRBACManager{}
	jam := NewJITAccessManager(rbacManager, &MockNotificationService{})

	// Setup common RBAC responses
	rbacManager.SetCheckPermissionResponse("user1", "read", "tenant1", false, "No access")
	rbacManager.SetCheckPermissionResponse("system", "jit_access.approve", "tenant1", true, "System can approve")

	const numConcurrentRequests = 10
	results := make(chan *JITAccessRequest, numConcurrentRequests)
	errors := make(chan error, numConcurrentRequests)

	// Create multiple concurrent requests
	for i := 0; i < numConcurrentRequests; i++ {
		go func(requestNum int) {
			requestSpec := &JITAccessRequestSpec{
				RequesterID:   "user1",
				TenantID:      "tenant1",
				Permissions:   []string{"read"},
				Duration:      time.Hour,
				Justification: "Concurrent testing",
				AutoApprove:   true, // Auto-approve to test activation
			}

			ctx := context.Background()
			request, err := jam.RequestAccess(ctx, requestSpec)

			if err != nil {
				errors <- err
			} else {
				results <- request
			}
		}(i)
	}

	// Collect results
	successCount := 0
	errorCount := 0

	for i := 0; i < numConcurrentRequests; i++ {
		select {
		case request := <-results:
			assert.NotNil(t, request)
			assert.NotEmpty(t, request.ID)
			successCount++
		case err := <-errors:
			t.Errorf("Unexpected error in concurrent test: %v", err)
			errorCount++
		case <-time.After(5 * time.Second):
			t.Fatal("Test timed out waiting for concurrent requests")
		}
	}

	assert.Equal(t, numConcurrentRequests, successCount)
	assert.Equal(t, 0, errorCount)

	// Verify all requests are stored
	assert.Len(t, jam.requests, numConcurrentRequests)
	assert.Len(t, jam.activeGrants, numConcurrentRequests)
}

// Mock implementations

type MockRBACManager struct {
	rbac.RBACManager
	responses map[string]*common.AccessResponse
}

func (m *MockRBACManager) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	key := m.makeKey(request.SubjectId, request.PermissionId, request.TenantId)
	if response, exists := m.responses[key]; exists {
		return response, nil
	}
	return &common.AccessResponse{Granted: false, Reason: "Default deny"}, nil
}

func (m *MockRBACManager) SetCheckPermissionResponse(subjectID, permissionID, tenantID string, granted bool, reason string) {
	if m.responses == nil {
		m.responses = make(map[string]*common.AccessResponse)
	}
	key := m.makeKey(subjectID, permissionID, tenantID)
	m.responses[key] = &common.AccessResponse{
		Granted: granted,
		Reason:  reason,
	}
}

func (m *MockRBACManager) makeKey(subjectID, permissionID, tenantID string) string {
	return subjectID + "|" + permissionID + "|" + tenantID
}

type MockNotificationService struct{}

func (m *MockNotificationService) SendRequestNotification(ctx context.Context, request *JITAccessRequest, eventType string) error {
	return nil
}

func (m *MockNotificationService) SendApprovalNotification(ctx context.Context, request *JITAccessRequest, approvers []string) error {
	return nil
}

func (m *MockNotificationService) SendReminderNotification(ctx context.Context, request *JITAccessRequest, recipient string) error {
	return nil
}

func (m *MockNotificationService) SendGrantNotification(ctx context.Context, grant *JITAccessGrant, eventType string) error {
	return nil
}

func (m *MockNotificationService) SendExpirationWarning(ctx context.Context, grant *JITAccessGrant, timeUntilExpiry time.Duration) error {
	return nil
}

func (m *MockNotificationService) SendRevocationNotification(ctx context.Context, grant *JITAccessGrant, reason string) error {
	return nil
}

func (m *MockNotificationService) SendEscalationNotification(ctx context.Context, request *JITAccessRequest, escalationLevel int) error {
	return nil
}

// Helper function to create a mock zero-trust engine
func createMockZeroTrustEngine() *zerotrust.ZeroTrustPolicyEngine {
	config := &zerotrust.ZeroTrustConfig{
		MaxEvaluationTime: 5 * time.Second,
		FailSecure:        true,
		MetricsInterval:   1 * time.Second,
	}
	return zerotrust.NewZeroTrustPolicyEngine(config)
}
