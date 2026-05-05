// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package jit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/jit"
	"github.com/cfgis/cfgms/features/rbac/zerotrust"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func TestNewJITAccessManager(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	notificationService := jit.NewSimpleNotificationService()

	jam := jit.NewJITAccessManager(rbacManager, notificationService)

	assert.NotNil(t, jam)
	assert.Equal(t, jit.ZeroTrustJITModeDisabled, jam.GetZeroTrustMode())

	// Smoke test: constructor wires all dependencies — RequestAccess processes the request.
	// Use admin (high-privilege) to prevent time-sensitive auto-approval from triggering.
	ctx := context.Background()
	smokeReq, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "smoke-user",
		TenantID:      "smoke-tenant",
		Permissions:   []string{"admin"},
		Duration:      time.Hour,
		Justification: "constructor smoke test",
	})
	require.NoError(t, err)
	assert.NotNil(t, smokeReq)
}

func TestJITAccessManager_EnableZeroTrustPolicies(t *testing.T) {
	tests := []struct {
		name     string
		engine   *zerotrust.ZeroTrustPolicyEngine
		mode     jit.ZeroTrustJITMode
		wantMode jit.ZeroTrustJITMode
	}{
		{
			name:     "Enable with valid engine and mode",
			engine:   createMockZeroTrustEngine(),
			mode:     jit.ZeroTrustJITModeComprehensive,
			wantMode: jit.ZeroTrustJITModeComprehensive,
		},
		{
			name:     "Disable with disabled mode",
			engine:   createMockZeroTrustEngine(),
			mode:     jit.ZeroTrustJITModeDisabled,
			wantMode: jit.ZeroTrustJITModeDisabled,
		},
		{
			name:     "Nil engine stores mode but keeps disabled effective state",
			engine:   nil,
			mode:     jit.ZeroTrustJITModeComprehensive,
			wantMode: jit.ZeroTrustJITModeComprehensive,
		},
		{
			name:     "Enable request validation mode",
			engine:   createMockZeroTrustEngine(),
			mode:     jit.ZeroTrustJITModeRequestValidation,
			wantMode: jit.ZeroTrustJITModeRequestValidation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jam := jit.NewJITAccessManager(newTestRBACManager(t), jit.NewSimpleNotificationService())

			jam.EnableZeroTrustPolicies(tt.engine, tt.mode)

			assert.Equal(t, tt.wantMode, jam.GetZeroTrustMode())
		})
	}
}

func TestJITAccessManager_SetZeroTrustMode(t *testing.T) {
	jam := jit.NewJITAccessManager(newTestRBACManager(t), jit.NewSimpleNotificationService())
	engine := createMockZeroTrustEngine()

	// First enable with an engine
	jam.EnableZeroTrustPolicies(engine, jit.ZeroTrustJITModeComprehensive)
	assert.NotEqual(t, jit.ZeroTrustJITModeDisabled, jam.GetZeroTrustMode())

	// Change mode to disabled
	jam.SetZeroTrustMode(jit.ZeroTrustJITModeDisabled)
	assert.Equal(t, jit.ZeroTrustJITModeDisabled, jam.GetZeroTrustMode())

	// Change mode back to enabled
	jam.SetZeroTrustMode(jit.ZeroTrustJITModeApprovalGating)
	assert.NotEqual(t, jit.ZeroTrustJITModeDisabled, jam.GetZeroTrustMode())
	assert.Equal(t, jit.ZeroTrustJITModeApprovalGating, jam.GetZeroTrustMode())
}

func TestJITAccessManager_RequestAccess_Success(t *testing.T) {
	tests := []struct {
		name        string
		requestSpec *jit.JITAccessRequestSpec
		setupPerms  func(*testing.T, *rbac.Manager)
	}{
		{
			name: "Valid access request with immediate approval",
			requestSpec: &jit.JITAccessRequestSpec{
				RequesterID:     "user1",
				TenantID:        "tenant1",
				Permissions:     []string{"read"},
				Duration:        time.Hour,
				Justification:   "Need access for troubleshooting",
				AutoApprove:     true,
				EmergencyAccess: false,
				Priority:        jit.AccessPriorityMedium,
			},
			setupPerms: func(t *testing.T, rbacMgr *rbac.Manager) {
				grantPermission(t, rbacMgr, "system", "jit_access.approve", "tenant1")
			},
		},
		{
			name: "Valid access request with workflow approval",
			requestSpec: &jit.JITAccessRequestSpec{
				RequesterID:   "user2",
				TenantID:      "tenant1",
				Permissions:   []string{"write", "delete"},
				Duration:      2 * time.Hour,
				Justification: "Urgent production fix required",
				AutoApprove:   false,
				Priority:      jit.AccessPriorityHigh,
			},
			setupPerms: nil,
		},
		{
			name: "Emergency access request",
			requestSpec: &jit.JITAccessRequestSpec{
				RequesterID:     "user3",
				TenantID:        "tenant1",
				Permissions:     []string{"admin"},
				Duration:        30 * time.Minute,
				Justification:   "Critical system failure - emergency access required",
				EmergencyAccess: true,
				Priority:        jit.AccessPriorityEmergency,
			},
			setupPerms: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbacManager := newTestRBACManager(t)
			jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

			if tt.setupPerms != nil {
				tt.setupPerms(t, rbacManager)
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
				assert.Equal(t, jit.JITAccessRequestStatusApproved, request.Status)
				assert.NotNil(t, request.GrantedAccess)
			} else {
				assert.Equal(t, jit.JITAccessRequestStatusPending, request.Status)
			}
		})
	}
}

func TestJITAccessManager_RequestAccess_ValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		requestSpec *jit.JITAccessRequestSpec
		expectedErr string
	}{
		{
			name: "Missing requester ID",
			requestSpec: &jit.JITAccessRequestSpec{
				TenantID:      "tenant1",
				Permissions:   []string{"read"},
				Duration:      time.Hour,
				Justification: "Test",
			},
			expectedErr: "requester ID is required",
		},
		{
			name: "Missing tenant ID",
			requestSpec: &jit.JITAccessRequestSpec{
				RequesterID:   "user1",
				Permissions:   []string{"read"},
				Duration:      time.Hour,
				Justification: "Test",
			},
			expectedErr: "tenant ID is required",
		},
		{
			name: "Missing permissions and roles",
			requestSpec: &jit.JITAccessRequestSpec{
				RequesterID:   "user1",
				TenantID:      "tenant1",
				Duration:      time.Hour,
				Justification: "Test",
			},
			expectedErr: "at least one permission or role is required",
		},
		{
			name: "Invalid duration (zero)",
			requestSpec: &jit.JITAccessRequestSpec{
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
			requestSpec: &jit.JITAccessRequestSpec{
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
			requestSpec: &jit.JITAccessRequestSpec{
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
			jam := jit.NewJITAccessManager(newTestRBACManager(t), jit.NewSimpleNotificationService())

			ctx := context.Background()
			request, err := jam.RequestAccess(ctx, tt.requestSpec)

			assert.Error(t, err)
			assert.Nil(t, request)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestJITAccessManager_RequestAccess_AlreadyHasAccess(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	// User already has the requested permission
	grantPermission(t, rbacManager, "user1", "read", "tenant1")

	requestSpec := &jit.JITAccessRequestSpec{
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
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	// Grant approval permissions to approver and system
	grantPermission(t, rbacManager, "approver1", "jit_access.approve", "tenant1")
	grantPermission(t, rbacManager, "system", "jit_access.approve", "tenant1")

	requestSpec := &jit.JITAccessRequestSpec{
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
	assert.Equal(t, jit.JITAccessRequestStatusPending, request.Status)

	// Now approve the request
	grant, err := jam.ApproveRequest(ctx, request.ID, "approver1", "Approved for testing")

	require.NoError(t, err)
	assert.NotNil(t, grant)
	assert.Equal(t, request.ID, grant.RequestID)
	assert.Equal(t, "approver1", grant.ApprovedBy)
	assert.Equal(t, "Approved for testing", grant.ApprovalReason)
	assert.Equal(t, jit.JITAccessGrantStatusActive, grant.Status)
	assert.NotZero(t, grant.GrantedAt)
	assert.Equal(t, request.ExpiresAt, grant.ExpiresAt)

	// Check request was updated
	updatedRequest, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, jit.JITAccessRequestStatusApproved, updatedRequest.Status)
	assert.Equal(t, "approver1", updatedRequest.ApprovedBy)
	assert.NotNil(t, updatedRequest.ApprovedAt)
	assert.Equal(t, grant, updatedRequest.GrantedAccess)
}

func TestJITAccessManager_ApproveRequest_Errors(t *testing.T) {
	tests := []struct {
		name          string
		setupRequest  func(*testing.T, *jit.JITAccessManager, *rbac.Manager, context.Context) *jit.JITAccessRequest
		approverID    string
		setupApprover func(*testing.T, *rbac.Manager, string, string)
		expectedErr   string
	}{
		{
			name: "Request not found",
			setupRequest: func(t *testing.T, jam *jit.JITAccessManager, rbacMgr *rbac.Manager, ctx context.Context) *jit.JITAccessRequest {
				return nil // Don't create a request
			},
			approverID:  "approver1",
			expectedErr: "not found",
		},
		{
			name: "Request not in pending status",
			setupRequest: func(t *testing.T, jam *jit.JITAccessManager, rbacMgr *rbac.Manager, ctx context.Context) *jit.JITAccessRequest {
				// Use admin (high-privilege) to prevent time-sensitive auto-approval.
				req := &jit.JITAccessRequestSpec{
					RequesterID:   "user1",
					TenantID:      "tenant1",
					Permissions:   []string{"admin"},
					Duration:      time.Hour,
					Justification: "Test",
				}

				request, err := jam.RequestAccess(ctx, req)
				require.NoError(t, err)
				require.NoError(t, jam.DenyRequest(ctx, request.ID, "reviewer1", "Denied for testing"))
				return request
			},
			approverID:  "approver1",
			expectedErr: "not in pending status",
		},
		{
			name: "Approver lacks permission",
			setupRequest: func(t *testing.T, jam *jit.JITAccessManager, rbacMgr *rbac.Manager, ctx context.Context) *jit.JITAccessRequest {
				// Use admin (high-privilege) to prevent time-sensitive auto-approval.
				req := &jit.JITAccessRequestSpec{
					RequesterID:   "user1",
					TenantID:      "tenant1",
					Permissions:   []string{"admin"},
					Duration:      time.Hour,
					Justification: "Test",
				}

				request, err := jam.RequestAccess(ctx, req)
				require.NoError(t, err)
				return request
			},
			approverID:    "unauthorized_approver",
			setupApprover: nil,
			expectedErr:   "does not have permission to approve",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbacManager := newTestRBACManager(t)
			jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

			ctx := context.Background()
			var requestID string

			if tt.setupRequest != nil {
				if request := tt.setupRequest(t, jam, rbacManager, ctx); request != nil {
					requestID = request.ID
				} else {
					requestID = "non-existent-request"
				}
			}

			if tt.setupApprover != nil {
				tt.setupApprover(t, rbacManager, tt.approverID, "tenant1")
			}

			grant, err := jam.ApproveRequest(ctx, requestID, tt.approverID, "Test approval")

			assert.Error(t, err)
			assert.Nil(t, grant)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func TestJITAccessManager_DenyRequest(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	// Create a pending request (default deny - user1 has no admin access)
	requestSpec := &jit.JITAccessRequestSpec{
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
	assert.Equal(t, jit.JITAccessRequestStatusPending, request.Status)

	// Deny the request
	err = jam.DenyRequest(ctx, request.ID, "reviewer1", "Access not justified")

	require.NoError(t, err)

	// Check request was updated
	updatedRequest, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, jit.JITAccessRequestStatusDenied, updatedRequest.Status)
	assert.Equal(t, "reviewer1", updatedRequest.ReviewedBy)
	assert.NotNil(t, updatedRequest.ReviewedAt)
	assert.Equal(t, "Access not justified", updatedRequest.DenialReason)
}

func TestJITAccessManager_ExtendAccess(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	// Grant approval permissions to approver and system
	grantPermission(t, rbacManager, "approver1", "jit_access.approve", "tenant1")
	grantPermission(t, rbacManager, "system", "jit_access.approve", "tenant1")

	requestSpec := &jit.JITAccessRequestSpec{
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

	// Verify extension via public GetActiveGrants
	grants, err := jam.GetActiveGrants(ctx, "user1", "tenant1")
	require.NoError(t, err)

	var extendedGrant *jit.JITAccessGrant
	for _, g := range grants {
		if g.ID == grant.ID {
			extendedGrant = g
			break
		}
	}
	require.NotNil(t, extendedGrant, "extended grant should still be active")

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
		setupGrant     func(*testing.T, *jit.JITAccessManager, *rbac.Manager, context.Context) *jit.JITAccessGrant
		extensionDur   time.Duration
		requesterID    string
		setupRequester func(*testing.T, *rbac.Manager, string, string)
		expectedErr    string
	}{
		{
			name: "Grant not found",
			setupGrant: func(t *testing.T, jam *jit.JITAccessManager, rbacMgr *rbac.Manager, ctx context.Context) *jit.JITAccessGrant {
				return nil // Don't create a grant
			},
			extensionDur: 30 * time.Minute,
			requesterID:  "user1",
			expectedErr:  "not found",
		},
		{
			name: "Maximum extensions reached",
			setupGrant: func(t *testing.T, jam *jit.JITAccessManager, rbacMgr *rbac.Manager, ctx context.Context) *jit.JITAccessGrant {
				// Create a grant and max out extensions via the public API.
				// Use admin (high-privilege) to prevent time-sensitive auto-approval before
				// approver1 can manually approve.
				grantPermission(t, rbacMgr, "approver1", "jit_access.approve", "tenant1")

				req := &jit.JITAccessRequestSpec{
					RequesterID:   "user1",
					TenantID:      "tenant1",
					Permissions:   []string{"admin"},
					Duration:      time.Hour,
					Justification: "Test",
				}

				request, err := jam.RequestAccess(ctx, req)
				require.NoError(t, err)
				grant, err := jam.ApproveRequest(ctx, request.ID, "approver1", "Approved")
				require.NoError(t, err)
				// Max out extensions through the public API (MaxExtensions = 3)
				for i := 0; i < 3; i++ {
					err = jam.ExtendAccess(ctx, grant.ID, 30*time.Minute, "user1", "extending")
					require.NoError(t, err, "pre-extend iteration %d should succeed", i+1)
				}
				return grant
			},
			extensionDur: 30 * time.Minute,
			requesterID:  "user1",
			expectedErr:  "maximum extensions",
		},
		{
			name: "Would exceed maximum duration",
			setupGrant: func(t *testing.T, jam *jit.JITAccessManager, rbacMgr *rbac.Manager, ctx context.Context) *jit.JITAccessGrant {
				// Use admin (high-privilege) to prevent time-sensitive auto-approval.
				grantPermission(t, rbacMgr, "approver1", "jit_access.approve", "tenant1")

				req := &jit.JITAccessRequestSpec{
					RequesterID:   "user1",
					TenantID:      "tenant1",
					Permissions:   []string{"admin"},
					Duration:      time.Hour,
					MaxDuration:   2 * time.Hour, // Short max duration
					Justification: "Test",
				}

				request, err := jam.RequestAccess(ctx, req)
				require.NoError(t, err)
				grant, err := jam.ApproveRequest(ctx, request.ID, "approver1", "Approved")
				require.NoError(t, err)
				return grant
			},
			extensionDur: 3 * time.Hour, // Would exceed max duration (total would be ~3 hours, max is 2)
			requesterID:  "user1",
			expectedErr:  "exceed maximum duration",
		},
		{
			name: "Unauthorized extender",
			setupGrant: func(t *testing.T, jam *jit.JITAccessManager, rbacMgr *rbac.Manager, ctx context.Context) *jit.JITAccessGrant {
				// Use admin (high-privilege) to prevent time-sensitive auto-approval.
				grantPermission(t, rbacMgr, "approver1", "jit_access.approve", "tenant1")

				req := &jit.JITAccessRequestSpec{
					RequesterID:   "user1",
					TenantID:      "tenant1",
					Permissions:   []string{"admin"},
					Duration:      time.Hour,
					Justification: "Test",
				}

				request, err := jam.RequestAccess(ctx, req)
				require.NoError(t, err)
				grant, err := jam.ApproveRequest(ctx, request.ID, "approver1", "Approved")
				require.NoError(t, err)
				return grant
			},
			extensionDur:   30 * time.Minute,
			requesterID:    "other_user",
			setupRequester: nil,
			expectedErr:    "not authorized to extend",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbacManager := newTestRBACManager(t)
			jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

			ctx := context.Background()
			var grantID string

			if tt.setupGrant != nil {
				if grant := tt.setupGrant(t, jam, rbacManager, ctx); grant != nil {
					grantID = grant.ID
				} else {
					grantID = "non-existent-grant"
				}
			}

			if tt.setupRequester != nil {
				tt.setupRequester(t, rbacManager, tt.requesterID, "tenant1")
			}

			err := jam.ExtendAccess(ctx, grantID, tt.extensionDur, tt.requesterID, "Test extension")

			assert.Error(t, err)
			if err != nil {
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}

func TestJITAccessManager_RevokeAccess(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	// Grant approval and revocation permissions
	grantPermission(t, rbacManager, "approver1", "jit_access.approve", "tenant1")
	grantPermission(t, rbacManager, "revoker1", "jit_access.revoke", "tenant1")

	requestSpec := &jit.JITAccessRequestSpec{
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
	assert.Equal(t, jit.JITAccessGrantStatusActive, grant.Status)

	// Revoke the access
	err = jam.RevokeAccess(ctx, grant.ID, "revoker1", "Security concern")

	require.NoError(t, err)

	// Verify revocation: revoked grant should no longer appear in active grants
	activeGrants, err := jam.GetActiveGrants(ctx, "user1", "tenant1")
	require.NoError(t, err)
	for _, g := range activeGrants {
		assert.NotEqual(t, grant.ID, g.ID, "revoked grant should not appear in active grants")
	}
}

func TestJITAccessManager_GetActiveGrants(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	// Grant system approval permission once for auto-approve
	grantPermission(t, rbacManager, "system", "jit_access.approve", "tenant1")

	// Create multiple grants for different users
	setupGrant := func(requesterID, permission string) *jit.JITAccessGrant {
		req := &jit.JITAccessRequestSpec{
			RequesterID:   requesterID,
			TenantID:      "tenant1",
			Permissions:   []string{permission},
			Duration:      time.Hour,
			Justification: "Testing",
			AutoApprove:   true,
		}

		request, err := jam.RequestAccess(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, request.GrantedAccess, "auto-approve should have granted access")
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

func TestJITAccessManager_ZeroTrustModeConfiguration(t *testing.T) {
	jam := jit.NewJITAccessManager(newTestRBACManager(t), jit.NewSimpleNotificationService())

	// Initial state: disabled
	assert.Equal(t, jit.ZeroTrustJITModeDisabled, jam.GetZeroTrustMode())

	// Enable zero-trust with comprehensive mode
	engine := createMockZeroTrustEngine()
	jam.EnableZeroTrustPolicies(engine, jit.ZeroTrustJITModeComprehensive)
	assert.Equal(t, jit.ZeroTrustJITModeComprehensive, jam.GetZeroTrustMode())

	// Test specific modes via SetZeroTrustMode
	jam.SetZeroTrustMode(jit.ZeroTrustJITModeRequestValidation)
	assert.Equal(t, jit.ZeroTrustJITModeRequestValidation, jam.GetZeroTrustMode())

	jam.SetZeroTrustMode(jit.ZeroTrustJITModeApprovalGating)
	assert.Equal(t, jit.ZeroTrustJITModeApprovalGating, jam.GetZeroTrustMode())

	jam.SetZeroTrustMode(jit.ZeroTrustJITModeGrantValidation)
	assert.Equal(t, jit.ZeroTrustJITModeGrantValidation, jam.GetZeroTrustMode())

	// Disable
	jam.SetZeroTrustMode(jit.ZeroTrustJITModeDisabled)
	assert.Equal(t, jit.ZeroTrustJITModeDisabled, jam.GetZeroTrustMode())
}

func TestJITAccessManager_ConcurrentAccess(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	// Grant system approval permission for auto-approve
	grantPermission(t, rbacManager, "system", "jit_access.approve", "tenant1")

	const numConcurrentRequests = 10
	results := make(chan *jit.JITAccessRequest, numConcurrentRequests)
	errors := make(chan error, numConcurrentRequests)

	// Create multiple concurrent requests
	for i := 0; i < numConcurrentRequests; i++ {
		go func(requestNum int) {
			requestSpec := &jit.JITAccessRequestSpec{
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

	ctx := context.Background()

	// Verify all requests produced active grants
	activeGrants, err := jam.GetActiveGrants(ctx, "user1", "tenant1")
	require.NoError(t, err)
	assert.Len(t, activeGrants, numConcurrentRequests)

	// Verify all requests are stored (via ListRequests)
	requests, err := jam.ListRequests(ctx, &jit.JITAccessRequestFilter{RequesterID: "user1"})
	require.NoError(t, err)
	assert.Len(t, requests, numConcurrentRequests)
}

func TestJITAuditManager_RecordsEvents(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "jit-test")
	require.NoError(t, err)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, auditMgr.Stop(ctx))
		assert.NoError(t, storageManager.Close())
	})

	rbacManager := newTestRBACManager(t)
	grantPermission(t, rbacManager, "approver1", "jit_access.approve", "tenant1")

	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())
	jam.SetAuditManager(auditMgr)

	ctx := context.Background()

	request, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"},
		Duration:      2 * time.Hour,
		Justification: "Need access for testing",
		AutoApprove:   false,
	})
	require.NoError(t, err)
	require.NotNil(t, request)

	_, err = jam.ApproveRequest(ctx, request.ID, "approver1", "Approved for testing")
	require.NoError(t, err)

	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	require.NoError(t, auditMgr.Flush(flushCtx))

	entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "tenant1",
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(entries), 2, "expected at least 2 audit events (created + approve)")

	byAction := make(map[string]*business.AuditEntry)
	for _, e := range entries {
		byAction[e.Action] = e
	}

	createdEntry, ok := byAction["created"]
	require.True(t, ok, "expected 'created' action event")
	assert.Equal(t, "tenant1", createdEntry.TenantID)
	assert.Equal(t, "user1", createdEntry.UserID)
	assert.Equal(t, "jit_access", createdEntry.ResourceType)

	approveEntry, ok := byAction["approve"]
	require.True(t, ok, "expected 'approve' action event")
	assert.Equal(t, "tenant1", approveEntry.TenantID)
	assert.Equal(t, "user1", approveEntry.UserID)
	assert.Equal(t, "jit_access", approveEntry.ResourceType)
}

func TestJITAuditManager_NilSafe(t *testing.T) {
	rbacManager := newTestRBACManager(t)

	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())
	// Intentionally do NOT call SetAuditManager

	ctx := context.Background()

	request, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"},
		Duration:      time.Hour,
		Justification: "Testing nil safety",
		AutoApprove:   false,
	})
	require.NoError(t, err)
	assert.NotNil(t, request)
}

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

// Helper function to create a mock zero-trust engine
func createMockZeroTrustEngine() *zerotrust.ZeroTrustPolicyEngine {
	config := &zerotrust.ZeroTrustConfig{
		MaxEvaluationTime: 5 * time.Second,
		FailSecure:        true,
		MetricsInterval:   1 * time.Second,
	}
	return zerotrust.NewZeroTrustPolicyEngine(config)
}
