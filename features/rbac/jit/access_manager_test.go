// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package jit_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/jit"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func TestNewJITAccessManager(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	notificationService := jit.NewSimpleNotificationService()

	jam := jit.NewJITAccessManager(rbacManager, notificationService)

	assert.NotNil(t, jam)

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
	// ExpiresAt is computed as GrantedAt+Duration (not request.ExpiresAt) so that
	// it is always strictly after CreatedAt even on low-resolution clocks (e.g. Windows).
	assert.True(t, grant.ExpiresAt.After(grant.GrantedAt), "grant must expire after it was granted")
	assert.WithinDuration(t, grant.GrantedAt.Add(requestSpec.Duration), grant.ExpiresAt, time.Second)

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

// makeMultiStageWorkflow builds a 2-stage sequential workflow for multi-stage tests.
// Stage approvers are explicit user IDs (ApprovalStageTypeUser).
func makeMultiStageWorkflow(s1Approvers []string, s1Min int, s2Approvers []string, s2Min int) *jit.ApprovalWorkflow {
	return &jit.ApprovalWorkflow{
		ID:   "two-stage",
		Name: "Two Stage Workflow",
		Type: jit.ApprovalTypeSequential,
		Approvers: []jit.ApprovalStage{
			{
				ID:           "stage-1",
				Type:         jit.ApprovalStageTypeUser,
				Approvers:    s1Approvers,
				MinApprovals: s1Min,
				TimeoutHours: 2,
			},
			{
				ID:           "stage-2",
				Type:         jit.ApprovalStageTypeUser,
				Approvers:    s2Approvers,
				MinApprovals: s2Min,
				TimeoutHours: 2,
			},
		},
	}
}

func TestJITAccessManager_MultiStageApproval_AdvancesStages(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	grantPermission(t, rbacManager, "approver1", "jit_access.approve", "tenant1")
	grantPermission(t, rbacManager, "approver2", "jit_access.approve", "tenant1")

	workflow := makeMultiStageWorkflow([]string{"approver1"}, 1, []string{"approver2"}, 1)
	jam.SetWorkflowProvider(func(_ context.Context, _ *jit.JITAccessRequest) (*jit.ApprovalWorkflow, error) {
		return workflow, nil
	})

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"},
		Duration:      2 * time.Hour,
		Justification: "multi-stage advance test",
	})
	require.NoError(t, err)
	assert.Equal(t, jit.JITAccessRequestStatusPending, request.Status)
	require.NotNil(t, request.WorkflowState, "WorkflowState must be initialised for multi-stage workflows")
	assert.Equal(t, 0, request.WorkflowState.CurrentStage)

	// Stage 1 approval — must not produce a grant; stage index advances to 1.
	grant, err := jam.ApproveRequest(ctx, request.ID, "approver1", "stage 1 ok")
	require.NoError(t, err)
	assert.Nil(t, grant)

	afterStage1, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, jit.JITAccessRequestStatusPending, afterStage1.Status)
	assert.Equal(t, 1, afterStage1.WorkflowState.CurrentStage)

	// Stage 2 approval — final stage, grant must be created.
	grant2, err := jam.ApproveRequest(ctx, request.ID, "approver2", "stage 2 ok")
	require.NoError(t, err)
	require.NotNil(t, grant2)

	final, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, jit.JITAccessRequestStatusApproved, final.Status)
	assert.Equal(t, grant2.ID, final.GrantedAccess.ID)
}

func TestJITAccessManager_MultiStageApproval_RequiresBothStages(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	grantPermission(t, rbacManager, "approver1", "jit_access.approve", "tenant1")

	workflow := makeMultiStageWorkflow([]string{"approver1"}, 1, []string{"approver1"}, 1)
	jam.SetWorkflowProvider(func(_ context.Context, _ *jit.JITAccessRequest) (*jit.ApprovalWorkflow, error) {
		return workflow, nil
	})

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"},
		Duration:      2 * time.Hour,
		Justification: "requires-both-stages test",
	})
	require.NoError(t, err)

	// Only stage 1 approved — request must remain pending with no grant.
	grant, err := jam.ApproveRequest(ctx, request.ID, "approver1", "stage 1")
	require.NoError(t, err)
	assert.Nil(t, grant, "no grant should be created until all stages complete")

	afterStage1, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, jit.JITAccessRequestStatusPending, afterStage1.Status)
	assert.Nil(t, afterStage1.GrantedAccess)

	// Stage 2 approval completes the workflow and creates the grant.
	grant2, err := jam.ApproveRequest(ctx, request.ID, "approver1", "stage 2")
	require.NoError(t, err)
	require.NotNil(t, grant2)

	afterStage2, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, jit.JITAccessRequestStatusApproved, afterStage2.Status)
	assert.NotNil(t, afterStage2.GrantedAccess)
}

func TestJITAccessManager_MultiStageApproval_DuplicateApproverIgnored(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	grantPermission(t, rbacManager, "approver1", "jit_access.approve", "tenant1")
	grantPermission(t, rbacManager, "approver1b", "jit_access.approve", "tenant1")

	// Stage 1 requires 2 distinct approvals so a duplicate call cannot accidentally advance the stage.
	workflow := makeMultiStageWorkflow([]string{"approver1", "approver1b"}, 2, []string{"approver2"}, 1)
	jam.SetWorkflowProvider(func(_ context.Context, _ *jit.JITAccessRequest) (*jit.ApprovalWorkflow, error) {
		return workflow, nil
	})

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"},
		Duration:      2 * time.Hour,
		Justification: "duplicate approver test",
	})
	require.NoError(t, err)

	// First approval.
	grant, err := jam.ApproveRequest(ctx, request.ID, "approver1", "first")
	require.NoError(t, err)
	assert.Nil(t, grant)

	afterFirst, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, len(afterFirst.WorkflowState.StageApprovals[0]))
	assert.Equal(t, 0, afterFirst.WorkflowState.CurrentStage)

	// Duplicate call — must be silently ignored: no error, no state change.
	grant2, err := jam.ApproveRequest(ctx, request.ID, "approver1", "duplicate")
	require.NoError(t, err)
	assert.Nil(t, grant2)

	afterDup, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, len(afterDup.WorkflowState.StageApprovals[0]), "set size must not grow on duplicate")
	assert.Equal(t, 0, afterDup.WorkflowState.CurrentStage, "stage must not advance on duplicate")
	assert.Equal(t, jit.JITAccessRequestStatusPending, afterDup.Status)

	// Second unique approver completes stage 1 — verifies the idempotency check did not
	// consume the stage advancement slot.
	grant3, err := jam.ApproveRequest(ctx, request.ID, "approver1b", "second unique")
	require.NoError(t, err)
	assert.Nil(t, grant3)

	afterAdvance, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, afterAdvance.WorkflowState.CurrentStage, "stage must advance after MinApprovals met")
	assert.Equal(t, 2, len(afterAdvance.WorkflowState.StageApprovals[0]))
}

func TestJITAccessManager_MultiStageApproval_MinApprovalsEnforced(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	grantPermission(t, rbacManager, "approver1a", "jit_access.approve", "tenant1")
	grantPermission(t, rbacManager, "approver1b", "jit_access.approve", "tenant1")
	grantPermission(t, rbacManager, "approver2", "jit_access.approve", "tenant1")

	// Stage 1 requires 2 distinct approvals before advancing.
	workflow := makeMultiStageWorkflow([]string{"approver1a", "approver1b"}, 2, []string{"approver2"}, 1)
	jam.SetWorkflowProvider(func(_ context.Context, _ *jit.JITAccessRequest) (*jit.ApprovalWorkflow, error) {
		return workflow, nil
	})

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"},
		Duration:      2 * time.Hour,
		Justification: "min-approvals test",
	})
	require.NoError(t, err)

	// First stage-1 approval — not yet at MinApprovals=2, stage must not advance.
	grant, err := jam.ApproveRequest(ctx, request.ID, "approver1a", "first of two")
	require.NoError(t, err)
	assert.Nil(t, grant)

	afterFirst, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, afterFirst.WorkflowState.CurrentStage, "stage must not advance before MinApprovals met")
	assert.Equal(t, jit.JITAccessRequestStatusPending, afterFirst.Status)

	// Second stage-1 approval — meets MinApprovals=2, stage advances to 1.
	grant2, err := jam.ApproveRequest(ctx, request.ID, "approver1b", "second of two")
	require.NoError(t, err)
	assert.Nil(t, grant2, "no grant until final stage completes")

	afterSecond, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, afterSecond.WorkflowState.CurrentStage, "stage must advance after MinApprovals met")

	// Final stage-2 approval creates the grant.
	grant3, err := jam.ApproveRequest(ctx, request.ID, "approver2", "final approval")
	require.NoError(t, err)
	require.NotNil(t, grant3)

	final, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, jit.JITAccessRequestStatusApproved, final.Status)
}

func TestJITAccessManager_MultiStageApproval_NonMemberRejected(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	// Intruder has the RBAC permission so the rejection comes from stage membership, not RBAC.
	grantPermission(t, rbacManager, "intruder", "jit_access.approve", "tenant1")

	workflow := makeMultiStageWorkflow([]string{"approver1"}, 1, []string{"approver2"}, 1)
	jam.SetWorkflowProvider(func(_ context.Context, _ *jit.JITAccessRequest) (*jit.ApprovalWorkflow, error) {
		return workflow, nil
	})

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"},
		Duration:      2 * time.Hour,
		Justification: "non-member rejection test",
	})
	require.NoError(t, err)

	grant, err := jam.ApproveRequest(ctx, request.ID, "intruder", "trying to approve stage 1")

	require.Error(t, err)
	assert.Nil(t, grant)
	// Error must be the stage-membership error, not the RBAC permission error.
	assert.Contains(t, err.Error(), "not a member of stage")
	assert.NotContains(t, err.Error(), "does not have permission to approve")

	// Request must still be pending.
	updated, err := jam.GetRequest(ctx, request.ID)
	require.NoError(t, err)
	assert.Equal(t, jit.JITAccessRequestStatusPending, updated.Status)
}

func TestJITAccessManager_MultiStageApproval_StageAuditEmitted(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "jit-stage-audit-test")
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

	// Two-stage workflow; approver1 is listed in both stages.
	workflow := makeMultiStageWorkflow([]string{"approver1"}, 1, []string{"approver1"}, 1)
	jam.SetWorkflowProvider(func(_ context.Context, _ *jit.JITAccessRequest) (*jit.ApprovalWorkflow, error) {
		return workflow, nil
	})

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"},
		Duration:      2 * time.Hour,
		Justification: "stage audit test",
	})
	require.NoError(t, err)

	// Approve stage 1 (intermediate — not the final stage).
	grant, err := jam.ApproveRequest(ctx, request.ID, "approver1", "stage 1")
	require.NoError(t, err)
	assert.Nil(t, grant)

	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	require.NoError(t, auditMgr.Flush(flushCtx))

	entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{TenantID: "tenant1"})
	require.NoError(t, err)

	var stageEntry *business.AuditEntry
	for _, e := range entries {
		e := e
		if e.Action == "stage_approved" {
			stageEntry = e
			break
		}
	}
	require.NotNil(t, stageEntry, "expected a stage_approved audit event")
	assert.Equal(t, "tenant1", stageEntry.TenantID)
	assert.Equal(t, "jit_access", stageEntry.ResourceType)

	stageID, ok := stageEntry.Details["stage_id"].(string)
	require.True(t, ok, "stage_id detail must be a string")
	assert.Equal(t, "stage-1", stageID)

	approverID, ok := stageEntry.Details["approver_id"].(string)
	require.True(t, ok, "approver_id detail must be a string")
	assert.Equal(t, "approver1", approverID)
}

func TestJITAccessManager_AutoApproval_BypassesStageCheck(t *testing.T) {
	rbacManager := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacManager, jit.NewSimpleNotificationService())

	// "system" (used by auto-approval) must have the RBAC permission but is intentionally
	// absent from both stage approvers lists to verify the bypass.
	grantPermission(t, rbacManager, "system", "jit_access.approve", "tenant1")

	workflow := makeMultiStageWorkflow([]string{"approver1"}, 1, []string{"approver2"}, 1)
	jam.SetWorkflowProvider(func(_ context.Context, _ *jit.JITAccessRequest) (*jit.ApprovalWorkflow, error) {
		return workflow, nil
	})

	ctx := context.Background()
	request, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"read"},
		Duration:      time.Hour,
		Justification: "auto-approve stage bypass test",
		AutoApprove:   true,
	})

	require.NoError(t, err, "auto-approval must succeed even when approverID='system' is not in any stage's approvers list")
	assert.Equal(t, jit.JITAccessRequestStatusApproved, request.Status)
	assert.NotNil(t, request.GrantedAccess)
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

// newTestStorageManager creates an isolated storage manager and registers cleanup.
func newTestStorageManager(t *testing.T) *interfaces.StorageManager {
	t.Helper()
	tmpDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, sm.Close()) })
	return sm
}

// approveAndGetGrant creates a pending request and approves it, returning the grant.
func approveAndGetGrant(t *testing.T, jam *jit.JITAccessManager, rbacMgr *rbac.Manager, requesterID, tenantID string, duration time.Duration) *jit.JITAccessGrant {
	t.Helper()
	ctx := context.Background()
	grantPermission(t, rbacMgr, "system", "jit_access.approve", tenantID)

	req, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   requesterID,
		TenantID:      tenantID,
		Permissions:   []string{"read"},
		Duration:      duration,
		Justification: "test grant",
		AutoApprove:   true,
	})
	require.NoError(t, err)
	require.NotNil(t, req.GrantedAccess, "auto-approve should produce a grant")
	return req.GrantedAccess
}

// TestJITAccessManager_GrantPersistence_SurvivesRestart verifies that a grant activated
// by manager 1 is recoverable by manager 2 after a Stop/Start cycle against the same store.
func TestJITAccessManager_GrantPersistence_SurvivesRestart(t *testing.T) {
	ctx := context.Background()
	sm := newTestStorageManager(t)
	rbacMgr := newTestRBACManager(t)
	sessionStore := sm.GetSessionStore()

	// Manager 1: activate a grant, then stop.
	mgr1 := jit.NewJITAccessManagerWithStore(rbacMgr, jit.NewSimpleNotificationService(), sessionStore)
	require.NoError(t, mgr1.Start(ctx, 30*time.Second))

	grant := approveAndGetGrant(t, mgr1, rbacMgr, "user1", "tenant1", time.Hour)

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	require.NoError(t, mgr1.Stop(stopCtx))

	// Manager 2: start against the same store and verify grant is recovered.
	mgr2 := jit.NewJITAccessManagerWithStore(rbacMgr, jit.NewSimpleNotificationService(), sessionStore)
	require.NoError(t, mgr2.Start(ctx, 30*time.Second))
	defer func() {
		stopCtx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
		defer cancel2()
		assert.NoError(t, mgr2.Stop(stopCtx2))
	}()

	grants, err := mgr2.GetActiveGrants(ctx, "user1", "tenant1")
	require.NoError(t, err)
	require.Len(t, grants, 1, "grant must be recovered from store after restart")
	assert.Equal(t, grant.ID, grants[0].ID)
}

// TestJITAccessManager_CleanupExpiredGrants_SweepsExpired verifies that CleanupExpiredGrants
// removes grants whose ExpiresAt has passed from the active grants map.
func TestJITAccessManager_CleanupExpiredGrants_SweepsExpired(t *testing.T) {
	ctx := context.Background()
	sm := newTestStorageManager(t)
	rbacMgr := newTestRBACManager(t)

	jam := jit.NewJITAccessManagerWithStore(rbacMgr, jit.NewSimpleNotificationService(), sm.GetSessionStore())

	// Use a 1 ms duration so the grant expires immediately.
	grant := approveAndGetGrant(t, jam, rbacMgr, "user1", "tenant1", time.Millisecond)

	// Wait for the grant to expire then run cleanup.
	time.Sleep(30 * time.Millisecond)
	require.NoError(t, jam.CleanupExpiredGrants(ctx))

	grants, err := jam.GetActiveGrants(ctx, "user1", "tenant1")
	require.NoError(t, err)
	for _, g := range grants {
		assert.NotEqual(t, grant.ID, g.ID, "expired grant must not appear in active grants after cleanup")
	}
}

// failingSessionStore wraps a real SessionStore and can be configured to fail UpdateSession.
// It is not a mock — it delegates all calls to the underlying real store.
type failingSessionStore struct {
	business.SessionStore
	failUpdate bool
}

func (f *failingSessionStore) UpdateSession(ctx context.Context, id string, session *business.Session) error {
	if f.failUpdate {
		return errors.New("simulated update failure")
	}
	return f.SessionStore.UpdateSession(ctx, id, session)
}

// TestJITAccessManager_CleanupExpiredGrants_FailedStoreUpdateRetained verifies that a grant
// is NOT removed from activeGrants when the store update fails, so the next tick can retry.
func TestJITAccessManager_CleanupExpiredGrants_FailedStoreUpdateRetained(t *testing.T) {
	ctx := context.Background()
	sm := newTestStorageManager(t)
	rbacMgr := newTestRBACManager(t)

	store := &failingSessionStore{SessionStore: sm.GetSessionStore()}
	jam := jit.NewJITAccessManagerWithStore(rbacMgr, jit.NewSimpleNotificationService(), store)

	grant := approveAndGetGrant(t, jam, rbacMgr, "user1", "tenant1", time.Millisecond)

	// Wait for grant to expire then configure the store to fail updates.
	time.Sleep(30 * time.Millisecond)
	store.failUpdate = true

	require.NoError(t, jam.CleanupExpiredGrants(ctx))

	// After a failed store update the backing session must still reflect Active — this proves
	// the in-memory entry was retained for retry rather than removed prematurely.
	session, err := sm.GetSessionStore().GetSession(ctx, grant.ID)
	require.NoError(t, err)
	assert.Equal(t, business.SessionStatusActive, session.Status,
		"store session must remain Active after failed update — retained for retry")

	// Retry with a working store — the cleanup must now succeed.
	store.failUpdate = false
	require.NoError(t, jam.CleanupExpiredGrants(ctx))

	grants, err := jam.GetActiveGrants(ctx, "user1", "tenant1")
	require.NoError(t, err)
	for _, g := range grants {
		assert.NotEqual(t, grant.ID, g.ID, "grant must be removed after successful retry")
	}

	// Verify the grant was ultimately expired in the store.
	session, err = sm.GetSessionStore().GetSession(ctx, grant.ID)
	require.NoError(t, err)
	assert.Equal(t, business.SessionStatusExpired, session.Status)
}

// TestJITAccessManager_RevokeAccess_StoreFailureBestEffort verifies that RevokeAccess
// succeeds in-memory even when the backing store update fails. deactivateAccess is
// best-effort: store errors are logged but do not roll back the in-memory revocation.
func TestJITAccessManager_RevokeAccess_StoreFailureBestEffort(t *testing.T) {
	ctx := context.Background()
	sm := newTestStorageManager(t)
	rbacMgr := newTestRBACManager(t)
	grantPermission(t, rbacMgr, "revoker1", "jit_access.revoke", "tenant1")

	store := &failingSessionStore{SessionStore: sm.GetSessionStore()}
	jam := jit.NewJITAccessManagerWithStore(rbacMgr, jit.NewSimpleNotificationService(), store)

	grant := approveAndGetGrant(t, jam, rbacMgr, "user1", "tenant1", time.Hour)

	// Fail the store update so deactivateAccess cannot persist the revocation.
	store.failUpdate = true

	// In-memory revocation must still succeed despite the store failure (best-effort).
	err := jam.RevokeAccess(ctx, grant.ID, "revoker1", "security test with failing store")
	require.NoError(t, err, "RevokeAccess must succeed even when store update fails")

	// The grant must no longer appear in active grants.
	grants, err := jam.GetActiveGrants(ctx, "user1", "tenant1")
	require.NoError(t, err)
	for _, g := range grants {
		assert.NotEqual(t, grant.ID, g.ID, "revoked grant must not appear in active grants")
	}
}

// TestJITAccessManager_CleanupExpiredRequests verifies that pending requests with a past
// RequestTTL are marked as expired.
func TestJITAccessManager_CleanupExpiredRequests(t *testing.T) {
	ctx := context.Background()
	rbacMgr := newTestRBACManager(t)
	jam := jit.NewJITAccessManager(rbacMgr, jit.NewSimpleNotificationService())

	// Create a pending request with a very short TTL (no auto-approve so it stays pending).
	req, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"}, // high privilege prevents auto-approve
		Duration:      2 * time.Hour,
		Justification: "test cleanup",
		RequestTTL:    time.Millisecond,
	})
	require.NoError(t, err)
	assert.Equal(t, jit.JITAccessRequestStatusPending, req.Status)

	// Wait for the TTL to expire then sweep.
	time.Sleep(30 * time.Millisecond)
	require.NoError(t, jam.CleanupExpiredRequests(ctx))

	updated, err := jam.GetRequest(ctx, req.ID)
	require.NoError(t, err)
	assert.Equal(t, jit.JITAccessRequestStatusExpired, updated.Status, "pending request with past TTL must be expired")
}

// TestJITAccessManager_TickerExpiresGrant verifies that the central cleanup ticker
// automatically expires grants without manual CleanupExpiredGrants calls.
func TestJITAccessManager_TickerExpiresGrant(t *testing.T) {
	ctx := context.Background()
	sm := newTestStorageManager(t)
	rbacMgr := newTestRBACManager(t)

	jam := jit.NewJITAccessManagerWithStore(rbacMgr, jit.NewSimpleNotificationService(), sm.GetSessionStore())
	require.NoError(t, jam.Start(ctx, 50*time.Millisecond))
	defer func() {
		stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		assert.NoError(t, jam.Stop(stopCtx))
	}()

	grant := approveAndGetGrant(t, jam, rbacMgr, "user1", "tenant1", 10*time.Millisecond)

	// Poll until the ticker sweeps the expired grant (up to 500 ms).
	// Error is intentionally discarded inside the poll closure: calling require.Fatal from a
	// goroutine spawned by require.Eventually would panic. GetActiveGrants never errors today;
	// if that changes, the grant would still not be found (empty slice), so the condition
	// would pass — a known acceptable trade-off for the poll pattern.
	require.Eventually(t, func() bool {
		grants, _ := jam.GetActiveGrants(ctx, "user1", "tenant1") //nolint:errcheck // see comment above
		for _, g := range grants {
			if g.ID == grant.ID {
				return false
			}
		}
		return true
	}, 500*time.Millisecond, 10*time.Millisecond, "ticker must expire the grant automatically")
}

// TestJITAccessManager_RevokeAccess_UpdatesStore verifies that RevokeAccess marks the
// backing session as SessionStatusTerminated.
func TestJITAccessManager_RevokeAccess_UpdatesStore(t *testing.T) {
	ctx := context.Background()
	sm := newTestStorageManager(t)
	rbacMgr := newTestRBACManager(t)
	grantPermission(t, rbacMgr, "revoker1", "jit_access.revoke", "tenant1")

	jam := jit.NewJITAccessManagerWithStore(rbacMgr, jit.NewSimpleNotificationService(), sm.GetSessionStore())
	grant := approveAndGetGrant(t, jam, rbacMgr, "user1", "tenant1", time.Hour)

	require.NoError(t, jam.RevokeAccess(ctx, grant.ID, "revoker1", "security test"))

	session, err := sm.GetSessionStore().GetSession(ctx, grant.ID)
	require.NoError(t, err)
	assert.Equal(t, business.SessionStatusTerminated, session.Status,
		"session must be terminated in store after revocation")
}

// TestJITAccessManager_ExtendAccess_UpdatesStore verifies that ExtendAccess updates
// both Session.ExpiresAt and JITSessionData.ExtensionsUsed in the backing store.
func TestJITAccessManager_ExtendAccess_UpdatesStore(t *testing.T) {
	ctx := context.Background()
	sm := newTestStorageManager(t)
	rbacMgr := newTestRBACManager(t)

	jam := jit.NewJITAccessManagerWithStore(rbacMgr, jit.NewSimpleNotificationService(), sm.GetSessionStore())
	grantPermission(t, rbacMgr, "approver1", "jit_access.approve", "tenant1")

	req, err := jam.RequestAccess(ctx, &jit.JITAccessRequestSpec{
		RequesterID:   "user1",
		TenantID:      "tenant1",
		Permissions:   []string{"admin"},
		Duration:      2 * time.Hour,
		MaxDuration:   4 * time.Hour,
		Justification: "extend store test",
	})
	require.NoError(t, err)

	grant, err := jam.ApproveRequest(ctx, req.ID, "approver1", "approved")
	require.NoError(t, err)

	// Capture the original ExpiresAt from the store.
	before, err := sm.GetSessionStore().GetSession(ctx, grant.ID)
	require.NoError(t, err)
	originalExpiry := before.ExpiresAt

	extension := 30 * time.Minute
	require.NoError(t, jam.ExtendAccess(ctx, grant.ID, extension, "user1", "need more time"))

	// Verify store was updated.
	after, err := sm.GetSessionStore().GetSession(ctx, grant.ID)
	require.NoError(t, err)
	assert.Equal(t, originalExpiry.Add(extension).Round(time.Second), after.ExpiresAt.Round(time.Second),
		"session ExpiresAt must be updated in store")
}

// TestJITAccessManager_LoadActiveGrants_SkipsAlreadyExpired verifies that sessions whose
// ExpiresAt is in the past are NOT loaded into activeGrants but are marked Expired in the store.
func TestJITAccessManager_LoadActiveGrants_SkipsAlreadyExpired(t *testing.T) {
	ctx := context.Background()
	sm := newTestStorageManager(t)
	rbacMgr := newTestRBACManager(t)

	// Manager 1: create a grant that expires almost immediately, stop before ticker fires.
	mgr1 := jit.NewJITAccessManagerWithStore(rbacMgr, jit.NewSimpleNotificationService(), sm.GetSessionStore())
	require.NoError(t, mgr1.Start(ctx, 30*time.Second)) // long interval so ticker doesn't clean up

	grant := approveAndGetGrant(t, mgr1, rbacMgr, "user1", "tenant1", 10*time.Millisecond)

	// Wait for the grant to expire in real time.
	time.Sleep(30 * time.Millisecond)

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	require.NoError(t, mgr1.Stop(stopCtx))

	// Manager 2: Start should NOT load the already-expired session and must mark it Expired.
	mgr2 := jit.NewJITAccessManagerWithStore(rbacMgr, jit.NewSimpleNotificationService(), sm.GetSessionStore())
	require.NoError(t, mgr2.Start(ctx, 30*time.Second))
	defer func() {
		stopCtx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
		defer cancel2()
		assert.NoError(t, mgr2.Stop(stopCtx2))
	}()

	grants, err := mgr2.GetActiveGrants(ctx, "user1", "tenant1")
	require.NoError(t, err)
	for _, g := range grants {
		assert.NotEqual(t, grant.ID, g.ID, "expired session must not be loaded into activeGrants")
	}

	// The session in the store must now be marked Expired.
	session, err := sm.GetSessionStore().GetSession(ctx, grant.ID)
	require.NoError(t, err)
	assert.Equal(t, business.SessionStatusExpired, session.Status,
		"already-expired session must be marked Expired in store during loadActiveGrants")
}

// TestJITAccessManager_ExpiryAuditEmitted verifies that CleanupExpiredGrants emits an
// audit event with action "expired" for each grant it expires.
func TestJITAccessManager_ExpiryAuditEmitted(t *testing.T) {
	ctx := context.Background()
	sm := newTestStorageManager(t)

	auditMgr, err := audit.NewManager(sm.GetAuditStore(), "jit-expiry-audit-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, auditMgr.Stop(stopCtx))
	})

	rbacMgr := newTestRBACManager(t)
	jam := jit.NewJITAccessManagerWithStore(rbacMgr, jit.NewSimpleNotificationService(), sm.GetSessionStore())
	jam.SetAuditManager(auditMgr)

	// Create a grant that expires immediately.
	grant := approveAndGetGrant(t, jam, rbacMgr, "user1", "tenant1", time.Millisecond)
	time.Sleep(30 * time.Millisecond)

	require.NoError(t, jam.CleanupExpiredGrants(ctx))

	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	require.NoError(t, auditMgr.Flush(flushCtx))

	entries, err := auditMgr.QueryEntries(ctx, &business.AuditFilter{TenantID: "tenant1"})
	require.NoError(t, err)

	var expiredEntry *business.AuditEntry
	for _, e := range entries {
		e := e
		if e.Action == "expired" && e.ResourceID == grant.ID {
			expiredEntry = e
			break
		}
	}
	require.NotNil(t, expiredEntry, "expected an 'expired' audit event for the expired grant")
	assert.Equal(t, "tenant1", expiredEntry.TenantID)
	assert.Equal(t, "jit_access", expiredEntry.ResourceType)
	assert.Equal(t, "user1", expiredEntry.UserID)
}
