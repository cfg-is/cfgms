// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package rbac

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Import storage providers for testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

func TestAdvancedPermissionManagement(t *testing.T) {
	// Use git storage for durable testing - minimum storage requirement
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":          "main",
		"auto_init":       true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	ctx := context.Background()

	err = manager.Initialize(ctx)
	require.NoError(t, err)

	// Create test subject
	subject := &common.Subject{
		Id:          "user1",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Test User",
		TenantId:    "tenant1",
		IsActive:    true,
	}
	require.NoError(t, manager.CreateSubject(ctx, subject))

	// Create test permission
	permission := &common.Permission{
		Id:           "test.config.update",
		Name:         "Test Configuration Update",
		Description:  "Update test configuration settings",
		ResourceType: "configuration",
		Actions:      []string{"update"},
	}
	require.NoError(t, manager.CreatePermission(ctx, permission))

	t.Run("ConditionalPermissions", func(t *testing.T) {
		// Create conditional permission with time and IP restrictions
		conditionalPerm := &common.ConditionalPermission{
			Id:           "conditional-config-update",
			PermissionId: "test.config.update",
			Conditions: []*common.Condition{
				{
					Type:     "time",
					Operator: common.ConditionOperator_CONDITION_OPERATOR_TIME_WITHIN,
					Values:   []string{time.Now().Add(-1 * time.Hour).Format(time.RFC3339), time.Now().Add(1 * time.Hour).Format(time.RFC3339)},
				},
				{
					Type:     "ip",
					Operator: common.ConditionOperator_CONDITION_OPERATOR_IP_IN_RANGE,
					Values:   []string{"192.168.1.0/24"},
				},
			},
		}

		// Test within allowed conditions
		authContext := &common.AuthorizationContext{
			TenantId:  "tenant1",
			SubjectId: "user1",
			Environment: map[string]string{
				"ip": "192.168.1.100",
			},
		}

		request := &common.AccessRequest{
			SubjectId:    "user1",
			PermissionId: "test.config.update",
			TenantId:     "tenant1",
		}

		// First grant the base permission
		role := &common.Role{
			Id:            "test-role",
			Name:          "Test Role",
			PermissionIds: []string{"test.config.update"},
			TenantId:      "tenant1",
		}
		require.NoError(t, manager.CreateRole(ctx, role))
		assignment := &common.RoleAssignment{
			SubjectId: "user1",
			RoleId:    "test-role",
			TenantId:  "tenant1",
		}
		require.NoError(t, manager.AssignRole(ctx, assignment))

		response, err := manager.CheckConditionalPermission(ctx, request, conditionalPerm, authContext)
		require.NoError(t, err)
		assert.True(t, response.Granted, "Should grant access when conditions are met")

		// Test outside allowed conditions (wrong IP)
		authContext.Environment["ip"] = "10.0.0.1"
		response, err = manager.CheckConditionalPermission(ctx, request, conditionalPerm, authContext)
		require.NoError(t, err)
		assert.False(t, response.Granted, "Should deny access when IP condition is not met")
	})

	t.Run("PermissionDelegation", func(t *testing.T) {
		// Create delegator and delegatee subjects
		delegator := &common.Subject{
			Id:          "admin1",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			DisplayName: "Admin User",
			TenantId:    "tenant1",
			IsActive:    true,
		}
		require.NoError(t, manager.CreateSubject(ctx, delegator))

		delegatee := &common.Subject{
			Id:          "temp-user1",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			DisplayName: "Temporary User",
			TenantId:    "tenant1",
			IsActive:    true,
		}
		require.NoError(t, manager.CreateSubject(ctx, delegatee))

		// Grant permission to delegator
		adminRole := &common.Role{
			Id:            "admin-role",
			Name:          "Admin Role",
			PermissionIds: []string{"test.config.update"},
			TenantId:      "tenant1",
		}
		require.NoError(t, manager.CreateRole(ctx, adminRole))
		adminAssignment := &common.RoleAssignment{
			SubjectId: "admin1",
			RoleId:    "admin-role",
			TenantId:  "tenant1",
		}
		require.NoError(t, manager.AssignRole(ctx, adminAssignment))

		// Create delegation
		delegationReq := &DelegationRequest{
			DelegatorID:   "admin1",
			DelegateeID:   "temp-user1",
			PermissionIDs: []string{"test.config.update"},
			ExpiresAt:     time.Now().Add(24 * time.Hour).Unix(),
			TenantID:      "tenant1",
		}

		delegation, err := manager.CreateDelegation(ctx, delegationReq)
		require.NoError(t, err)
		assert.NotEmpty(t, delegation.Id)

		// Check delegated permission
		request := &common.AccessRequest{
			SubjectId:    "temp-user1",
			PermissionId: "test.config.update",
			TenantId:     "tenant1",
		}

		response, err := manager.CheckPermission(ctx, request)
		require.NoError(t, err)
		assert.True(t, response.Granted, "Should grant access through delegation")
		assert.Contains(t, response.Reason, "delegation")

		// Revoke delegation
		err = manager.RevokeDelegation(ctx, delegation.Id, "admin1")
		require.NoError(t, err)

		// Check that permission is no longer granted
		response, err = manager.CheckPermission(ctx, request)
		require.NoError(t, err)
		assert.False(t, response.Granted, "Should deny access after delegation revoked")
	})

	t.Run("ResourceScoping", func(t *testing.T) {
		scopeEngine := NewScopeEngine()

		// Test specific resource IDs
		scope := &common.PermissionScope{
			ResourceIds: []string{"config1", "config2"},
		}

		allowed, reason := scopeEngine.EvaluateScope(ctx, scope, "config1", nil)
		assert.True(t, allowed, "Should allow access to specific resource")
		assert.Contains(t, reason, "explicitly allowed")

		allowed, reason = scopeEngine.EvaluateScope(ctx, scope, "config3", nil)
		assert.False(t, allowed, "Should deny access to non-listed resource")
		assert.Contains(t, reason, "not in allowed resource list")

		// Test wildcard patterns
		scope = &common.PermissionScope{
			ResourcePatterns: []string{"config*", "settings/*"},
		}

		allowed, reason = scopeEngine.EvaluateScope(ctx, scope, "config123", nil)
		assert.True(t, allowed, "Should allow access matching wildcard pattern")
		assert.Contains(t, reason, "matches")

		allowed, reason = scopeEngine.EvaluateScope(ctx, scope, "settings/db", nil)
		assert.True(t, allowed, "Should allow access matching path pattern")
		assert.Contains(t, reason, "matches")

		allowed, reason = scopeEngine.EvaluateScope(ctx, scope, "other/resource", nil)
		assert.False(t, allowed, "Should deny access not matching any pattern")
		assert.Contains(t, reason, "does not match")

		// Test exclusions
		scope = &common.PermissionScope{
			ResourcePatterns:  []string{"*"},
			ExcludedResources: []string{"secret*"},
		}

		allowed, reason = scopeEngine.EvaluateScope(ctx, scope, "normalfile", nil)
		assert.True(t, allowed, "Should allow access to non-excluded resource")
		assert.Contains(t, reason, "allowed")

		allowed, reason = scopeEngine.EvaluateScope(ctx, scope, "secretfile", nil)
		assert.False(t, allowed, "Should deny access to excluded resource")
		assert.Contains(t, reason, "excluded")
	})

	t.Run("AuditLogging", func(t *testing.T) {
		// Check that permission checks are being audited
		request := &common.AccessRequest{
			SubjectId:    "user1",
			PermissionId: "test.config.update",
			TenantId:     "tenant1",
			Context: map[string]string{
				"source_ip":  "192.168.1.100",
				"user_agent": "TestAgent/1.0",
			},
		}

		response, err := manager.CheckPermission(ctx, request)
		require.NoError(t, err)

		// Get audit entries
		filter := &AuditFilter{
			SubjectID: "user1",
			Action:    "check",
			Limit:     10,
		}

		entries, err := manager.GetAuditEntries(ctx, filter)
		require.NoError(t, err)
		assert.Greater(t, len(entries), 0, "Should have audit entries")

		entry := entries[0]
		assert.Equal(t, "user1", entry.SubjectId)
		assert.Equal(t, "check", entry.Action)
		assert.Equal(t, "test.config.update", entry.PermissionId)
		assert.Equal(t, response.Granted, entry.Granted)
		assert.Equal(t, "192.168.1.100", entry.SourceIp)
		assert.Equal(t, "TestAgent/1.0", entry.UserAgent)
	})

	t.Run("PermissionTemplates", func(t *testing.T) {
		// Create a permission template
		templateReq := &TemplateCreateRequest{
			Name:          "Developer Template",
			Description:   "Standard developer permissions",
			Category:      "development",
			PermissionIDs: []string{"test.config.update"},
			TenantID:      "tenant1",
		}

		template, err := manager.CreateTemplate(ctx, templateReq)
		require.NoError(t, err)
		assert.Equal(t, "Developer Template", template.Name)
		assert.Equal(t, "development", template.Category)

		// List templates
		templates, err := manager.ListTemplates(ctx, "tenant1", "")
		require.NoError(t, err)
		assert.Greater(t, len(templates), 0, "Should have templates")

		// Check that both system and tenant templates are returned
		hasSystemTemplate := false
		hasTenantTemplate := false
		for _, tmpl := range templates {
			if tmpl.IsSystemTemplate {
				hasSystemTemplate = true
			} else if tmpl.Id == template.Id {
				hasTenantTemplate = true
			}
		}
		assert.True(t, hasSystemTemplate, "Should include system templates")
		assert.True(t, hasTenantTemplate, "Should include tenant template")

		// Apply template
		newUser := &common.Subject{
			Id:          "dev1",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			DisplayName: "Developer",
			TenantId:    "tenant1",
			IsActive:    true,
		}
		require.NoError(t, manager.CreateSubject(ctx, newUser))

		err = manager.ApplyTemplate(ctx, template.Id, "dev1", "tenant1", nil)
		require.NoError(t, err)

		// Verify the user now has the permissions from the template
		permissions, err := manager.GetSubjectPermissions(ctx, "dev1", "tenant1")
		require.NoError(t, err)
		assert.Greater(t, len(permissions), 0, "Should have permissions from template")

		hasConfigUpdate := false
		for _, perm := range permissions {
			if perm.Id == "test.config.update" {
				hasConfigUpdate = true
				break
			}
		}
		assert.True(t, hasConfigUpdate, "Should have test.config.update permission from template")
	})

	t.Run("ComplianceReporting", func(t *testing.T) {
		// Generate some audit data by making permission checks
		for i := 0; i < 5; i++ {
			request := &common.AccessRequest{
				SubjectId:    "user1",
				PermissionId: "test.config.update",
				TenantId:     "tenant1",
			}
			_, _ = manager.CheckPermission(ctx, request)
		}

		// Generate compliance report
		filter := &AuditFilter{
			TenantID:  "tenant1",
			StartTime: time.Now().Add(-1 * time.Hour).Unix(),
		}

		report, err := manager.GetComplianceReport(ctx, filter)
		require.NoError(t, err)
		assert.Greater(t, report.TotalEntries, 0, "Should have audit entries in report")
		assert.Greater(t, report.UniqueSubjectCount, 0, "Should have unique subjects")
		assert.Contains(t, report.ActionBreakdown, "check", "Should have check actions")
	})

	t.Run("SecurityAlerts", func(t *testing.T) {
		// Generate failed access attempts to trigger alerts
		for i := 0; i < 12; i++ {
			request := &common.AccessRequest{
				SubjectId:    "user1",
				PermissionId: "non-existent-permission",
				TenantId:     "tenant1",
			}
			_, _ = manager.CheckPermission(ctx, request)
		}

		// Check for security alerts
		alerts, err := manager.GetSecurityAlerts(ctx, 1)
		require.NoError(t, err)

		// Should have alert for excessive failed attempts
		hasFailedAttemptsAlert := false
		for _, alert := range alerts {
			if alert.Type == "excessive_failed_attempts" {
				hasFailedAttemptsAlert = true
				break
			}
		}
		assert.True(t, hasFailedAttemptsAlert, "Should generate alert for excessive failed attempts")
	})

	t.Run("TemporaryPermissions", func(t *testing.T) {
		// Create a temporary permission request
		tempReq := &TemporaryPermissionRequest{
			SubjectID:    "user1",
			PermissionID: "emergency.access",
			TenantID:     "tenant1",
			Conditions: []*common.Condition{
				{
					Type:     "time",
					Operator: common.ConditionOperator_CONDITION_OPERATOR_LESS_THAN,
					Values:   []string{time.Now().Add(2 * time.Hour).Format(time.RFC3339)},
				},
			},
			ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
			GrantedBy: "admin1",
			GrantedAt: time.Now().Unix(),
		}

		conditionalPerm, err := manager.CreateTemporaryPermission(ctx, tempReq)
		require.NoError(t, err)
		assert.Equal(t, "emergency.access", conditionalPerm.PermissionId)
		assert.Equal(t, "admin1", conditionalPerm.GrantedBy)
		assert.Greater(t, conditionalPerm.ExpiresAt, int64(0))
		assert.Len(t, conditionalPerm.Conditions, 1)
	})
}
