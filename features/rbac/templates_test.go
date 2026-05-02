// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
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
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func setupTemplateTestManager(t *testing.T) (*Manager, context.Context) {
	t.Helper()
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager := NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	ctx := context.Background()
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(stopCtx)
	})
	require.NoError(t, manager.Initialize(ctx))
	return manager, ctx
}

// TestGetSystemTemplates_BreakGlass_NoDynamicTimestamp verifies that the break-glass
// template does not embed a fixed RFC3339 timestamp computed at template load time.
// The condition value must be a duration string (e.g. "4h") resolved at assignment time.
func TestGetSystemTemplates_BreakGlass_NoDynamicTimestamp(t *testing.T) {
	tm := NewTemplateManager(nil)
	templates := tm.getSystemTemplates()

	var breakGlass *common.PermissionTemplate
	for _, tmpl := range templates {
		if tmpl.Id == "emergency.break-glass" {
			breakGlass = tmpl
			break
		}
	}
	require.NotNil(t, breakGlass, "emergency.break-glass template must exist in system templates")
	require.NotEmpty(t, breakGlass.ConditionalPermissions, "break-glass template must have conditional permissions")

	for _, condPerm := range breakGlass.ConditionalPermissions {
		for _, cond := range condPerm.Conditions {
			for _, val := range cond.Values {
				// An RFC3339 timestamp contains "T" and ends with "Z" or a numeric offset.
				// A duration string like "4h" contains neither.
				isTimestamp := len(val) > 10 && containsDateTimeSeparator(val)
				assert.False(t, isTimestamp,
					"condition value %q looks like a fixed RFC3339 timestamp; must be a duration string (e.g. \"4h\")", val)
				assert.Equal(t, "4h", val,
					"break-glass condition value must be the duration string \"4h\", got %q", val)
			}
		}
	}
}

// containsDateTimeSeparator checks whether a string looks like an RFC3339 timestamp
// (contains "T" separating date and time components, followed by a timezone indicator).
func containsDateTimeSeparator(s string) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == 'T' && i > 0 && (s[len(s)-1] == 'Z' || s[len(s)-1] == '+' || s[len(s)-1] == ':') {
			return true
		}
	}
	return false
}

// TestApplyTemplate_BreakGlass_SetsExpiresAt verifies that applying the break-glass
// template sets ExpiresAt on the resulting RoleAssignment to approximately now + 4h.
func TestApplyTemplate_BreakGlass_SetsExpiresAt(t *testing.T) {
	manager, ctx := setupTemplateTestManager(t)

	subject := &common.Subject{
		Id:          "emergency-user",
		DisplayName: "Emergency User",
		TenantId:    "test-tenant",
		IsActive:    true,
	}
	require.NoError(t, manager.CreateSubject(ctx, subject))

	before := time.Now()
	err := manager.ApplyTemplate(ctx, "emergency.break-glass", "emergency-user", "test-tenant", nil)
	require.NoError(t, err)
	after := time.Now()

	assignments, err := manager.GetSubjectAssignments(ctx, "emergency-user", "test-tenant")
	require.NoError(t, err)
	require.Len(t, assignments, 1, "exactly one assignment must be created by ApplyTemplate for this subject")

	assignment := assignments[0]
	require.NotZero(t, assignment.ExpiresAt, "ExpiresAt must be non-zero for break-glass assignment")

	minExpiry := before.Add(3*time.Hour + 55*time.Minute).Unix()
	maxExpiry := after.Add(4*time.Hour + 5*time.Minute).Unix()
	assert.GreaterOrEqual(t, assignment.ExpiresAt, minExpiry,
		"ExpiresAt must be at least now + 3h55m (got %v, min %v)", assignment.ExpiresAt, minExpiry)
	assert.LessOrEqual(t, assignment.ExpiresAt, maxExpiry,
		"ExpiresAt must be at most now + 4h5m (got %v, max %v)", assignment.ExpiresAt, maxExpiry)
}

// TestApplyTemplate_BreakGlass_NoWildcardPermission verifies that no role created by
// the break-glass template has PermissionIds containing the literal "*".
func TestApplyTemplate_BreakGlass_NoWildcardPermission(t *testing.T) {
	manager, ctx := setupTemplateTestManager(t)

	subject := &common.Subject{
		Id:          "emergency-user-2",
		DisplayName: "Emergency User 2",
		TenantId:    "test-tenant",
		IsActive:    true,
	}
	require.NoError(t, manager.CreateSubject(ctx, subject))

	err := manager.ApplyTemplate(ctx, "emergency.break-glass", "emergency-user-2", "test-tenant", nil)
	require.NoError(t, err)

	roles, err := manager.ListRoles(ctx, "test-tenant")
	require.NoError(t, err)

	for _, role := range roles {
		for _, permID := range role.PermissionIds {
			assert.NotEqual(t, "*", permID,
				"role %q (id=%s) must not have wildcard \"*\" in PermissionIds after break-glass template application", role.Name, role.Id)
		}
	}
}
