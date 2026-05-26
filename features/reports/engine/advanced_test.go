// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package engine

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// makeRBACTestEngine constructs an AdvancedEngine suitable for validateTenantAccess tests.
// Non-RBAC dependencies are nil because validateTenantAccess does not exercise them.
func makeRBACTestEngine(rbacManager *rbac.Manager) *AdvancedEngine {
	return NewAdvancedEngine(nil, nil, nil, nil, rbacManager, logging.NewNoopLogger())
}

// grantReportsRead creates the reports:read permission, a role containing it,
// a user subject, and assigns the role to that user for the given tenant.
func grantReportsRead(t *testing.T, m *rbac.Manager, tenantID, userID string) {
	t.Helper()
	ctx := context.Background()
	ctxJ := rbac.WithSensitiveOperationJustification(ctx, "test: grant reports:read for validateTenantAccess")

	require.NoError(t, m.CreatePermission(ctxJ, &common.Permission{
		Id:           "reports:read",
		Name:         "Read Reports",
		Description:  "Read reports for a tenant",
		ResourceType: "reports",
		Actions:      []string{"read"},
	}))

	roleID := tenantID + ".reports.viewer"
	require.NoError(t, m.CreateRole(ctxJ, &common.Role{
		Id:            roleID,
		Name:          "Reports Viewer",
		Description:   "Read-only access to tenant reports",
		PermissionIds: []string{"reports:read"},
		TenantId:      tenantID,
		IsSystemRole:  false,
	}))

	require.NoError(t, m.CreateSubject(ctx, &common.Subject{
		Id:       userID,
		Type:     common.SubjectType_SUBJECT_TYPE_USER,
		TenantId: tenantID,
		IsActive: true,
	}))

	require.NoError(t, m.AssignRole(ctxJ, &common.RoleAssignment{
		SubjectId: userID,
		RoleId:    roleID,
		TenantId:  tenantID,
	}))
}

// TestValidateTenantAccess_Authorized verifies that a user holding reports:read
// for a tenant passes the RBAC gate.
func TestValidateTenantAccess_Authorized(t *testing.T) {
	m := pkgtesting.SetupTestRBACManager(t)
	tenantID := "test-tenant"
	userID := "authorized-user"
	grantReportsRead(t, m, tenantID, userID)

	engine := makeRBACTestEngine(m)
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, userID)

	err := engine.validateTenantAccess(ctx, []string{tenantID})
	assert.NoError(t, err)
}

// TestValidateTenantAccess_Unauthorized verifies that a user without reports:read
// receives a permission-denied error and that the error does not name the tenant.
func TestValidateTenantAccess_Unauthorized(t *testing.T) {
	m := pkgtesting.SetupTestRBACManager(t)
	engine := makeRBACTestEngine(m)

	// User exists in context but holds no role in the target tenant.
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "user-no-perms")

	err := engine.validateTenantAccess(ctx, []string{"any-tenant"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
	// Must not leak the tenant name to the caller.
	assert.NotContains(t, err.Error(), "any-tenant")
}

// TestValidateTenantAccess_MissingUserID verifies that a context without a user ID
// is rejected immediately, without consulting the RBAC store.
func TestValidateTenantAccess_MissingUserID(t *testing.T) {
	m := pkgtesting.SetupTestRBACManager(t)
	engine := makeRBACTestEngine(m)

	err := engine.validateTenantAccess(context.Background(), []string{"any-tenant"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

// TestValidateTenantAccess_NilRBACManager verifies that a nil manager disables
// the RBAC gate so callers without a manager configured are not blocked.
func TestValidateTenantAccess_NilRBACManager(t *testing.T) {
	engine := makeRBACTestEngine(nil)

	err := engine.validateTenantAccess(context.Background(), []string{"any-tenant"})
	assert.NoError(t, err)
}

// TestValidateTenantAccess_TooManyTenants verifies that exceeding MaxTenantsPerReport
// returns an error before any RBAC check is performed.
func TestValidateTenantAccess_TooManyTenants(t *testing.T) {
	engine := makeRBACTestEngine(nil)

	tenants := make([]string, engine.config.MaxTenantsPerReport+1)
	for i := range tenants {
		tenants[i] = fmt.Sprintf("tenant-%d", i)
	}

	err := engine.validateTenantAccess(context.Background(), tenants)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many tenants requested")
}
