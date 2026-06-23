// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package rbac

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
)

// TestAgentDevRole_ExistsInDefaultRoles verifies the agent.dev system role is present
// in DefaultRoles so it is seeded at rbacManager.Initialize().
func TestAgentDevRole_ExistsInDefaultRoles(t *testing.T) {
	role := findDefaultRole("agent.dev")
	require.NotNil(t, role, "agent.dev must exist in DefaultRoles")
	assert.Equal(t, "agent.dev", role.Id)
	assert.True(t, role.IsSystemRole, "agent.dev must be a system role so it is seeded at Initialize")
	assert.Equal(t, "", role.TenantId, "system-wide role must have empty TenantId")
}

// TestAgentDevRole_HasExactPermissions asserts the agent.dev role carries exactly the
// five read-only permissions specified in story #2123, no more and no fewer.
func TestAgentDevRole_HasExactPermissions(t *testing.T) {
	role := findDefaultRole("agent.dev")
	require.NotNil(t, role)

	got := make([]string, len(role.PermissionIds))
	copy(got, role.PermissionIds)
	sort.Strings(got)

	want := []string{
		"config.read",
		"config.validate",
		"module.read",
		"steward.read",
		"tenant.read",
	}
	assert.Equal(t, want, got,
		"agent.dev must carry exactly the 5 story-specified permissions (sorted)")
}

// TestAgentDevRole_HasNoWriteOrAdminPerms asserts that agent.dev does not include any
// write, delete, manage, terminal, rbac, or system-admin permission IDs.
func TestAgentDevRole_HasNoWriteOrAdminPerms(t *testing.T) {
	role := findDefaultRole("agent.dev")
	require.NotNil(t, role)

	forbidden := []string{
		"config.create",
		"config.update",
		"config.delete",
		"steward.manage",
		"terminal.session.create",
		"terminal.session.terminate",
		"terminal.admin",
		"rbac.role.manage",
		"rbac.assignment.manage",
		"system.admin",
	}
	for _, f := range forbidden {
		assert.NotContains(t, role.PermissionIds, f,
			"agent.dev must not include write/admin permission %q", f)
	}
}

// findDefaultRole searches DefaultRoles by ID and returns nil if not found.
func findDefaultRole(id string) *common.Role {
	for _, role := range DefaultRoles {
		if role.Id == id {
			return role
		}
	}
	return nil
}
