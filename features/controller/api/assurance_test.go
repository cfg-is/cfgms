// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// TestPermissionAssurance_SourceOfTruth validates that the canonical permissionAssurance
// registry is non-empty and that every entry uses the resource:action format.
func TestPermissionAssurance_SourceOfTruth(t *testing.T) {
	require.NotEmpty(t, permissionAssurance, "permissionAssurance must declare at least one entry")
	for perm, req := range permissionAssurance {
		assert.NotEmpty(t, perm, "permissionAssurance must not contain empty permission IDs")
		assert.Contains(t, perm, ":", "permission ID %q must use resource:action format", perm)
		assert.GreaterOrEqual(t, int(req.Min), int(session.AssuranceMachine),
			"permission %q Min must be >= AssuranceMachine", perm)
		assert.LessOrEqual(t, int(req.Min), int(session.AssuranceStrong),
			"permission %q Min must be a known AssuranceLevel", perm)
	}
}

// TestPermissionAssurance_FormerTier3SetPresent verifies that every permission that was
// in the former tier3Permissions map is present in permissionAssurance with at least
// Min: AssuranceStrong. This acts as a migration completeness guard.
func TestPermissionAssurance_FormerTier3SetPresent(t *testing.T) {
	formerTier3 := []string{
		"certificate:provision",
		"certificate:rotate",
		"rbac:create-role",
		"rbac:update-role",
		"rbac:delete-role",
		"api-key:create",
		"api-key:delete",
		"registration:create-token",
		"registration:delete-token",
		"registration:revoke-token",
		"registration:rotate-token",
		"registration:approve",
		"registration:manage-ip-trust",
		"tenant:create",
		"refresh:approve",
		"refresh:set-policy",
		"steward:move",
		"steward:decommission",
		"web-account:create",
		"web-account:delete",
	}
	for _, perm := range formerTier3 {
		req, found := permissionAssurance[perm]
		require.True(t, found, "former Tier-3 permission %q must be in permissionAssurance", perm)
		assert.Equal(t, session.AssuranceStrong, req.Min,
			"former Tier-3 permission %q must require AssuranceStrong", perm)
	}
}

// TestPermissionAssurance_NewPermissionsPresent verifies that the new permissions
// introduced in Issue #2780 and #2784 are present in the registry with the correct requirements.
func TestPermissionAssurance_NewPermissionsPresent(t *testing.T) {
	newPerms := map[string]session.AssuranceLevel{
		"cluster:drain-node":        session.AssuranceStrong,
		"cluster:decommission-node": session.AssuranceStrong,
		"session:create":            session.AssuranceStrong,
		"webauthn:assert-presence":  session.AssuranceStrong, // Issue #2784: presence-ceremony endpoint
	}
	for perm, wantMin := range newPerms {
		req, found := permissionAssurance[perm]
		require.True(t, found, "new permission %q must be in permissionAssurance", perm)
		assert.Equal(t, wantMin, req.Min, "permission %q must have Min: %v", perm, wantMin)
	}
}

// TestPermissionAssurance_SessionListRevoke_Absent verifies that session:list and
// session:revoke are deliberately absent from permissionAssurance. These are ordinary
// grant permissions (de-escalation/safety actions must not require AssuranceStrong).
func TestPermissionAssurance_SessionListRevoke_Absent(t *testing.T) {
	for _, perm := range []string{"session:list", "session:revoke"} {
		_, found := permissionAssurance[perm]
		assert.False(t, found,
			"permission %q must be absent from permissionAssurance — "+
				"revoking/listing sessions is a safety action, not a credential-minting operation", perm)
	}
}

// TestPermissionAssurance_CatastrophicForwardDeclarations verifies that all
// catastrophic permissions carry RequireUserPresence: true (Issue #2784, #2969).
func TestPermissionAssurance_CatastrophicForwardDeclarations(t *testing.T) {
	catastrophic := []string{
		"module:approve",
		"module:reject",
		"publisher-trust:add",
		"registration:approve-by-cidr", // Issue #2969: bulk CIDR approval
	}
	for _, perm := range catastrophic {
		req, found := permissionAssurance[perm]
		require.True(t, found, "catastrophic permission %q must be in permissionAssurance", perm)
		assert.Equal(t, session.AssuranceStrong, req.Min, "catastrophic permission %q must require AssuranceStrong", perm)
		assert.True(t, req.RequireUserPresence, "catastrophic permission %q must have RequireUserPresence: true", perm)
	}
}

// TestPermissionAssurance_ApproveByCIDRIsGrantable verifies that
// registration:approve-by-cidr is in the knownPermissions allow-list (Issue #2969).
// Splitting approve-by-cidr out of registration:approve is only usable if the new
// permission can actually be granted: handleCreateWebAccount and handleCreateAPIKey
// reject any permission ID absent from that list with 400 INVALID_PERMISSION, which
// would make the web console's CIDR approval flow ungrantable.
func TestPermissionAssurance_ApproveByCIDRIsGrantable(t *testing.T) {
	assert.True(t, isKnownPermission("registration:approve-by-cidr"),
		"registration:approve-by-cidr must be grantable to web accounts")
	// The permission it was split out of remains grantable and unchanged.
	assert.True(t, isKnownPermission("registration:approve"),
		"registration:approve must remain grantable for single approve + approve-all")
	// Sanity: the allow-list still rejects the wildcard.
	assert.False(t, isKnownPermission("*"), "wildcard must never be a valid permission ID")
}

// TestPermissionAssurance_NonCatastrophicNoUserPresence verifies that non-catastrophic
// permissions do not accidentally have RequireUserPresence set.
func TestPermissionAssurance_NonCatastrophicNoUserPresence(t *testing.T) {
	catastrophic := map[string]bool{
		"module:approve":               true,
		"module:reject":                true,
		"publisher-trust:add":          true,
		"registration:approve-by-cidr": true, // Issue #2969
	}
	for perm, req := range permissionAssurance {
		if catastrophic[perm] {
			continue
		}
		assert.False(t, req.RequireUserPresence,
			"permission %q should not have RequireUserPresence (only catastrophic permissions carry this flag)", perm)
	}
}
