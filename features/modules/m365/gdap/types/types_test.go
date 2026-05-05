// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package gdaptypes_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	gdaptypes "github.com/cfgis/cfgms/features/modules/m365/gdap/types"
)

// compile-time assertion: mockProvider implements GDAPProvider
type mockProvider struct{}

func (m *mockProvider) DiscoverGDAPCustomers(_ context.Context) ([]gdaptypes.GDAPRelationship, error) {
	return nil, nil
}

func (m *mockProvider) ValidateGDAPAccess(_ context.Context, _ string, _ []string) (*gdaptypes.GDAPRelationship, error) {
	return nil, nil
}

var _ gdaptypes.GDAPProvider = (*mockProvider)(nil)

func TestGDAPRelationshipFields(t *testing.T) {
	expires := time.Now().Add(30 * 24 * time.Hour)
	created := time.Now().Add(-7 * 24 * time.Hour)

	rel := gdaptypes.GDAPRelationship{
		RelationshipID:   "rel-abc",
		CustomerTenantID: "tenant-xyz",
		CustomerName:     "Contoso Ltd",
		Status:           gdaptypes.GDAPStatusActive,
		Roles: []gdaptypes.GDAPRole{
			{RoleDefinitionID: "62e90394-69f5-4237-9190-012177145e10", RoleName: "Global Administrator"},
		},
		ExpiresAt:    expires,
		CreatedAt:    created,
		LastModified: created,
	}

	assert.Equal(t, "rel-abc", rel.RelationshipID)
	assert.Equal(t, "tenant-xyz", rel.CustomerTenantID)
	assert.Equal(t, "Contoso Ltd", rel.CustomerName)
	assert.Equal(t, gdaptypes.GDAPStatusActive, rel.Status)
	assert.Len(t, rel.Roles, 1)
	assert.Equal(t, "Global Administrator", rel.Roles[0].RoleName)
	assert.Equal(t, expires, rel.ExpiresAt)
}

func TestGDAPRelationshipStatusConstants(t *testing.T) {
	assert.Equal(t, gdaptypes.GDAPRelationshipStatus("pending"), gdaptypes.GDAPStatusPending)
	assert.Equal(t, gdaptypes.GDAPRelationshipStatus("active"), gdaptypes.GDAPStatusActive)
	assert.Equal(t, gdaptypes.GDAPRelationshipStatus("expired"), gdaptypes.GDAPStatusExpired)
	assert.Equal(t, gdaptypes.GDAPRelationshipStatus("terminated"), gdaptypes.GDAPStatusTerminated)
}

func TestGDAPRoleFields(t *testing.T) {
	role := gdaptypes.GDAPRole{
		RoleDefinitionID: "role-def-id",
		RoleName:         "User Administrator",
		RoleDescription:  "Manages users and groups",
	}

	assert.Equal(t, "role-def-id", role.RoleDefinitionID)
	assert.Equal(t, "User Administrator", role.RoleName)
	assert.Equal(t, "Manages users and groups", role.RoleDescription)
}
