// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/memory"
)

// Simplified test without direct zero-trust mocking due to circular import constraints

// Mock stores for testing
type MockPermissionStore struct{ mock.Mock }
type MockRoleStore struct{ mock.Mock }
type MockSubjectStore struct{ mock.Mock }
type MockRoleAssignmentStore struct{ mock.Mock }

func (m *MockPermissionStore) CreatePermission(ctx context.Context, permission *common.Permission) error {
	return nil
}
func (m *MockPermissionStore) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	return nil, nil
}
func (m *MockPermissionStore) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	return nil, nil
}
func (m *MockPermissionStore) UpdatePermission(ctx context.Context, permission *common.Permission) error {
	return nil
}
func (m *MockPermissionStore) DeletePermission(ctx context.Context, id string) error { return nil }

func (m *MockRoleStore) CreateRole(ctx context.Context, role *common.Role) error { return nil }
func (m *MockRoleStore) GetRole(ctx context.Context, id string) (*common.Role, error) {
	return nil, nil
}
func (m *MockRoleStore) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	return nil, nil
}
func (m *MockRoleStore) UpdateRole(ctx context.Context, role *common.Role) error { return nil }
func (m *MockRoleStore) DeleteRole(ctx context.Context, id string) error         { return nil }
func (m *MockRoleStore) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	return []*common.Permission{
		{Id: "steward.register", Name: "Register Steward", Description: "Allow steward registration"},
	}, nil
}
func (m *MockRoleStore) GetRoleHierarchy(ctx context.Context, roleID string) (*memory.RoleHierarchy, error) {
	return nil, nil
}
func (m *MockRoleStore) GetChildRoles(ctx context.Context, roleID string) ([]*common.Role, error) {
	return nil, nil
}
func (m *MockRoleStore) GetParentRole(ctx context.Context, roleID string) (*common.Role, error) {
	return nil, nil
}
func (m *MockRoleStore) SetRoleParent(ctx context.Context, roleID, parentRoleID string, inheritanceType common.RoleInheritanceType) error {
	return nil
}
func (m *MockRoleStore) RemoveRoleParent(ctx context.Context, roleID string) error      { return nil }
func (m *MockRoleStore) ValidateRoleHierarchy(ctx context.Context, roleID string) error { return nil }

func (m *MockSubjectStore) CreateSubject(ctx context.Context, subject *common.Subject) error {
	return nil
}
func (m *MockSubjectStore) GetSubject(ctx context.Context, id string) (*common.Subject, error) {
	return &common.Subject{
		Id:          id,
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Test User",
		IsActive:    true,
	}, nil
}
func (m *MockSubjectStore) ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error) {
	return nil, nil
}
func (m *MockSubjectStore) UpdateSubject(ctx context.Context, subject *common.Subject) error {
	return nil
}
func (m *MockSubjectStore) DeleteSubject(ctx context.Context, id string) error { return nil }
func (m *MockSubjectStore) GetSubjectRoles(ctx context.Context, subjectID, tenantID string) ([]*common.Role, error) {
	return []*common.Role{
		{Id: "admin", Name: "Administrator", Description: "Full admin access"},
	}, nil
}

func (m *MockRoleAssignmentStore) AssignRole(ctx context.Context, assignment *common.RoleAssignment) error {
	return nil
}
func (m *MockRoleAssignmentStore) RevokeRole(ctx context.Context, subjectID, roleID, tenantID string) error {
	return nil
}
func (m *MockRoleAssignmentStore) GetAssignment(ctx context.Context, id string) (*common.RoleAssignment, error) {
	return nil, nil
}
func (m *MockRoleAssignmentStore) ListAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error) {
	return nil, nil
}
func (m *MockRoleAssignmentStore) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	return nil, nil
}

func TestAdvancedAuthEngine_BasicRBACFlow(t *testing.T) {
	// Setup
	mockPerm := &MockPermissionStore{}
	mockRole := &MockRoleStore{}
	mockSubject := &MockSubjectStore{}
	mockAssignment := &MockRoleAssignmentStore{}

	engine := NewAdvancedAuthEngine(mockPerm, mockRole, mockSubject, mockAssignment)

	// Test basic RBAC flow without zero-trust (disabled mode)
	assert.Equal(t, ZeroTrustModeDisabled, engine.GetZeroTrustMode())

	// Create test request
	request := &common.AccessRequest{
		SubjectId:    "user123",
		PermissionId: "steward.register",
		TenantId:     "tenant456",
		Context: map[string]string{
			"source_ip":  "192.168.1.100",
			"user_agent": "test-agent",
		},
	}

	// Execute
	response, err := engine.CheckPermission(context.Background(), request)

	// Verify
	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.True(t, response.Granted)
	assert.Contains(t, response.Reason, "Access granted via role 'Administrator' with permission 'Register Steward'")
}

func TestAdvancedAuthEngine_ZeroTrustModeConfiguration(t *testing.T) {
	engine := NewAdvancedAuthEngine(nil, nil, nil, nil)

	// Test initial state
	assert.Equal(t, ZeroTrustModeDisabled, engine.GetZeroTrustMode())

	// Test that nil zero-trust engine doesn't enable zero-trust
	engine.EnableZeroTrust(ZeroTrustModeAugmented)
	assert.Equal(t, ZeroTrustModeDisabled, engine.GetZeroTrustMode())

	// Test disabling zero-trust
	engine.DisableZeroTrust()
	assert.Equal(t, ZeroTrustModeDisabled, engine.GetZeroTrustMode())
}
