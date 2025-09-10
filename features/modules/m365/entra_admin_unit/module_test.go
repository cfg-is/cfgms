package entra_admin_unit

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gopkg.in/yaml.v3"
)

// Mock implementations for testing

type MockAuthProvider struct {
	mock.Mock
}

func (m *MockAuthProvider) GetAccessToken(ctx context.Context, tenantID string) (*auth.AccessToken, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AccessToken), args.Error(1)
}

func (m *MockAuthProvider) GetDelegatedAccessToken(ctx context.Context, tenantID string, userContext *auth.UserContext) (*auth.AccessToken, error) {
	args := m.Called(ctx, tenantID, userContext)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AccessToken), args.Error(1)
}

func (m *MockAuthProvider) RefreshToken(ctx context.Context, refreshToken string) (*auth.AccessToken, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AccessToken), args.Error(1)
}

func (m *MockAuthProvider) RefreshDelegatedToken(ctx context.Context, refreshToken string, userContext *auth.UserContext) (*auth.AccessToken, error) {
	args := m.Called(ctx, refreshToken, userContext)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AccessToken), args.Error(1)
}

func (m *MockAuthProvider) IsTokenValid(token *auth.AccessToken) bool {
	args := m.Called(token)
	return args.Bool(0)
}

func (m *MockAuthProvider) ValidatePermissions(ctx context.Context, token *auth.AccessToken, requiredScopes []string) error {
	args := m.Called(ctx, token, requiredScopes)
	return args.Error(0)
}

type MockGraphClient struct {
	mock.Mock
}

// Implementation of all required Graph client methods (simplified for testing)
func (m *MockGraphClient) GetUser(ctx context.Context, token *auth.AccessToken, userPrincipalName string) (*graph.User, error) {
	args := m.Called(ctx, token, userPrincipalName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.User), args.Error(1)
}

func (m *MockGraphClient) CreateUser(ctx context.Context, token *auth.AccessToken, request *graph.CreateUserRequest) (*graph.User, error) {
	args := m.Called(ctx, token, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.User), args.Error(1)
}

func (m *MockGraphClient) UpdateUser(ctx context.Context, token *auth.AccessToken, userID string, request *graph.UpdateUserRequest) error {
	args := m.Called(ctx, token, userID, request)
	return args.Error(0)
}

func (m *MockGraphClient) DeleteUser(ctx context.Context, token *auth.AccessToken, userID string) error {
	args := m.Called(ctx, token, userID)
	return args.Error(0)
}

func (m *MockGraphClient) GetUserLicenses(ctx context.Context, token *auth.AccessToken, userID string) ([]graph.LicenseAssignment, error) {
	args := m.Called(ctx, token, userID)
	return args.Get(0).([]graph.LicenseAssignment), args.Error(1)
}

func (m *MockGraphClient) AssignLicense(ctx context.Context, token *auth.AccessToken, userID, skuID string, disabledPlans []string) error {
	args := m.Called(ctx, token, userID, skuID, disabledPlans)
	return args.Error(0)
}

func (m *MockGraphClient) RemoveLicense(ctx context.Context, token *auth.AccessToken, userID, skuID string) error {
	args := m.Called(ctx, token, userID, skuID)
	return args.Error(0)
}

func (m *MockGraphClient) GetUserGroups(ctx context.Context, token *auth.AccessToken, userID string) ([]string, error) {
	args := m.Called(ctx, token, userID)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockGraphClient) AddUserToGroup(ctx context.Context, token *auth.AccessToken, userID, groupName string) error {
	args := m.Called(ctx, token, userID, groupName)
	return args.Error(0)
}

func (m *MockGraphClient) RemoveUserFromGroup(ctx context.Context, token *auth.AccessToken, userID, groupName string) error {
	args := m.Called(ctx, token, userID, groupName)
	return args.Error(0)
}

func (m *MockGraphClient) GetConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, policyID string) (*graph.ConditionalAccessPolicy, error) {
	args := m.Called(ctx, token, policyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.ConditionalAccessPolicy), args.Error(1)
}

func (m *MockGraphClient) CreateConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, request *graph.CreateConditionalAccessPolicyRequest) (*graph.ConditionalAccessPolicy, error) {
	args := m.Called(ctx, token, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.ConditionalAccessPolicy), args.Error(1)
}

func (m *MockGraphClient) UpdateConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, policyID string, request *graph.UpdateConditionalAccessPolicyRequest) error {
	args := m.Called(ctx, token, policyID, request)
	return args.Error(0)
}

func (m *MockGraphClient) DeleteConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, policyID string) error {
	args := m.Called(ctx, token, policyID)
	return args.Error(0)
}

func (m *MockGraphClient) GetDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string) (*graph.DeviceConfiguration, error) {
	args := m.Called(ctx, token, configurationID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.DeviceConfiguration), args.Error(1)
}

func (m *MockGraphClient) CreateDeviceConfiguration(ctx context.Context, token *auth.AccessToken, request *graph.CreateDeviceConfigurationRequest) (*graph.DeviceConfiguration, error) {
	args := m.Called(ctx, token, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.DeviceConfiguration), args.Error(1)
}

func (m *MockGraphClient) UpdateDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string, request *graph.UpdateDeviceConfigurationRequest) error {
	args := m.Called(ctx, token, configurationID, request)
	return args.Error(0)
}

func (m *MockGraphClient) DeleteDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string) error {
	args := m.Called(ctx, token, configurationID)
	return args.Error(0)
}

// Application operations
func (m *MockGraphClient) GetApplication(ctx context.Context, token *auth.AccessToken, applicationID string) (*graph.Application, error) {
	args := m.Called(ctx, token, applicationID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.Application), args.Error(1)
}

func (m *MockGraphClient) CreateApplication(ctx context.Context, token *auth.AccessToken, request *graph.CreateApplicationRequest) (*graph.Application, error) {
	args := m.Called(ctx, token, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.Application), args.Error(1)
}

func (m *MockGraphClient) UpdateApplication(ctx context.Context, token *auth.AccessToken, applicationID string, request *graph.UpdateApplicationRequest) error {
	args := m.Called(ctx, token, applicationID, request)
	return args.Error(0)
}

func (m *MockGraphClient) DeleteApplication(ctx context.Context, token *auth.AccessToken, applicationID string) error {
	args := m.Called(ctx, token, applicationID)
	return args.Error(0)
}

func (m *MockGraphClient) ListApplications(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.Application, error) {
	args := m.Called(ctx, token, filter)
	return args.Get(0).([]graph.Application), args.Error(1)
}

// Administrative Unit operations
func (m *MockGraphClient) GetAdministrativeUnit(ctx context.Context, token *auth.AccessToken, unitID string) (*graph.AdministrativeUnit, error) {
	args := m.Called(ctx, token, unitID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.AdministrativeUnit), args.Error(1)
}

func (m *MockGraphClient) CreateAdministrativeUnit(ctx context.Context, token *auth.AccessToken, request *graph.CreateAdministrativeUnitRequest) (*graph.AdministrativeUnit, error) {
	args := m.Called(ctx, token, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.AdministrativeUnit), args.Error(1)
}

func (m *MockGraphClient) UpdateAdministrativeUnit(ctx context.Context, token *auth.AccessToken, unitID string, request *graph.UpdateAdministrativeUnitRequest) error {
	args := m.Called(ctx, token, unitID, request)
	return args.Error(0)
}

func (m *MockGraphClient) DeleteAdministrativeUnit(ctx context.Context, token *auth.AccessToken, unitID string) error {
	args := m.Called(ctx, token, unitID)
	return args.Error(0)
}

func (m *MockGraphClient) ListAdministrativeUnits(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.AdministrativeUnit, error) {
	args := m.Called(ctx, token, filter)
	return args.Get(0).([]graph.AdministrativeUnit), args.Error(1)
}

// Group operations (extend existing)
func (m *MockGraphClient) GetGroup(ctx context.Context, token *auth.AccessToken, groupID string) (*graph.Group, error) {
	args := m.Called(ctx, token, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.Group), args.Error(1)
}

func (m *MockGraphClient) CreateGroup(ctx context.Context, token *auth.AccessToken, request *graph.CreateGroupRequest) (*graph.Group, error) {
	args := m.Called(ctx, token, request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.Group), args.Error(1)
}

func (m *MockGraphClient) UpdateGroup(ctx context.Context, token *auth.AccessToken, groupID string, request *graph.UpdateGroupRequest) error {
	args := m.Called(ctx, token, groupID, request)
	return args.Error(0)
}

func (m *MockGraphClient) DeleteGroup(ctx context.Context, token *auth.AccessToken, groupID string) error {
	args := m.Called(ctx, token, groupID)
	return args.Error(0)
}

// Test functions

func TestNew(t *testing.T) {
	mockAuth := &MockAuthProvider{}
	mockGraph := &MockGraphClient{}

	module := New(mockAuth, mockGraph)
	assert.NotNil(t, module)
}

func TestEntraAdminUnitConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *EntraAdminUnitConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &EntraAdminUnitConfig{
				DisplayName: "Test Admin Unit",
				TenantID:    "test-tenant-id",
				Visibility:  "Public",
			},
			expectError: false,
		},
		{
			name: "missing display name",
			config: &EntraAdminUnitConfig{
				TenantID: "test-tenant-id",
			},
			expectError: true,
			errorMsg:    "display_name is required",
		},
		{
			name: "missing tenant ID",
			config: &EntraAdminUnitConfig{
				DisplayName: "Test Admin Unit",
			},
			expectError: true,
			errorMsg:    "tenant_id is required",
		},
		{
			name: "invalid visibility",
			config: &EntraAdminUnitConfig{
				DisplayName: "Test Admin Unit",
				TenantID:    "test-tenant-id",
				Visibility:  "Invalid",
			},
			expectError: true,
			errorMsg:    "invalid visibility: Invalid",
		},
		{
			name: "valid hidden membership visibility",
			config: &EntraAdminUnitConfig{
				DisplayName: "Test Admin Unit",
				TenantID:    "test-tenant-id",
				Visibility:  "HiddenMembership",
			},
			expectError: false,
		},
		{
			name: "invalid membership type",
			config: &EntraAdminUnitConfig{
				DisplayName:    "Test Admin Unit",
				TenantID:       "test-tenant-id",
				MembershipType: "Invalid",
			},
			expectError: true,
			errorMsg:    "invalid membership_type: Invalid",
		},
		{
			name: "valid dynamic membership",
			config: &EntraAdminUnitConfig{
				DisplayName:    "Test Admin Unit",
				TenantID:       "test-tenant-id",
				MembershipType: "Dynamic",
				MembershipRule: "user.department -eq \"Engineering\"",
			},
			expectError: false,
		},
		{
			name: "dynamic membership without rule",
			config: &EntraAdminUnitConfig{
				DisplayName:    "Test Admin Unit",
				TenantID:       "test-tenant-id",
				MembershipType: "Dynamic",
			},
			expectError: true,
			errorMsg:    "membership_rule is required when membership_type is Dynamic",
		},
		{
			name: "valid assigned membership",
			config: &EntraAdminUnitConfig{
				DisplayName:    "Test Admin Unit",
				TenantID:       "test-tenant-id",
				MembershipType: "Assigned",
				UserMembers:    []string{"user1", "user2"},
			},
			expectError: false,
		},
		{
			name: "valid scoped role member",
			config: &EntraAdminUnitConfig{
				DisplayName: "Test Admin Unit",
				TenantID:    "test-tenant-id",
				ScopedRoleMembers: []ScopedRoleMember{
					{
						PrincipalID:      "user123",
						PrincipalType:    "User",
						RoleDefinitionID: "role456",
						RoleName:         "User Administrator",
					},
				},
			},
			expectError: false,
		},
		{
			name: "scoped role member missing principal ID",
			config: &EntraAdminUnitConfig{
				DisplayName: "Test Admin Unit",
				TenantID:    "test-tenant-id",
				ScopedRoleMembers: []ScopedRoleMember{
					{
						RoleDefinitionID: "role456",
					},
				},
			},
			expectError: true,
			errorMsg:    "scoped_role_member 0: principal_id is required",
		},
		{
			name: "scoped role member missing role definition ID",
			config: &EntraAdminUnitConfig{
				DisplayName: "Test Admin Unit",
				TenantID:    "test-tenant-id",
				ScopedRoleMembers: []ScopedRoleMember{
					{
						PrincipalID: "user123",
					},
				},
			},
			expectError: true,
			errorMsg:    "scoped_role_member 0: role_definition_id is required",
		},
		{
			name: "scoped role member invalid principal type",
			config: &EntraAdminUnitConfig{
				DisplayName: "Test Admin Unit",
				TenantID:    "test-tenant-id",
				ScopedRoleMembers: []ScopedRoleMember{
					{
						PrincipalID:      "user123",
						PrincipalType:    "Invalid",
						RoleDefinitionID: "role456",
					},
				},
			},
			expectError: true,
			errorMsg:    "scoped_role_member 0: invalid principal_type: Invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEntraAdminUnitConfig_AsMap(t *testing.T) {
	config := &EntraAdminUnitConfig{
		DisplayName:    "Test Admin Unit",
		Description:    "Test description",
		Visibility:     "Public",
		MembershipType: "Assigned",
		UserMembers:    []string{"user1", "user2"},
		ScopedRoleMembers: []ScopedRoleMember{
			{
				PrincipalID:      "user123",
				RoleDefinitionID: "role456",
			},
		},
		ExtensionAttributes: map[string]interface{}{
			"customAttribute": "value",
		},
		IsMemberManagementRestricted: true,
		RestrictedManagementUnits:    []string{"unit1", "unit2"},
		TenantID:                     "test-tenant-id",
	}

	result := config.AsMap()

	expectedKeys := []string{
		"display_name", "description", "visibility", "membership_type",
		"user_members", "scoped_role_members", "extension_attributes",
		"is_member_management_restricted", "restricted_management_units",
		"tenant_id",
	}

	for _, key := range expectedKeys {
		assert.Contains(t, result, key, "Expected key %s to be present in map", key)
	}

	assert.Equal(t, "Test Admin Unit", result["display_name"])
	assert.Equal(t, "Test description", result["description"])
	assert.Equal(t, "Public", result["visibility"])
	assert.Equal(t, "Assigned", result["membership_type"])
	assert.Equal(t, []string{"user1", "user2"}, result["user_members"])
	assert.True(t, result["is_member_management_restricted"].(bool))
	assert.Equal(t, "test-tenant-id", result["tenant_id"])
}

func TestEntraAdminUnitConfig_AsMap_MinimalConfig(t *testing.T) {
	config := &EntraAdminUnitConfig{
		DisplayName: "Minimal Admin Unit",
		Visibility:  "Public",
		TenantID:    "test-tenant-id",
	}

	result := config.AsMap()

	// Should contain required fields only
	assert.Contains(t, result, "display_name")
	assert.Contains(t, result, "visibility")
	assert.Contains(t, result, "tenant_id")

	// Should not contain optional fields when empty
	assert.NotContains(t, result, "description")
	assert.NotContains(t, result, "membership_type")
	assert.NotContains(t, result, "user_members")
	assert.NotContains(t, result, "is_member_management_restricted")
}

func TestEntraAdminUnitConfig_GetManagedFields(t *testing.T) {
	tests := []struct {
		name           string
		config         *EntraAdminUnitConfig
		expectedFields []string
	}{
		{
			name: "explicit managed fields",
			config: &EntraAdminUnitConfig{
				DisplayName:       "Test",
				ManagedFieldsList: []string{"display_name", "description"},
			},
			expectedFields: []string{"display_name", "description"},
		},
		{
			name: "default fields - minimal config",
			config: &EntraAdminUnitConfig{
				DisplayName: "Test",
				Visibility:  "Public",
			},
			expectedFields: []string{"display_name", "visibility"},
		},
		{
			name: "default fields - with description",
			config: &EntraAdminUnitConfig{
				DisplayName: "Test",
				Description: "Test description",
				Visibility:  "Public",
			},
			expectedFields: []string{"display_name", "visibility", "description"},
		},
		{
			name: "default fields - with membership settings",
			config: &EntraAdminUnitConfig{
				DisplayName:    "Test",
				Visibility:     "Public",
				MembershipType: "Assigned",
				UserMembers:    []string{"user1"},
			},
			expectedFields: []string{"display_name", "visibility", "membership_type", "user_members"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := tt.config.GetManagedFields()

			// Check that all expected fields are present
			for _, expectedField := range tt.expectedFields {
				assert.Contains(t, fields, expectedField, "Expected field %s to be managed", expectedField)
			}

			// For explicit managed fields, check exact match
			if len(tt.config.ManagedFieldsList) > 0 {
				assert.Equal(t, tt.expectedFields, fields)
			}
		})
	}
}

func TestEntraAdminUnitConfig_YAMLSerialization(t *testing.T) {
	config := &EntraAdminUnitConfig{
		DisplayName:    "Test Admin Unit",
		Description:    "Test description",
		Visibility:     "Public",
		MembershipType: "Assigned",
		UserMembers:    []string{"user1", "user2"},
		ScopedRoleMembers: []ScopedRoleMember{
			{
				PrincipalID:      "user123",
				PrincipalType:    "User",
				RoleDefinitionID: "role456",
				RoleName:         "User Administrator",
			},
		},
		TenantID: "test-tenant-id",
	}

	// Test ToYAML
	yamlData, err := config.ToYAML()
	assert.NoError(t, err)
	assert.NotEmpty(t, yamlData)

	// Test FromYAML
	var deserializedConfig EntraAdminUnitConfig
	err = deserializedConfig.FromYAML(yamlData)
	assert.NoError(t, err)

	// Verify deserialized config matches original
	assert.Equal(t, config.DisplayName, deserializedConfig.DisplayName)
	assert.Equal(t, config.Description, deserializedConfig.Description)
	assert.Equal(t, config.Visibility, deserializedConfig.Visibility)
	assert.Equal(t, config.MembershipType, deserializedConfig.MembershipType)
	assert.Equal(t, config.UserMembers, deserializedConfig.UserMembers)
	assert.Equal(t, config.TenantID, deserializedConfig.TenantID)
	assert.Equal(t, len(config.ScopedRoleMembers), len(deserializedConfig.ScopedRoleMembers))

	if len(deserializedConfig.ScopedRoleMembers) > 0 {
		assert.Equal(t, config.ScopedRoleMembers[0].PrincipalID, deserializedConfig.ScopedRoleMembers[0].PrincipalID)
		assert.Equal(t, config.ScopedRoleMembers[0].PrincipalType, deserializedConfig.ScopedRoleMembers[0].PrincipalType)
		assert.Equal(t, config.ScopedRoleMembers[0].RoleDefinitionID, deserializedConfig.ScopedRoleMembers[0].RoleDefinitionID)
		assert.Equal(t, config.ScopedRoleMembers[0].RoleName, deserializedConfig.ScopedRoleMembers[0].RoleName)
	}
}

func TestEntraAdminUnitConfig_YAMLSerialization_InvalidYAML(t *testing.T) {
	var config EntraAdminUnitConfig
	invalidYAML := []byte("invalid: yaml: content: [")

	err := config.FromYAML(invalidYAML)
	assert.Error(t, err)
}

func TestScopedRoleMember_CompleteStructure(t *testing.T) {
	roleMember := ScopedRoleMember{
		PrincipalID:      "user-12345",
		PrincipalType:    "User",
		RoleDefinitionID: "role-67890",
		RoleName:         "Helpdesk Administrator",
		AssignmentType:   "Active",
		StartDateTime:    "2023-01-01T00:00:00Z",
		EndDateTime:      "2023-12-31T23:59:59Z",
		Justification:    "Required for helpdesk operations",
	}

	// Test that all fields are properly set
	assert.Equal(t, "user-12345", roleMember.PrincipalID)
	assert.Equal(t, "User", roleMember.PrincipalType)
	assert.Equal(t, "role-67890", roleMember.RoleDefinitionID)
	assert.Equal(t, "Helpdesk Administrator", roleMember.RoleName)
	assert.Equal(t, "Active", roleMember.AssignmentType)
	assert.Equal(t, "2023-01-01T00:00:00Z", roleMember.StartDateTime)
	assert.Equal(t, "2023-12-31T23:59:59Z", roleMember.EndDateTime)
	assert.Equal(t, "Required for helpdesk operations", roleMember.Justification)

	// Test YAML serialization of ScopedRoleMember
	data, err := yaml.Marshal(roleMember)
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	var deserializedRoleMember ScopedRoleMember
	err = yaml.Unmarshal(data, &deserializedRoleMember)
	assert.NoError(t, err)
	assert.Equal(t, roleMember, deserializedRoleMember)
}

func TestEntraAdminUnitConfig_ExtensionAttributes(t *testing.T) {
	config := &EntraAdminUnitConfig{
		DisplayName: "Test Admin Unit",
		TenantID:    "test-tenant-id",
		ExtensionAttributes: map[string]interface{}{
			"department":    "IT",
			"costCenter":    12345,
			"isProduction":  true,
			"customFields":  []string{"field1", "field2"},
		},
	}

	// Test AsMap includes extension attributes
	result := config.AsMap()
	assert.Contains(t, result, "extension_attributes")
	
	extensionAttrs := result["extension_attributes"].(map[string]interface{})
	assert.Equal(t, "IT", extensionAttrs["department"])
	assert.Equal(t, 12345, extensionAttrs["costCenter"])
	assert.Equal(t, true, extensionAttrs["isProduction"])

	// Test YAML serialization preserves extension attributes
	yamlData, err := config.ToYAML()
	assert.NoError(t, err)

	var deserializedConfig EntraAdminUnitConfig
	err = deserializedConfig.FromYAML(yamlData)
	assert.NoError(t, err)
	
	// Check individual attributes (YAML deserialization may change slice types)
	assert.Equal(t, "IT", deserializedConfig.ExtensionAttributes["department"])
	assert.Equal(t, 12345, deserializedConfig.ExtensionAttributes["costCenter"])
	assert.Equal(t, true, deserializedConfig.ExtensionAttributes["isProduction"])
	
	// Check that custom fields array exists and has correct length
	customFields := deserializedConfig.ExtensionAttributes["customFields"]
	assert.NotNil(t, customFields)
	if arr, ok := customFields.([]interface{}); ok {
		assert.Len(t, arr, 2)
		assert.Equal(t, "field1", arr[0])
		assert.Equal(t, "field2", arr[1])
	}
}