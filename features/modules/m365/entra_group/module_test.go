// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package entra_group

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
)

// MockAuthProvider is a mock implementation of auth.Provider
type MockAuthProvider struct {
	mock.Mock
}

func (m *MockAuthProvider) GetAccessToken(ctx context.Context, tenantID string) (*auth.AccessToken, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).(*auth.AccessToken), args.Error(1)
}

func (m *MockAuthProvider) GetDelegatedAccessToken(ctx context.Context, tenantID string, userContext *auth.UserContext) (*auth.AccessToken, error) {
	args := m.Called(ctx, tenantID, userContext)
	return args.Get(0).(*auth.AccessToken), args.Error(1)
}

func (m *MockAuthProvider) RefreshToken(ctx context.Context, refreshToken string) (*auth.AccessToken, error) {
	args := m.Called(ctx, refreshToken)
	return args.Get(0).(*auth.AccessToken), args.Error(1)
}

func (m *MockAuthProvider) RefreshDelegatedToken(ctx context.Context, refreshToken string, userContext *auth.UserContext) (*auth.AccessToken, error) {
	args := m.Called(ctx, refreshToken, userContext)
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

// MockGraphClient is a mock implementation of graph.Client
type MockGraphClient struct {
	mock.Mock
}

func (m *MockGraphClient) GetUser(ctx context.Context, token *auth.AccessToken, userPrincipalName string) (*graph.User, error) {
	args := m.Called(ctx, token, userPrincipalName)
	return args.Get(0).(*graph.User), args.Error(1)
}

func (m *MockGraphClient) ListUsers(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.User, error) {
	args := m.Called(ctx, token, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]graph.User), args.Error(1)
}

func (m *MockGraphClient) CreateUser(ctx context.Context, token *auth.AccessToken, request *graph.CreateUserRequest) (*graph.User, error) {
	args := m.Called(ctx, token, request)
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
	return args.Get(0).(*graph.ConditionalAccessPolicy), args.Error(1)
}

func (m *MockGraphClient) CreateConditionalAccessPolicy(ctx context.Context, token *auth.AccessToken, request *graph.CreateConditionalAccessPolicyRequest) (*graph.ConditionalAccessPolicy, error) {
	args := m.Called(ctx, token, request)
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
	return args.Get(0).(*graph.DeviceConfiguration), args.Error(1)
}

func (m *MockGraphClient) CreateDeviceConfiguration(ctx context.Context, token *auth.AccessToken, request *graph.CreateDeviceConfigurationRequest) (*graph.DeviceConfiguration, error) {
	args := m.Called(ctx, token, request)
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

func (m *MockGraphClient) ListDeviceConfigurationAssignments(ctx context.Context, token *auth.AccessToken, configurationID string) ([]graph.DeviceConfigurationAssignment, error) {
	args := m.Called(ctx, token, configurationID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]graph.DeviceConfigurationAssignment), args.Error(1)
}

func (m *MockGraphClient) AssignDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string, assignments []graph.DeviceConfigurationAssignment) error {
	args := m.Called(ctx, token, configurationID, assignments)
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

func (m *MockGraphClient) ListApplications(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.Application, error) {
	args := m.Called(ctx, token, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]graph.Application), args.Error(1)
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

// Administrative Unit operations
func (m *MockGraphClient) GetAdministrativeUnit(ctx context.Context, token *auth.AccessToken, unitID string) (*graph.AdministrativeUnit, error) {
	args := m.Called(ctx, token, unitID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.AdministrativeUnit), args.Error(1)
}

func (m *MockGraphClient) ListAdministrativeUnits(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.AdministrativeUnit, error) {
	args := m.Called(ctx, token, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]graph.AdministrativeUnit), args.Error(1)
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

// Group operations (extend existing)
func (m *MockGraphClient) GetGroup(ctx context.Context, token *auth.AccessToken, groupID string) (*graph.Group, error) {
	args := m.Called(ctx, token, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.Group), args.Error(1)
}

func (m *MockGraphClient) ListGroups(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.Group, error) {
	args := m.Called(ctx, token, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]graph.Group), args.Error(1)
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

func (m *MockGraphClient) ListGroupMembers(ctx context.Context, token *auth.AccessToken, groupID string) ([]string, error) {
	return nil, nil
}

func (m *MockGraphClient) AddGroupMember(ctx context.Context, token *auth.AccessToken, groupID, memberUPN string) error {
	return nil
}

func (m *MockGraphClient) RemoveGroupMember(ctx context.Context, token *auth.AccessToken, groupID, memberUPN string) error {
	return nil
}

func (m *MockGraphClient) ListGroupOwners(ctx context.Context, token *auth.AccessToken, groupID string) ([]string, error) {
	return nil, nil
}

func (m *MockGraphClient) AddGroupOwner(ctx context.Context, token *auth.AccessToken, groupID, ownerUPN string) error {
	return nil
}

func (m *MockGraphClient) RemoveGroupOwner(ctx context.Context, token *auth.AccessToken, groupID, ownerUPN string) error {
	return nil
}

func (m *MockGraphClient) ListAdminUnitUserMembers(ctx context.Context, token *auth.AccessToken, unitID string) ([]string, error) {
	return nil, nil
}

func (m *MockGraphClient) ListAdminUnitGroupMembers(ctx context.Context, token *auth.AccessToken, unitID string) ([]string, error) {
	return nil, nil
}

func (m *MockGraphClient) ListAdminUnitScopedRoleMembers(ctx context.Context, token *auth.AccessToken, unitID string) ([]graph.AdminUnitScopedRoleMember, error) {
	return nil, nil
}

func (m *MockGraphClient) AddAdminUnitMember(ctx context.Context, token *auth.AccessToken, unitID, memberID string) error {
	return nil
}

func (m *MockGraphClient) AddAdminUnitScopedRoleMember(ctx context.Context, token *auth.AccessToken, unitID string, request *graph.AddScopedRoleMemberRequest) (*graph.AdminUnitScopedRoleMember, error) {
	return nil, nil
}

func (m *MockGraphClient) RemoveAdminUnitMember(ctx context.Context, token *auth.AccessToken, unitID, memberID string) error {
	return nil
}

func (m *MockGraphClient) RemoveAdminUnitScopedRoleMember(ctx context.Context, token *auth.AccessToken, unitID, scopedRoleMemberID string) error {
	return nil
}

func (m *MockGraphClient) GetTeam(ctx context.Context, token *auth.AccessToken, groupID string) (*graph.Team, error) {
	args := m.Called(ctx, token, groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*graph.Team), args.Error(1)
}

func (m *MockGraphClient) CreateTeam(ctx context.Context, token *auth.AccessToken, groupID string, request *graph.CreateTeamRequest) error {
	args := m.Called(ctx, token, groupID, request)
	return args.Error(0)
}

func (m *MockGraphClient) UpdateTeamSettings(ctx context.Context, token *auth.AccessToken, teamID string, request *graph.UpdateTeamSettingsRequest) error {
	args := m.Called(ctx, token, teamID, request)
	return args.Error(0)
}

func TestEntraGroupConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *EntraGroupConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid configuration",
			config: &EntraGroupConfig{
				DisplayName:     "Test Group",
				MailNickname:    "testgroup",
				TenantID:        "test-tenant-id",
				MailEnabled:     false,
				SecurityEnabled: true,
			},
			wantErr: false,
		},
		{
			name: "missing display name",
			config: &EntraGroupConfig{
				MailNickname:    "testgroup",
				TenantID:        "test-tenant-id",
				MailEnabled:     false,
				SecurityEnabled: true,
			},
			wantErr: true,
			errMsg:  "display_name is required",
		},
		{
			name: "missing mail nickname",
			config: &EntraGroupConfig{
				DisplayName:     "Test Group",
				TenantID:        "test-tenant-id",
				MailEnabled:     false,
				SecurityEnabled: true,
			},
			wantErr: true,
			errMsg:  "mail_nickname is required",
		},
		{
			name: "missing tenant ID",
			config: &EntraGroupConfig{
				DisplayName:     "Test Group",
				MailNickname:    "testgroup",
				MailEnabled:     false,
				SecurityEnabled: true,
			},
			wantErr: true,
			errMsg:  "tenant_id is required",
		},
		{
			name: "invalid group type",
			config: &EntraGroupConfig{
				DisplayName:     "Test Group",
				MailNickname:    "testgroup",
				TenantID:        "test-tenant-id",
				GroupType:       "InvalidType",
				MailEnabled:     false,
				SecurityEnabled: true,
			},
			wantErr: true,
			errMsg:  "invalid group_type: InvalidType",
		},
		{
			name: "invalid visibility",
			config: &EntraGroupConfig{
				DisplayName:     "Test Group",
				MailNickname:    "testgroup",
				TenantID:        "test-tenant-id",
				Visibility:      "InvalidVisibility",
				MailEnabled:     false,
				SecurityEnabled: true,
			},
			wantErr: true,
			errMsg:  "invalid visibility: InvalidVisibility",
		},
		{
			name: "team channel without display name",
			config: &EntraGroupConfig{
				DisplayName:   "Test Group",
				MailNickname:  "testgroup",
				TenantID:      "test-tenant-id",
				IsTeamEnabled: true,
				TeamChannels: []TeamChannel{
					{Description: "Test channel without name"},
				},
				MailEnabled:     false,
				SecurityEnabled: true,
			},
			wantErr: true,
			errMsg:  "team channel 0: display_name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEntraGroupConfig_GetManagedFields(t *testing.T) {
	tests := []struct {
		name     string
		config   *EntraGroupConfig
		expected []string
	}{
		{
			name: "basic configuration",
			config: &EntraGroupConfig{
				DisplayName:     "Test Group",
				MailEnabled:     false,
				SecurityEnabled: true,
			},
			expected: []string{"display_name", "mail_enabled", "security_enabled"},
		},
		{
			name: "configuration with optional fields",
			config: &EntraGroupConfig{
				DisplayName:     "Test Group",
				Description:     "Test description",
				GroupType:       "Security",
				Visibility:      "Private",
				Members:         []string{"user1", "user2"},
				Owners:          []string{"owner1"},
				MailEnabled:     false,
				SecurityEnabled: true,
			},
			expected: []string{
				"display_name", "mail_enabled", "security_enabled",
				"description", "group_type", "visibility", "members", "owners",
			},
		},
		{
			name: "team-enabled group",
			config: &EntraGroupConfig{
				DisplayName:     "Test Team",
				IsTeamEnabled:   true,
				TeamSettings:    &TeamSettings{AllowAddRemoveApps: true},
				TeamChannels:    []TeamChannel{{DisplayName: "General"}},
				MailEnabled:     true,
				SecurityEnabled: false,
			},
			expected: []string{
				"display_name", "mail_enabled", "security_enabled",
				"is_team_enabled", "team_settings", "team_channels",
			},
		},
		{
			name: "explicit managed fields",
			config: &EntraGroupConfig{
				DisplayName:       "Test Group",
				Description:       "This won't be managed",
				ManagedFieldsList: []string{"display_name", "members"},
				MailEnabled:       false,
				SecurityEnabled:   true,
			},
			expected: []string{"display_name", "members"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetManagedFields()
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestEntraGroupConfig_AsMap(t *testing.T) {
	config := &EntraGroupConfig{
		DisplayName:     "Test Group",
		Description:     "Test description",
		MailNickname:    "testgroup",
		MailEnabled:     false,
		SecurityEnabled: true,
		GroupType:       "Security",
		Visibility:      "Private",
		Members:         []string{"user1", "user2"},
		Owners:          []string{"owner1"},
		TenantID:        "test-tenant-id",
	}

	result := config.AsMap()

	expected := map[string]interface{}{
		"display_name":     "Test Group",
		"description":      "Test description",
		"mail_nickname":    "testgroup",
		"mail_enabled":     false,
		"security_enabled": true,
		"group_type":       "Security",
		"visibility":       "Private",
		"members":          []string{"user1", "user2"},
		"owners":           []string{"owner1"},
		"tenant_id":        "test-tenant-id",
	}

	assert.Equal(t, expected, result)
}

func TestEntraGroupModule_Creation(t *testing.T) {
	mockAuth := &MockAuthProvider{}
	mockGraph := &MockGraphClient{}

	module := New(mockAuth, mockGraph)
	assert.NotNil(t, module)

	// Verify it's the correct type
	groupModule, ok := module.(*entraGroupModule)
	assert.True(t, ok)
	assert.Equal(t, mockAuth, groupModule.authProvider)
	assert.Equal(t, mockGraph, groupModule.graphClient)
}

func TestParseEntraGroupResourceID(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		wantTenant string
		wantGroup  string
		wantErr    bool
	}{
		{
			name:       "valid resource ID",
			resourceID: "tenant-123:group-456",
			wantTenant: "tenant-123",
			wantGroup:  "group-456",
			wantErr:    false,
		},
		{
			name:       "invalid resource ID - missing colon",
			resourceID: "tenant-123-group-456",
			wantErr:    true,
		},
		{
			name:       "invalid resource ID - missing group",
			resourceID: "tenant-123:",
			wantTenant: "tenant-123",
			wantGroup:  "",
			wantErr:    false,
		},
		{
			name:       "invalid resource ID - empty",
			resourceID: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant, group, err := parseEntraGroupResourceID(tt.resourceID)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantTenant, tenant)
				assert.Equal(t, tt.wantGroup, group)
			}
		})
	}
}

func TestEntraGroupConfig_ToYAML(t *testing.T) {
	config := &EntraGroupConfig{
		DisplayName:     "Test Group",
		Description:     "Test description",
		MailNickname:    "testgroup",
		MailEnabled:     false,
		SecurityEnabled: true,
		TenantID:        "test-tenant-id",
	}

	yaml, err := config.ToYAML()
	assert.NoError(t, err)
	assert.Contains(t, string(yaml), "display_name: Test Group")
	assert.Contains(t, string(yaml), "tenant_id: test-tenant-id")
}

func TestEntraGroupConfig_FromYAML(t *testing.T) {
	yamlData := `
display_name: Test Group
description: Test description
mail_nickname: testgroup
mail_enabled: false
security_enabled: true
tenant_id: test-tenant-id
`

	config := &EntraGroupConfig{}
	err := config.FromYAML([]byte(yamlData))
	assert.NoError(t, err)

	assert.Equal(t, "Test Group", config.DisplayName)
	assert.Equal(t, "Test description", config.Description)
	assert.Equal(t, "testgroup", config.MailNickname)
	assert.Equal(t, false, config.MailEnabled)
	assert.Equal(t, true, config.SecurityEnabled)
	assert.Equal(t, "test-tenant-id", config.TenantID)
}

// TestEntraGroupModule_Set_CreateNewGroup verifies Set() creates a group when none exists
func TestEntraGroupModule_Set_CreateNewGroup(t *testing.T) {
	mockAuth := &MockAuthProvider{}
	mockGraph := &MockGraphClient{}

	token := &auth.AccessToken{
		Token:     "mock-token",
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		TenantID:  "test-tenant-id",
	}
	mockAuth.On("GetAccessToken", mock.Anything, "test-tenant-id").Return(token, nil)

	// GetGroup returns not-found → falls back to ListGroups by display name
	mockGraph.On("GetGroup", mock.Anything, token, "new-group").
		Return((*graph.Group)(nil), &graph.GraphError{StatusCode: 404, Code: "Request_ResourceNotFound", Message: "not found"})
	// ListGroups returns empty → no duplicate, proceeds to create
	mockGraph.On("ListGroups", mock.Anything, token, mock.Anything).
		Return([]graph.Group{}, nil)

	createdGroup := &graph.Group{
		ID:           "new-group",
		DisplayName:  "Test Security Group",
		MailNickname: "testsecuritygroup",
	}
	mockGraph.On("CreateGroup", mock.Anything, token, mock.Anything).Return(createdGroup, nil)

	// Use zero propagation delay to avoid 2-second stall in unit tests
	module := &entraGroupModule{
		authProvider:     mockAuth,
		graphClient:      mockGraph,
		propagationDelay: 0,
	}

	config := &EntraGroupConfig{
		DisplayName:     "Test Security Group",
		MailNickname:    "testsecuritygroup",
		MailEnabled:     false,
		SecurityEnabled: true,
		GroupType:       "Security",
		TenantID:        "test-tenant-id",
	}

	err := module.Set(context.Background(), "test-tenant-id:new-group", config)
	assert.NoError(t, err)
	mockAuth.AssertExpectations(t)
	mockGraph.AssertExpectations(t)
}

// TestEntraGroupModule_Set_AuthError verifies Set() returns an error when auth fails
func TestEntraGroupModule_Set_AuthError(t *testing.T) {
	mockAuth := &MockAuthProvider{}
	mockGraph := &MockGraphClient{}

	mockAuth.On("GetAccessToken", mock.Anything, "test-tenant-id").
		Return((*auth.AccessToken)(nil), fmt.Errorf("auth failure"))

	module := New(mockAuth, mockGraph)

	config := &EntraGroupConfig{
		DisplayName:     "Test Group",
		MailNickname:    "testgroup",
		MailEnabled:     false,
		SecurityEnabled: true,
		TenantID:        "test-tenant-id",
	}

	err := module.Set(context.Background(), "test-tenant-id:some-group", config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth failure")
	mockAuth.AssertExpectations(t)
}

func TestDiffUPNSets_AddOnly(t *testing.T) {
	current := []string{"a@contoso.com"}
	desired := []string{"a@contoso.com", "b@contoso.com"}
	toAdd, toRemove := diffUPNSets(current, desired)
	assert.ElementsMatch(t, []string{"b@contoso.com"}, toAdd)
	assert.Empty(t, toRemove)
}

func TestDiffUPNSets_RemoveOnly(t *testing.T) {
	current := []string{"a@contoso.com", "b@contoso.com"}
	desired := []string{"a@contoso.com"}
	toAdd, toRemove := diffUPNSets(current, desired)
	assert.Empty(t, toAdd)
	assert.ElementsMatch(t, []string{"b@contoso.com"}, toRemove)
}

func TestDiffUPNSets_Mixed(t *testing.T) {
	current := []string{"a@contoso.com", "b@contoso.com"}
	desired := []string{"b@contoso.com", "c@contoso.com"}
	toAdd, toRemove := diffUPNSets(current, desired)
	assert.ElementsMatch(t, []string{"c@contoso.com"}, toAdd)
	assert.ElementsMatch(t, []string{"a@contoso.com"}, toRemove)
}

func TestDiffUPNSets_NoOp(t *testing.T) {
	current := []string{"a@contoso.com", "b@contoso.com"}
	desired := []string{"a@contoso.com", "b@contoso.com"}
	toAdd, toRemove := diffUPNSets(current, desired)
	assert.Empty(t, toAdd)
	assert.Empty(t, toRemove)
}

func TestDiffUPNSets_EmptyCurrent(t *testing.T) {
	current := []string{}
	desired := []string{"a@contoso.com", "b@contoso.com"}
	toAdd, toRemove := diffUPNSets(current, desired)
	assert.ElementsMatch(t, []string{"a@contoso.com", "b@contoso.com"}, toAdd)
	assert.Empty(t, toRemove)
}

func TestDiffUPNSets_EmptyDesired(t *testing.T) {
	current := []string{"a@contoso.com", "b@contoso.com"}
	desired := []string{}
	toAdd, toRemove := diffUPNSets(current, desired)
	assert.Empty(t, toAdd)
	assert.ElementsMatch(t, []string{"a@contoso.com", "b@contoso.com"}, toRemove)
}

func TestIsTeamGroup_TeamExists(t *testing.T) {
	mockGraph := &MockGraphClient{}
	token := &auth.AccessToken{Token: "tok", TenantID: "t1"}
	mockGraph.On("GetTeam", mock.Anything, token, "group-1").
		Return(&graph.Team{ID: "group-1"}, nil)

	m := &entraGroupModule{graphClient: mockGraph}
	result := m.isTeamGroup(context.Background(), token, "group-1")
	assert.True(t, result)
	mockGraph.AssertExpectations(t)
}

func TestIsTeamGroup_NotFound(t *testing.T) {
	mockGraph := &MockGraphClient{}
	token := &auth.AccessToken{Token: "tok", TenantID: "t1"}
	mockGraph.On("GetTeam", mock.Anything, token, "group-2").
		Return((*graph.Team)(nil), &graph.GraphError{StatusCode: 404, Code: "Request_ResourceNotFound", Message: "not found"})

	m := &entraGroupModule{graphClient: mockGraph}
	result := m.isTeamGroup(context.Background(), token, "group-2")
	assert.False(t, result)
	mockGraph.AssertExpectations(t)
}

func TestIsTeamGroup_NonNotFoundError(t *testing.T) {
	mockGraph := &MockGraphClient{}
	token := &auth.AccessToken{Token: "tok", TenantID: "t1"}
	mockGraph.On("GetTeam", mock.Anything, token, "group-3").
		Return((*graph.Team)(nil), &graph.GraphError{StatusCode: 403, Code: "Authorization_RequestDenied", Message: "forbidden"})

	m := &entraGroupModule{graphClient: mockGraph}
	// Should not panic and should return false
	result := m.isTeamGroup(context.Background(), token, "group-3")
	assert.False(t, result)
	mockGraph.AssertExpectations(t)
}

func TestMapFunSettings_Strict(t *testing.T) {
	result := mapFunSettings("strict")
	assert.NotNil(t, result)
	assert.Equal(t, false, *result.AllowGiphy)
	assert.Equal(t, false, *result.AllowStickersAndMemes)
	assert.Equal(t, false, *result.AllowCustomMemes)
	assert.Nil(t, result.GiphyContentRating)
}

func TestMapFunSettings_Moderate(t *testing.T) {
	result := mapFunSettings("moderate")
	assert.NotNil(t, result)
	assert.Equal(t, true, *result.AllowGiphy)
	assert.Equal(t, "strict", *result.GiphyContentRating)
	assert.Equal(t, true, *result.AllowStickersAndMemes)
	assert.Equal(t, false, *result.AllowCustomMemes)
}

func TestMapFunSettings_Enabled(t *testing.T) {
	result := mapFunSettings("enabled")
	assert.NotNil(t, result)
	assert.Equal(t, true, *result.AllowGiphy)
	assert.Equal(t, "moderate", *result.GiphyContentRating)
	assert.Equal(t, true, *result.AllowStickersAndMemes)
	assert.Equal(t, true, *result.AllowCustomMemes)
}

func TestMapFunSettings_Unknown(t *testing.T) {
	result := mapFunSettings("unknown")
	assert.Nil(t, result)
}

func TestMapTeamSettingsToCreateRequest_NilSettings(t *testing.T) {
	req := mapTeamSettingsToCreateRequest(nil)
	assert.NotNil(t, req)
	assert.Nil(t, req.MemberSettings)
	assert.Nil(t, req.MessagingSettings)
	assert.Nil(t, req.FunSettings)
	assert.Nil(t, req.GuestSettings)
}

func TestMapTeamSettingsToCreateRequest_FullSettings(t *testing.T) {
	settings := &TeamSettings{
		AllowAddRemoveApps:         true,
		AllowCreatePrivateChannels: true,
		AllowCreateUpdateChannels:  false,
		AllowDeleteChannels:        false,
		AllowUserEditMessages:      true,
		AllowGuestCreateChannels:   false,
		AllowGuestDeleteChannels:   false,
		Fun:                        "moderate",
	}
	req := mapTeamSettingsToCreateRequest(settings)
	assert.NotNil(t, req.MemberSettings)
	assert.Equal(t, true, *req.MemberSettings.AllowAddRemoveApps)
	assert.Equal(t, true, *req.MemberSettings.AllowCreatePrivateChannels)
	assert.Equal(t, false, *req.MemberSettings.AllowCreateUpdateChannels)
	assert.NotNil(t, req.MessagingSettings)
	assert.Equal(t, true, *req.MessagingSettings.AllowUserEditMessages)
	assert.NotNil(t, req.FunSettings)
	assert.Equal(t, true, *req.FunSettings.AllowGiphy)
	assert.NotNil(t, req.GuestSettings)
	assert.Equal(t, false, *req.GuestSettings.AllowCreateUpdateChannels)
}

func TestCreateTeam_NonUnifiedGroupType(t *testing.T) {
	mockGraph := &MockGraphClient{}
	token := &auth.AccessToken{Token: "tok", TenantID: "t1"}

	m := &entraGroupModule{graphClient: mockGraph}
	err := m.createTeam(context.Background(), token, "group-1", "Security", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unified")
	// No Graph API calls should be made
	mockGraph.AssertNotCalled(t, "CreateTeam")
}

func TestCreateTeam_UnifiedGroup(t *testing.T) {
	mockGraph := &MockGraphClient{}
	token := &auth.AccessToken{Token: "tok", TenantID: "t1"}
	mockGraph.On("CreateTeam", mock.Anything, token, "group-1", mock.Anything).Return(nil)

	m := &entraGroupModule{graphClient: mockGraph}
	err := m.createTeam(context.Background(), token, "group-1", "Unified", nil)
	assert.NoError(t, err)
	mockGraph.AssertExpectations(t)
}

func TestUpdateTeamSettings_DelegatesToGraphClient(t *testing.T) {
	mockGraph := &MockGraphClient{}
	token := &auth.AccessToken{Token: "tok", TenantID: "t1"}
	mockGraph.On("UpdateTeamSettings", mock.Anything, token, "team-1", mock.Anything).Return(nil)

	m := &entraGroupModule{graphClient: mockGraph}
	err := m.updateTeamSettings(context.Background(), token, "team-1", &TeamSettings{Fun: "enabled"})
	assert.NoError(t, err)
	mockGraph.AssertExpectations(t)
}

func TestCreateTeam_GraphClientError(t *testing.T) {
	mockGraph := &MockGraphClient{}
	token := &auth.AccessToken{Token: "tok", TenantID: "t1"}
	graphErr := &graph.GraphError{StatusCode: 500, Code: "InternalServerError", Message: "boom"}
	mockGraph.On("CreateTeam", mock.Anything, token, "group-1", mock.Anything).Return(graphErr)

	m := &entraGroupModule{graphClient: mockGraph}
	err := m.createTeam(context.Background(), token, "group-1", "Unified", nil)
	assert.Error(t, err)
	mockGraph.AssertExpectations(t)
}

func TestUpdateTeamSettings_GraphClientError(t *testing.T) {
	mockGraph := &MockGraphClient{}
	token := &auth.AccessToken{Token: "tok", TenantID: "t1"}
	graphErr := &graph.GraphError{StatusCode: 403, Code: "Authorization_RequestDenied", Message: "forbidden"}
	mockGraph.On("UpdateTeamSettings", mock.Anything, token, "team-1", mock.Anything).Return(graphErr)

	m := &entraGroupModule{graphClient: mockGraph}
	err := m.updateTeamSettings(context.Background(), token, "team-1", nil)
	assert.Error(t, err)
	mockGraph.AssertExpectations(t)
}

func TestUpdateTeamSettings_GraphClientError_WithNonNilSettings(t *testing.T) {
	mockGraph := &MockGraphClient{}
	token := &auth.AccessToken{Token: "tok", TenantID: "t1"}
	graphErr := &graph.GraphError{StatusCode: 500, Code: "InternalServerError", Message: "server error"}
	mockGraph.On("UpdateTeamSettings", mock.Anything, token, "team-1", mock.Anything).Return(graphErr)

	settings := &TeamSettings{
		AllowCreateUpdateChannels: true,
		AllowDeleteChannels:       false,
		AllowAddRemoveApps:        true,
		AllowUserEditMessages:     true,
		Fun:                       "enabled",
	}
	m := &entraGroupModule{graphClient: mockGraph}
	err := m.updateTeamSettings(context.Background(), token, "team-1", settings)
	assert.Error(t, err)
	mockGraph.AssertExpectations(t)
}

func TestEntraGroupModule_Set_GroupSearch_UsesListGroupsFilter(t *testing.T) {
	token := &auth.AccessToken{Token: "tok", TenantID: "tenant-1"}
	var listGroupsCalled bool
	gc := &stubEntraGroupGC{
		getGroupFn: func(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Group, error) {
			return nil, &graph.GraphError{StatusCode: 404, Code: "Request_ResourceNotFound", Message: "not found"}
		},
		listGroupsFn: func(_ context.Context, _ *auth.AccessToken, filter string) ([]graph.Group, error) {
			listGroupsCalled = true
			assert.Contains(t, filter, "Test Group")
			return []graph.Group{}, nil
		},
		createGroupFn: func(_ context.Context, _ *auth.AccessToken, _ *graph.CreateGroupRequest) (*graph.Group, error) {
			return &graph.Group{ID: "new-gid", DisplayName: "Test Group", MailNickname: "testgroup"}, nil
		},
	}
	ap := &stubEntraGroupAP{token: token}
	config := &EntraGroupConfig{
		DisplayName:     "Test Group",
		MailNickname:    "testgroup",
		SecurityEnabled: true,
		TenantID:        "tenant-1",
	}
	m := &entraGroupModule{authProvider: ap, graphClient: gc, propagationDelay: 0}
	err := m.Set(context.Background(), "tenant-1:new-gid", config)
	assert.NoError(t, err)
	assert.True(t, listGroupsCalled, "ListGroups must be called as fallback display-name search")
}

func TestEntraGroupModule_FindGroupByDisplayName_EscapesQuotes(t *testing.T) {
	var capturedFilter string
	gc := &stubEntraGroupGC{
		listGroupsFn: func(_ context.Context, _ *auth.AccessToken, filter string) ([]graph.Group, error) {
			capturedFilter = filter
			return []graph.Group{}, nil
		},
	}
	m := &entraGroupModule{graphClient: gc}
	_, _ = m.findGroupByDisplayName(context.Background(), &auth.AccessToken{}, "O'Reilly Group")
	assert.Contains(t, capturedFilter, "O''Reilly Group", "single quotes must be doubled for OData filter safety")
}

func TestEntraGroupModule_Get_TeamsEnabled_PopulatesTeamFields(t *testing.T) {
	token := &auth.AccessToken{Token: "tok", TenantID: "tenant-1"}
	allowPrivate := true
	gc := &stubEntraGroupGC{
		getGroupFn: func(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Group, error) {
			return &graph.Group{
				ID: "group-1", DisplayName: "Teams Group", MailNickname: "teamsgroup",
				MailEnabled: true, SecurityEnabled: false,
			}, nil
		},
		listMembersFn: func(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
			return []string{}, nil
		},
		listOwnersFn: func(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
			return []string{}, nil
		},
		getTeamFn: func(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Team, error) {
			return &graph.Team{
				ID: "group-1",
				MemberSettings: &graph.TeamMemberSettings{
					AllowCreatePrivateChannels: &allowPrivate,
				},
			}, nil
		},
	}
	ap := &stubEntraGroupAP{token: token}
	m := &entraGroupModule{authProvider: ap, graphClient: gc}
	state, err := m.Get(context.Background(), "tenant-1:group-1")
	assert.NoError(t, err)

	cfg, ok := state.(*EntraGroupConfig)
	assert.True(t, ok)
	assert.True(t, cfg.IsTeamEnabled)
	assert.NotNil(t, cfg.TeamSettings)
	assert.True(t, cfg.TeamSettings.AllowCreatePrivateChannels)
}

// --- struct-based test doubles (no mock framework) ---

// stubEntraGroupAP is a minimal auth.Provider double
type stubEntraGroupAP struct {
	token *auth.AccessToken
}

func (s *stubEntraGroupAP) GetAccessToken(_ context.Context, _ string) (*auth.AccessToken, error) {
	return s.token, nil
}
func (s *stubEntraGroupAP) GetDelegatedAccessToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return s.token, nil
}
func (s *stubEntraGroupAP) RefreshToken(_ context.Context, _ string) (*auth.AccessToken, error) {
	return s.token, nil
}
func (s *stubEntraGroupAP) RefreshDelegatedToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return s.token, nil
}
func (s *stubEntraGroupAP) IsTokenValid(_ *auth.AccessToken) bool { return true }
func (s *stubEntraGroupAP) ValidatePermissions(_ context.Context, _ *auth.AccessToken, _ []string) error {
	return nil
}

// stubEntraGroupGC is a graph.Client double with configurable function fields
type stubEntraGroupGC struct {
	getGroupFn    func(ctx context.Context, token *auth.AccessToken, groupID string) (*graph.Group, error)
	listGroupsFn  func(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.Group, error)
	createGroupFn func(ctx context.Context, token *auth.AccessToken, req *graph.CreateGroupRequest) (*graph.Group, error)
	listMembersFn func(ctx context.Context, token *auth.AccessToken, groupID string) ([]string, error)
	listOwnersFn  func(ctx context.Context, token *auth.AccessToken, groupID string) ([]string, error)
	getTeamFn     func(ctx context.Context, token *auth.AccessToken, groupID string) (*graph.Team, error)
}

func (s *stubEntraGroupGC) GetGroup(ctx context.Context, t *auth.AccessToken, id string) (*graph.Group, error) {
	if s.getGroupFn != nil {
		return s.getGroupFn(ctx, t, id)
	}
	return nil, fmt.Errorf("group not found")
}
func (s *stubEntraGroupGC) ListGroups(ctx context.Context, t *auth.AccessToken, filter string) ([]graph.Group, error) {
	if s.listGroupsFn != nil {
		return s.listGroupsFn(ctx, t, filter)
	}
	return nil, nil
}
func (s *stubEntraGroupGC) CreateGroup(ctx context.Context, t *auth.AccessToken, req *graph.CreateGroupRequest) (*graph.Group, error) {
	if s.createGroupFn != nil {
		return s.createGroupFn(ctx, t, req)
	}
	return nil, nil
}
func (s *stubEntraGroupGC) ListGroupMembers(ctx context.Context, t *auth.AccessToken, id string) ([]string, error) {
	if s.listMembersFn != nil {
		return s.listMembersFn(ctx, t, id)
	}
	return nil, nil
}
func (s *stubEntraGroupGC) ListGroupOwners(ctx context.Context, t *auth.AccessToken, id string) ([]string, error) {
	if s.listOwnersFn != nil {
		return s.listOwnersFn(ctx, t, id)
	}
	return nil, nil
}
func (s *stubEntraGroupGC) GetTeam(ctx context.Context, t *auth.AccessToken, id string) (*graph.Team, error) {
	if s.getTeamFn != nil {
		return s.getTeamFn(ctx, t, id)
	}
	return nil, fmt.Errorf("not a team")
}

// Remaining graph.Client methods as no-ops
func (s *stubEntraGroupGC) GetUser(_ context.Context, _ *auth.AccessToken, _ string) (*graph.User, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) ListUsers(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.User, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) CreateUser(_ context.Context, _ *auth.AccessToken, _ *graph.CreateUserRequest) (*graph.User, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) UpdateUser(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateUserRequest) error {
	return nil
}
func (s *stubEntraGroupGC) DeleteUser(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) GetUserLicenses(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.LicenseAssignment, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) AssignLicense(_ context.Context, _ *auth.AccessToken, _, _ string, _ []string) error {
	return nil
}
func (s *stubEntraGroupGC) RemoveLicense(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) GetUserGroups(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) AddUserToGroup(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) RemoveUserFromGroup(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) GetConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string) (*graph.ConditionalAccessPolicy, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) CreateConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ *graph.CreateConditionalAccessPolicyRequest) (*graph.ConditionalAccessPolicy, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) UpdateConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateConditionalAccessPolicyRequest) error {
	return nil
}
func (s *stubEntraGroupGC) DeleteConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) GetDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string) (*graph.DeviceConfiguration, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) ListDeviceConfigurationAssignments(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.DeviceConfigurationAssignment, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) AssignDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string, _ []graph.DeviceConfigurationAssignment) error {
	return nil
}
func (s *stubEntraGroupGC) CreateDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ *graph.CreateDeviceConfigurationRequest) (*graph.DeviceConfiguration, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) UpdateDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateDeviceConfigurationRequest) error {
	return nil
}
func (s *stubEntraGroupGC) DeleteDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) GetApplication(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Application, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) ListApplications(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.Application, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) CreateApplication(_ context.Context, _ *auth.AccessToken, _ *graph.CreateApplicationRequest) (*graph.Application, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) UpdateApplication(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateApplicationRequest) error {
	return nil
}
func (s *stubEntraGroupGC) DeleteApplication(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) GetAdministrativeUnit(_ context.Context, _ *auth.AccessToken, _ string) (*graph.AdministrativeUnit, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) ListAdministrativeUnits(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.AdministrativeUnit, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) CreateAdministrativeUnit(_ context.Context, _ *auth.AccessToken, _ *graph.CreateAdministrativeUnitRequest) (*graph.AdministrativeUnit, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) UpdateAdministrativeUnit(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateAdministrativeUnitRequest) error {
	return nil
}
func (s *stubEntraGroupGC) DeleteAdministrativeUnit(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) UpdateGroup(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateGroupRequest) error {
	return nil
}
func (s *stubEntraGroupGC) DeleteGroup(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) AddGroupMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) RemoveGroupMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) AddGroupOwner(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) RemoveGroupOwner(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) ListAdminUnitUserMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) ListAdminUnitGroupMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) ListAdminUnitScopedRoleMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.AdminUnitScopedRoleMember, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) AddAdminUnitMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) AddAdminUnitScopedRoleMember(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.AddScopedRoleMemberRequest) (*graph.AdminUnitScopedRoleMember, error) {
	return nil, nil
}
func (s *stubEntraGroupGC) RemoveAdminUnitMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) RemoveAdminUnitScopedRoleMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubEntraGroupGC) CreateTeam(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.CreateTeamRequest) error {
	return nil
}
func (s *stubEntraGroupGC) UpdateTeamSettings(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateTeamSettingsRequest) error {
	return nil
}
