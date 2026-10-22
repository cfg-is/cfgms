// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package entra_application

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// Mock implementations
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

type MockGraphClient struct {
	mock.Mock
}

// User operations
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

// License operations
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

// Group operations
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

// Conditional Access operations
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

// Intune operations
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
	return nil, nil
}

func (m *MockGraphClient) AssignDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string, assignments []graph.DeviceConfigurationAssignment) error {
	return nil
}

// Application operations
func (m *MockGraphClient) GetApplication(ctx context.Context, token *auth.AccessToken, applicationID string) (*graph.Application, error) {
	args := m.Called(ctx, token, applicationID)
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

func TestNew(t *testing.T) {
	mockAuth := &MockAuthProvider{}
	mockGraph := &MockGraphClient{}

	module := New(mockAuth, mockGraph)

	assert.NotNil(t, module)
	appModule, ok := module.(*entraApplicationModule)
	assert.True(t, ok)
	assert.Equal(t, mockAuth, appModule.authProvider)
	assert.Equal(t, mockGraph, appModule.graphClient)
}

func TestEntraApplicationConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  EntraApplicationConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: EntraApplicationConfig{
				DisplayName:    "Test App",
				SignInAudience: "AzureADMyOrg",
				TenantID:       "12345678-1234-1234-1234-123456789012",
			},
			wantErr: false,
		},
		{
			name: "missing display name",
			config: EntraApplicationConfig{
				SignInAudience: "AzureADMyOrg",
				TenantID:       "12345678-1234-1234-1234-123456789012",
			},
			wantErr: true,
			errMsg:  "display_name is required",
		},
		{
			name: "missing sign in audience",
			config: EntraApplicationConfig{
				DisplayName: "Test App",
				TenantID:    "12345678-1234-1234-1234-123456789012",
			},
			wantErr: true,
			errMsg:  "sign_in_audience is required",
		},
		{
			name: "missing tenant ID",
			config: EntraApplicationConfig{
				DisplayName:    "Test App",
				SignInAudience: "AzureADMyOrg",
			},
			wantErr: true,
			errMsg:  "tenant_id is required",
		},
		{
			name: "invalid sign in audience",
			config: EntraApplicationConfig{
				DisplayName:    "Test App",
				SignInAudience: "InvalidAudience",
				TenantID:       "12345678-1234-1234-1234-123456789012",
			},
			wantErr: true,
			errMsg:  "invalid sign_in_audience: InvalidAudience",
		},
		{
			name: "valid multiple audiences",
			config: EntraApplicationConfig{
				DisplayName:    "Test App",
				SignInAudience: "AzureADandPersonalMicrosoftAccount",
				TenantID:       "12345678-1234-1234-1234-123456789012",
			},
			wantErr: false,
		},
		{
			name: "app role missing display name",
			config: EntraApplicationConfig{
				DisplayName:    "Test App",
				SignInAudience: "AzureADMyOrg",
				TenantID:       "12345678-1234-1234-1234-123456789012",
				AppRoles: []AppRole{
					{
						Value:              "admin",
						AllowedMemberTypes: []string{"User"},
					},
				},
			},
			wantErr: true,
			errMsg:  "app_role 0: display_name is required",
		},
		{
			name: "app role missing value",
			config: EntraApplicationConfig{
				DisplayName:    "Test App",
				SignInAudience: "AzureADMyOrg",
				TenantID:       "12345678-1234-1234-1234-123456789012",
				AppRoles: []AppRole{
					{
						DisplayName:        "Admin Role",
						AllowedMemberTypes: []string{"User"},
					},
				},
			},
			wantErr: true,
			errMsg:  "app_role 0: value is required",
		},
		{
			name: "app role missing allowed member types",
			config: EntraApplicationConfig{
				DisplayName:    "Test App",
				SignInAudience: "AzureADMyOrg",
				TenantID:       "12345678-1234-1234-1234-123456789012",
				AppRoles: []AppRole{
					{
						DisplayName: "Admin Role",
						Value:       "admin",
					},
				},
			},
			wantErr: true,
			errMsg:  "app_role 0: at least one allowed_member_type is required",
		},
		{
			name: "oauth2 permission missing admin consent display name",
			config: EntraApplicationConfig{
				DisplayName:    "Test App",
				SignInAudience: "AzureADMyOrg",
				TenantID:       "12345678-1234-1234-1234-123456789012",
				OAuth2Permissions: []OAuth2Scope{
					{
						Value: "read",
					},
				},
			},
			wantErr: true,
			errMsg:  "oauth2_permission 0: admin_consent_display_name is required",
		},
		{
			name: "oauth2 permission missing value",
			config: EntraApplicationConfig{
				DisplayName:    "Test App",
				SignInAudience: "AzureADMyOrg",
				TenantID:       "12345678-1234-1234-1234-123456789012",
				OAuth2Permissions: []OAuth2Scope{
					{
						AdminConsentDisplayName: "Read Access",
					},
				},
			},
			wantErr: true,
			errMsg:  "oauth2_permission 0: value is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEntraApplicationConfig_AsMap(t *testing.T) {
	config := &EntraApplicationConfig{
		DisplayName:    "Test App",
		Description:    "Test Description",
		SignInAudience: "AzureADMyOrg",
		TenantID:       "12345678-1234-1234-1234-123456789012",
		IdentifierUris: []string{"https://example.com/app"},
		RedirectUris: &RedirectUris{
			Web: []string{"https://example.com/callback"},
		},
		LogoutURL: "https://example.com/logout",
		RequiredResourceAccess: []ResourceAccess{
			{
				ResourceAppID: "00000003-0000-0000-c000-000000000000",
				ResourceAccess: []PermissionScope{
					{ID: "e1fe6dd8-ba31-4d61-89e7-88639da4683d", Type: "Scope"},
				},
			},
		},
		OAuth2Permissions: []OAuth2Scope{
			{
				ID:                      "12345",
				AdminConsentDisplayName: "Read Access",
				Value:                   "read",
				Type:                    "Admin",
				IsEnabled:               true,
			},
		},
		AppRoles: []AppRole{
			{
				ID:                 "67890",
				DisplayName:        "Admin Role",
				Value:              "admin",
				AllowedMemberTypes: []string{"User"},
				IsEnabled:          true,
			},
		},
		PasswordCredentials: []PasswordCredential{
			{
				DisplayName: "Test Secret",
				EndDateTime: "2024-12-31T23:59:59Z",
				SecretText:  "secret-value", // This should be excluded in AsMap
			},
		},
		KeyCredentials: []KeyCredential{
			{
				DisplayName: "Test Cert",
				Type:        "AsymmetricX509Cert",
				Usage:       "Sign",
			},
		},
		OptionalClaims: &OptionalClaims{
			IDToken: []OptionalClaim{
				{Name: "email", Essential: true},
			},
		},
		CreateServicePrincipal: true,
		ServicePrincipalSettings: &ServicePrincipalConfig{
			AccountEnabled: true,
			Tags:           []string{"WindowsAzureActiveDirectoryIntegratedApp"},
		},
	}

	result := config.AsMap()

	// Check required fields
	assert.Equal(t, "Test App", result["display_name"])
	assert.Equal(t, "AzureADMyOrg", result["sign_in_audience"])
	assert.Equal(t, "12345678-1234-1234-1234-123456789012", result["tenant_id"])

	// Check optional fields
	assert.Equal(t, "Test Description", result["description"])
	assert.Equal(t, []string{"https://example.com/app"}, result["identifier_uris"])
	assert.Equal(t, config.RedirectUris, result["redirect_uris"])
	assert.Equal(t, "https://example.com/logout", result["logout_url"])
	assert.Equal(t, config.RequiredResourceAccess, result["required_resource_access"])
	assert.Equal(t, config.OAuth2Permissions, result["oauth2_permissions"])
	assert.Equal(t, config.AppRoles, result["app_roles"])
	assert.Equal(t, config.KeyCredentials, result["key_credentials"])
	assert.Equal(t, config.OptionalClaims, result["optional_claims"])
	assert.Equal(t, true, result["create_service_principal"])
	assert.Equal(t, config.ServicePrincipalSettings, result["service_principal_settings"])

	// Check that password credentials are sanitized (secret text removed)
	passwordCreds, exists := result["password_credentials"]
	assert.True(t, exists)
	sanitizedCreds := passwordCreds.([]PasswordCredential)
	assert.Len(t, sanitizedCreds, 1)
	assert.Equal(t, "Test Secret", sanitizedCreds[0].DisplayName)
	assert.Equal(t, "2024-12-31T23:59:59Z", sanitizedCreds[0].EndDateTime)
	assert.Empty(t, sanitizedCreds[0].SecretText) // Secret should be removed
}

func TestEntraApplicationConfig_GetManagedFields(t *testing.T) {
	tests := []struct {
		name     string
		config   EntraApplicationConfig
		expected []string
	}{
		{
			name: "minimal config",
			config: EntraApplicationConfig{
				DisplayName:    "Test App",
				SignInAudience: "AzureADMyOrg",
			},
			expected: []string{"display_name", "sign_in_audience"},
		},
		{
			name: "explicit managed fields",
			config: EntraApplicationConfig{
				DisplayName:       "Test App",
				SignInAudience:    "AzureADMyOrg",
				ManagedFieldsList: []string{"display_name", "description"},
			},
			expected: []string{"display_name", "description"},
		},
		{
			name: "full config",
			config: EntraApplicationConfig{
				DisplayName:    "Test App",
				Description:    "Test Description",
				SignInAudience: "AzureADMyOrg",
				IdentifierUris: []string{"https://example.com"},
				RedirectUris: &RedirectUris{
					Web: []string{"https://example.com/callback"},
				},
				RequiredResourceAccess: []ResourceAccess{
					{ResourceAppID: "test-app-id"},
				},
				OAuth2Permissions: []OAuth2Scope{
					{Value: "read"},
				},
				AppRoles: []AppRole{
					{Value: "admin"},
				},
				PasswordCredentials: []PasswordCredential{
					{DisplayName: "Test Secret"},
				},
				KeyCredentials: []KeyCredential{
					{DisplayName: "Test Cert"},
				},
				CreateServicePrincipal: true,
			},
			expected: []string{
				"display_name", "sign_in_audience", "description", "identifier_uris",
				"redirect_uris", "required_resource_access", "oauth2_permissions",
				"app_roles", "password_credentials", "key_credentials", "create_service_principal",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetManagedFields()
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestEntraApplicationConfig_ToYAML(t *testing.T) {
	config := &EntraApplicationConfig{
		DisplayName:    "Test App",
		SignInAudience: "AzureADMyOrg",
		TenantID:       "12345678-1234-1234-1234-123456789012",
		PasswordCredentials: []PasswordCredential{
			{
				DisplayName: "Test Secret",
				EndDateTime: "2024-12-31T23:59:59Z",
				SecretText:  "secret-value", // Should be excluded from YAML
			},
		},
	}

	yamlData, err := config.ToYAML()
	assert.NoError(t, err)
	assert.NotEmpty(t, yamlData)

	// Verify the YAML doesn't contain secret text
	yamlStr := string(yamlData)
	assert.NotContains(t, yamlStr, "secret-value")
	assert.Contains(t, yamlStr, "display_name: Test App")
	assert.Contains(t, yamlStr, "sign_in_audience: AzureADMyOrg")
}

func TestEntraApplicationConfig_FromYAML(t *testing.T) {
	yamlData := `
display_name: "Test App"
sign_in_audience: "AzureADMyOrg"
tenant_id: "12345678-1234-1234-1234-123456789012"
description: "Test Description"
identifier_uris:
  - "https://example.com/app"
redirect_uris:
  web:
    - "https://example.com/callback"
  spa:
    - "https://example.com/spa"
password_credentials:
  - display_name: "Test Secret"
    end_date_time: "2024-12-31T23:59:59Z"
app_roles:
  - id: "role-123"
    display_name: "Admin Role"
    value: "admin"
    allowed_member_types: ["User"]
    is_enabled: true
oauth2_permissions:
  - id: "perm-123"
    admin_consent_display_name: "Read Access"
    value: "read"
    type: "Admin"
    is_enabled: true
create_service_principal: true
service_principal_settings:
  account_enabled: true
  tags: ["WindowsAzureActiveDirectoryIntegratedApp"]
`

	config := &EntraApplicationConfig{}
	err := config.FromYAML([]byte(yamlData))
	assert.NoError(t, err)

	assert.Equal(t, "Test App", config.DisplayName)
	assert.Equal(t, "AzureADMyOrg", config.SignInAudience)
	assert.Equal(t, "12345678-1234-1234-1234-123456789012", config.TenantID)
	assert.Equal(t, "Test Description", config.Description)
	assert.Equal(t, []string{"https://example.com/app"}, config.IdentifierUris)

	// Check redirect URIs
	assert.NotNil(t, config.RedirectUris)
	assert.Equal(t, []string{"https://example.com/callback"}, config.RedirectUris.Web)
	assert.Equal(t, []string{"https://example.com/spa"}, config.RedirectUris.Spa)

	// Check password credentials
	assert.Len(t, config.PasswordCredentials, 1)
	assert.Equal(t, "Test Secret", config.PasswordCredentials[0].DisplayName)
	assert.Equal(t, "2024-12-31T23:59:59Z", config.PasswordCredentials[0].EndDateTime)

	// Check app roles
	assert.Len(t, config.AppRoles, 1)
	assert.Equal(t, "role-123", config.AppRoles[0].ID)
	assert.Equal(t, "Admin Role", config.AppRoles[0].DisplayName)
	assert.Equal(t, "admin", config.AppRoles[0].Value)
	assert.Equal(t, []string{"User"}, config.AppRoles[0].AllowedMemberTypes)
	assert.True(t, config.AppRoles[0].IsEnabled)

	// Check OAuth2 permissions
	assert.Len(t, config.OAuth2Permissions, 1)
	assert.Equal(t, "perm-123", config.OAuth2Permissions[0].ID)
	assert.Equal(t, "Read Access", config.OAuth2Permissions[0].AdminConsentDisplayName)
	assert.Equal(t, "read", config.OAuth2Permissions[0].Value)
	assert.Equal(t, "Admin", config.OAuth2Permissions[0].Type)
	assert.True(t, config.OAuth2Permissions[0].IsEnabled)

	// Check service principal settings
	assert.True(t, config.CreateServicePrincipal)
	assert.NotNil(t, config.ServicePrincipalSettings)
	assert.True(t, config.ServicePrincipalSettings.AccountEnabled)
	assert.Equal(t, []string{"WindowsAzureActiveDirectoryIntegratedApp"}, config.ServicePrincipalSettings.Tags)
}

func TestParseEntraApplicationResourceID(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		wantTenant string
		wantAppID  string
		wantErr    bool
	}{
		{
			name:       "valid resource ID",
			resourceID: "12345678-1234-1234-1234-123456789012:app-id-123",
			wantTenant: "12345678-1234-1234-1234-123456789012",
			wantAppID:  "app-id-123",
			wantErr:    false,
		},
		{
			name:       "invalid format - no colon",
			resourceID: "12345678-1234-1234-1234-123456789012",
			wantErr:    true,
		},
		{
			name:       "invalid format - empty app ID",
			resourceID: "12345678-1234-1234-1234-123456789012:",
			wantTenant: "12345678-1234-1234-1234-123456789012",
			wantAppID:  "",
			wantErr:    false,
		},
		{
			name:       "invalid format - empty tenant ID",
			resourceID: ":app-id-123",
			wantTenant: "",
			wantAppID:  "app-id-123",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant, appID, err := parseEntraApplicationResourceID(tt.resourceID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantTenant, tenant)
				assert.Equal(t, tt.wantAppID, appID)
			}
		})
	}
}

func TestExtractApplicationID(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		expected   string
	}{
		{
			name:       "valid resource ID",
			resourceID: "12345678-1234-1234-1234-123456789012:app-id-123",
			expected:   "app-id-123",
		},
		{
			name:       "invalid format - returns empty",
			resourceID: "invalid-format",
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractApplicationID(tt.resourceID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected bool
	}{
		{
			name:     "item exists",
			slice:    []string{"a", "b", "c"},
			item:     "b",
			expected: true,
		},
		{
			name:     "item doesn't exist",
			slice:    []string{"a", "b", "c"},
			item:     "d",
			expected: false,
		},
		{
			name:     "empty slice",
			slice:    []string{},
			item:     "a",
			expected: false,
		},
		{
			name:     "nil slice",
			slice:    nil,
			item:     "a",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.slice, tt.item)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test complex structure serialization
func TestComplexStructureSerialization(t *testing.T) {
	config := &EntraApplicationConfig{
		DisplayName:    "Complex App",
		SignInAudience: "AzureADMultipleOrgs",
		TenantID:       "tenant-123",
		OptionalClaims: &OptionalClaims{
			IDToken: []OptionalClaim{
				{
					Name:      "email",
					Essential: true,
					AdditionalProperties: []OptionalClaimProperty{
						{Name: "include_externally_authenticated_upn", Value: "true"},
					},
				},
			},
			AccessToken: []OptionalClaim{
				{
					Name:   "groups",
					Source: "user",
				},
			},
		},
		RequiredResourceAccess: []ResourceAccess{
			{
				ResourceAppID: "00000003-0000-0000-c000-000000000000", // Microsoft Graph
				ResourceAccess: []PermissionScope{
					{ID: "e1fe6dd8-ba31-4d61-89e7-88639da4683d", Type: "Scope"}, // User.Read
					{ID: "405a51b5-8d8d-430b-9842-8be4b0e9f324", Type: "Role"},  // User.Read.All
				},
			},
		},
	}

	// Test YAML serialization/deserialization
	yamlData, err := config.ToYAML()
	assert.NoError(t, err)

	deserializedConfig := &EntraApplicationConfig{}
	err = deserializedConfig.FromYAML(yamlData)
	assert.NoError(t, err)

	// Verify complex structures are preserved
	assert.Equal(t, config.DisplayName, deserializedConfig.DisplayName)
	assert.Equal(t, config.SignInAudience, deserializedConfig.SignInAudience)
	assert.NotNil(t, deserializedConfig.OptionalClaims)
	assert.Len(t, deserializedConfig.OptionalClaims.IDToken, 1)
	assert.Equal(t, "email", deserializedConfig.OptionalClaims.IDToken[0].Name)
	assert.True(t, deserializedConfig.OptionalClaims.IDToken[0].Essential)
	assert.Len(t, deserializedConfig.OptionalClaims.IDToken[0].AdditionalProperties, 1)

	assert.Len(t, deserializedConfig.RequiredResourceAccess, 1)
	assert.Equal(t, "00000003-0000-0000-c000-000000000000", deserializedConfig.RequiredResourceAccess[0].ResourceAppID)
	assert.Len(t, deserializedConfig.RequiredResourceAccess[0].ResourceAccess, 2)
}

// Test edge cases for managed fields
func TestManagedFieldsEdgeCases(t *testing.T) {
	// Test with empty redirect URIs object
	config := &EntraApplicationConfig{
		DisplayName:    "Test App",
		SignInAudience: "AzureADMyOrg",
		RedirectUris:   &RedirectUris{}, // Empty but not nil
	}

	fields := config.GetManagedFields()
	assert.Contains(t, fields, "redirect_uris")

	// Test with nil redirect URIs
	config.RedirectUris = nil
	fields = config.GetManagedFields()
	assert.NotContains(t, fields, "redirect_uris")
}

// Test validation edge cases
func TestValidationEdgeCases(t *testing.T) {
	// Test with valid complete configuration
	config := &EntraApplicationConfig{
		DisplayName:    "Complete App",
		SignInAudience: "PersonalMicrosoftAccount",
		TenantID:       "tenant-123",
		AppRoles: []AppRole{
			{
				ID:                 "role-1",
				DisplayName:        "Admin",
				Description:        "Administrator role",
				Value:              "admin",
				AllowedMemberTypes: []string{"User", "Application"},
				IsEnabled:          true,
			},
		},
		OAuth2Permissions: []OAuth2Scope{
			{
				ID:                      "scope-1",
				AdminConsentDisplayName: "Read data",
				AdminConsentDescription: "Allows reading data",
				UserConsentDisplayName:  "Read your data",
				UserConsentDescription:  "Allows the app to read your data",
				Value:                   "data.read",
				Type:                    "User",
				IsEnabled:               true,
			},
		},
	}

	err := config.Validate()
	assert.NoError(t, err)
}

// tenantIsolationAuthProvider is a real auth.Provider implementation (not a
// mock) that maps each CFGMS tenant to the M365 tenant its credentials belong
// to and records every tenant a token was requested for, so a test can prove
// which credentials a module invocation selected (Issue #4421).
type tenantIsolationAuthProvider struct {
	m365ByCFGMS map[string]string
	mu          sync.Mutex
	requested   []string
}

func (p *tenantIsolationAuthProvider) GetAccessToken(_ context.Context, tenantID string) (*auth.AccessToken, error) {
	p.mu.Lock()
	p.requested = append(p.requested, tenantID)
	p.mu.Unlock()
	m365, ok := p.m365ByCFGMS[tenantID]
	if !ok {
		return nil, fmt.Errorf("no credentials for tenant")
	}
	return &auth.AccessToken{Token: "tok-" + m365, TokenType: "Bearer", TenantID: m365, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (p *tenantIsolationAuthProvider) GetDelegatedAccessToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *tenantIsolationAuthProvider) RefreshToken(_ context.Context, _ string) (*auth.AccessToken, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *tenantIsolationAuthProvider) RefreshDelegatedToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return nil, fmt.Errorf("not supported")
}
func (p *tenantIsolationAuthProvider) IsTokenValid(_ *auth.AccessToken) bool { return true }
func (p *tenantIsolationAuthProvider) ValidatePermissions(_ context.Context, _ *auth.AccessToken, _ []string) error {
	return nil
}

func (p *tenantIsolationAuthProvider) requestedTenants() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.requested...)
}

// unreachableGraphClient embeds a nil graph.Client: any Graph call made by a
// refused invocation panics, failing the test loudly.
type unreachableGraphClient struct{ graph.Client }

func newIsolationModule() (*entraApplicationModule, *tenantIsolationAuthProvider) {
	ap := &tenantIsolationAuthProvider{m365ByCFGMS: map[string]string{
		"cfgms-tenant-a": "m365-tenant-a",
		"cfgms-tenant-b": "m365-tenant-b",
	}}
	return &entraApplicationModule{authProvider: ap, graphClient: unreachableGraphClient{}}, ap
}

func isolationCtx(cfgmsTenant string) context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantID, cfgmsTenant)
}

func isolationConfig(tenant string) *EntraApplicationConfig {
	return &EntraApplicationConfig{DisplayName: "App", SignInAudience: "AzureADMyOrg", TenantID: tenant}
}

// TestSet_RefusesConfigTenantOfAnotherM365Tenant proves a workflow whose
// execution context is CFGMS tenant A cannot select tenant B's credentials by
// naming B's M365 tenant in tenant_id.
func TestSet_RefusesConfigTenantOfAnotherM365Tenant(t *testing.T) {
	m, ap := newIsolationModule()

	err := m.Set(isolationCtx("cfgms-tenant-a"), "m365-tenant-b:obj-1", isolationConfig("m365-tenant-b"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "m365-tenant-b", "refusal must name the rejected tenant_id")
	assert.Equal(t, []string{"cfgms-tenant-a"}, ap.requestedTenants(),
		"only the execution tenant's credentials may be requested; none for tenant B")
}

// TestGet_RefusesResourceTenantOfAnotherM365Tenant proves the tenant segment of
// a resource ID never selects credentials.
func TestGet_RefusesResourceTenantOfAnotherM365Tenant(t *testing.T) {
	m, ap := newIsolationModule()

	_, err := m.Get(isolationCtx("cfgms-tenant-a"), "m365-tenant-b:obj-1")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "m365-tenant-b", "refusal must name the rejected tenant")
	assert.Equal(t, []string{"cfgms-tenant-a"}, ap.requestedTenants(),
		"only the execution tenant's credentials may be requested; none for tenant B")
}

// TestSetGet_FailClosedWithoutExecutionTenant proves a missing tenant context
// is refused before any token is requested.
func TestSetGet_FailClosedWithoutExecutionTenant(t *testing.T) {
	m, ap := newIsolationModule()

	err := m.Set(context.Background(), "m365-tenant-a:obj-1", isolationConfig("m365-tenant-a"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant context required")

	_, err = m.Get(context.Background(), "m365-tenant-a:obj-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant context required")

	assert.Empty(t, ap.requestedTenants(), "no token may be requested without an execution tenant")
}

// mapState is a ConfigState backed by a raw step-configuration map.
type mapState map[string]interface{}

func (s mapState) AsMap() map[string]interface{} { return s }
func (s mapState) ToYAML() ([]byte, error)       { return yaml.Marshal(map[string]interface{}(s)) }
func (s mapState) FromYAML(data []byte) error    { return yaml.Unmarshal(data, &s) }
func (s mapState) GetManagedFields() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}
func (s mapState) Validate() error { return nil }

// graphRequest is one request received by fakeGraphServer.
type graphRequest struct {
	Method string
	Path   string
	Body   []byte
}

// fakeGraphServer is a real HTTP server standing in for Microsoft Graph. It
// serves at most one existing application and records every request it
// receives, so tests drive the module through the real graph.HTTPClient.
type fakeGraphServer struct {
	mu       sync.Mutex
	existing map[string]interface{}
	requests []graphRequest
}

func (f *fakeGraphServer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		f.mu.Lock()
		f.requests = append(f.requests, graphRequest{Method: r.Method, Path: r.URL.Path, Body: raw})
		existing := f.existing
		f.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		existingPath := ""
		if existing != nil {
			existingPath = "/applications/" + existing["id"].(string)
		}
		switch {
		case r.Method == http.MethodGet && existingPath != "" && r.URL.Path == existingPath:
			assert.NoError(t, json.NewEncoder(w).Encode(existing))
		case r.Method == http.MethodPatch && existingPath != "" && r.URL.Path == existingPath:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/applications":
			w.WriteHeader(http.StatusCreated)
			_, werr := w.Write([]byte(`{"id":"obj-2","appId":"app-2"}`))
			assert.NoError(t, werr)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, werr := w.Write([]byte(`{"error":{"code":"Request_ResourceNotFound","message":"not found"}}`))
			assert.NoError(t, werr)
		}
	})
}

func (f *fakeGraphServer) recorded() []graphRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]graphRequest(nil), f.requests...)
}

// only returns the single request with the given method, failing otherwise.
func (f *fakeGraphServer) only(t *testing.T, method string) graphRequest {
	t.Helper()
	var found []graphRequest
	for _, r := range f.recorded() {
		if r.Method == method {
			found = append(found, r)
		}
	}
	require.Len(t, found, 1, "expected exactly one %s request to Graph", method)
	return found[0]
}

func setupSetModule(t *testing.T, existing map[string]interface{}) (*entraApplicationModule, *fakeGraphServer, *tenantIsolationAuthProvider, context.Context) {
	t.Helper()
	fg := &fakeGraphServer{existing: existing}
	srv := httptest.NewServer(fg.handler(t))
	t.Cleanup(srv.Close)
	ap := &tenantIsolationAuthProvider{m365ByCFGMS: map[string]string{"cfgms-t": "m365-t"}}
	gc := graph.NewHTTPClient(graph.WithBaseURL(srv.URL), graph.WithHTTPClient(srv.Client()))
	return &entraApplicationModule{authProvider: ap, graphClient: gc}, fg, ap, isolationCtx("cfgms-t")
}

func baseStep(extra map[string]interface{}) mapState {
	s := mapState{"display_name": "App", "sign_in_audience": "AzureADMyOrg", "tenant_id": "m365-t"}
	for k, v := range extra {
		s[k] = v
	}
	return s
}

func TestSet_UpdateSendsMappedFields(t *testing.T) {
	m, fg, _, ctx := setupSetModule(t, map[string]interface{}{
		"id": "obj-1", "displayName": "App", "signInAudience": "AzureADMyOrg",
		"identifierUris": []string{"api://old"}, "tags": []string{"old"},
		"web": map[string]interface{}{"redirectUris": []string{"https://old/cb"}, "logoutUrl": "https://old/logout"},
	})

	err := m.Set(ctx, "m365-t:obj-1", baseStep(map[string]interface{}{
		"identifier_uris": []interface{}{"api://new"},
		"redirect_uris":   map[string]interface{}{"web": []interface{}{"https://new/cb"}},
		"tags":            []string{"new"},
		"managed_fields":  []interface{}{"identifier_uris", "redirect_uris", "tags"},
	}))
	require.NoError(t, err)

	patch := fg.only(t, http.MethodPatch)
	assert.Equal(t, "/applications/obj-1", patch.Path)
	var got graph.UpdateApplicationRequest
	require.NoError(t, json.Unmarshal(patch.Body, &got))
	assert.Equal(t, []string{"api://new"}, got.IdentifierUris)
	assert.Equal(t, []string{"new"}, got.Tags)
	require.NotNil(t, got.Web)
	assert.Equal(t, []string{"https://new/cb"}, got.Web.RedirectUris)
	assert.Equal(t, "https://old/logout", got.Web.LogoutURL, "unmanaged logout URL must be preserved")
	assert.Nil(t, got.Spa, "unchanged spa redirect URIs must not be sent")
	assert.Nil(t, got.DisplayName, "unmanaged display_name must not be sent")
}

func TestSet_CreateSendsMappedFields(t *testing.T) {
	m, fg, _, ctx := setupSetModule(t, nil)

	err := m.Set(ctx, "m365-t:obj-2", baseStep(map[string]interface{}{
		"identifier_uris": []string{"api://new"},
		"redirect_uris":   &RedirectUris{Web: []string{"https://new/cb"}, Spa: []string{"https://spa/cb"}},
		"logout_url":      "https://new/logout",
		"tags":            []string{"t1"},
	}))
	require.NoError(t, err)

	post := fg.only(t, http.MethodPost)
	assert.Equal(t, "/applications", post.Path)
	var got graph.CreateApplicationRequest
	require.NoError(t, json.Unmarshal(post.Body, &got))
	assert.Equal(t, []string{"api://new"}, got.IdentifierUris)
	assert.Equal(t, []string{"t1"}, got.Tags)
	require.NotNil(t, got.Web)
	assert.Equal(t, []string{"https://new/cb"}, got.Web.RedirectUris)
	assert.Equal(t, "https://new/logout", got.Web.LogoutURL)
	require.NotNil(t, got.Spa)
	assert.Equal(t, []string{"https://spa/cb"}, got.Spa.RedirectUris)
}

func TestSet_RejectsUnapplicableFieldsWithoutGraphCalls(t *testing.T) {
	cases := map[string]map[string]interface{}{
		"redirect_uris.mobile":            {"redirect_uris": map[string]interface{}{"mobile": []interface{}{"x://cb"}}},
		"redirect_uris.desktop":           {"redirect_uris": map[string]interface{}{"desktop": []interface{}{"x://cb"}}},
		"required_resource_access":        {"required_resource_access": []interface{}{map[string]interface{}{"resource_app_id": "r"}}},
		"oauth2_permissions":              {"oauth2_permissions": []interface{}{map[string]interface{}{"id": "1", "admin_consent_display_name": "a", "value": "v"}}},
		"app_roles":                       {"app_roles": []interface{}{map[string]interface{}{"display_name": "a", "value": "v", "allowed_member_types": []interface{}{"User"}}}},
		"optional_claims":                 {"optional_claims": map[string]interface{}{"id_token": []interface{}{map[string]interface{}{"name": "email"}}}},
		"accept_mapped_claims":            {"accept_mapped_claims": true},
		"known_client_applications":       {"known_client_applications": []interface{}{"a"}},
		"pre_authorized_applications":     {"pre_authorized_applications": []interface{}{"a"}},
		"requested_access_token_version":  {"requested_access_token_version": 2},
		"publisher_domain":                {"publisher_domain": "example.com"},
		"create_service_principal":        {"create_service_principal": true},
		"service_principal_settings":      {"service_principal_settings": map[string]interface{}{"account_enabled": true}},
		"password_credentials":            {"password_credentials": []interface{}{map[string]interface{}{"display_name": "s", "secret_text": "hunter2-secret"}}},
		"key_credentials":                 {"key_credentials": []interface{}{map[string]interface{}{"display_name": "k", "key": "KEYMATERIAL"}}},
		"managed app_roles (empty)":       {"managed_fields": []interface{}{"app_roles"}},
		"managed password_credentials":    {"managed_fields": []interface{}{"password_credentials"}},
		"managed key_credentials":         {"managed_fields": []interface{}{"key_credentials"}},
		"managed tags (empty)":            {"managed_fields": []string{"tags"}},
		"managed identifier_uris (empty)": {"managed_fields": []string{"identifier_uris"}},
		"managed logout_url (empty)":      {"managed_fields": []string{"logout_url"}},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			m, fg, ap, ctx := setupSetModule(t, map[string]interface{}{
				"id": "obj-1", "displayName": "App", "signInAudience": "AzureADMyOrg",
			})
			err := m.Set(ctx, "m365-t:obj-1", baseStep(extra))
			require.Error(t, err)
			field := strings.Fields(strings.TrimPrefix(name, "managed "))[0]
			assert.Contains(t, err.Error(), field)
			assert.NotContains(t, err.Error(), "hunter2-secret")
			assert.NotContains(t, err.Error(), "KEYMATERIAL")
			assert.Empty(t, fg.recorded(), "no Graph call may be made")
			assert.Empty(t, ap.requestedTenants(), "no token may be requested")
		})
	}
}

func TestSet_WrongTypeNamesKey(t *testing.T) {
	for key, val := range map[string]interface{}{
		"tags": "not-a-list", "identifier_uris": 5, "managed_fields": []interface{}{1},
		"logout_url": 3, "redirect_uris": "x", "accept_mapped_claims": "yes",
	} {
		t.Run(key, func(t *testing.T) {
			m, fg, ap, ctx := setupSetModule(t, nil)
			err := m.Set(ctx, "m365-t:obj-1", baseStep(map[string]interface{}{key: val}))
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
			assert.Empty(t, fg.recorded(), "no Graph call may be made")
			assert.Empty(t, ap.requestedTenants(), "no token may be requested")
		})
	}
}

func TestUnsupportedHelpersFailClosed(t *testing.T) {
	m := &entraApplicationModule{}
	ctx := context.Background()
	calls := map[string]error{
		"createServicePrincipal":  m.createServicePrincipal(ctx, nil, "app", &ServicePrincipalConfig{}),
		"addPasswordCredential":   m.addPasswordCredential(ctx, nil, "obj", &PasswordCredential{}),
		"addKeyCredential":        m.addKeyCredential(ctx, nil, "obj", &KeyCredential{Key: "KEYMATERIAL"}),
		"syncPasswordCredentials": m.syncPasswordCredentials(ctx, nil, "obj", []PasswordCredential{{}}),
		"syncKeyCredentials":      m.syncKeyCredentials(ctx, nil, "obj", []KeyCredential{{Key: "KEYMATERIAL"}}),
	}
	for name, err := range calls {
		t.Run(name, func(t *testing.T) {
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unsupported")
			assert.NotContains(t, err.Error(), "SecretText")
			assert.NotContains(t, err.Error(), "KEYMATERIAL")
		})
	}
}
