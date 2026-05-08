// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package m365

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cfgis/cfgms/features/controller/directory"
	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/directory/types"
)

// Mock implementations for testing

type MockLogger struct {
	mock.Mock
}

func (m *MockLogger) Debug(msg string, keysAndValues ...interface{}) {
	args := []interface{}{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) Info(msg string, keysAndValues ...interface{}) {
	args := []interface{}{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) Warn(msg string, keysAndValues ...interface{}) {
	args := []interface{}{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) Error(msg string, keysAndValues ...interface{}) {
	args := []interface{}{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) Fatal(msg string, keysAndValues ...interface{}) {
	args := []interface{}{msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) DebugCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	args := []interface{}{ctx, msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) InfoCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	args := []interface{}{ctx, msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) WarnCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	args := []interface{}{ctx, msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) ErrorCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	args := []interface{}{ctx, msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

func (m *MockLogger) FatalCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	args := []interface{}{ctx, msg}
	args = append(args, keysAndValues...)
	m.Called(args...)
}

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

func (m *MockGraphClient) ListDeviceConfigurationAssignments(ctx context.Context, token *auth.AccessToken, configurationID string) ([]graph.DeviceConfigurationAssignment, error) {
	return nil, nil
}

func (m *MockGraphClient) AssignDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string, assignments []graph.DeviceConfigurationAssignment) error {
	return nil
}

// Missing methods for interface compliance
func (m *MockGraphClient) ListUsers(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.User, error) {
	args := m.Called(ctx, token, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]graph.User), args.Error(1)
}

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

// Test functions

func TestNewEntraIDDirectoryProvider(t *testing.T) {
	mockLogger := &MockLogger{}
	mockAuth := &MockAuthProvider{}
	mockGraph := &MockGraphClient{}

	provider := NewEntraIDDirectoryProvider(mockLogger, mockAuth, mockGraph)

	assert.NotNil(t, provider)
	assert.Equal(t, "entraid", provider.Name())
	assert.Equal(t, "Microsoft Entra ID", provider.DisplayName())
	assert.Equal(t, "Microsoft Entra ID (formerly Azure Active Directory) directory provider", provider.Description())
	assert.False(t, provider.IsConnected())

	capabilities := provider.Capabilities()
	assert.True(t, capabilities.UserManagement)
	assert.True(t, capabilities.GroupManagement)
	assert.True(t, capabilities.AdvancedSearch)
	assert.False(t, capabilities.BulkOperations)
	assert.False(t, capabilities.RealTimeSync)
	assert.True(t, capabilities.CrossDirectoryOps)
	assert.False(t, capabilities.OUSupport)
	assert.True(t, capabilities.AdminUnitSupport)
	assert.Equal(t, []string{"oauth2", "client_credentials"}, capabilities.SupportedAuthMethods)
	assert.Equal(t, 999, capabilities.MaxSearchResults)
	assert.NotNil(t, capabilities.RateLimit)
}

func TestEntraIDDirectoryProvider_Connect(t *testing.T) {
	tests := []struct {
		name          string
		config        directory.ProviderConfig
		setupMocks    func(*MockLogger, *MockAuthProvider, *MockGraphClient)
		expectError   bool
		expectConnect bool
	}{
		{
			name: "successful connection",
			config: directory.ProviderConfig{
				ProviderName: "entraid",
				Settings: map[string]interface{}{
					"tenant_id": "test-tenant-id",
					"client_id": "test-client-id",
				},
				Credentials: map[string]string{
					"client_secret": "test-client-secret",
				},
			},
			setupMocks: func(mockLogger *MockLogger, mockAuth *MockAuthProvider, mockGraph *MockGraphClient) {
				mockToken := &auth.AccessToken{Token: "test-token"}
				mockAuth.On("GetAccessToken", mock.Anything, "test-tenant-id").Return(mockToken, nil)
				mockUser := &graph.User{ID: "me"}
				mockGraph.On("GetUser", mock.Anything, mockToken, "me").Return(mockUser, nil)
				mockLogger.On("Info", "Connected to Entra ID", "tenant_id", "test-tenant-id").Return()
			},
			expectError:   false,
			expectConnect: true,
		},
		{
			name: "invalid configuration",
			config: directory.ProviderConfig{
				ProviderName: "entraid",
				Settings: map[string]interface{}{
					"invalid_field": "value",
				},
			},
			setupMocks: func(mockLogger *MockLogger, mockAuth *MockAuthProvider, mockGraph *MockGraphClient) {
				// No mocks needed as this should fail config parsing
			},
			expectError:   true,
			expectConnect: false,
		},
		{
			name: "authentication failure",
			config: directory.ProviderConfig{
				ProviderName: "entraid",
				Settings: map[string]interface{}{
					"tenant_id": "test-tenant-id",
					"client_id": "test-client-id",
				},
				Credentials: map[string]string{
					"client_secret": "test-client-secret",
				},
			},
			setupMocks: func(mockLogger *MockLogger, mockAuth *MockAuthProvider, mockGraph *MockGraphClient) {
				mockAuth.On("GetAccessToken", mock.Anything, "test-tenant-id").Return(nil, errors.New("auth failed"))
			},
			expectError:   true,
			expectConnect: false,
		},
		{
			name: "graph api failure",
			config: directory.ProviderConfig{
				ProviderName: "entraid",
				Settings: map[string]interface{}{
					"tenant_id": "test-tenant-id",
					"client_id": "test-client-id",
				},
				Credentials: map[string]string{
					"client_secret": "test-client-secret",
				},
			},
			setupMocks: func(mockLogger *MockLogger, mockAuth *MockAuthProvider, mockGraph *MockGraphClient) {
				mockToken := &auth.AccessToken{Token: "test-token"}
				mockAuth.On("GetAccessToken", mock.Anything, "test-tenant-id").Return(mockToken, nil)
				mockGraph.On("GetUser", mock.Anything, mockToken, "me").Return(nil, errors.New("graph failed"))
				mockLogger.On("Debug", "Graph API test call completed", "error", errors.New("graph failed")).Return()
				mockLogger.On("Info", "Connected to Entra ID", "tenant_id", "test-tenant-id").Return()
			},
			expectError:   false,
			expectConnect: true, // Graph API failure is expected with client credentials
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLogger := &MockLogger{}
			mockAuth := &MockAuthProvider{}
			mockGraph := &MockGraphClient{}

			tt.setupMocks(mockLogger, mockAuth, mockGraph)

			provider := NewEntraIDDirectoryProvider(mockLogger, mockAuth, mockGraph)

			ctx := context.Background()
			err := provider.Connect(ctx, tt.config)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.expectConnect, provider.IsConnected())

			mockAuth.AssertExpectations(t)
			mockGraph.AssertExpectations(t)
			mockLogger.AssertExpectations(t)
		})
	}
}

func TestEntraIDDirectoryProvider_Disconnect(t *testing.T) {
	mockLogger := &MockLogger{}
	mockAuth := &MockAuthProvider{}
	mockGraph := &MockGraphClient{}

	mockLogger.On("Info", "Disconnected from Entra ID").Return()

	provider := NewEntraIDDirectoryProvider(mockLogger, mockAuth, mockGraph)

	// Simulate connected state
	provider.connected = true

	ctx := context.Background()
	err := provider.Disconnect(ctx)

	assert.NoError(t, err)
	assert.False(t, provider.IsConnected())

	mockLogger.AssertExpectations(t)
}

func TestEntraIDDirectoryProvider_HealthCheck(t *testing.T) {
	tests := []struct {
		name           string
		connected      bool
		setupMocks     func(*MockAuthProvider)
		expectHealthy  bool
		expectError    bool
		expectedErrMsg string
	}{
		{
			name:           "not connected",
			connected:      false,
			setupMocks:     func(mockAuth *MockAuthProvider) {},
			expectHealthy:  false,
			expectError:    false,
			expectedErrMsg: "not connected to Entra ID",
		},
		{
			name:      "connected and healthy",
			connected: true,
			setupMocks: func(mockAuth *MockAuthProvider) {
				mockToken := &auth.AccessToken{Token: "test-token"}
				mockAuth.On("GetAccessToken", mock.Anything, "test-tenant-id").Return(mockToken, nil)
			},
			expectHealthy: true,
			expectError:   false,
		},
		{
			name:      "connected but auth failure",
			connected: true,
			setupMocks: func(mockAuth *MockAuthProvider) {
				mockAuth.On("GetAccessToken", mock.Anything, "test-tenant-id").Return(nil, errors.New("token failed"))
			},
			expectHealthy:  false,
			expectError:    false,
			expectedErrMsg: "token retrieval failed: token failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLogger := &MockLogger{}
			mockAuth := &MockAuthProvider{}
			mockGraph := &MockGraphClient{}

			tt.setupMocks(mockAuth)

			provider := NewEntraIDDirectoryProvider(mockLogger, mockAuth, mockGraph)
			provider.connected = tt.connected
			if tt.connected {
				provider.config = &ProviderConfig{TenantID: "test-tenant-id"}
			}

			ctx := context.Background()
			health, err := provider.HealthCheck(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.NotNil(t, health)
			assert.Equal(t, tt.expectHealthy, health.IsHealthy)
			assert.False(t, health.LastCheck.IsZero())

			if tt.expectedErrMsg != "" {
				assert.Equal(t, tt.expectedErrMsg, health.ErrorMessage)
			}

			if tt.expectHealthy {
				// Windows timer resolution may cause ResponseTime to be 0 for very fast operations
				// This is acceptable and doesn't indicate a failure
				if runtime.GOOS != "windows" {
					assert.NotZero(t, health.ResponseTime)
				}
			}

			mockAuth.AssertExpectations(t)
		})
	}
}

func TestEntraIDDirectoryProvider_GetUser(t *testing.T) {
	tests := []struct {
		name        string
		connected   bool
		userID      string
		setupMocks  func(*MockAuthProvider, *MockGraphClient)
		expectError bool
		expectUser  *types.DirectoryUser
	}{
		{
			name:      "not connected",
			connected: false,
			userID:    "test-user-id",
			setupMocks: func(mockAuth *MockAuthProvider, mockGraph *MockGraphClient) {
				// No mocks needed
			},
			expectError: true,
		},
		{
			name:      "successful get user",
			connected: true,
			userID:    "test-user-id",
			setupMocks: func(mockAuth *MockAuthProvider, mockGraph *MockGraphClient) {
				mockToken := &auth.AccessToken{Token: "test-token"}
				mockAuth.On("GetAccessToken", mock.Anything, "test-tenant-id").Return(mockToken, nil)

				mockUser := &graph.User{
					ID:                "test-user-id",
					UserPrincipalName: "test@example.com",
					DisplayName:       "Test User",
					AccountEnabled:    true,
					Mail:              "test@example.com",
				}
				mockGraph.On("GetUser", mock.Anything, mockToken, "test-user-id").Return(mockUser, nil)
			},
			expectError: false,
			expectUser: &types.DirectoryUser{
				ID:                "test-user-id",
				UserPrincipalName: "test@example.com",
				DisplayName:       "Test User",
				AccountEnabled:    true,
				EmailAddress:      "test@example.com",
				Mail:              "test@example.com",
				Source:            "entraid",
			},
		},
		{
			name:      "auth token failure",
			connected: true,
			userID:    "test-user-id",
			setupMocks: func(mockAuth *MockAuthProvider, mockGraph *MockGraphClient) {
				mockAuth.On("GetAccessToken", mock.Anything, "test-tenant-id").Return(nil, errors.New("auth failed"))
			},
			expectError: true,
		},
		{
			name:      "graph api failure",
			connected: true,
			userID:    "test-user-id",
			setupMocks: func(mockAuth *MockAuthProvider, mockGraph *MockGraphClient) {
				mockToken := &auth.AccessToken{Token: "test-token"}
				mockAuth.On("GetAccessToken", mock.Anything, "test-tenant-id").Return(mockToken, nil)
				mockGraph.On("GetUser", mock.Anything, mockToken, "test-user-id").Return(nil, errors.New("graph failed"))
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLogger := &MockLogger{}
			mockAuth := &MockAuthProvider{}
			mockGraph := &MockGraphClient{}

			tt.setupMocks(mockAuth, mockGraph)

			provider := NewEntraIDDirectoryProvider(mockLogger, mockAuth, mockGraph)
			provider.connected = tt.connected
			if tt.connected {
				provider.config = &ProviderConfig{TenantID: "test-tenant-id"}
			}

			ctx := context.Background()
			user, err := provider.GetUser(ctx, tt.userID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)

				// Compare key fields
				assert.Equal(t, tt.expectUser.ID, user.ID)
				assert.Equal(t, tt.expectUser.UserPrincipalName, user.UserPrincipalName)
				assert.Equal(t, tt.expectUser.DisplayName, user.DisplayName)
				assert.Equal(t, tt.expectUser.AccountEnabled, user.AccountEnabled)
				assert.Equal(t, tt.expectUser.EmailAddress, user.EmailAddress)
				assert.Equal(t, tt.expectUser.Mail, user.Mail)
				assert.Equal(t, tt.expectUser.Source, user.Source)
			}

			mockAuth.AssertExpectations(t)
			mockGraph.AssertExpectations(t)
		})
	}
}

func TestEntraIDDirectoryProvider_SupportsOUs(t *testing.T) {
	mockLogger := &MockLogger{}
	mockAuth := &MockAuthProvider{}
	mockGraph := &MockGraphClient{}

	provider := NewEntraIDDirectoryProvider(mockLogger, mockAuth, mockGraph)

	// Entra ID doesn't support OUs
	assert.False(t, provider.SupportsOUs())
}

func TestEntraIDDirectoryProvider_SupportsAdminUnits(t *testing.T) {
	mockLogger := &MockLogger{}
	mockAuth := &MockAuthProvider{}
	mockGraph := &MockGraphClient{}

	provider := NewEntraIDDirectoryProvider(mockLogger, mockAuth, mockGraph)

	// Entra ID supports Administrative Units
	assert.True(t, provider.SupportsAdminUnits())
}

// --- struct-based test doubles (no mock framework) ---

// stubLogger is a no-op logger double
type stubLogger struct{}

func (s *stubLogger) Debug(msg string, _ ...interface{})                       {}
func (s *stubLogger) Info(msg string, _ ...interface{})                        {}
func (s *stubLogger) Warn(msg string, _ ...interface{})                        {}
func (s *stubLogger) Error(msg string, _ ...interface{})                       {}
func (s *stubLogger) Fatal(msg string, _ ...interface{})                       {}
func (s *stubLogger) DebugCtx(_ context.Context, msg string, _ ...interface{}) {}
func (s *stubLogger) InfoCtx(_ context.Context, msg string, _ ...interface{})  {}
func (s *stubLogger) WarnCtx(_ context.Context, msg string, _ ...interface{})  {}
func (s *stubLogger) ErrorCtx(_ context.Context, msg string, _ ...interface{}) {}
func (s *stubLogger) FatalCtx(_ context.Context, msg string, _ ...interface{}) {}
func (s *stubLogger) With(_ ...interface{}) interface{}                        { return s }
func (s *stubLogger) WithContext(_ context.Context) interface{}                { return s }
func (s *stubLogger) Named(_ string) interface{}                               { return s }
func (s *stubLogger) Sync() error                                              { return nil }

// stubAuthProvider always returns a fixed token
type stubAuthProvider struct{}

func (s *stubAuthProvider) GetAccessToken(_ context.Context, _ string) (*auth.AccessToken, error) {
	return &auth.AccessToken{Token: "stub-token"}, nil
}
func (s *stubAuthProvider) GetDelegatedAccessToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return &auth.AccessToken{Token: "stub-token"}, nil
}
func (s *stubAuthProvider) RefreshToken(_ context.Context, _ string) (*auth.AccessToken, error) {
	return &auth.AccessToken{Token: "stub-token"}, nil
}
func (s *stubAuthProvider) RefreshDelegatedToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return &auth.AccessToken{Token: "stub-token"}, nil
}
func (s *stubAuthProvider) IsTokenValid(_ *auth.AccessToken) bool { return true }
func (s *stubAuthProvider) ValidatePermissions(_ context.Context, _ *auth.AccessToken, _ []string) error {
	return nil
}

// stubGraphClient is a configurable graph.Client double with function fields
type stubGraphClient struct {
	getGroupFn            func(ctx context.Context, token *auth.AccessToken, groupID string) (*graph.Group, error)
	listGroupsFn          func(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.Group, error)
	createGroupFn         func(ctx context.Context, token *auth.AccessToken, req *graph.CreateGroupRequest) (*graph.Group, error)
	updateGroupFn         func(ctx context.Context, token *auth.AccessToken, groupID string, req *graph.UpdateGroupRequest) error
	deleteGroupFn         func(ctx context.Context, token *auth.AccessToken, groupID string) error
	getUserGroupsFn       func(ctx context.Context, token *auth.AccessToken, userID string) ([]string, error)
	addUserToGroupFn      func(ctx context.Context, token *auth.AccessToken, userID, groupName string) error
	removeUserFromGroupFn func(ctx context.Context, token *auth.AccessToken, userID, groupName string) error
	listGroupMembersFn    func(ctx context.Context, token *auth.AccessToken, groupID string) ([]string, error)
	getUserFn             func(ctx context.Context, token *auth.AccessToken, upn string) (*graph.User, error)
	getAdminUnitFn        func(ctx context.Context, token *auth.AccessToken, unitID string) (*graph.AdministrativeUnit, error)
	listAdminUnitsFn      func(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.AdministrativeUnit, error)
	createAdminUnitFn     func(ctx context.Context, token *auth.AccessToken, req *graph.CreateAdministrativeUnitRequest) (*graph.AdministrativeUnit, error)
	updateAdminUnitFn     func(ctx context.Context, token *auth.AccessToken, unitID string, req *graph.UpdateAdministrativeUnitRequest) error
	deleteAdminUnitFn     func(ctx context.Context, token *auth.AccessToken, unitID string) error
}

// Mandatory interface method stubs
func (s *stubGraphClient) GetUser(ctx context.Context, t *auth.AccessToken, u string) (*graph.User, error) {
	if s.getUserFn != nil {
		return s.getUserFn(ctx, t, u)
	}
	return &graph.User{ID: u, UserPrincipalName: u}, nil
}
func (s *stubGraphClient) ListUsers(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.User, error) {
	return nil, nil
}
func (s *stubGraphClient) CreateUser(_ context.Context, _ *auth.AccessToken, _ *graph.CreateUserRequest) (*graph.User, error) {
	return nil, nil
}
func (s *stubGraphClient) UpdateUser(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateUserRequest) error {
	return nil
}
func (s *stubGraphClient) DeleteUser(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubGraphClient) GetUserLicenses(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.LicenseAssignment, error) {
	return nil, nil
}
func (s *stubGraphClient) AssignLicense(_ context.Context, _ *auth.AccessToken, _, _ string, _ []string) error {
	return nil
}
func (s *stubGraphClient) RemoveLicense(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) GetUserGroups(ctx context.Context, t *auth.AccessToken, userID string) ([]string, error) {
	if s.getUserGroupsFn != nil {
		return s.getUserGroupsFn(ctx, t, userID)
	}
	return nil, nil
}
func (s *stubGraphClient) AddUserToGroup(ctx context.Context, t *auth.AccessToken, userID, groupName string) error {
	if s.addUserToGroupFn != nil {
		return s.addUserToGroupFn(ctx, t, userID, groupName)
	}
	return nil
}
func (s *stubGraphClient) RemoveUserFromGroup(ctx context.Context, t *auth.AccessToken, userID, groupName string) error {
	if s.removeUserFromGroupFn != nil {
		return s.removeUserFromGroupFn(ctx, t, userID, groupName)
	}
	return nil
}
func (s *stubGraphClient) GetConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string) (*graph.ConditionalAccessPolicy, error) {
	return nil, nil
}
func (s *stubGraphClient) CreateConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ *graph.CreateConditionalAccessPolicyRequest) (*graph.ConditionalAccessPolicy, error) {
	return nil, nil
}
func (s *stubGraphClient) UpdateConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateConditionalAccessPolicyRequest) error {
	return nil
}
func (s *stubGraphClient) DeleteConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubGraphClient) GetDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string) (*graph.DeviceConfiguration, error) {
	return nil, nil
}
func (s *stubGraphClient) ListDeviceConfigurationAssignments(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.DeviceConfigurationAssignment, error) {
	return nil, nil
}
func (s *stubGraphClient) AssignDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string, _ []graph.DeviceConfigurationAssignment) error {
	return nil
}
func (s *stubGraphClient) CreateDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ *graph.CreateDeviceConfigurationRequest) (*graph.DeviceConfiguration, error) {
	return nil, nil
}
func (s *stubGraphClient) UpdateDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateDeviceConfigurationRequest) error {
	return nil
}
func (s *stubGraphClient) DeleteDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubGraphClient) GetApplication(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Application, error) {
	return nil, nil
}
func (s *stubGraphClient) ListApplications(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.Application, error) {
	return nil, nil
}
func (s *stubGraphClient) CreateApplication(_ context.Context, _ *auth.AccessToken, _ *graph.CreateApplicationRequest) (*graph.Application, error) {
	return nil, nil
}
func (s *stubGraphClient) UpdateApplication(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateApplicationRequest) error {
	return nil
}
func (s *stubGraphClient) DeleteApplication(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubGraphClient) GetAdministrativeUnit(ctx context.Context, t *auth.AccessToken, unitID string) (*graph.AdministrativeUnit, error) {
	if s.getAdminUnitFn != nil {
		return s.getAdminUnitFn(ctx, t, unitID)
	}
	return nil, nil
}
func (s *stubGraphClient) ListAdministrativeUnits(ctx context.Context, t *auth.AccessToken, filter string) ([]graph.AdministrativeUnit, error) {
	if s.listAdminUnitsFn != nil {
		return s.listAdminUnitsFn(ctx, t, filter)
	}
	return nil, nil
}
func (s *stubGraphClient) CreateAdministrativeUnit(ctx context.Context, t *auth.AccessToken, req *graph.CreateAdministrativeUnitRequest) (*graph.AdministrativeUnit, error) {
	if s.createAdminUnitFn != nil {
		return s.createAdminUnitFn(ctx, t, req)
	}
	return nil, nil
}
func (s *stubGraphClient) UpdateAdministrativeUnit(ctx context.Context, t *auth.AccessToken, unitID string, req *graph.UpdateAdministrativeUnitRequest) error {
	if s.updateAdminUnitFn != nil {
		return s.updateAdminUnitFn(ctx, t, unitID, req)
	}
	return nil
}
func (s *stubGraphClient) DeleteAdministrativeUnit(ctx context.Context, t *auth.AccessToken, unitID string) error {
	if s.deleteAdminUnitFn != nil {
		return s.deleteAdminUnitFn(ctx, t, unitID)
	}
	return nil
}
func (s *stubGraphClient) GetGroup(ctx context.Context, t *auth.AccessToken, groupID string) (*graph.Group, error) {
	if s.getGroupFn != nil {
		return s.getGroupFn(ctx, t, groupID)
	}
	return nil, nil
}
func (s *stubGraphClient) ListGroups(ctx context.Context, t *auth.AccessToken, filter string) ([]graph.Group, error) {
	if s.listGroupsFn != nil {
		return s.listGroupsFn(ctx, t, filter)
	}
	return nil, nil
}
func (s *stubGraphClient) CreateGroup(ctx context.Context, t *auth.AccessToken, req *graph.CreateGroupRequest) (*graph.Group, error) {
	if s.createGroupFn != nil {
		return s.createGroupFn(ctx, t, req)
	}
	return nil, nil
}
func (s *stubGraphClient) UpdateGroup(ctx context.Context, t *auth.AccessToken, groupID string, req *graph.UpdateGroupRequest) error {
	if s.updateGroupFn != nil {
		return s.updateGroupFn(ctx, t, groupID, req)
	}
	return nil
}
func (s *stubGraphClient) DeleteGroup(ctx context.Context, t *auth.AccessToken, groupID string) error {
	if s.deleteGroupFn != nil {
		return s.deleteGroupFn(ctx, t, groupID)
	}
	return nil
}
func (s *stubGraphClient) ListGroupMembers(ctx context.Context, t *auth.AccessToken, groupID string) ([]string, error) {
	if s.listGroupMembersFn != nil {
		return s.listGroupMembersFn(ctx, t, groupID)
	}
	return nil, nil
}
func (s *stubGraphClient) AddGroupMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) RemoveGroupMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) ListGroupOwners(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubGraphClient) AddGroupOwner(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) RemoveGroupOwner(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) ListAdminUnitUserMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubGraphClient) ListAdminUnitGroupMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubGraphClient) ListAdminUnitScopedRoleMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.AdminUnitScopedRoleMember, error) {
	return nil, nil
}
func (s *stubGraphClient) AddAdminUnitMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) AddAdminUnitScopedRoleMember(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.AddScopedRoleMemberRequest) (*graph.AdminUnitScopedRoleMember, error) {
	return nil, nil
}
func (s *stubGraphClient) RemoveAdminUnitMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) RemoveAdminUnitScopedRoleMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubGraphClient) GetTeam(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Team, error) {
	return nil, nil
}
func (s *stubGraphClient) CreateTeam(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.CreateTeamRequest) error {
	return nil
}
func (s *stubGraphClient) UpdateTeamSettings(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateTeamSettingsRequest) error {
	return nil
}

// newConnectedProvider creates a connected provider with stub auth and given graph client double
func newConnectedProvider(gc graph.Client) *EntraIDDirectoryProvider {
	p := NewEntraIDDirectoryProvider(&stubLogger{}, &stubAuthProvider{}, gc)
	p.connected = true
	p.config = &ProviderConfig{TenantID: "test-tenant", ClientID: "cid", ClientSecret: "cs"}
	return p
}

func TestEntraIDDirectoryProvider_GetGroup(t *testing.T) {
	want := &graph.Group{ID: "gid-1", DisplayName: "Eng", MailNickname: "eng", SecurityEnabled: true}
	gc := &stubGraphClient{
		getGroupFn: func(_ context.Context, _ *auth.AccessToken, id string) (*graph.Group, error) {
			if id != "gid-1" {
				return nil, errors.New("unexpected id")
			}
			return want, nil
		},
	}
	p := newConnectedProvider(gc)

	got, err := p.GetGroup(context.Background(), "gid-1")
	assert.NoError(t, err)
	assert.Equal(t, "gid-1", got.ID)
	assert.Equal(t, "Eng", got.DisplayName)
}

func TestEntraIDDirectoryProvider_GetGroup_Error(t *testing.T) {
	gc := &stubGraphClient{
		getGroupFn: func(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Group, error) {
			return nil, errors.New("not found")
		},
	}
	p := newConnectedProvider(gc)
	_, err := p.GetGroup(context.Background(), "missing")
	assert.Error(t, err)
}

func TestEntraIDDirectoryProvider_CreateGroup(t *testing.T) {
	var captured *graph.CreateGroupRequest
	gc := &stubGraphClient{
		createGroupFn: func(_ context.Context, _ *auth.AccessToken, req *graph.CreateGroupRequest) (*graph.Group, error) {
			captured = req
			return &graph.Group{ID: "new-gid", DisplayName: req.DisplayName, MailNickname: req.MailNickname}, nil
		},
	}
	p := newConnectedProvider(gc)

	input := &types.DirectoryGroup{
		DisplayName:     "Sales",
		MailNickname:    "sales",
		SecurityEnabled: true,
		GroupType:       types.GroupTypeSecurity,
	}
	got, err := p.CreateGroup(context.Background(), input)
	assert.NoError(t, err)
	assert.Equal(t, "new-gid", got.ID)
	assert.Equal(t, "Sales", captured.DisplayName)
}

func TestEntraIDDirectoryProvider_UpdateGroup(t *testing.T) {
	calls := 0
	gc := &stubGraphClient{
		updateGroupFn: func(_ context.Context, _ *auth.AccessToken, id string, _ *graph.UpdateGroupRequest) error {
			calls++
			assert.Equal(t, "gid-u", id)
			return nil
		},
		getGroupFn: func(_ context.Context, _ *auth.AccessToken, id string) (*graph.Group, error) {
			return &graph.Group{ID: id, DisplayName: "Updated"}, nil
		},
	}
	p := newConnectedProvider(gc)

	_, err := p.UpdateGroup(context.Background(), "gid-u", &types.DirectoryGroup{
		DisplayName: "Updated", GroupType: types.GroupTypeSecurity,
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, calls)
}

func TestEntraIDDirectoryProvider_DeleteGroup(t *testing.T) {
	var deleted string
	gc := &stubGraphClient{
		deleteGroupFn: func(_ context.Context, _ *auth.AccessToken, id string) error {
			deleted = id
			return nil
		},
	}
	p := newConnectedProvider(gc)
	err := p.DeleteGroup(context.Background(), "gid-del")
	assert.NoError(t, err)
	assert.Equal(t, "gid-del", deleted)
}

func TestEntraIDDirectoryProvider_SearchGroups(t *testing.T) {
	var capturedFilter string
	gc := &stubGraphClient{
		listGroupsFn: func(_ context.Context, _ *auth.AccessToken, filter string) ([]graph.Group, error) {
			capturedFilter = filter
			return []graph.Group{{ID: "g1", DisplayName: "Engineering"}}, nil
		},
	}
	p := newConnectedProvider(gc)

	q := &directory.SearchQuery{Query: "Engineering"}
	groups, err := p.SearchGroups(context.Background(), q)
	assert.NoError(t, err)
	assert.Len(t, groups, 1)
	assert.Contains(t, capturedFilter, "Engineering")
}

func TestEntraIDDirectoryProvider_SearchGroups_SanitizesInput(t *testing.T) {
	var capturedFilter string
	gc := &stubGraphClient{
		listGroupsFn: func(_ context.Context, _ *auth.AccessToken, filter string) ([]graph.Group, error) {
			capturedFilter = filter
			return nil, nil
		},
	}
	p := newConnectedProvider(gc)

	_, err := p.SearchGroups(context.Background(), &directory.SearchQuery{Query: "O'Reilly Group"})
	assert.NoError(t, err)
	assert.Contains(t, capturedFilter, "O''Reilly Group") // single-quote escaped
}

func TestEntraIDDirectoryProvider_AddUserToGroup(t *testing.T) {
	var gotUser, gotGroup string
	gc := &stubGraphClient{
		addUserToGroupFn: func(_ context.Context, _ *auth.AccessToken, userID, groupName string) error {
			gotUser, gotGroup = userID, groupName
			return nil
		},
	}
	p := newConnectedProvider(gc)
	err := p.AddUserToGroup(context.Background(), "user@example.com", "group-id")
	assert.NoError(t, err)
	assert.Equal(t, "user@example.com", gotUser)
	assert.Equal(t, "group-id", gotGroup)
}

func TestEntraIDDirectoryProvider_RemoveUserFromGroup(t *testing.T) {
	var gotUser, gotGroup string
	gc := &stubGraphClient{
		removeUserFromGroupFn: func(_ context.Context, _ *auth.AccessToken, userID, groupName string) error {
			gotUser, gotGroup = userID, groupName
			return nil
		},
	}
	p := newConnectedProvider(gc)
	err := p.RemoveUserFromGroup(context.Background(), "user@example.com", "group-id")
	assert.NoError(t, err)
	assert.Equal(t, "user@example.com", gotUser)
	assert.Equal(t, "group-id", gotGroup)
}

func TestEntraIDDirectoryProvider_GetUserGroups(t *testing.T) {
	gc := &stubGraphClient{
		getUserGroupsFn: func(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
			return []string{"gid-1", "gid-2"}, nil
		},
		getGroupFn: func(_ context.Context, _ *auth.AccessToken, id string) (*graph.Group, error) {
			return &graph.Group{ID: id, DisplayName: "Group-" + id}, nil
		},
	}
	p := newConnectedProvider(gc)
	groups, err := p.GetUserGroups(context.Background(), "uid")
	assert.NoError(t, err)
	assert.Len(t, groups, 2)
}

func TestEntraIDDirectoryProvider_GetGroupMembers(t *testing.T) {
	gc := &stubGraphClient{
		listGroupMembersFn: func(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
			return []string{"user1@example.com", "user2@example.com"}, nil
		},
		getUserFn: func(_ context.Context, _ *auth.AccessToken, upn string) (*graph.User, error) {
			return &graph.User{ID: "id-" + upn, UserPrincipalName: upn, DisplayName: "User " + upn}, nil
		},
	}
	p := newConnectedProvider(gc)
	members, err := p.GetGroupMembers(context.Background(), "gid")
	assert.NoError(t, err)
	assert.Len(t, members, 2)
}

func TestEntraIDDirectoryProvider_GetAdminUnit(t *testing.T) {
	gc := &stubGraphClient{
		getAdminUnitFn: func(_ context.Context, _ *auth.AccessToken, id string) (*graph.AdministrativeUnit, error) {
			return &graph.AdministrativeUnit{ID: id, DisplayName: "AU-1", Visibility: "Public"}, nil
		},
	}
	p := newConnectedProvider(gc)
	au, err := p.GetAdminUnit(context.Background(), "au-id")
	assert.NoError(t, err)
	assert.Equal(t, "au-id", au.ID)
	assert.Equal(t, "AU-1", au.DisplayName)
	assert.Equal(t, "Public", au.Visibility)
}

func TestEntraIDDirectoryProvider_CreateAdminUnit(t *testing.T) {
	var capturedReq *graph.CreateAdministrativeUnitRequest
	gc := &stubGraphClient{
		createAdminUnitFn: func(_ context.Context, _ *auth.AccessToken, req *graph.CreateAdministrativeUnitRequest) (*graph.AdministrativeUnit, error) {
			capturedReq = req
			return &graph.AdministrativeUnit{ID: "new-au", DisplayName: req.DisplayName, Visibility: req.Visibility}, nil
		},
	}
	p := newConnectedProvider(gc)

	au, err := p.CreateAdminUnit(context.Background(), &directory.AdministrativeUnit{
		DisplayName: "IT-West", Visibility: "Public",
	})
	assert.NoError(t, err)
	assert.Equal(t, "new-au", au.ID)
	assert.Equal(t, "IT-West", capturedReq.DisplayName)
	assert.Equal(t, "Public", capturedReq.Visibility)
}

func TestEntraIDDirectoryProvider_ListAdminUnits(t *testing.T) {
	gc := &stubGraphClient{
		listAdminUnitsFn: func(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.AdministrativeUnit, error) {
			return []graph.AdministrativeUnit{
				{ID: "au-1", DisplayName: "AU One"},
				{ID: "au-2", DisplayName: "AU Two"},
			}, nil
		},
	}
	p := newConnectedProvider(gc)
	units, err := p.ListAdminUnits(context.Background())
	assert.NoError(t, err)
	assert.Len(t, units, 2)
	assert.Equal(t, "au-1", units[0].ID)
	assert.Equal(t, "au-2", units[1].ID)
}

// Configuration validation is covered by the Connect tests above
