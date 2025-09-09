package m365

import (
	"context"
	"errors"
	"testing"

	"github.com/cfgis/cfgms/features/controller/directory"
	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/directory/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
		name            string
		connected       bool
		setupMocks      func(*MockAuthProvider)
		expectHealthy   bool
		expectError     bool
		expectedErrMsg  string
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
				assert.NotZero(t, health.ResponseTime)
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

// Configuration validation is covered by the Connect tests above