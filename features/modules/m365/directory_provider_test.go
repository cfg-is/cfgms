// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package m365

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/controller/directory"
	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/directory/types"
)

// Test functions

func TestNewEntraIDDirectoryProvider(t *testing.T) {
	provider := NewEntraIDDirectoryProvider(&stubLogger{}, &stubAuthProvider{}, &stubGraphClient{})

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

// validConnectConfig returns a well-formed provider config for Connect tests.
func validConnectConfig() directory.ProviderConfig {
	return directory.ProviderConfig{
		ProviderName: "entraid",
		Settings: map[string]interface{}{
			"tenant_id": "test-tenant-id",
			"client_id": "test-client-id",
		},
		Credentials: map[string]string{
			"client_secret": "test-client-secret",
		},
	}
}

func TestEntraIDDirectoryProvider_Connect(t *testing.T) {
	tests := []struct {
		name          string
		config        directory.ProviderConfig
		authProvider  auth.Provider
		graphClient   graph.Client
		expectError   bool
		expectConnect bool
	}{
		{
			name:         "successful connection",
			config:       validConnectConfig(),
			authProvider: &stubAuthProvider{},
			graphClient: &stubGraphClient{
				getUserFn: func(_ context.Context, _ *auth.AccessToken, _ string) (*graph.User, error) {
					return &graph.User{ID: "me"}, nil
				},
			},
			expectError:   false,
			expectConnect: true,
		},
		{
			name: "invalid configuration",
			config: directory.ProviderConfig{
				ProviderName: "entraid",
				Settings:     map[string]interface{}{"invalid_field": "value"},
			},
			authProvider:  &stubAuthProvider{},
			graphClient:   &stubGraphClient{},
			expectError:   true,
			expectConnect: false,
		},
		{
			name:   "authentication failure",
			config: validConnectConfig(),
			authProvider: &stubAuthProvider{
				getAccessTokenFn: func(_ context.Context, _ string) (*auth.AccessToken, error) {
					return nil, errors.New("auth failed")
				},
			},
			graphClient:   &stubGraphClient{},
			expectError:   true,
			expectConnect: false,
		},
		{
			name:         "graph api failure is tolerated with client credentials",
			config:       validConnectConfig(),
			authProvider: &stubAuthProvider{},
			graphClient: &stubGraphClient{
				getUserFn: func(_ context.Context, _ *auth.AccessToken, _ string) (*graph.User, error) {
					return nil, errors.New("graph failed")
				},
			},
			expectError:   false,
			expectConnect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewEntraIDDirectoryProvider(&stubLogger{}, tt.authProvider, tt.graphClient)
			err := provider.Connect(context.Background(), tt.config)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectConnect, provider.IsConnected())
		})
	}
}

func TestEntraIDDirectoryProvider_Disconnect(t *testing.T) {
	provider := NewEntraIDDirectoryProvider(&stubLogger{}, &stubAuthProvider{}, &stubGraphClient{})
	provider.connected = true
	err := provider.Disconnect(context.Background())
	assert.NoError(t, err)
	assert.False(t, provider.IsConnected())
}

func TestEntraIDDirectoryProvider_HealthCheck(t *testing.T) {
	tests := []struct {
		name           string
		connected      bool
		authProvider   auth.Provider
		expectHealthy  bool
		expectedErrMsg string
	}{
		{
			name:           "not connected",
			connected:      false,
			authProvider:   &stubAuthProvider{},
			expectHealthy:  false,
			expectedErrMsg: "not connected to Entra ID",
		},
		{
			name:          "connected and healthy",
			connected:     true,
			authProvider:  &stubAuthProvider{},
			expectHealthy: true,
		},
		{
			name:      "connected but auth failure",
			connected: true,
			authProvider: &stubAuthProvider{
				getAccessTokenFn: func(_ context.Context, _ string) (*auth.AccessToken, error) {
					return nil, errors.New("token failed")
				},
			},
			expectHealthy:  false,
			expectedErrMsg: "token retrieval failed: token failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewEntraIDDirectoryProvider(&stubLogger{}, tt.authProvider, &stubGraphClient{})
			provider.connected = tt.connected
			if tt.connected {
				provider.config = &ProviderConfig{TenantID: "test-tenant-id"}
			}

			health, err := provider.HealthCheck(context.Background())
			assert.NoError(t, err)
			assert.NotNil(t, health)
			assert.Equal(t, tt.expectHealthy, health.IsHealthy)
			assert.False(t, health.LastCheck.IsZero())

			if tt.expectedErrMsg != "" {
				assert.Equal(t, tt.expectedErrMsg, health.ErrorMessage)
			}

			if tt.expectHealthy {
				if runtime.GOOS != "windows" {
					assert.NotZero(t, health.ResponseTime)
				}
			}
		})
	}
}

func TestEntraIDDirectoryProvider_GetUser(t *testing.T) {
	tests := []struct {
		name         string
		connected    bool
		userID       string
		authProvider auth.Provider
		graphClient  graph.Client
		expectError  bool
		expectUser   *types.DirectoryUser
	}{
		{
			name:         "not connected",
			connected:    false,
			userID:       "test-user-id",
			authProvider: &stubAuthProvider{},
			graphClient:  &stubGraphClient{},
			expectError:  true,
		},
		{
			name:         "successful get user",
			connected:    true,
			userID:       "test-user-id",
			authProvider: &stubAuthProvider{},
			graphClient: &stubGraphClient{
				getUserFn: func(_ context.Context, _ *auth.AccessToken, id string) (*graph.User, error) {
					return &graph.User{
						ID:                id,
						UserPrincipalName: "test@example.com",
						DisplayName:       "Test User",
						AccountEnabled:    true,
						Mail:              "test@example.com",
					}, nil
				},
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
			authProvider: &stubAuthProvider{
				getAccessTokenFn: func(_ context.Context, _ string) (*auth.AccessToken, error) {
					return nil, errors.New("auth failed")
				},
			},
			graphClient: &stubGraphClient{},
			expectError: true,
		},
		{
			name:         "graph api failure",
			connected:    true,
			userID:       "test-user-id",
			authProvider: &stubAuthProvider{},
			graphClient: &stubGraphClient{
				getUserFn: func(_ context.Context, _ *auth.AccessToken, _ string) (*graph.User, error) {
					return nil, errors.New("graph failed")
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewEntraIDDirectoryProvider(&stubLogger{}, tt.authProvider, tt.graphClient)
			provider.connected = tt.connected
			if tt.connected {
				provider.config = &ProviderConfig{TenantID: "test-tenant-id"}
			}

			user, err := provider.GetUser(context.Background(), tt.userID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tt.expectUser.ID, user.ID)
				assert.Equal(t, tt.expectUser.UserPrincipalName, user.UserPrincipalName)
				assert.Equal(t, tt.expectUser.DisplayName, user.DisplayName)
				assert.Equal(t, tt.expectUser.AccountEnabled, user.AccountEnabled)
				assert.Equal(t, tt.expectUser.EmailAddress, user.EmailAddress)
				assert.Equal(t, tt.expectUser.Mail, user.Mail)
				assert.Equal(t, tt.expectUser.Source, user.Source)
			}
		})
	}
}

func TestEntraIDDirectoryProvider_SupportsOUs(t *testing.T) {
	provider := NewEntraIDDirectoryProvider(&stubLogger{}, &stubAuthProvider{}, &stubGraphClient{})
	assert.False(t, provider.SupportsOUs())
}

func TestEntraIDDirectoryProvider_SupportsAdminUnits(t *testing.T) {
	provider := NewEntraIDDirectoryProvider(&stubLogger{}, &stubAuthProvider{}, &stubGraphClient{})
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

// stubAuthProvider returns a fixed token by default; set getAccessTokenFn to override.
type stubAuthProvider struct {
	getAccessTokenFn func(ctx context.Context, tenantID string) (*auth.AccessToken, error)
}

func (s *stubAuthProvider) GetAccessToken(ctx context.Context, tenantID string) (*auth.AccessToken, error) {
	if s.getAccessTokenFn != nil {
		return s.getAccessTokenFn(ctx, tenantID)
	}
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
	listUsersFn           func(ctx context.Context, token *auth.AccessToken, filter string) ([]graph.User, error)
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
func (s *stubGraphClient) ListUsers(ctx context.Context, t *auth.AccessToken, filter string) ([]graph.User, error) {
	if s.listUsersFn != nil {
		return s.listUsersFn(ctx, t, filter)
	}
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

// --- SearchUsers tests ---

func TestEntraIDDirectoryProvider_SearchUsers_NotConnected(t *testing.T) {
	p := NewEntraIDDirectoryProvider(&stubLogger{}, &stubAuthProvider{}, &stubGraphClient{})
	_, err := p.SearchUsers(context.Background(), &directory.SearchQuery{Query: "alice"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestEntraIDDirectoryProvider_SearchUsers_EmptyQuery(t *testing.T) {
	p := newConnectedProvider(&stubGraphClient{})
	_, err := p.SearchUsers(context.Background(), &directory.SearchQuery{Query: ""})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestEntraIDDirectoryProvider_SearchUsers_WhitespaceOnlyQuery(t *testing.T) {
	p := newConnectedProvider(&stubGraphClient{})
	_, err := p.SearchUsers(context.Background(), &directory.SearchQuery{Query: "   "})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestEntraIDDirectoryProvider_SearchUsers_AuthTokenFailure(t *testing.T) {
	p := NewEntraIDDirectoryProvider(&stubLogger{}, &stubAuthProvider{
		getAccessTokenFn: func(_ context.Context, _ string) (*auth.AccessToken, error) {
			return nil, errors.New("token expired")
		},
	}, &stubGraphClient{})
	p.connected = true
	p.config = &ProviderConfig{TenantID: "test-tenant"}

	_, err := p.SearchUsers(context.Background(), &directory.SearchQuery{Query: "alice"})
	assert.Error(t, err)
}

func TestEntraIDDirectoryProvider_SearchUsers_GraphError(t *testing.T) {
	gc := &stubGraphClient{
		listUsersFn: func(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.User, error) {
			return nil, errors.New("graph unavailable")
		},
	}
	p := newConnectedProvider(gc)
	_, err := p.SearchUsers(context.Background(), &directory.SearchQuery{Query: "alice"})
	assert.Error(t, err)
}

func TestEntraIDDirectoryProvider_SearchUsers_FilterContainsQuery(t *testing.T) {
	var capturedFilter string
	gc := &stubGraphClient{
		listUsersFn: func(_ context.Context, _ *auth.AccessToken, filter string) ([]graph.User, error) {
			capturedFilter = filter
			return []graph.User{{ID: "u1", DisplayName: "Alice", UserPrincipalName: "alice@example.com"}}, nil
		},
	}
	p := newConnectedProvider(gc)
	users, err := p.SearchUsers(context.Background(), &directory.SearchQuery{Query: "Alice"})
	assert.NoError(t, err)
	assert.Len(t, users, 1)
	assert.Contains(t, capturedFilter, "Alice")
	assert.Contains(t, capturedFilter, "startswith")
	assert.Contains(t, capturedFilter, "displayName")
	assert.Contains(t, capturedFilter, "userPrincipalName")
}

func TestEntraIDDirectoryProvider_SearchUsers_SanitizesQuotes(t *testing.T) {
	var capturedFilter string
	gc := &stubGraphClient{
		listUsersFn: func(_ context.Context, _ *auth.AccessToken, filter string) ([]graph.User, error) {
			capturedFilter = filter
			return nil, nil
		},
	}
	p := newConnectedProvider(gc)
	_, err := p.SearchUsers(context.Background(), &directory.SearchQuery{Query: "O'Brien"})
	assert.NoError(t, err)
	assert.Contains(t, capturedFilter, "O''Brien") // single-quote doubled
}

func TestEntraIDDirectoryProvider_SearchUsers_MapsResultsToDirectoryUsers(t *testing.T) {
	gc := &stubGraphClient{
		listUsersFn: func(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.User, error) {
			return []graph.User{
				{ID: "uid-1", DisplayName: "Alice Test", UserPrincipalName: "alice@example.com", Mail: "alice@example.com"},
				{ID: "uid-2", DisplayName: "Bob Test", UserPrincipalName: "bob@example.com", Mail: "bob@example.com"},
			}, nil
		},
	}
	p := newConnectedProvider(gc)
	users, err := p.SearchUsers(context.Background(), &directory.SearchQuery{Query: "Test"})
	assert.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, "uid-1", users[0].ID)
	assert.Equal(t, "Alice Test", users[0].DisplayName)
	assert.Equal(t, "alice@example.com", users[0].UserPrincipalName)
	assert.Equal(t, "entraid", users[0].Source)
}

// writeGraphResponse encodes v as JSON and writes it to w.
func writeGraphResponse(t *testing.T, w http.ResponseWriter, v interface{}) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("writeGraphResponse: %v", err)
	}
}

func TestEntraIDDirectoryProvider_SearchUsers_MockHTTPServer_SinglePage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.Header.Get("Authorization"), "Bearer")
		filter := r.URL.Query().Get("$filter")
		assert.Contains(t, filter, "startswith")
		writeGraphResponse(t, w, map[string]interface{}{
			"value": []map[string]interface{}{
				{"id": "u1", "displayName": "John Doe", "userPrincipalName": "john@example.com", "mail": "john@example.com"},
				{"id": "u2", "displayName": "John Smith", "userPrincipalName": "jsmith@example.com", "mail": "jsmith@example.com"},
			},
		})
	}))
	defer server.Close()

	gc := graph.NewHTTPClient(graph.WithBaseURL(server.URL))
	p := newConnectedProvider(gc)

	users, err := p.SearchUsers(context.Background(), &directory.SearchQuery{Query: "John"})
	assert.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, "u1", users[0].ID)
	assert.Equal(t, "John Doe", users[0].DisplayName)
}

func TestEntraIDDirectoryProvider_SearchUsers_MockHTTPServer_MultiPage(t *testing.T) {
	var serverURL string
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.URL.Query().Get("$skiptoken") == "" {
			// First page: includes nextLink
			writeGraphResponse(t, w, map[string]interface{}{
				"@odata.nextLink": serverURL + "/users?$skiptoken=page2token&$select=id,displayName,userPrincipalName,mail",
				"value": []map[string]interface{}{
					{"id": "u1", "displayName": "Alice A", "userPrincipalName": "alice@example.com"},
				},
			})
		} else {
			// Second page: no nextLink
			writeGraphResponse(t, w, map[string]interface{}{
				"value": []map[string]interface{}{
					{"id": "u2", "displayName": "Alice B", "userPrincipalName": "aliceb@example.com"},
				},
			})
		}
	}))
	defer server.Close()
	serverURL = server.URL

	gc := graph.NewHTTPClient(graph.WithBaseURL(server.URL))
	p := newConnectedProvider(gc)

	users, err := p.SearchUsers(context.Background(), &directory.SearchQuery{Query: "Alice"})
	assert.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, 2, callCount, "expected exactly 2 HTTP calls (initial page + nextLink page)")
	assert.Equal(t, "u1", users[0].ID)
	assert.Equal(t, "u2", users[1].ID)
}

func TestEntraIDDirectoryProvider_SearchUsers_MockHTTPServer_CapsAt1000(t *testing.T) {
	var serverURL string
	pageSize := 200
	callCount := 0

	// Build a page of users
	makePage := func(offset int, count int) []map[string]interface{} {
		users := make([]map[string]interface{}, count)
		for i := 0; i < count; i++ {
			n := offset + i
			users[i] = map[string]interface{}{
				"id":                fmt.Sprintf("u%d", n),
				"displayName":       fmt.Sprintf("User %d", n),
				"userPrincipalName": fmt.Sprintf("user%d@example.com", n),
			}
		}
		return users
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := callCount
		callCount++
		offset := page * pageSize
		// Always return a nextLink so we can verify capping behaviour
		writeGraphResponse(t, w, map[string]interface{}{
			"@odata.nextLink": serverURL + fmt.Sprintf("/users?$skiptoken=page%d", page+1),
			"value":           makePage(offset, pageSize),
		})
	}))
	defer server.Close()
	serverURL = server.URL

	gc := graph.NewHTTPClient(graph.WithBaseURL(server.URL))
	p := newConnectedProvider(gc)

	users, err := p.SearchUsers(context.Background(), &directory.SearchQuery{Query: "User"})
	assert.NoError(t, err)
	// With pageSize=200 and nextLink always present the loop stops exactly at 1000.
	assert.Equal(t, 1000, len(users), "results must be capped at exactly 1000")
}

// Configuration validation is covered by the Connect tests above
