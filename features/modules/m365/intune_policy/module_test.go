// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package intune_policy

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestIntunePolicyModule_DefaultLoggingSupport_embed(t *testing.T) {
	mod := &intunePolicyModule{}

	// intunePolicyModule must implement LoggingInjectable via DefaultLoggingSupport embed
	injectable, ok := modules.Module(mod).(modules.LoggingInjectable)
	require.True(t, ok, "intunePolicyModule must implement modules.LoggingInjectable")

	// Before injection, GetLogger returns nil, false
	logger, injected := injectable.GetLogger()
	assert.Nil(t, logger)
	assert.False(t, injected)

	// After SetLogger, GetLogger returns the injected logger
	mock := pkgtesting.NewMockLogger(true)
	require.NoError(t, injectable.SetLogger(mock))

	logger, injected = injectable.GetLogger()
	assert.Equal(t, mock, logger)
	assert.True(t, injected)
}

// stubIntuneGraphClient is a minimal graph.Client double for intune tests
type stubIntuneGraphClient struct {
	assignFn func(ctx context.Context, token *auth.AccessToken, configID string, assignments []graph.DeviceConfigurationAssignment) error
}

func (s *stubIntuneGraphClient) GetUser(_ context.Context, _ *auth.AccessToken, _ string) (*graph.User, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) ListUsers(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.User, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) CreateUser(_ context.Context, _ *auth.AccessToken, _ *graph.CreateUserRequest) (*graph.User, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) UpdateUser(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateUserRequest) error {
	return nil
}
func (s *stubIntuneGraphClient) DeleteUser(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) GetUserLicenses(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.LicenseAssignment, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) AssignLicense(_ context.Context, _ *auth.AccessToken, _, _ string, _ []string) error {
	return nil
}
func (s *stubIntuneGraphClient) RemoveLicense(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) GetUserGroups(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) AddUserToGroup(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) RemoveUserFromGroup(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) GetConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string) (*graph.ConditionalAccessPolicy, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) CreateConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ *graph.CreateConditionalAccessPolicyRequest) (*graph.ConditionalAccessPolicy, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) UpdateConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateConditionalAccessPolicyRequest) error {
	return nil
}
func (s *stubIntuneGraphClient) DeleteConditionalAccessPolicy(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) GetDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string) (*graph.DeviceConfiguration, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) ListDeviceConfigurationAssignments(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.DeviceConfigurationAssignment, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) AssignDeviceConfiguration(ctx context.Context, token *auth.AccessToken, configID string, assignments []graph.DeviceConfigurationAssignment) error {
	if s.assignFn != nil {
		return s.assignFn(ctx, token, configID, assignments)
	}
	return nil
}
func (s *stubIntuneGraphClient) CreateDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ *graph.CreateDeviceConfigurationRequest) (*graph.DeviceConfiguration, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) UpdateDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateDeviceConfigurationRequest) error {
	return nil
}
func (s *stubIntuneGraphClient) DeleteDeviceConfiguration(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) GetApplication(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Application, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) ListApplications(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.Application, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) CreateApplication(_ context.Context, _ *auth.AccessToken, _ *graph.CreateApplicationRequest) (*graph.Application, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) UpdateApplication(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateApplicationRequest) error {
	return nil
}
func (s *stubIntuneGraphClient) DeleteApplication(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) GetAdministrativeUnit(_ context.Context, _ *auth.AccessToken, _ string) (*graph.AdministrativeUnit, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) ListAdministrativeUnits(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.AdministrativeUnit, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) CreateAdministrativeUnit(_ context.Context, _ *auth.AccessToken, _ *graph.CreateAdministrativeUnitRequest) (*graph.AdministrativeUnit, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) UpdateAdministrativeUnit(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateAdministrativeUnitRequest) error {
	return nil
}
func (s *stubIntuneGraphClient) DeleteAdministrativeUnit(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) GetGroup(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Group, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) ListGroups(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.Group, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) CreateGroup(_ context.Context, _ *auth.AccessToken, _ *graph.CreateGroupRequest) (*graph.Group, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) UpdateGroup(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateGroupRequest) error {
	return nil
}
func (s *stubIntuneGraphClient) DeleteGroup(_ context.Context, _ *auth.AccessToken, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) ListGroupMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) AddGroupMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) RemoveGroupMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) ListGroupOwners(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) AddGroupOwner(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) RemoveGroupOwner(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) ListAdminUnitUserMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) ListAdminUnitGroupMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]string, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) ListAdminUnitScopedRoleMembers(_ context.Context, _ *auth.AccessToken, _ string) ([]graph.AdminUnitScopedRoleMember, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) AddAdminUnitMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) AddAdminUnitScopedRoleMember(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.AddScopedRoleMemberRequest) (*graph.AdminUnitScopedRoleMember, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) RemoveAdminUnitMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) RemoveAdminUnitScopedRoleMember(_ context.Context, _ *auth.AccessToken, _, _ string) error {
	return nil
}
func (s *stubIntuneGraphClient) GetTeam(_ context.Context, _ *auth.AccessToken, _ string) (*graph.Team, error) {
	return nil, nil
}
func (s *stubIntuneGraphClient) CreateTeam(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.CreateTeamRequest) error {
	return nil
}
func (s *stubIntuneGraphClient) UpdateTeamSettings(_ context.Context, _ *auth.AccessToken, _ string, _ *graph.UpdateTeamSettingsRequest) error {
	return nil
}

func TestIntunePolicyModule_assignConfiguration_callsGraphAPI(t *testing.T) {
	var capturedConfigID string
	var capturedAssignments []graph.DeviceConfigurationAssignment
	gc := &stubIntuneGraphClient{
		assignFn: func(_ context.Context, _ *auth.AccessToken, configID string, assignments []graph.DeviceConfigurationAssignment) error {
			capturedConfigID = configID
			capturedAssignments = assignments
			return nil
		},
	}
	mod := &intunePolicyModule{graphClient: gc}

	assignments := []PolicyAssignment{
		{Target: PolicyAssignmentTarget{TargetType: "allDevices"}},
		{Target: PolicyAssignmentTarget{TargetType: "groupAssignmentTarget", GroupID: "gid-1"}},
	}
	err := mod.assignConfiguration(context.Background(), nil, "config-123", assignments)
	require.NoError(t, err)
	assert.Equal(t, "config-123", capturedConfigID)
	assert.Len(t, capturedAssignments, 2)
	assert.Equal(t, "#microsoft.graph.allDevicesAssignmentTarget", capturedAssignments[0].Target.ODataType)
	assert.Equal(t, "gid-1", capturedAssignments[1].Target.GroupID)
}

func TestIntunePolicyModule_assignConfiguration_propagatesError(t *testing.T) {
	gc := &stubIntuneGraphClient{
		assignFn: func(_ context.Context, _ *auth.AccessToken, _ string, _ []graph.DeviceConfigurationAssignment) error {
			return errors.New("Graph API error")
		},
	}
	mod := &intunePolicyModule{graphClient: gc}
	err := mod.assignConfiguration(context.Background(), nil, "config-123", []PolicyAssignment{
		{Target: PolicyAssignmentTarget{TargetType: "allUsers"}},
	})
	assert.Error(t, err)
}
