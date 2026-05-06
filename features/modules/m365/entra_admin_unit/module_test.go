// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package entra_admin_unit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
)

// testHTTPAuthProvider is a minimal auth.Provider for httptest.Server-based tests.
// It returns a preset token without making any network calls.
type testHTTPAuthProvider struct {
	token *auth.AccessToken
}

func (p *testHTTPAuthProvider) GetAccessToken(_ context.Context, _ string) (*auth.AccessToken, error) {
	return p.token, nil
}
func (p *testHTTPAuthProvider) GetDelegatedAccessToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return p.token, nil
}
func (p *testHTTPAuthProvider) RefreshToken(_ context.Context, _ string) (*auth.AccessToken, error) {
	return p.token, nil
}
func (p *testHTTPAuthProvider) RefreshDelegatedToken(_ context.Context, _ string, _ *auth.UserContext) (*auth.AccessToken, error) {
	return p.token, nil
}
func (p *testHTTPAuthProvider) IsTokenValid(_ *auth.AccessToken) bool { return true }
func (p *testHTTPAuthProvider) ValidatePermissions(_ context.Context, _ *auth.AccessToken, _ []string) error {
	return nil
}

// newTestToken creates a non-expired AccessToken for tests.
func newTestToken() *auth.AccessToken {
	return &auth.AccessToken{
		Token:     "test-bearer-token",
		TokenType: "Bearer",
		TenantID:  "test-tenant-id",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
}

// TestAdminUnitMemberOperations verifies that member operations make real Graph API HTTP calls
// to the correct endpoints and return the expected data. Uses an httptest.Server to stand in
// for the Microsoft Graph API without requiring a live tenant.
func TestAdminUnitMemberOperations(t *testing.T) {
	const auID = "au-test-id"
	const userID = "user-abc-123"
	const groupID = "group-def-456"
	const roleID = "role-ghi-789"
	const principalID = "principal-jkl-000"
	const assignmentID = "assignment-mno-111"

	token := newTestToken()

	mux := http.NewServeMux()

	// GET /administrativeUnits/{auID}/members/microsoft.graph.user
	mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/members/microsoft.graph.user", auID),
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]string{{"id": userID}},
			})
		})

	// GET /administrativeUnits/{auID}/members/microsoft.graph.group
	mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/members/microsoft.graph.group", auID),
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]string{{"id": groupID}},
			})
		})

	// GET /administrativeUnits/{auID}/scopedRoleMembers
	mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/scopedRoleMembers", auID),
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"value": []map[string]interface{}{
					{
						"id":     assignmentID,
						"roleId": roleID,
						"roleMemberInfo": map[string]string{
							"id":          principalID,
							"displayName": "Test Principal",
						},
					},
				},
			})
		})

	// POST /administrativeUnits/{auID}/members/$ref
	mux.HandleFunc(fmt.Sprintf("POST /administrativeUnits/%s/members/$ref", auID),
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

	// POST /administrativeUnits/{auID}/scopedRoleMembers
	mux.HandleFunc(fmt.Sprintf("POST /administrativeUnits/%s/scopedRoleMembers", auID),
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":     assignmentID,
				"roleId": roleID,
				"roleMemberInfo": map[string]string{
					"id": principalID,
				},
			})
		})

	// DELETE /administrativeUnits/{auID}/members/{userID}/$ref
	mux.HandleFunc(fmt.Sprintf("DELETE /administrativeUnits/%s/members/%s/$ref", auID, userID),
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

	// DELETE /administrativeUnits/{auID}/scopedRoleMembers/{assignmentID}
	mux.HandleFunc(fmt.Sprintf("DELETE /administrativeUnits/%s/scopedRoleMembers/%s", auID, assignmentID),
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

	server := httptest.NewServer(mux)
	defer server.Close()

	graphClient := graph.NewHTTPClient(graph.WithBaseURL(server.URL))
	module := &entraAdminUnitModule{
		authProvider: &testHTTPAuthProvider{token: token},
		graphClient:  graphClient,
	}
	ctx := context.Background()

	t.Run("AddUserMember", func(t *testing.T) {
		err := module.addUserMember(ctx, token, auID, userID)
		require.NoError(t, err, "addUserMember must not return an error for 204 response")
	})

	t.Run("AddGroupMember", func(t *testing.T) {
		err := module.addGroupMember(ctx, token, auID, groupID)
		require.NoError(t, err, "addGroupMember must not return an error for 204 response")
	})

	t.Run("ListUserMembers", func(t *testing.T) {
		members, err := module.getAdminUnitUserMembers(ctx, token, auID)
		require.NoError(t, err)
		assert.Equal(t, []string{userID}, members, "expected exactly the seeded user ID")
	})

	t.Run("ListGroupMembers", func(t *testing.T) {
		members, err := module.getAdminUnitGroupMembers(ctx, token, auID)
		require.NoError(t, err)
		assert.Equal(t, []string{groupID}, members, "expected exactly the seeded group ID")
	})

	t.Run("ListScopedRoleMembers", func(t *testing.T) {
		members, err := module.getAdminUnitScopedRoleMembers(ctx, token, auID)
		require.NoError(t, err)
		require.Len(t, members, 1)
		assert.Equal(t, principalID, members[0].PrincipalID)
		assert.Equal(t, roleID, members[0].RoleDefinitionID)
	})

	t.Run("AddScopedRoleMember", func(t *testing.T) {
		rm := &ScopedRoleMember{
			PrincipalID:      principalID,
			RoleDefinitionID: roleID,
		}
		err := module.addScopedRoleMember(ctx, token, auID, rm)
		require.NoError(t, err, "addScopedRoleMember must not return an error for 201 response")
	})
}

// TestAdminUnitMemberErrors_PropagateCorrectly verifies that non-2xx HTTP responses from the
// Graph API are returned as errors and never silently swallowed.
func TestAdminUnitMemberErrors_PropagateCorrectly(t *testing.T) {
	const auID = "au-err-id"
	token := newTestToken()

	errorBody := `{"error":{"code":"Forbidden","message":"Insufficient privileges"}}`

	cases := []struct {
		name       string
		statusCode int
		setup      func(mux *http.ServeMux)
		run        func(t *testing.T, m *entraAdminUnitModule, ctx context.Context)
	}{
		{
			name:       "ListUserMembers_403",
			statusCode: http.StatusForbidden,
			setup: func(mux *http.ServeMux) {
				mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/members/microsoft.graph.user", auID),
					func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusForbidden)
						_, _ = fmt.Fprint(w, errorBody)
					})
			},
			run: func(t *testing.T, m *entraAdminUnitModule, ctx context.Context) {
				_, err := m.getAdminUnitUserMembers(ctx, token, auID)
				assert.Error(t, err, "must propagate 403 error from list user members")
			},
		},
		{
			name:       "ListGroupMembers_500",
			statusCode: http.StatusInternalServerError,
			setup: func(mux *http.ServeMux) {
				mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/members/microsoft.graph.group", auID),
					func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusInternalServerError)
						_, _ = fmt.Fprint(w, errorBody)
					})
			},
			run: func(t *testing.T, m *entraAdminUnitModule, ctx context.Context) {
				_, err := m.getAdminUnitGroupMembers(ctx, token, auID)
				assert.Error(t, err, "must propagate 500 error from list group members")
			},
		},
		{
			name:       "ListScopedRoleMembers_404",
			statusCode: http.StatusNotFound,
			setup: func(mux *http.ServeMux) {
				mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/scopedRoleMembers", auID),
					func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusNotFound)
						_, _ = fmt.Fprint(w, errorBody)
					})
			},
			run: func(t *testing.T, m *entraAdminUnitModule, ctx context.Context) {
				_, err := m.getAdminUnitScopedRoleMembers(ctx, token, auID)
				assert.Error(t, err, "must propagate 404 error from list scoped role members")
			},
		},
		{
			name:       "AddMember_403",
			statusCode: http.StatusForbidden,
			setup: func(mux *http.ServeMux) {
				mux.HandleFunc(fmt.Sprintf("POST /administrativeUnits/%s/members/$ref", auID),
					func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusForbidden)
						_, _ = fmt.Fprint(w, errorBody)
					})
			},
			run: func(t *testing.T, m *entraAdminUnitModule, ctx context.Context) {
				err := m.addUserMember(ctx, token, auID, "some-user-id")
				assert.Error(t, err, "must propagate 403 error from add user member")
				err = m.addGroupMember(ctx, token, auID, "some-group-id")
				assert.Error(t, err, "must propagate 403 error from add group member")
			},
		},
		{
			name:       "AddScopedRoleMember_403",
			statusCode: http.StatusForbidden,
			setup: func(mux *http.ServeMux) {
				mux.HandleFunc(fmt.Sprintf("POST /administrativeUnits/%s/scopedRoleMembers", auID),
					func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusForbidden)
						_, _ = fmt.Fprint(w, errorBody)
					})
			},
			run: func(t *testing.T, m *entraAdminUnitModule, ctx context.Context) {
				err := m.addScopedRoleMember(ctx, token, auID, &ScopedRoleMember{
					PrincipalID:      "p-id",
					RoleDefinitionID: "r-id",
				})
				assert.Error(t, err, "must propagate 403 error from add scoped role member")
			},
		},
		{
			name:       "RemoveUserMember_403",
			statusCode: http.StatusForbidden,
			setup: func(mux *http.ServeMux) {
				const staleUserID = "stale-user-id"
				mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/members/microsoft.graph.user", auID),
					func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]interface{}{
							"value": []map[string]string{{"id": staleUserID}},
						})
					})
				mux.HandleFunc(fmt.Sprintf("DELETE /administrativeUnits/%s/members/%s/$ref", auID, staleUserID),
					func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusForbidden)
						_, _ = fmt.Fprint(w, errorBody)
					})
			},
			run: func(t *testing.T, m *entraAdminUnitModule, ctx context.Context) {
				err := m.syncUserMembers(ctx, token, auID, []string{})
				assert.Error(t, err, "must propagate 403 error from remove user member")
			},
		},
		{
			name:       "RemoveScopedRoleMember_403",
			statusCode: http.StatusForbidden,
			setup: func(mux *http.ServeMux) {
				const staleAssignmentID = "stale-assignment-id"
				mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/scopedRoleMembers", auID),
					func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(map[string]interface{}{
							"value": []map[string]interface{}{
								{
									"id":             staleAssignmentID,
									"roleId":         "stale-role-id",
									"roleMemberInfo": map[string]string{"id": "stale-principal-id"},
								},
							},
						})
					})
				mux.HandleFunc(fmt.Sprintf("DELETE /administrativeUnits/%s/scopedRoleMembers/%s", auID, staleAssignmentID),
					func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusForbidden)
						_, _ = fmt.Fprint(w, errorBody)
					})
			},
			run: func(t *testing.T, m *entraAdminUnitModule, ctx context.Context) {
				err := m.syncScopedRoleMembers(ctx, token, auID, []ScopedRoleMember{})
				assert.Error(t, err, "must propagate 403 error from remove scoped role member")
			},
		},
	}

	noRetryOpts := []graph.ClientOption{
		graph.WithRetryConfig(&graph.RetryConfig{MaxRetries: 0}),
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			tc.setup(mux)
			server := httptest.NewServer(mux)
			defer server.Close()

			opts := append([]graph.ClientOption{graph.WithBaseURL(server.URL)}, noRetryOpts...)
			graphClient := graph.NewHTTPClient(opts...)
			m := &entraAdminUnitModule{
				authProvider: &testHTTPAuthProvider{token: token},
				graphClient:  graphClient,
			}
			tc.run(t, m, context.Background())
		})
	}
}

// Test functions

func TestNew(t *testing.T) {
	module := New(&testHTTPAuthProvider{token: newTestToken()}, graph.NewHTTPClient())
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
			"department":   "IT",
			"costCenter":   12345,
			"isProduction": true,
			"customFields": []string{"field1", "field2"},
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

// TestAdminUnitSyncMemberOperations verifies that sync methods add missing members and remove
// stale members by making the correct Graph API HTTP calls.
func TestAdminUnitSyncMemberOperations(t *testing.T) {
	const auID = "au-sync-id"
	const userID = "user-sync-123"
	const groupID = "group-sync-456"
	const roleID = "role-sync-789"
	const principalID = "principal-sync-000"
	const assignmentID = "assignment-sync-111"

	token := newTestToken()
	noRetry := graph.WithRetryConfig(&graph.RetryConfig{MaxRetries: 0})

	t.Run("SyncUserMembers_AddsNewMember", func(t *testing.T) {
		var addCalled bool
		mux := http.NewServeMux()
		mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/members/microsoft.graph.user", auID),
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
			})
		mux.HandleFunc(fmt.Sprintf("POST /administrativeUnits/%s/members/$ref", auID),
			func(w http.ResponseWriter, r *http.Request) {
				addCalled = true
				w.WriteHeader(http.StatusNoContent)
			})
		server := httptest.NewServer(mux)
		defer server.Close()

		m := &entraAdminUnitModule{
			authProvider: &testHTTPAuthProvider{token: token},
			graphClient:  graph.NewHTTPClient(graph.WithBaseURL(server.URL), noRetry),
		}
		require.NoError(t, m.syncUserMembers(context.Background(), token, auID, []string{userID}))
		assert.True(t, addCalled, "should have called add member for new user")
	})

	t.Run("SyncUserMembers_RemovesStaleMembers", func(t *testing.T) {
		var deleteCalled bool
		mux := http.NewServeMux()
		mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/members/microsoft.graph.user", auID),
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"value": []map[string]string{{"id": userID}},
				})
			})
		mux.HandleFunc(fmt.Sprintf("DELETE /administrativeUnits/%s/members/%s/$ref", auID, userID),
			func(w http.ResponseWriter, r *http.Request) {
				deleteCalled = true
				w.WriteHeader(http.StatusNoContent)
			})
		server := httptest.NewServer(mux)
		defer server.Close()

		m := &entraAdminUnitModule{
			authProvider: &testHTTPAuthProvider{token: token},
			graphClient:  graph.NewHTTPClient(graph.WithBaseURL(server.URL), noRetry),
		}
		require.NoError(t, m.syncUserMembers(context.Background(), token, auID, []string{}))
		assert.True(t, deleteCalled, "should have removed the stale user member")
	})

	t.Run("SyncGroupMembers_AddsNewMember", func(t *testing.T) {
		var addCalled bool
		mux := http.NewServeMux()
		mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/members/microsoft.graph.group", auID),
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
			})
		mux.HandleFunc(fmt.Sprintf("POST /administrativeUnits/%s/members/$ref", auID),
			func(w http.ResponseWriter, r *http.Request) {
				addCalled = true
				w.WriteHeader(http.StatusNoContent)
			})
		server := httptest.NewServer(mux)
		defer server.Close()

		m := &entraAdminUnitModule{
			authProvider: &testHTTPAuthProvider{token: token},
			graphClient:  graph.NewHTTPClient(graph.WithBaseURL(server.URL), noRetry),
		}
		require.NoError(t, m.syncGroupMembers(context.Background(), token, auID, []string{groupID}))
		assert.True(t, addCalled, "should have called add member for new group")
	})

	t.Run("SyncGroupMembers_RemovesStaleMembers", func(t *testing.T) {
		var deleteCalled bool
		mux := http.NewServeMux()
		mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/members/microsoft.graph.group", auID),
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"value": []map[string]string{{"id": groupID}},
				})
			})
		mux.HandleFunc(fmt.Sprintf("DELETE /administrativeUnits/%s/members/%s/$ref", auID, groupID),
			func(w http.ResponseWriter, r *http.Request) {
				deleteCalled = true
				w.WriteHeader(http.StatusNoContent)
			})
		server := httptest.NewServer(mux)
		defer server.Close()

		m := &entraAdminUnitModule{
			authProvider: &testHTTPAuthProvider{token: token},
			graphClient:  graph.NewHTTPClient(graph.WithBaseURL(server.URL), noRetry),
		}
		require.NoError(t, m.syncGroupMembers(context.Background(), token, auID, []string{}))
		assert.True(t, deleteCalled, "should have removed the stale group member")
	})

	t.Run("SyncScopedRoleMembers_AddsNewMember", func(t *testing.T) {
		var addCalled bool
		mux := http.NewServeMux()
		mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/scopedRoleMembers", auID),
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
			})
		mux.HandleFunc(fmt.Sprintf("POST /administrativeUnits/%s/scopedRoleMembers", auID),
			func(w http.ResponseWriter, r *http.Request) {
				addCalled = true
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"id": assignmentID, "roleId": roleID,
					"roleMemberInfo": map[string]string{"id": principalID},
				})
			})
		server := httptest.NewServer(mux)
		defer server.Close()

		m := &entraAdminUnitModule{
			authProvider: &testHTTPAuthProvider{token: token},
			graphClient:  graph.NewHTTPClient(graph.WithBaseURL(server.URL), noRetry),
		}
		err := m.syncScopedRoleMembers(context.Background(), token, auID, []ScopedRoleMember{
			{PrincipalID: principalID, RoleDefinitionID: roleID},
		})
		require.NoError(t, err)
		assert.True(t, addCalled, "should have added the new scoped role member")
	})

	t.Run("SyncScopedRoleMembers_RemovesStaleMembers", func(t *testing.T) {
		var deleteCalled bool
		mux := http.NewServeMux()
		mux.HandleFunc(fmt.Sprintf("GET /administrativeUnits/%s/scopedRoleMembers", auID),
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"value": []map[string]interface{}{
						{
							"id":             assignmentID,
							"roleId":         roleID,
							"roleMemberInfo": map[string]string{"id": principalID},
						},
					},
				})
			})
		mux.HandleFunc(fmt.Sprintf("DELETE /administrativeUnits/%s/scopedRoleMembers/%s", auID, assignmentID),
			func(w http.ResponseWriter, r *http.Request) {
				deleteCalled = true
				w.WriteHeader(http.StatusNoContent)
			})
		server := httptest.NewServer(mux)
		defer server.Close()

		m := &entraAdminUnitModule{
			authProvider: &testHTTPAuthProvider{token: token},
			graphClient:  graph.NewHTTPClient(graph.WithBaseURL(server.URL), noRetry),
		}
		require.NoError(t, m.syncScopedRoleMembers(context.Background(), token, auID, []ScopedRoleMember{}))
		assert.True(t, deleteCalled, "should have removed the stale scoped role member")
	})
}
