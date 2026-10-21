// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package entra_group

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
)

type recordedRequest struct {
	Method string
	Path   string
	Body   map[string]interface{}
}

// graphRecorder is a real HTTP server standing in for Microsoft Graph that
// serves one existing group and records every mutating request it receives.
type graphRecorder struct {
	mu       sync.Mutex
	requests []recordedRequest
	group    map[string]interface{}
	team     bool
}

func (g *graphRecorder) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		raw, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodGet {
			rec := recordedRequest{Method: r.Method, Path: r.URL.Path}
			if len(raw) > 0 {
				require.NoError(t, json.Unmarshal(raw, &rec.Body))
			}
			g.mu.Lock()
			g.requests = append(g.requests, rec)
			g.mu.Unlock()
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/groups/grp-1":
			_ = json.NewEncoder(w).Encode(g.group)
		case r.Method == http.MethodGet && r.URL.Path == "/teams/grp-1" && g.team:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "grp-1"})
		case r.Method == http.MethodPatch:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && (r.URL.Path == "/groups/grp-1/members" || r.URL.Path == "/groups/grp-1/owners"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"value": []interface{}{}})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"Request_ResourceNotFound","message":"not found"}}`))
		}
	})
}

func (g *graphRecorder) find(method, path string) *recordedRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range g.requests {
		if g.requests[i].Method == method && g.requests[i].Path == path {
			return &g.requests[i]
		}
	}
	return nil
}

func newRecorderModule(t *testing.T, rec *graphRecorder) *entraGroupModule {
	srv := httptest.NewServer(rec.handler(t))
	t.Cleanup(srv.Close)
	token := &auth.AccessToken{Token: "tok", TokenType: "Bearer", ExpiresAt: time.Now().Add(time.Hour), TenantID: "m365-tenant"}
	return &entraGroupModule{
		authProvider: &stubEntraGroupAP{token: token},
		graphClient:  graph.NewHTTPClient(graph.WithBaseURL(srv.URL), graph.WithHTTPClient(srv.Client())),
	}
}

func existingPublicGroup() map[string]interface{} {
	return map[string]interface{}{
		"id": "grp-1", "displayName": "Team A", "mailNickname": "teama",
		"securityEnabled": false, "mailEnabled": true, "visibility": "Public",
		"groupTypes": []string{"Unified"},
	}
}

func TestSet_ExistingGroup_SendsChangedVisibility(t *testing.T) {
	rec := &graphRecorder{group: existingPublicGroup()}
	m := newRecorderModule(t, rec)

	err := m.Set(ctxForTenant("cfgms-t"), "m365-tenant:grp-1", &EntraGroupConfig{
		DisplayName: "Team A", MailNickname: "teama", MailEnabled: true,
		TenantID: "m365-tenant", GroupType: "Unified", Visibility: "Private",
	})
	require.NoError(t, err)

	patch := rec.find(http.MethodPatch, "/groups/grp-1")
	require.NotNil(t, patch, "visibility change must reach Graph as a group PATCH")
	assert.Equal(t, "Private", patch.Body["visibility"])
}

func TestSet_ExistingGroup_SendsMembershipRule(t *testing.T) {
	rec := &graphRecorder{group: existingPublicGroup()}
	m := newRecorderModule(t, rec)

	err := m.Set(ctxForTenant("cfgms-t"), "m365-tenant:grp-1", &EntraGroupConfig{
		DisplayName: "Team A", MailNickname: "teama", MailEnabled: true, TenantID: "m365-tenant",
		MembershipRule: `user.department -eq "Sales"`, MembershipRuleEnabled: true,
	})
	require.NoError(t, err)

	patch := rec.find(http.MethodPatch, "/groups/grp-1")
	require.NotNil(t, patch)
	assert.Equal(t, `user.department -eq "Sales"`, patch.Body["membershipRule"])
	assert.Equal(t, "On", patch.Body["membershipRuleProcessingState"])
	assert.ElementsMatch(t, []interface{}{"Unified", "DynamicMembership"}, patch.Body["groupTypes"])
}

func TestSet_ManagedFieldsLimitUpdate(t *testing.T) {
	rec := &graphRecorder{group: existingPublicGroup()}
	m := newRecorderModule(t, rec)

	err := m.Set(ctxForTenant("cfgms-t"), "m365-tenant:grp-1", &EntraGroupConfig{
		DisplayName: "Renamed", MailNickname: "teama", MailEnabled: true, TenantID: "m365-tenant",
		Visibility: "Private", ManagedFieldsList: []string{"visibility"},
	})
	require.NoError(t, err)

	patch := rec.find(http.MethodPatch, "/groups/grp-1")
	require.NotNil(t, patch)
	assert.Equal(t, "Private", patch.Body["visibility"])
	assert.NotContains(t, patch.Body, "displayName", "fields outside managed_fields must not be updated")
}

func TestSet_ManagedFieldsFromWorkflowMap(t *testing.T) {
	rec := &graphRecorder{group: existingPublicGroup()}
	m := newRecorderModule(t, rec)

	cfg := mapConfig{
		"display_name": "Renamed", "mail_nickname": "teama", "mail_enabled": true, "tenant_id": "m365-tenant",
		"visibility": "Private", "managed_fields": []interface{}{"visibility"},
	}
	require.NoError(t, m.Set(ctxForTenant("cfgms-t"), "m365-tenant:grp-1", cfg))

	patch := rec.find(http.MethodPatch, "/groups/grp-1")
	require.NotNil(t, patch)
	assert.NotContains(t, patch.Body, "displayName")
}

func TestSet_ExistingTeam_SendsTeamSettings(t *testing.T) {
	for name, ts := range map[string]interface{}{
		"struct pointer": &TeamSettings{AllowAddRemoveApps: true, Fun: "strict"},
		"workflow map":   map[string]interface{}{"allow_add_remove_apps": true, "fun_settings": "strict"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &graphRecorder{group: existingPublicGroup(), team: true}
			m := newRecorderModule(t, rec)

			cfg := mapConfig{
				"display_name": "Team A", "mail_nickname": "teama", "mail_enabled": true, "tenant_id": "m365-tenant",
				"is_team_enabled": true, "team_settings": ts,
			}
			require.NoError(t, m.Set(ctxForTenant("cfgms-t"), "m365-tenant:grp-1", cfg))

			patch := rec.find(http.MethodPatch, "/teams/grp-1")
			require.NotNil(t, patch, "team_settings must reach Graph as a team PATCH")
			member, _ := patch.Body["memberSettings"].(map[string]interface{})
			assert.Equal(t, true, member["allowAddRemoveApps"])
			assert.NotNil(t, patch.Body["funSettings"])
		})
	}
}

func TestCreateGroup_SendsVisibilityAndRule(t *testing.T) {
	var created graph.CreateGroupRequest
	gc := &stubEntraGroupGC{
		createGroupFn: func(_ context.Context, _ *auth.AccessToken, req *graph.CreateGroupRequest) (*graph.Group, error) {
			created = *req
			return &graph.Group{ID: "new"}, nil
		},
	}
	m := &entraGroupModule{graphClient: gc}
	err := m.createGroup(context.Background(), &auth.AccessToken{}, &EntraGroupConfig{
		DisplayName: "G", MailNickname: "g", GroupType: "Unified", Visibility: "Private",
		MembershipRule: "user.city -eq \"Oslo\"", MembershipRuleEnabled: false,
	})
	require.NoError(t, err)
	assert.Equal(t, "Private", created.Visibility)
	assert.Equal(t, "user.city -eq \"Oslo\"", created.MembershipRule)
	assert.Equal(t, "Paused", created.MembershipRuleProcessingState)
	assert.Contains(t, created.GroupTypes, "DynamicMembership")
}

func TestValidate_RejectsUnsupportedAndOrphanFields(t *testing.T) {
	base := func() *EntraGroupConfig {
		return &EntraGroupConfig{DisplayName: "G", MailNickname: "g", TenantID: "t"}
	}
	c := base()
	c.AllowExternalSenders = true
	assert.ErrorContains(t, c.Validate(), "allow_external_senders")

	c = base()
	c.AutoSubscribeNewMembers = true
	assert.ErrorContains(t, c.Validate(), "auto_subscribe_new_members")

	c = base()
	c.TeamSettings = &TeamSettings{Fun: "strict"}
	assert.ErrorContains(t, c.Validate(), "team_settings")
}

func TestSet_RejectsBadTeamSettingsAndExternalSenders(t *testing.T) {
	m := &entraGroupModule{}
	cfg := mapConfig{
		"display_name": "G", "mail_nickname": "g", "tenant_id": "t", "is_team_enabled": true,
		"team_settings": map[string]interface{}{"no_such_setting": true},
	}
	assert.ErrorContains(t, m.Set(ctxForTenant("c"), "t:g", cfg), "team_settings")

	cfg = mapConfig{"display_name": "G", "mail_nickname": "g", "tenant_id": "t", "allow_external_senders": true}
	assert.ErrorContains(t, m.Set(ctxForTenant("c"), "t:g", cfg), "allow_external_senders")
}

// mapConfig is a modules.ConfigState backed by a plain map, as a workflow step supplies.
type mapConfig map[string]interface{}

func (c mapConfig) AsMap() map[string]interface{} { return c }
func (c mapConfig) ToYAML() ([]byte, error)       { return nil, nil }
func (c mapConfig) FromYAML([]byte) error         { return nil }
func (c mapConfig) Validate() error               { return nil }
func (c mapConfig) GetManagedFields() []string    { return nil }
