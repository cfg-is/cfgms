// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/session"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// Handlers that record who acted, directly or through a helper (a SetByUserID,
// ApprovedBy, an audit User(...), a CommandRecord.IssuedBy, a session PrincipalID, an
// operator-assertion source), resolve the actor through requireActingPrincipal and
// refuse with 401 AUTHENTICATION_REQUIRED, changing nothing, when the context holds no
// principal or one with an empty ID (group B, part 2, of the #6425 sweep). Each test
// drives one handler directly with every noActorCases shape against an otherwise
// complete request, checks that nothing was stored and nothing audited, and then sends
// the same request as a real principal to show that the actor was the only reason it
// was refused.

// ---- handleAssertEdge ----------------------------------------------------------------

func TestHandleAssertEdge_NoActor_Returns401(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	server := newEntityRWTestServer(t, p)
	const tenantID = "test-tenant"
	const fromSubject, toSubject = "host:b2-edge-from", "host:b2-edge-to"
	reportEntity(t, p, fromSubject, tenantID, "host")
	reportEntity(t, p, toSubject, tenantID, "host")
	body, err := json.Marshal(assertEdgeRequest{EdgeType: "depends-on", FromEID: fromSubject, ToEID: toSubject})
	require.NoError(t, err)
	postEdge := func(pr *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleAssertEdge(rec, actorRequest(http.MethodPost, "/api/v1/entities/edges", body, nil, tenantID, pr))
		return rec
	}
	fromEID, err := egtypes.ParseEID(fromSubject)
	require.NoError(t, err)
	edgeCount := func() int {
		edges, err := p.GetEdges(context.Background(), eginterfaces.EdgeFilter{FromEID: &fromEID, Types: []string{"depends-on"}})
		require.NoError(t, err)
		return len(edges)
	}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, server)
			assertAuthenticationRequired(t, postEdge(tc.principal))
			assert.Zero(t, edgeCount(), "no edge may be stored")
			assert.Equal(t, auditBefore, auditEntryCount(t, server), "no audit entry may be written")
		})
	}

	// A UserIDKey on the context is not an actor: only the principal is.
	t.Run("user id without principal", func(t *testing.T) {
		req := actorRequest(http.MethodPost, "/api/v1/entities/edges", body, nil, tenantID, nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.UserIDKey, "ctx-user"))
		rec := httptest.NewRecorder()
		server.handleAssertEdge(rec, req)
		assertAuthenticationRequired(t, rec)
		require.Zero(t, edgeCount())
	})

	operator := &Principal{ID: "operator-7", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := postEdge(operator)
	require.Equal(t, http.StatusCreated, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	require.Equal(t, 1, edgeCount())
	edges, err := p.GetEdges(context.Background(), eginterfaces.EdgeFilter{FromEID: &fromEID, Types: []string{"depends-on"}})
	require.NoError(t, err)
	require.NotNil(t, edges[0].Edge)
	assert.Contains(t, edges[0].Edge.Sources[0].Source, "operator-7")
}

// ---- handleDeleteRoleConfig ----------------------------------------------------------

func TestHandleDeleteRoleConfig_NoActor_Returns401(t *testing.T) {
	server := setupTagServer(t)
	server.SetRoleConfigStore(pkgtesting.SetupTestStorage(t).GetConfigStore())
	server.controllerService.SetTagStore(server.tagStore)
	_, cmdStore := newSyncRecorder(t, server)
	ctx := context.Background()
	const tenantID = "role-del-tenant"
	addTagTestSteward(t, server, "s-role-del", tenantID)
	_, err := server.tagStore.Update(ctx, "s-role-del", func([]string) ([]string, error) {
		return []string{"b2-role"}, nil
	})
	require.NoError(t, err)

	operator := &Principal{ID: "operator-7", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := httptest.NewRecorder()
	server.handleCreateRoleConfig(rec, actorRequest(http.MethodPost, "/api/v1/roles",
		validRolePayload("b2-role", "tag:b2-role"), nil, tenantID, operator))
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	syncsAfterCreate := len(syncConfigRecords(t, cmdStore, "s-role-del"))
	key := &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: "role-policies", Name: "b2-role"}

	del := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleDeleteRoleConfig(rec, actorRequest(http.MethodDelete, "/api/v1/roles/b2-role", nil,
			map[string]string{"name": "b2-role"}, tenantID, p))
		return rec
	}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, del(tc.principal))
			_, getErr := server.roleConfigStore.GetConfig(ctx, key)
			assert.NoError(t, getErr, "the role config must not be deleted")
			assert.Len(t, syncConfigRecords(t, cmdStore, "s-role-del"), syncsAfterCreate, "no sync command may be recorded")
		})
	}

	rec = del(operator)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	_, getErr := server.roleConfigStore.GetConfig(ctx, key)
	assert.ErrorIs(t, getErr, cfgconfig.ErrConfigNotFound)
	recs := syncConfigRecords(t, cmdStore, "s-role-del")
	require.Len(t, recs, syncsAfterCreate+1)
	assert.Equal(t, operator.ID, recs[len(recs)-1].IssuedBy)
}

// ---- handlePutScriptPrivilege --------------------------------------------------------

func TestHandlePutScriptPrivilege_NoActor_Returns401(t *testing.T) {
	server, repo := setupScriptLibraryServer(t)
	const tenantID = "test-tenant"
	seedLibraryScript(t, repo, "b2-priv", "B2 Priv")
	body := []byte(`{"required_api_scope": []}`)
	put := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handlePutScriptPrivilege(rec, actorRequest(http.MethodPut, "/api/v1/scripts/b2-priv/privilege", body,
			map[string]string{"id": "b2-priv"}, tenantID, p))
		return rec
	}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, put(tc.principal))
			_, err := server.loadPrivilegeMetadata(context.Background(), tenantID, "b2-priv")
			assert.ErrorIs(t, err, cfgconfig.ErrConfigNotFound, "no privilege metadata may be stored")
		})
	}

	operator := &Principal{ID: "operator-7", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := put(operator)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	meta, err := server.loadPrivilegeMetadata(context.Background(), tenantID, "b2-priv")
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, operator.ID, meta.SetByUserID)
}

// ---- handleSessionCreate -------------------------------------------------------------

func TestHandleSessionCreate_NoActor_Returns401(t *testing.T) {
	server, mgr, _ := setupTestServerWithSession(t)
	const tenantID = "session-tenant"
	create := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleSessionCreate(rec, actorRequest(http.MethodPost, "/api/v1/sessions",
			[]byte(`{"connection_name":"b2-cli"}`), nil, tenantID, p))
		return rec
	}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, create(tc.principal))
			sessions, err := mgr.List(context.Background())
			require.NoError(t, err)
			assert.Empty(t, sessions, "no session may be issued")
		})
	}

	operator := &Principal{ID: "operator-7", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := create(operator)
	require.Equal(t, http.StatusCreated, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	sessions, err := mgr.List(context.Background())
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, operator.ID, sessions[0].PrincipalID)
}

// ---- handleApproveStewardBinary (approveStewardBinaryCaller) -------------------------

func TestHandleApproveStewardBinary_NoActor_Returns401(t *testing.T) {
	f := newApproveFixture(t)
	const version, platform, arch = "v1.0.0", "linux", "amd64"
	sha := f.publish(version, platform, arch, []byte("binary awaiting approval"), false)
	body := []byte(`{"sha256":"` + sha + `"}`)
	approve := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		f.srv.handleApproveStewardBinary(rec, actorRequest(http.MethodPost,
			"/api/v1/installer/steward-binaries/"+version+"/"+platform+"/"+arch+"/approve", body,
			map[string]string{"version": version, "platform": platform, "arch": arch}, approveTestTenant, p))
		return rec
	}

	for _, tc := range noActorCases(approveTestTenant) {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, f.srv)
			assertAuthenticationRequired(t, approve(tc.principal))
			assert.False(t, f.approved(version, platform, arch, sha), "no approval may be recorded")
			assert.Equal(t, auditBefore, auditEntryCount(t, f.srv), "no audit entry may be written")
		})
	}

	operator := &Principal{ID: "operator-7", TenantID: approveTestTenant, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := approve(operator)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	assert.True(t, f.approved(version, platform, arch, sha))
	var resp approveResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, operator.ID, resp.Data.ApprovedBy)
}

// ---- handlePutUnattendedRollout ------------------------------------------------------

func TestHandlePutUnattendedRollout_NoActor_Returns401(t *testing.T) {
	f := newUnattendedRolloutFixture(t)
	put := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		f.srv.handlePutUnattendedRollout(rec, actorRequest(http.MethodPut, "/api/v1/rollout-settings/unattended",
			[]byte(`{"enabled":true}`), nil, unattendedTestTenant, p))
		return rec
	}

	for _, tc := range noActorCases(unattendedTestTenant) {
		t.Run(tc.name, func(t *testing.T) {
			auditBefore := auditEntryCount(t, f.srv)
			assertAuthenticationRequired(t, put(tc.principal))
			assert.False(t, f.enabled(t), "the setting must not change")
			assert.Equal(t, auditBefore, auditEntryCount(t, f.srv), "no audit entry may be written")
		})
	}

	operator := &Principal{ID: "operator-7", TenantID: unattendedTestTenant, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := put(operator)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	assert.True(t, f.enabled(t))
	var resp unattendedResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, operator.ID, resp.Data.ChangedBy)
}

// ---- handleAddStewardTags and handleDeleteStewardTags (syncStewardAfterTagChange) ----

func TestHandleAddStewardTags_NoActor_Returns401(t *testing.T) {
	server := setupTagServer(t)
	_, cmdStore := newSyncRecorder(t, server)
	const tenantID = "tag-tenant"
	addTagTestSteward(t, server, "s-b2-add", tenantID)
	add := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleAddStewardTags(rec, actorRequest(http.MethodPost, "/api/v1/stewards/s-b2-add/tags",
			[]byte(`{"tags":["b2-tag"]}`), map[string]string{"id": "s-b2-add"}, tenantID, p))
		return rec
	}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, add(tc.principal))
			tags, err := server.tagStore.Get(context.Background(), "s-b2-add")
			require.NoError(t, err)
			assert.Empty(t, tags, "no tag may be stored")
			assert.Empty(t, syncConfigRecords(t, cmdStore, "s-b2-add"), "no sync command may be recorded")
		})
	}

	operator := &Principal{ID: "operator-7", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := add(operator)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	tags, err := server.tagStore.Get(context.Background(), "s-b2-add")
	require.NoError(t, err)
	assert.Equal(t, []string{"b2-tag"}, tags)
	recs := syncConfigRecords(t, cmdStore, "s-b2-add")
	require.Len(t, recs, 1)
	assert.Equal(t, operator.ID, recs[0].IssuedBy)
}

func TestHandleDeleteStewardTags_NoActor_Returns401(t *testing.T) {
	server := setupTagServer(t)
	_, cmdStore := newSyncRecorder(t, server)
	const tenantID = "tag-tenant"
	addTagTestSteward(t, server, "s-b2-del", tenantID)
	_, err := server.tagStore.Update(context.Background(), "s-b2-del", func([]string) ([]string, error) {
		return []string{"b2-tag"}, nil
	})
	require.NoError(t, err)
	del := func(p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleDeleteStewardTags(rec, actorRequest(http.MethodDelete, "/api/v1/stewards/s-b2-del/tags",
			[]byte(`{"tags":["b2-tag"]}`), map[string]string{"id": "s-b2-del"}, tenantID, p))
		return rec
	}

	for _, tc := range noActorCases(tenantID) {
		t.Run(tc.name, func(t *testing.T) {
			assertAuthenticationRequired(t, del(tc.principal))
			tags, err := server.tagStore.Get(context.Background(), "s-b2-del")
			require.NoError(t, err)
			assert.Equal(t, []string{"b2-tag"}, tags, "the tag must not be removed")
			assert.Empty(t, syncConfigRecords(t, cmdStore, "s-b2-del"), "no sync command may be recorded")
		})
	}

	operator := &Principal{ID: "operator-7", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true}
	rec := del(operator)
	require.Equal(t, http.StatusOK, rec.Code, "the same request from an authenticated principal succeeds: %s", rec.Body.String())
	tags, err := server.tagStore.Get(context.Background(), "s-b2-del")
	require.NoError(t, err)
	assert.Empty(t, tags)
	recs := syncConfigRecords(t, cmdStore, "s-b2-del")
	require.Len(t, recs, 1)
	assert.Equal(t, operator.ID, recs[0].IssuedBy)
}
