// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Characterization tests for handleListStewards, handleUpdateStewardConfig,
// handleMoveSteward and handleGetStewardLogs (Issue #5827). They pin the
// externally visible behavior (status, error code, check order) so the
// complexity refactor of those handlers is provably behavior-preserving.

// handlersstewardsCharErrCode decodes the error code from an ErrorResponse body.
func handlersstewardsCharErrCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), rec.Body.String())
	require.NotNil(t, resp.Error, rec.Body.String())
	return resp.Error.Code
}

// handlersstewardsCharListAs calls handleListStewards directly as the principal.
func handlersstewardsCharListAs(server *Server, rawQuery string, p *Principal) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards?"+rawQuery, nil)
	req = withPrincipal(req, p)
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)
	return rec
}

func handlersstewardsCharRoot() *Principal {
	return &Principal{ID: "root-admin", Assurance: session.AssuranceStrong, TenantID: ""}
}

func handlersstewardsCharScoped(tenantID string) *Principal {
	return &Principal{ID: "scoped-admin", Assurance: session.AssuranceStrong, TenantID: tenantID}
}

// handlersstewardsCharData decodes the success envelope's data field.
func handlersstewardsCharData(t *testing.T, rec *httptest.ResponseRecorder, out interface{}) {
	t.Helper()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	require.NoError(t, json.Unmarshal(env.Data, out), rec.Body.String())
}

// ---- handleListStewards ------------------------------------------------------

func TestHandlersStewardsChar_List_SelectorOutsideSubtree_403CrossTenant(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: multiTenantFleet()})

	q := url.Values{"q": {"msp-b/client-1/all"}}.Encode()
	rec := handlersstewardsCharListAs(server, q, handlersstewardsCharScoped("msp-a/client-1"))

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "CROSS_TENANT", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_List_SelectorInvalid_400(t *testing.T) {
	server := setupTestServer(t)
	q := url.Values{"q": {"bogus:value"}}.Encode()
	rec := handlersstewardsCharListAs(server, q, handlersstewardsCharRoot())

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "INVALID_SELECTOR", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_List_SelectorBadPagination_400(t *testing.T) {
	server := setupTestServer(t)
	q := url.Values{"q": {"all"}, "limit": {"0"}}.Encode()
	rec := handlersstewardsCharListAs(server, q, handlersstewardsCharRoot())

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "INVALID_PAGINATION", handlersstewardsCharErrCode(t, rec))
}

// The selector tenant check runs before pagination validation.
func TestHandlersStewardsChar_List_SelectorTenantCheckBeforePagination(t *testing.T) {
	server := setupTestServer(t)
	q := url.Values{"q": {"msp-b/client-1/all"}, "limit": {"0"}}.Encode()
	rec := handlersstewardsCharListAs(server, q, handlersstewardsCharScoped("msp-a/client-1"))

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "CROSS_TENANT", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_List_SelectorSearchError_500(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = &failingFleetQuery{}
	rec := handlersstewardsCharListAs(server, url.Values{"q": {"all"}}.Encode(), handlersstewardsCharRoot())

	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.Equal(t, "INTERNAL_ERROR", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_List_SelectorRootWithTenantPath_AndPagination(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: multiTenantFleet()})

	rec := handlersstewardsCharListAs(server, url.Values{"q": {"msp-a/client-1/servers/web/all"}}.Encode(), handlersstewardsCharRoot())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var list []StewardInfo
	handlersstewardsCharData(t, rec, &list)
	require.Len(t, list, 1)
	assert.Equal(t, "s-msp-a-client-1-web", list[0].ID)
	require.NotNil(t, list[0].DNA)
	assert.Equal(t, "web-1", list[0].DNA.Hostname)
	assert.Equal(t, "msp-a/client-1/servers/web", list[0].DNA.Attributes["tenant"])

	rec = handlersstewardsCharListAs(server, url.Values{"q": {"all"}, "limit": {"2"}, "offset": {"1"}}.Encode(), handlersstewardsCharRoot())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var page StewardListPage
	handlersstewardsCharData(t, rec, &page)
	assert.Equal(t, 4, page.Total)
	assert.Equal(t, 2, page.Limit)
	assert.Equal(t, 1, page.Offset)
	require.Len(t, page.Stewards, 2)
	assert.True(t, page.Stewards[0].ID < page.Stewards[1].ID, "page is sorted by steward ID")
}

func TestHandlersStewardsChar_List_ScopedSelectorWithoutPath_ScopedToSubtree(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: multiTenantFleet()})

	rec := handlersstewardsCharListAs(server, url.Values{"q": {"all"}}.Encode(), handlersstewardsCharScoped("msp-b"))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var list []StewardInfo
	handlersstewardsCharData(t, rec, &list)
	for _, s := range list {
		assert.NotContains(t, s.TenantID, "msp-a", "scoped caller must not see other tenants")
	}
}

func TestHandlersStewardsChar_List_InvalidFilter_400(t *testing.T) {
	server := setupTestServer(t)
	rec := handlersstewardsCharListAs(server, "status=bogus", handlersstewardsCharRoot())

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "INVALID_FILTER", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_List_FilterBeforePagination(t *testing.T) {
	server := setupTestServer(t)
	rec := handlersstewardsCharListAs(server, "status=bogus&limit=0", handlersstewardsCharRoot())

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "INVALID_FILTER", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_List_PaginationErrors_400(t *testing.T) {
	for name, query := range map[string]string{
		"offset without limit": "offset=1",
		"limit not a number":   "limit=abc",
		"limit over max":       "limit=501",
		"negative offset":      "limit=5&offset=-1",
		"filtered path":        "os=linux&limit=0",
	} {
		t.Run(name, func(t *testing.T) {
			server := setupTestServer(t)
			rec := handlersstewardsCharListAs(server, query, handlersstewardsCharRoot())
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, "INVALID_PAGINATION", handlersstewardsCharErrCode(t, rec))
		})
	}
}

func TestHandlersStewardsChar_List_FilteredPaginated(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: []fleet.StewardData{
		{ID: "b", TenantID: "t", Status: "online", LastHeartbeat: time.Now(),
			DNAAttributes: map[string]string{"os": "linux", "steward.version": "1.2.3"}},
		{ID: "a", TenantID: "t", Status: "online", LastHeartbeat: time.Now(),
			DNAAttributes: map[string]string{"os": "linux"}},
		{ID: "c", TenantID: "t", Status: "online", LastHeartbeat: time.Now(),
			DNAAttributes: map[string]string{"os": "windows"}},
	}})

	rec := handlersstewardsCharListAs(server, "os=linux&limit=1&offset=1", handlersstewardsCharRoot())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var page StewardListPage
	handlersstewardsCharData(t, rec, &page)
	assert.Equal(t, 2, page.Total)
	require.Len(t, page.Stewards, 1)
	assert.Equal(t, "b", page.Stewards[0].ID)
	assert.Equal(t, "1.2.3", page.Stewards[0].Version)

	rec = handlersstewardsCharListAs(server, "os=linux", handlersstewardsCharRoot())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var list []StewardInfo
	handlersstewardsCharData(t, rec, &list)
	assert.Len(t, list, 2)
}

func TestHandlersStewardsChar_List_UnfilteredPaginatedAndVisibility(t *testing.T) {
	ctx := context.Background()
	server := setupTestServer(t)
	st, _ := newTestStewardDurableStore(t)
	server.SetStewardStore(st)

	// One steward attached to a peer node (durable only), one deregistered, one hidden.
	for _, rec := range []*business.StewardRecord{
		{ID: "peer-1", TenantID: "t", Status: business.StewardStatusActive},
		{ID: "gone-1", TenantID: "t", Status: business.StewardStatusDeregistered},
		{ID: "hidden-1", TenantID: "t", Status: business.StewardStatusActive, Hidden: true},
	} {
		require.NoError(t, st.RegisterSteward(ctx, rec))
	}
	require.NoError(t, server.controllerService.RegisterSteward("local-1", "t", "addr", "registered"))

	rec := handlersstewardsCharListAs(server, "", handlersstewardsCharRoot())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var list []StewardInfo
	handlersstewardsCharData(t, rec, &list)
	var ids []string
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	assert.Contains(t, ids, "local-1")
	assert.Contains(t, ids, "peer-1")
	assert.NotContains(t, ids, "gone-1")
	assert.NotContains(t, ids, "hidden-1")

	rec = handlersstewardsCharListAs(server, "include_deregistered=true&include_hidden=true", handlersstewardsCharRoot())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	list = nil
	handlersstewardsCharData(t, rec, &list)
	ids = nil
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	assert.Contains(t, ids, "gone-1")
	assert.Contains(t, ids, "hidden-1")

	rec = handlersstewardsCharListAs(server, "limit=1&offset=1", handlersstewardsCharRoot())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var page StewardListPage
	handlersstewardsCharData(t, rec, &page)
	assert.Equal(t, 2, page.Total)
	assert.Len(t, page.Stewards, 1)
}

// ---- handleUpdateStewardConfig -----------------------------------------------

// handlersstewardsCharTrackingBody records whether the handler read the body.
type handlersstewardsCharTrackingBody struct {
	r    *bytes.Reader
	read bool
}

func (b *handlersstewardsCharTrackingBody) Read(p []byte) (int, error) {
	b.read = true
	return b.r.Read(p)
}

// handlersstewardsCharFailingBody fails every read.
type handlersstewardsCharFailingBody struct{}

func (handlersstewardsCharFailingBody) Read([]byte) (int, error) { return 0, errors.New("boom") }

func handlersstewardsCharPutConfig(server *Server, stewardID, contentType string, body *http.Request, p *Principal) *httptest.ResponseRecorder {
	req := withPrincipal(body, p)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleUpdateStewardConfig(rec, req)
	return rec
}

func TestHandlersStewardsChar_UpdateConfig_InvalidStewardID_400(t *testing.T) {
	server := setupTestServer(t)
	tb := &handlersstewardsCharTrackingBody{r: bytes.NewReader(validCfgUploadBody("x"))}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/stewards/bad.id/config", tb)
	rec := handlersstewardsCharPutConfig(server, "bad.id", "application/yaml", req, handlersstewardsCharRoot())

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "INVALID_STEWARD_ID", handlersstewardsCharErrCode(t, rec))
	assert.False(t, tb.read, "body must not be read for an invalid steward ID")
}

func TestHandlersStewardsChar_UpdateConfig_UnauthorizedTenant_404BeforeBodyRead(t *testing.T) {
	server := setupTestServer(t)
	require.NoError(t, server.controllerService.RegisterSteward("char-other", "tenant-b", "addr", "active"))

	tb := &handlersstewardsCharTrackingBody{r: bytes.NewReader([]byte("not valid at all: ["))}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/stewards/char-other/config", tb)
	rec := handlersstewardsCharPutConfig(server, "char-other", "application/yaml", req, handlersstewardsCharScoped("tenant-a"))

	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Equal(t, "STEWARD_NOT_FOUND", handlersstewardsCharErrCode(t, rec))
	assert.False(t, tb.read, "body must not be read before tenant authorization")
}

func TestHandlersStewardsChar_UpdateConfig_RootWithoutCrossing_Challenged(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedTenantTree(t, server)
	require.NoError(t, server.controllerService.RegisterSteward("char-msp", "msp-a", "addr", "active"))

	tb := &handlersstewardsCharTrackingBody{r: bytes.NewReader(validCfgUploadBody("char-msp"))}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/stewards/char-msp/config", tb)
	rec := handlersstewardsCharPutConfig(server, "char-msp", "application/yaml", req, rootScopedPrincipal("root-operator"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "tenant_crossing_required")
	assert.False(t, tb.read, "body must not be read before the crossing decision")
}

func TestHandlersStewardsChar_UpdateConfig_BodyErrors_400(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        func() *http.Request
		wantCode    string
	}{
		{"unreadable body", "application/yaml", func() *http.Request {
			return httptest.NewRequest(http.MethodPut, "/c", handlersstewardsCharFailingBody{})
		}, "READ_ERROR"},
		{"invalid yaml", "application/yaml", func() *http.Request {
			return httptest.NewRequest(http.MethodPut, "/c", strings.NewReader("resources: [unclosed"))
		}, "INVALID_YAML"},
		{"invalid x-yaml", "application/x-yaml", func() *http.Request {
			return httptest.NewRequest(http.MethodPut, "/c", strings.NewReader("resources: [unclosed"))
		}, "INVALID_YAML"},
		{"invalid json reports INVALID_YAML code", "application/json", func() *http.Request {
			return httptest.NewRequest(http.MethodPut, "/c", strings.NewReader("{not json"))
		}, "INVALID_YAML"},
		{"no content type is json", "", func() *http.Request {
			return httptest.NewRequest(http.MethodPut, "/c", strings.NewReader("{not json"))
		}, "INVALID_YAML"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := setupTestServer(t)
			rec := handlersstewardsCharPutConfig(server, "char-s1", tc.contentType, tc.body(), handlersstewardsCharRoot())
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, tc.wantCode, handlersstewardsCharErrCode(t, rec))
		})
	}
}

func TestHandlersStewardsChar_UpdateConfig_JSONBodyAccepted_AndUnknownStewardUsesCallerTenant(t *testing.T) {
	server := setupTestServer(t)
	body, err := json.Marshal(map[string]any{
		"steward": map[string]any{"id": "char-new", "mode": "standalone"},
		"resources": []map[string]any{{
			"name": "f", "module": "file",
			"config": map[string]any{"path": "/tmp/x", "content": "x", "state": "present"},
		}},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/c", bytes.NewReader(body))
	rec := handlersstewardsCharPutConfig(server, "char-new", "application/json", req, handlersstewardsCharScoped("tenant-a"))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var data map[string]any
	handlersstewardsCharData(t, rec, &data)
	assert.Equal(t, "char-new", data["steward_id"])
	assert.Equal(t, "tenant-a", data["tenant_id"])
	assert.Equal(t, "stored", data["status"])
}

// ---- handleMoveSteward -------------------------------------------------------

func handlersstewardsCharMove(server *Server, stewardID, rawBody string, p *Principal) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+stewardID+"/move", strings.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, p)
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)
	return rec
}

func TestHandlersStewardsChar_Move_InvalidJSON_400(t *testing.T) {
	server, _, _ := setupMoveStewardServer(t)
	rec := handlersstewardsCharMove(server, "s-1", "{nope", handlersstewardsCharRoot())

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "INVALID_JSON", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_Move_StoreNotConfigured_500(t *testing.T) {
	server := setupTestServer(t)
	server.SetStewardStore(nil)
	rec := handlersstewardsCharMove(server, "s-1", `{"new_tenant_id":"dest-tenant"}`, handlersstewardsCharRoot())

	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.Equal(t, "INTERNAL_ERROR", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_Move_SiblingDestination_403(t *testing.T) {
	server, st := setupMoveAuthServer(t)
	seedTenantTree(t, server)
	seedSteward(t, st, &business.StewardRecord{ID: "s-sib", TenantID: "client-1", Status: business.StewardStatusRegistered})

	// msp-ab merely shares a string prefix with msp-a: not a descendant.
	rec := handlersstewardsCharMove(server, "s-sib", `{"new_tenant_id":"msp-ab"}`, handlersstewardsCharScoped("msp-a"))

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "INSUFFICIENT_SCOPE", handlersstewardsCharErrCode(t, rec))
	got, err := st.GetSteward(context.Background(), "s-sib")
	require.NoError(t, err)
	assert.Equal(t, "client-1", got.TenantID, "denied move must not change the tenant")
}

func TestHandlersStewardsChar_Move_RootWithoutCrossing_Challenged(t *testing.T) {
	server := setupCrossingTestServer(t)
	seedTenantTree(t, server)
	st, _ := newTestStewardDurableStore(t)
	server.SetStewardStore(st)
	seedSteward(t, st, &business.StewardRecord{ID: "s-root", TenantID: "msp-a", Status: business.StewardStatusRegistered})

	rec := handlersstewardsCharMove(server, "s-root", `{"new_tenant_id":"msp-b"}`, rootScopedPrincipal("root-operator"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "tenant_crossing_required")
	got, err := st.GetSteward(context.Background(), "s-root")
	require.NoError(t, err)
	assert.Equal(t, "msp-a", got.TenantID, "challenged move must not change the tenant")
}

func TestHandlersStewardsChar_Move_StatusNotAllowed_400(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)
	seedSteward(t, st, &business.StewardRecord{ID: "s-stat", TenantID: "source-tenant", Status: business.StewardStatus("bogus")})

	rec := handlersstewardsCharMove(server, "s-stat", `{"new_tenant_id":"dest-tenant"}`, handlersstewardsCharRoot())

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "STEWARD_STATUS_INVALID", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_Move_TenantManagerNotConfigured_500(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)
	seedSteward(t, st, &business.StewardRecord{ID: "s-tm", TenantID: "source-tenant", Status: business.StewardStatusRegistered})
	server.tenantManager = nil

	rec := handlersstewardsCharMove(server, "s-tm", `{"new_tenant_id":"dest-tenant"}`, handlersstewardsCharRoot())

	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.Equal(t, "INTERNAL_ERROR", handlersstewardsCharErrCode(t, rec))
}

// ---- handleGetStewardLogs ----------------------------------------------------

func handlersstewardsCharLogs(server *Server, stewardID, rawQuery string, p *Principal) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/"+stewardID+"/logs?"+rawQuery, nil)
	req = withPrincipal(req, p)
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleGetStewardLogs(rec, req)
	return rec
}

func TestHandlersStewardsChar_Logs_MissingID_400(t *testing.T) {
	server := setupTestServer(t)
	rec := handlersstewardsCharLogs(server, "", "", handlersstewardsCharRoot())

	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "MISSING_STEWARD_ID", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_Logs_InvalidParameters_400(t *testing.T) {
	cases := map[string]string{
		"tail over 1000":    "tail=1001",
		"tail zero":         "tail=0",
		"tail not a number": "tail=abc",
		"bad since":         "since=yesterday",
		"bad level":         "level=TRACE",
		"lowercase level":   "level=info",
		"module 129 chars":  "module=" + strings.Repeat("m", 129),
	}
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			server := setupTestServer(t)
			// The unknown steward would be a 404 if validation ran after the
			// authorization check: validation must come first.
			rec := handlersstewardsCharLogs(server, "char-unknown", query, handlersstewardsCharRoot())
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, "INVALID_PARAMETER", handlersstewardsCharErrCode(t, rec))
		})
	}
}

func TestHandlersStewardsChar_Logs_ValidParameterBoundaries_PassValidation(t *testing.T) {
	for name, query := range map[string]string{
		"tail 1":       "tail=1",
		"tail 1000":    "tail=1000",
		"since":        "since=90m",
		"level":        "level=WARN",
		"module 128":   "module=" + strings.Repeat("m", 128),
		"all together": "tail=5&since=1h&level=ERROR&module=file",
	} {
		t.Run(name, func(t *testing.T) {
			server := setupTestServer(t)
			// Valid params proceed to the authorization check: unknown steward is 404.
			rec := handlersstewardsCharLogs(server, "char-unknown", query, handlersstewardsCharRoot())
			require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			assert.Equal(t, "STEWARD_NOT_FOUND", handlersstewardsCharErrCode(t, rec))
		})
	}
}

func TestHandlersStewardsChar_Logs_NoManager_EmptyEvents(t *testing.T) {
	server := setupTestServer(t)
	require.NoError(t, server.controllerService.RegisterSteward("char-logs", "tenant-a", "addr", "active"))
	rec := handlersstewardsCharLogs(server, "char-logs", "tail=5", handlersstewardsCharRoot())

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var data struct {
		Events []stewardLogRecord `json:"events"`
	}
	handlersstewardsCharData(t, rec, &data)
	assert.NotNil(t, data.Events)
	assert.Empty(t, data.Events)
}

func TestHandlersStewardsChar_Logs_CrossTenant_404(t *testing.T) {
	server := setupTestServer(t)
	require.NoError(t, server.controllerService.RegisterSteward("char-logs-b", "tenant-b", "addr", "active"))
	rec := handlersstewardsCharLogs(server, "char-logs-b", "", handlersstewardsCharScoped("tenant-a"))

	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Equal(t, "STEWARD_NOT_FOUND", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_Logs_FiltersAndScopesToPathSteward(t *testing.T) {
	server := setupTestServer(t)
	mgr := newTestStewardEventManager(t)
	server.SetStewardEventLoggingManager(mgr)
	require.NoError(t, server.controllerService.RegisterSteward("char-logs", "tenant-a", "addr", "active"))

	writeTestStewardEvent(t, mgr, "char-logs", "INFO", "mine-info", "")
	writeTestStewardEvent(t, mgr, "char-logs", "ERROR", "mine-error", "")
	writeTestStewardEvent(t, mgr, "char-other", "INFO", "theirs", "")

	rec := handlersstewardsCharLogs(server, "char-logs", "since=1h&tail=50", handlersstewardsCharRoot())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "mine-info")
	assert.Contains(t, rec.Body.String(), "mine-error")
	assert.NotContains(t, rec.Body.String(), "theirs", "entries of other stewards must be post-filtered out")
}

func TestHandlersStewardsChar_Logs_FlushFailure_500(t *testing.T) {
	server := setupTestServer(t)
	mgr := newTestStewardEventManager(t)
	require.NoError(t, server.controllerService.RegisterSteward("char-logs", "tenant-a", "addr", "active"))
	server.SetStewardEventLoggingManager(mgr)
	require.NoError(t, mgr.Close())

	rec := handlersstewardsCharLogs(server, "char-logs", "", handlersstewardsCharRoot())
	require.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
	assert.Equal(t, "QUERY_ERROR", handlersstewardsCharErrCode(t, rec))
}

func TestHandlersStewardsChar_UpdateConfig_WithPublisher_ReportsDeliveredRecord(t *testing.T) {
	server := setupTestServer(t)
	cp, store := newSyncRecorder(t, server)
	req := httptest.NewRequest(http.MethodPut, "/c", bytes.NewReader(validCfgUploadBody("char-deliver")))
	rec := handlersstewardsCharPutConfig(server, "char-deliver", "application/yaml", req, handlersstewardsCharScoped("tenant-a"))

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var data map[string]any
	handlersstewardsCharData(t, rec, &data)
	commandID, _ := data["command_id"].(string)
	require.NotEmpty(t, commandID)
	assert.Equal(t, string(business.DeliveryStatusDelivered), data["delivery_status"])
	assert.NotContains(t, data, "status")
	assert.Equal(t, []string{"char-deliver"}, cp.ReceivedIDs())

	got, err := store.GetCommandRecord(context.Background(), commandID)
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusDelivered, got.DeliveryStatus)
	assert.Equal(t, "tenant-a", got.TenantID)
	assert.Equal(t, "scoped-admin", got.IssuedBy)
}

func TestHandlersStewardsChar_Logs_LevelAndModuleFiltersApplied(t *testing.T) {
	server := setupTestServer(t)
	mgr := newTestStewardEventManager(t)
	server.SetStewardEventLoggingManager(mgr)
	require.NoError(t, server.controllerService.RegisterSteward("char-logs", "tenant-a", "addr", "active"))
	writeTestStewardEvent(t, mgr, "char-logs", "INFO", "info-entry", "")
	writeTestStewardEvent(t, mgr, "char-logs", "ERROR", "error-entry", "")

	rec := handlersstewardsCharLogs(server, "char-logs", "level=ERROR", handlersstewardsCharRoot())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "error-entry")
	assert.NotContains(t, rec.Body.String(), "info-entry")

	rec = handlersstewardsCharLogs(server, "char-logs", "module=no-such-component", handlersstewardsCharRoot())
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "error-entry")
	assert.NotContains(t, rec.Body.String(), "info-entry")
}
