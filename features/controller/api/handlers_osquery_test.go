// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
)

// ---- Test doubles -----------------------------------------------------------

// stubOsqueryDispatcher is a real (non-mock) dispatcher that carries a fixed
// response. It records calls for assertion without expectations (not a mock).
// handleOsqueryQuery fans out to stewards concurrently, so calls is guarded by
// mu — every test exercising more than one target steward hits this
// concurrently (verified by `go test -race`).
type stubOsqueryDispatcher struct {
	rows []*transportpb.OsqueryRow
	err  error

	mu sync.Mutex
	// calls records (stewardID, catalogID, params) for assertion.
	calls []osqueryDispatchCall
}

type osqueryDispatchCall struct {
	stewardID string
	catalogID string
	params    map[string]string
}

func (d *stubOsqueryDispatcher) QuerySteward(_ context.Context, stewardID, catalogID string, params map[string]string) ([]*transportpb.OsqueryRow, error) {
	d.mu.Lock()
	d.calls = append(d.calls, osqueryDispatchCall{stewardID: stewardID, catalogID: catalogID, params: params})
	d.mu.Unlock()
	return d.rows, d.err
}

// partialOsqueryDispatcher fails for a specific steward and succeeds for all others.
type partialOsqueryDispatcher struct {
	failSteward string
	failErr     error
	rows        []*transportpb.OsqueryRow
}

func (d *partialOsqueryDispatcher) QuerySteward(_ context.Context, stewardID, _ string, _ map[string]string) ([]*transportpb.OsqueryRow, error) {
	if stewardID == d.failSteward {
		return nil, d.failErr
	}
	return d.rows, nil
}

// ---- Helpers ----------------------------------------------------------------

// osqueryStrongPrincipal returns a Strong-assurance principal for testing
// AssuranceStrong + RequireUserPresence gates on POST /api/v1/osquery/query.
func osqueryStrongPrincipal() *Principal {
	return &Principal{
		ID:            "cert-admin",
		Name:          "mtls-cert:cert-admin",
		Assurance:     session.AssuranceStrong,
		CertSerial:    "test-serial",
		ImplicitAdmin: true,
	}
}

// makeOsqueryRequest builds a POST /api/v1/osquery/query request with a strong
// principal and a fresh single-use presence token (osquery:execute requires both).
func makeOsqueryRequest(t *testing.T, s *Server, body interface{}, principal *Principal) *http.Request {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/osquery/query", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, principal))
	// Inject presence token: osquery:execute carries RequireUserPresence: true.
	token := mintPresenceToken(t, s, principal.ID)
	req.Header.Set(presenceTokenHeader, token)
	return req
}

// stewardIDs builds a fleet.FleetQuery backed by stewards with the given IDs.
func fleetWithStewardIDs(ids ...string) fleet.FleetQuery {
	data := make([]fleet.StewardData, len(ids))
	for i, id := range ids {
		data[i] = fleet.StewardData{
			ID:       id,
			TenantID: "root",
			Status:   "online",
		}
	}
	return seededFleetQuery(data...)
}

// fleetWithTenantStewards builds a fleet.FleetQuery from stewardID → tenantID pairs.
func fleetWithTenantStewards(pairs map[string]string) fleet.FleetQuery {
	data := make([]fleet.StewardData, 0, len(pairs))
	for id, tenant := range pairs {
		data = append(data, fleet.StewardData{
			ID:       id,
			TenantID: tenant,
			Status:   "online",
		})
	}
	return seededFleetQuery(data...)
}

// makeOsqueryRequestForTenant is makeOsqueryRequest with an authenticated caller
// tenant in the request context — the value the auth middleware installs under
// ctxkeys.TenantID for API-key, session, and JWT principals.
func makeOsqueryRequestForTenant(t *testing.T, s *Server, body interface{}, principal *Principal, tenantID string) *http.Request {
	t.Helper()
	req := makeOsqueryRequest(t, s, body, principal)
	if tenantID != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, tenantID))
	}
	return req
}

// dispatchedStewardIDs returns the set of steward IDs the stub dispatcher saw.
func dispatchedStewardIDs(d *stubOsqueryDispatcher) map[string]bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	ids := make(map[string]bool, len(d.calls))
	for _, c := range d.calls {
		ids[c.stewardID] = true
	}
	return ids
}

// ---- Tests: tenant isolation ------------------------------------------------

// TestHandleOsqueryQuery_CrossTenantSelectorRejected verifies that a tenant-scoped
// caller cannot target another tenant's subtree by putting a foreign tenant prefix
// in the selector. Without the authz check, selector.Parse discards the parsed
// tenant path and fleet.Filter{TenantSubtree: ""} fans the query out fleet-wide,
// leaking process lists and steward IDs across tenants.
func TestHandleOsqueryQuery_CrossTenantSelectorRejected(t *testing.T) {
	server := setupTestServer(t)
	disp := &stubOsqueryDispatcher{}
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithTenantStewards(map[string]string{
		"steward-a": "msp-a",
		"steward-b": "msp-b",
	})

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "msp-b/all"}
	req := makeOsqueryRequestForTenant(t, server, body, osqueryStrongPrincipal(), "msp-a")
	rec := httptest.NewRecorder()

	server.handleOsqueryQuery(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code,
		"a selector naming another tenant's subtree must be rejected with 403")

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "CROSS_TENANT", errResp.Error.Code,
		"cross-tenant rejection must carry the CROSS_TENANT code")

	assert.Empty(t, disp.calls,
		"no steward may be dispatched to when the tenant boundary is violated")
}

// TestHandleOsqueryQuery_TenantScopedCallerLimitedToOwnSubtree verifies that a
// tenant-scoped caller sending the unqualified "all" selector reaches only its own
// tenant and descendants — never a sibling tenant's stewards.
func TestHandleOsqueryQuery_TenantScopedCallerLimitedToOwnSubtree(t *testing.T) {
	server := setupTestServer(t)
	disp := &stubOsqueryDispatcher{}
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithTenantStewards(map[string]string{
		"steward-a":       "msp-a",
		"steward-a-child": "msp-a/client-1",
		"steward-b":       "msp-b",
		"steward-root":    "root",
	})

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "all"}
	req := makeOsqueryRequestForTenant(t, server, body, osqueryStrongPrincipal(), "msp-a")
	rec := httptest.NewRecorder()

	handler := server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery))
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	ids := dispatchedStewardIDs(disp)
	assert.True(t, ids["steward-a"], "caller's own tenant must be targeted")
	assert.True(t, ids["steward-a-child"], "descendant tenants must be targeted")
	assert.False(t, ids["steward-b"], "sibling tenant steward must not be targeted")
	assert.False(t, ids["steward-root"], "parent tenant steward must not be targeted")
	assert.Len(t, ids, 2, "exactly the caller's subtree must be dispatched to")
}

// TestHandleOsqueryQuery_TenantPrefixWithinSubtreeAllowed verifies that a selector
// prefix naming a descendant of the caller's tenant narrows the dispatch instead of
// being rejected.
func TestHandleOsqueryQuery_TenantPrefixWithinSubtreeAllowed(t *testing.T) {
	server := setupTestServer(t)
	disp := &stubOsqueryDispatcher{}
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithTenantStewards(map[string]string{
		"steward-a":       "msp-a",
		"steward-a-child": "msp-a/client-1",
		"steward-b":       "msp-b",
	})

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "msp-a/client-1/all"}
	req := makeOsqueryRequestForTenant(t, server, body, osqueryStrongPrincipal(), "msp-a")
	rec := httptest.NewRecorder()

	handler := server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery))
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	ids := dispatchedStewardIDs(disp)
	assert.True(t, ids["steward-a-child"], "the named descendant tenant must be targeted")
	assert.Len(t, ids, 1, "a descendant prefix must narrow the dispatch to that subtree only")
}

// TestHandleOsqueryQuery_AdminCallerUnrestricted verifies that an admin caller
// (no tenant in context — e.g. an mTLS cert admin) still reaches the whole fleet,
// so the tenant check does not regress the admin path.
func TestHandleOsqueryQuery_AdminCallerUnrestricted(t *testing.T) {
	server := setupTestServer(t)
	disp := &stubOsqueryDispatcher{}
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithTenantStewards(map[string]string{
		"steward-a": "msp-a",
		"steward-b": "msp-b",
	})

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "all"}
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal()) // no ctxkeys.TenantID
	rec := httptest.NewRecorder()

	handler := server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery))
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	ids := dispatchedStewardIDs(disp)
	assert.Len(t, ids, 2, "an admin caller with no tenant scope reaches the whole fleet")
}

// ---- Tests: REQUIRED TEST — leadership gate ---------------------------------

// TestHandleOsqueryQuery_NonLeaderRejects verifies that a non-authoritative
// controller node (HasLeadership() == false) returns 503 without dispatching.
// This is the REQUIRED TEST for the leadership AC (Issue #3569).
func TestHandleOsqueryQuery_NonLeaderRejects(t *testing.T) {
	server := setupTestServer(t)
	disp := &stubOsqueryDispatcher{}
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithStewardIDs("steward-1")
	server.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "all"}
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()

	server.handleOsqueryQuery(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"non-leader must return 503 — dispatching from a follower violates leadership invariant")
	assert.Empty(t, disp.calls, "dispatcher must not be called on a non-leader node")
}

// TestHandleOsqueryQuery_LeaderNilChecker verifies that a nil
// registrationLeaderStatus (single-node deployment) dispatches normally.
func TestHandleOsqueryQuery_LeaderNilChecker(t *testing.T) {
	disp := &stubOsqueryDispatcher{
		rows: []*transportpb.OsqueryRow{
			{Columns: map[string]string{"hostname": "host-a"}},
		},
	}
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithStewardIDs("steward-1")
	// registrationLeaderStatus is nil by default (setupTestServer does not wire HA).

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "all"}
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery))
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code,
		"nil leadership checker must not reject the request (single-node mode)")
	assert.Len(t, disp.calls, 1, "dispatcher must be called once for the single target steward")
}

// ---- Tests: REQUIRED TEST — assurance gate ----------------------------------

// TestHandleOsqueryQuery_APIKeyRejected verifies that an API-key principal
// (Machine assurance) is rejected because osquery:execute requires AssuranceStrong.
// This is the REQUIRED TEST for the assurance AC (Issue #3569).
func TestHandleOsqueryQuery_APIKeyRejected(t *testing.T) {
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(&stubOsqueryDispatcher{})
	server.fleetQuery = fleetWithStewardIDs("steward-1")

	// An API key has Machine assurance — cannot satisfy AssuranceStrong.
	apiKey := NewTestKey(t, server, []string{"osquery:execute"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/osquery/query",
		bytes.NewBufferString(`{"catalog_id":"host_info","selector":"all"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"API-key principal must be rejected with 403 (AssuranceStrong gate)")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
		"Machine-assurance 403 must not include a step-up challenge")
}

// TestHandleOsqueryQuery_NoPresenceToken verifies that a Strong-assurance principal
// without a presence token is rejected because osquery:execute has RequireUserPresence.
// This is the REQUIRED TEST for the presence AC (Issue #3569).
func TestHandleOsqueryQuery_NoPresenceToken(t *testing.T) {
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(&stubOsqueryDispatcher{})
	server.fleetQuery = fleetWithStewardIDs("steward-1")

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "all"}
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/osquery/query", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	// Inject a strong principal but NO presence token.
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, osqueryStrongPrincipal()))
	// Deliberately omit presenceTokenHeader.

	rec := httptest.NewRecorder()
	handler := server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery))
	handler.ServeHTTP(rec, req)

	// Missing presence token must return 401 with step-up challenge.
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"missing presence token must return 401 (RequireUserPresence gate)")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "presence",
		"response must include step-up challenge when presence token is absent")
}

// ---- Tests: fan-out and partial results -------------------------------------

// TestHandleOsqueryQuery_FanOutSuccess verifies that a successful dispatch to
// multiple stewards returns per-steward rows in the response.
func TestHandleOsqueryQuery_FanOutSuccess(t *testing.T) {
	rows := []*transportpb.OsqueryRow{
		{Columns: map[string]string{"hostname": "host-a"}},
	}
	disp := &stubOsqueryDispatcher{rows: rows}
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithStewardIDs("steward-1", "steward-2")

	body := osqueryQueryRequest{
		CatalogID: "host_info",
		Selector:  "all",
	}
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery))
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var qResp osqueryQueryResponse
	require.NoError(t, json.Unmarshal(raw, &qResp))

	require.Len(t, qResp.Results, 2, "must return one result per targeted steward")
	for _, res := range qResp.Results {
		assert.Empty(t, res.Error, "successful dispatch must not set error")
		require.Len(t, res.Rows, 1)
		assert.Equal(t, "host-a", res.Rows[0]["hostname"])
	}

	// Both stewards must have been dispatched to (fan-out, not short-circuit).
	ids := make(map[string]bool)
	for _, c := range disp.calls {
		ids[c.stewardID] = true
	}
	assert.True(t, ids["steward-1"], "steward-1 must be dispatched to")
	assert.True(t, ids["steward-2"], "steward-2 must be dispatched to")
}

// TestHandleOsqueryQuery_PartialFailure verifies that when one steward fails the
// response still includes a result entry for it with an error field, while the
// other steward's rows are returned normally (partial success, AC "per-steward error
// status on individual failures").
func TestHandleOsqueryQuery_PartialFailure(t *testing.T) {
	partialDisp := &partialOsqueryDispatcher{
		failSteward: "steward-2",
		failErr:     errors.New("steward not connected to osquery stream"),
		rows:        []*transportpb.OsqueryRow{{Columns: map[string]string{"hostname": "host-1"}}},
	}
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(partialDisp)
	server.fleetQuery = fleetWithStewardIDs("steward-1", "steward-2")

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "all"}
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery))
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"partial failure must return 200 — per-steward error status is in the body")

	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var qResp osqueryQueryResponse
	require.NoError(t, json.Unmarshal(raw, &qResp))

	require.Len(t, qResp.Results, 2)

	resultsByID := make(map[string]osqueryStewardResult)
	for _, r := range qResp.Results {
		resultsByID[r.StewardID] = r
	}

	s1 := resultsByID["steward-1"]
	assert.Empty(t, s1.Error, "steward-1 result must not carry an error")
	require.Len(t, s1.Rows, 1, "steward-1 must return the expected row")
	assert.Equal(t, "host-1", s1.Rows[0]["hostname"])

	s2 := resultsByID["steward-2"]
	assert.NotEmpty(t, s2.Error, "steward-2 result must carry a per-steward error")
	assert.Empty(t, s2.Rows, "steward-2 result must have no rows on failure")
}

// ---- Tests: validation ------------------------------------------------------

// TestHandleOsqueryQuery_EmptySelector verifies that an empty selector returns 400.
func TestHandleOsqueryQuery_EmptySelector(t *testing.T) {
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(&stubOsqueryDispatcher{})

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: ""}
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()

	server.handleOsqueryQuery(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleOsqueryQuery_EmptyCatalogID verifies that a missing catalog_id returns 400.
func TestHandleOsqueryQuery_EmptyCatalogID(t *testing.T) {
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(&stubOsqueryDispatcher{})

	body := osqueryQueryRequest{CatalogID: "", Selector: "all"}
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()

	server.handleOsqueryQuery(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleOsqueryQuery_NilDispatcherReturns503 verifies that a nil dispatcher returns 503.
func TestHandleOsqueryQuery_NilDispatcherReturns503(t *testing.T) {
	server := setupTestServer(t)
	// osqueryDispatcher is nil by default (no SetOsqueryDispatcher call).

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "all"}
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()

	server.handleOsqueryQuery(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleOsqueryQuery_NoTargets verifies that a selector matching zero stewards
// returns an empty results list with 200.
func TestHandleOsqueryQuery_NoTargets(t *testing.T) {
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(&stubOsqueryDispatcher{})
	server.fleetQuery = fleetWithStewardIDs() // empty fleet

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "all"}
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery))
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	raw, err := json.Marshal(resp.Data)
	require.NoError(t, err)
	var qResp osqueryQueryResponse
	require.NoError(t, json.Unmarshal(raw, &qResp))

	assert.Empty(t, qResp.Results, "zero-target selector must return empty results, not an error")
}

// TestHandleOsqueryQuery_ParamPassthrough verifies that params are passed through
// to the dispatcher without modification — catalog validation is S7's responsibility.
func TestHandleOsqueryQuery_ParamPassthrough(t *testing.T) {
	disp := &stubOsqueryDispatcher{}
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithStewardIDs("steward-1")

	body := osqueryQueryRequest{
		CatalogID: "file_info",
		Params:    map[string]string{"path": "/etc/os-release"},
		Selector:  "all",
	}
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery))
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, disp.calls, 1)
	assert.Equal(t, "file_info", disp.calls[0].catalogID,
		"catalog_id must be passed through unchanged (no controller-side re-validation)")
	assert.Equal(t, map[string]string{"path": "/etc/os-release"}, disp.calls[0].params,
		"params must be passed through unchanged (catalog validation is S7's responsibility)")
}

// TestHandleOsqueryQuery_AuditEmitted verifies that a successful dispatch results
// in an audit event being emitted, recording the steward target, the catalog
// query ID, and the caller identity.
func TestHandleOsqueryQuery_AuditEmitted(t *testing.T) {
	rows := []*transportpb.OsqueryRow{
		{Columns: map[string]string{"hostname": "host-audit"}},
	}
	server := setupTestServer(t)
	server.SetOsqueryDispatcher(&stubOsqueryDispatcher{rows: rows})
	server.fleetQuery = fleetWithStewardIDs("steward-audit")

	body := osqueryQueryRequest{CatalogID: "host_info", Selector: "all"}
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery))
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"audit emission must not prevent a 200 response")

	require.NoError(t, server.auditManager.Flush(context.Background()),
		"flush so the audit event reaches the store before it is queried")

	auditRec := getAuditEntries(server, "root", "")
	require.Equal(t, http.StatusOK, auditRec.Code)

	var resp auditResp
	require.NoError(t, json.NewDecoder(auditRec.Body).Decode(&resp))
	require.NotEmpty(t, resp.Data.Entries, "expected an audit entry for the osquery dispatch")

	entry := resp.Data.Entries[0]
	assert.Equal(t, "osquery.query.dispatch", entry.Action)
	assert.Equal(t, "cert-admin", entry.UserID, "caller identity must be recorded")
	assert.Equal(t, "host_info", entry.Details["catalog_id"], "catalog query ID must be recorded")
	assert.Equal(t, "steward-audit", entry.Details["steward_0"], "steward target must be recorded")
}
