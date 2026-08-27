// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// setupCasesTestServer creates a test Server with a real SQLite-backed CaseStore.
func setupCasesTestServer(t *testing.T) *Server {
	t.Helper()
	srv := setupTestServer(t)
	sm := pkgtesting.SetupTestStorage(t)
	cs := sm.GetCaseStore()
	require.NotNil(t, cs, "OSS composite storage must provide a CaseStore")
	srv.SetCasesStore(cs)
	return srv
}

// newCasesTestKey creates an API key scoped to the given tenant with all case permissions.
func newCasesTestKey(t *testing.T, srv *Server, tenantID string) string {
	t.Helper()
	return NewEphemeralTestKey(t, srv,
		[]string{"case:create", "case:list", "case:read", "case:update"},
		tenantID, 5*time.Minute)
}

// seedCase creates a case in the store directly and returns it. Used to set up
// cross-tenant tests without going through the HTTP handler.
func seedCase(t *testing.T, cs business.CaseStore, tenantID string) *business.Case {
	t.Helper()
	now := time.Now().UTC()
	c := &business.Case{
		// A random suffix, not a timestamp: tests that seed several cases into one
		// tenant do so within the same second, and a second-resolution ID collides.
		// The tenant path is flattened: a nested tenant ("msp/client-a") would put a
		// '/' in the case ID, and the router would then fail to match
		// /api/v1/cases/{id}/pins at all — a 404 from mux that reads exactly like the
		// tenant-denial 404 the nested-tenant tests assert.
		ID:       "seed-case-" + strings.ReplaceAll(tenantID, "/", "-") + "-" + uuid.NewString(),
		TenantID: tenantID,
		Status:   business.CaseStatusOpen,
		Ticket: business.Ticket{
			Title: business.TicketField{Value: "test case for " + tenantID, Source: business.TicketFieldSourceOperator, Filled: true},
		},
		Pins:      []*business.Pin{},
		Content:   []*business.ContentEntry{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, cs.CreateCase(context.Background(), c))
	return c
}

// ── No-store returns 503 ────────────────────────────────────────────────────

func TestHandleCases_NoStore_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	// No SetCasesStore call — store is nil.
	apiKey := NewEphemeralTestKey(t, srv, []string{"case:create", "case:list", "case:read", "case:update"}, "test-tenant", 5*time.Minute)

	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/api/v1/cases", `{"tenant_id":"test-tenant"}`},
		{"GET", "/api/v1/cases", ""},
		{"GET", "/api/v1/cases/nonexistent-id", ""},
		{"PUT", "/api/v1/cases/nonexistent-id", `{"status":"closed"}`},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var body *bytes.Buffer
			if tc.body != "" {
				body = bytes.NewBufferString(tc.body)
			} else {
				body = &bytes.Buffer{}
			}
			req := httptest.NewRequest(tc.method, tc.path, body)
			req.Header.Set("X-API-Key", apiKey)
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			srv.router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		})
	}
}

// ── CREATE ──────────────────────────────────────────────────────────────────

func TestHandleCreateCase_CreatesInCallerTenant(t *testing.T) {
	srv := setupCasesTestServer(t)
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"ticket": map[string]interface{}{
			"title": map[string]interface{}{"value": "test case", "source": "operator"},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, "create should return 201: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "response must have data field")
	assert.Equal(t, "test-tenant", data["tenant_id"])
	assert.Equal(t, "open", data["status"])
	assert.NotEmpty(t, data["id"])
	// Pins must be an empty array (never null/omitted) — downstream cockpit stories
	// read pins from this response without a separate pin-list call.
	pins, ok := data["pins"].([]interface{})
	require.True(t, ok, "pins must be an array")
	assert.Empty(t, pins, "pins must be empty for a newly created case")
}

// TestHandleCreateCase_MalformedBodyReturns400 exercises the decode-failure branch
// in handleCreateCase: a body that is not JSON must be rejected at the handler's
// input boundary, never reach the store.
func TestHandleCreateCase_MalformedBodyReturns400(t *testing.T) {
	srv := setupCasesTestServer(t)
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewBufferString("not-json"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"a non-JSON body must be rejected with 400: %s", rec.Body.String())
	// Pins the 400 to the handler's own decode branch rather than to a middleware
	// rejection that would make this test pass without exercising the handler.
	assert.Contains(t, rec.Body.String(), "invalid request body")

	// Nothing may have been persisted by a rejected request.
	cases, err := srv.CasesStore().ListCases(context.Background(), "test-tenant")
	require.NoError(t, err)
	assert.Empty(t, cases, "a rejected create must not persist a case")
}

// TestHandleCreateCase_RejectsUnknownTicketFieldSource proves the ticket-field
// provenance enum is validated on create: an arbitrary source string must not be
// castable into the persisted record.
func TestHandleCreateCase_RejectsUnknownTicketFieldSource(t *testing.T) {
	srv := setupCasesTestServer(t)
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"ticket": map[string]interface{}{
			"title": map[string]interface{}{"value": "test case", "source": "forged-provenance"},
		},
	}
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"an unknown ticket field source must be rejected with 400: %s", rec.Body.String())

	cases, listErr := srv.CasesStore().ListCases(context.Background(), "test-tenant")
	require.NoError(t, listErr)
	assert.Empty(t, cases, "a rejected create must not persist a case")
}

// TestHandleCreateCase_OmittedSourceDefaultsToOperator pins the provenance default
// for API-supplied ticket fields: an omitted source is operator, never empty.
func TestHandleCreateCase_OmittedSourceDefaultsToOperator(t *testing.T) {
	srv := setupCasesTestServer(t)
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"ticket": map[string]interface{}{
			"title": map[string]interface{}{"value": "no source supplied"},
		},
	}
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, "create should return 201: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "response must have data field")
	ticket, ok := data["ticket"].(map[string]interface{})
	require.True(t, ok, "response must carry a ticket")
	title, ok := ticket["title"].(map[string]interface{})
	require.True(t, ok, "ticket must carry a title field")
	assert.Equal(t, string(business.TicketFieldSourceOperator), title["source"])
	assert.Equal(t, true, title["filled"])
}

func TestHandleCreateCase_RejectsTenantOutsideSubtree(t *testing.T) {
	srv := setupCasesTestServer(t)
	// Caller is scoped to "test-tenant"; "other-tenant" is outside that subtree.
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"tenant_id": "other-tenant",
		"ticket":    map[string]interface{}{},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"creating a case for another tenant must be rejected with 403")
}

// TestHandleCreateCase_NonLeaderRejects exercises the leadership-rejection branch
// in handleCreateCase: a node that is not authoritative must refuse the mutation
// with 503 and persist nothing. The store is wired here, so the 503 can only come
// from the leadership guard, never from the nil-store branch.
func TestHandleCreateCase_NonLeaderRejects(t *testing.T) {
	srv := setupCasesTestServer(t)
	srv.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"ticket": map[string]interface{}{
			"title": map[string]interface{}{"value": "case from a follower", "source": "operator"},
		},
	}
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"a non-leader must reject create with 503: %s", rec.Body.String())

	cases, listErr := srv.CasesStore().ListCases(context.Background(), "test-tenant")
	require.NoError(t, listErr)
	assert.Empty(t, cases, "a create rejected by the leadership gate must not persist a case")
}

// ── LIST ────────────────────────────────────────────────────────────────────

func TestHandleListCases_ReturnsCallerTenantCases(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cases", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "list should return 200: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp["data"].([]interface{})
	require.True(t, ok, "data must be an array")
	assert.NotEmpty(t, data, "caller's tenant should have at least one case")
}

// TestHandleCases_CrossTenantDenial is the REQUIRED TEST from AC #6:
// A case created in tenant A must be absent from a list scoped to tenant B,
// and a direct GET by ID from tenant B must return 404.
func TestHandleCases_CrossTenantDenial(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()

	// Seed a case in "tenant-alpha" directly.
	caseAlpha := seedCase(t, cs, "tenant-alpha")

	// Key scoped to "tenant-beta" — cannot see tenant-alpha cases.
	keyBeta := NewEphemeralTestKey(t, srv,
		[]string{"case:create", "case:list", "case:read", "case:update"},
		"tenant-beta", 5*time.Minute)

	// 1. List from tenant-beta perspective: tenant-alpha case must be absent.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cases", nil)
	req.Header.Set("X-API-Key", keyBeta)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "list must succeed: %s", rec.Body.String())
	var listResp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&listResp))
	listData, ok := listResp["data"].([]interface{})
	require.True(t, ok, "list data must be an array")
	for _, item := range listData {
		entry, ok := item.(map[string]interface{})
		require.True(t, ok)
		assert.NotEqual(t, caseAlpha.ID, entry["id"],
			"tenant-alpha case must not appear in tenant-beta list")
	}

	// 2. GET /api/v1/cases/{id} from tenant-beta perspective: must return 404,
	// indistinguishable from a nonexistent id (existence-oracle prevention).
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/cases/"+caseAlpha.ID, nil)
	req2.Header.Set("X-API-Key", keyBeta)
	rec2 := httptest.NewRecorder()
	srv.router.ServeHTTP(rec2, req2)

	assert.Equal(t, http.StatusNotFound, rec2.Code,
		"GET from another tenant must return 404 (same as nonexistent)")
}

// TestHandleListCases_IncludesDescendantTenant proves GET /api/v1/cases scoped
// to a parent tenant includes a case belonging to a child tenant beneath it
// (subtree, not exact-match, semantics), while a sibling tenant's case is
// still excluded.
func TestHandleListCases_IncludesDescendantTenant(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()

	caseParent := seedCase(t, cs, "tenant-parent")
	caseChild := seedCase(t, cs, "tenant-parent/client-1")
	caseSibling := seedCase(t, cs, "tenant-parent-sibling")

	keyParent := NewEphemeralTestKey(t, srv,
		[]string{"case:create", "case:list", "case:read", "case:update"},
		"tenant-parent", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cases", nil)
	req.Header.Set("X-API-Key", keyParent)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "list should return 200: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp["data"].([]interface{})
	require.True(t, ok, "data must be an array")

	var seenIDs []string
	for _, item := range data {
		entry, ok := item.(map[string]interface{})
		require.True(t, ok)
		seenIDs = append(seenIDs, entry["id"].(string))
	}

	assert.Contains(t, seenIDs, caseParent.ID, "parent tenant's own case must be listed")
	assert.Contains(t, seenIDs, caseChild.ID, "descendant tenant's case must be listed under subtree filtering")
	assert.NotContains(t, seenIDs, caseSibling.ID, "sibling tenant's case must not be listed")
}

// ── GET BY ID ───────────────────────────────────────────────────────────────

func TestHandleGetCase_ReturnsCaseWithPins(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cases/"+c.ID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "get should return 200: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "data must be an object")
	assert.Equal(t, c.ID, data["id"])

	// pins must be an array (empty is fine; must not be null or absent).
	pins, ok := data["pins"].([]interface{})
	require.True(t, ok, "pins field must be an array, not null or absent")
	assert.Empty(t, pins, "no pins were added; must be empty array")
}

func TestHandleGetCase_NonexistentReturns404(t *testing.T) {
	srv := setupCasesTestServer(t)
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/cases/does-not-exist", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ── UPDATE ──────────────────────────────────────────────────────────────────

func TestHandleUpdateCase_UpdatesStatus(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"status": "closed",
		"ticket": map[string]interface{}{
			"title": map[string]interface{}{"value": "updated title", "source": "operator"},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/cases/"+c.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "update should return 200: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "data must be an object")
	assert.Equal(t, "closed", data["status"])
}

// TestHandleUpdateCase_MalformedBodyReturns400 exercises the decode-failure branch
// in handleUpdateCase. The case exists and is in the caller's tenant, so the
// request reaches the decode step; only the body is invalid.
func TestHandleUpdateCase_MalformedBodyReturns400(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/cases/"+c.ID, bytes.NewBufferString("not-json"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"a non-JSON body must be rejected with 400: %s", rec.Body.String())
	// Pins the 400 to the handler's own decode branch rather than to a middleware
	// rejection that would make this test pass without exercising the handler.
	assert.Contains(t, rec.Body.String(), "invalid request body")

	// The stored case must be untouched by a rejected update.
	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	assert.Equal(t, business.CaseStatusOpen, stored.Status)
	assert.Equal(t, c.Ticket.Title.Value, stored.Ticket.Title.Value)
}

// TestHandleUpdateCase_RejectsUnknownStatus proves an arbitrary status string is
// not cast into the persisted record. Neither case-store schema constrains the
// column, so this handler is the only place the enum is enforced.
func TestHandleUpdateCase_RejectsUnknownStatus(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	for _, status := range []string{"escalated", "OPEN", "'; DROP TABLE cases; --", " open"} {
		t.Run(status, func(t *testing.T) {
			body := map[string]interface{}{"status": status}
			bodyBytes, err := json.Marshal(body)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPut, "/api/v1/cases/"+c.ID, bytes.NewReader(bodyBytes))
			req.Header.Set("X-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusBadRequest, rec.Code,
				"status %q must be rejected with 400: %s", status, rec.Body.String())

			stored, err := cs.GetCase(context.Background(), c.ID)
			require.NoError(t, err)
			assert.Equal(t, business.CaseStatusOpen, stored.Status,
				"a rejected update must leave the persisted status untouched")
		})
	}
}

// TestHandleUpdateCase_RejectsUnknownTicketFieldSource proves the provenance enum
// is enforced on update as well as create.
func TestHandleUpdateCase_RejectsUnknownTicketFieldSource(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"status": "closed",
		"ticket": map[string]interface{}{
			"client": map[string]interface{}{"value": "acme-corp", "source": "psa-import"},
		},
	}
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/cases/"+c.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"an unknown ticket field source must be rejected with 400: %s", rec.Body.String())

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	assert.Equal(t, business.CaseStatusOpen, stored.Status,
		"a rejected update must not apply the status change either")
}

// TestHandleUpdateCase_AcceptsEveryDeclaredTicketFieldSource proves the validation
// admits all five declared provenance values — it bounds the enum, not the feature.
func TestHandleUpdateCase_AcceptsEveryDeclaredTicketFieldSource(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	for _, source := range []business.TicketFieldSource{
		business.TicketFieldSourceEmail,
		business.TicketFieldSourceCallerID,
		business.TicketFieldSourcePSA,
		business.TicketFieldSourceOperator,
		business.TicketFieldSourceInferred,
	} {
		t.Run(string(source), func(t *testing.T) {
			c := seedCase(t, cs, "test-tenant")
			body := map[string]interface{}{
				"ticket": map[string]interface{}{
					"title": map[string]interface{}{"value": "provenanced title", "source": string(source)},
				},
			}
			bodyBytes, err := json.Marshal(body)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPut, "/api/v1/cases/"+c.ID, bytes.NewReader(bodyBytes))
			req.Header.Set("X-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusOK, rec.Code, "update should return 200: %s", rec.Body.String())

			stored, err := cs.GetCase(context.Background(), c.ID)
			require.NoError(t, err)
			assert.Equal(t, source, stored.Ticket.Title.Source)
		})
	}
}

func TestHandleUpdateCase_CrossTenantReturns404(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")

	// Attempt update from a key scoped to "tenant-beta".
	keyBeta := NewEphemeralTestKey(t, srv,
		[]string{"case:create", "case:list", "case:read", "case:update"},
		"tenant-beta", 5*time.Minute)

	body := map[string]interface{}{"status": "closed"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/cases/"+c.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", keyBeta)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"PUT from another tenant must return 404, not 403 (existence-oracle prevention)")
}

// TestHandleUpdateCase_NonLeaderRejects exercises the leadership-rejection branch
// in handleUpdateCase: a node that is not authoritative must refuse the mutation
// with 503 and leave the stored case untouched. The case exists and is in the
// caller's tenant, and the store is wired, so the 503 can only come from the
// leadership guard.
func TestHandleUpdateCase_NonLeaderRejects(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	srv.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"status": "closed",
		"ticket": map[string]interface{}{
			"title": map[string]interface{}{"value": "updated by a follower", "source": "operator"},
		},
	}
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/cases/"+c.ID, bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"a non-leader must reject update with 503: %s", rec.Body.String())

	stored, getErr := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, getErr)
	assert.Equal(t, business.CaseStatusOpen, stored.Status,
		"an update rejected by the leadership gate must not change the persisted status")
	assert.Equal(t, c.Ticket.Title.Value, stored.Ticket.Title.Value,
		"an update rejected by the leadership gate must not change the persisted ticket")
}

func TestHandleUpdateCase_NonexistentReturns404(t *testing.T) {
	srv := setupCasesTestServer(t)
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{"status": "closed"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/cases/does-not-exist", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ── PIN helpers ─────────────────────────────────────────────────────────────

// setupCasesWithEGTestServer creates a test server with both a CaseStore and an
// entity graph provider. Used by pin tests that need EID tenant verification.
func setupCasesWithEGTestServer(t *testing.T) (*Server, *sqlite.SQLiteEntityGraphProvider) {
	t.Helper()
	srv := setupCasesTestServer(t)
	p := newTestEntityGraphProvider(t)
	srv.SetEntityGraphProvider(p)
	return srv, p
}

// seedPin adds a pin directly to the store (bypassing the HTTP handler) so that
// remove tests can set up a known pin without a live entity graph.
func seedPin(t *testing.T, cs business.CaseStore, caseID, kind, ref string) *business.Pin {
	t.Helper()
	pin := &business.Pin{
		ID:         "seed-pin-" + uuid.NewString(),
		CaseID:     caseID,
		Ref:        business.PinRef{Kind: business.PinRefKind(kind), ObservationVersion: ref},
		Annotation: "seeded",
		Author:     "test",
		PinnedAt:   time.Now().UTC(),
	}
	require.NoError(t, cs.AddPin(context.Background(), caseID, pin))
	return pin
}

// ── ADD PIN (POST /api/v1/cases/{id}/pins) ──────────────────────────────────

func TestHandlePins_NoStore_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	// No SetCasesStore — store is nil.
	apiKey := NewEphemeralTestKey(t, srv, []string{"case:update"}, "test-tenant", 5*time.Minute)

	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/api/v1/cases/some-id/pins", `{"kind":"observation-version","observation_version":"v1"}`},
		{"DELETE", "/api/v1/cases/some-id/pins/pin-id", ""},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var bodyBuf *bytes.Buffer
			if tc.body != "" {
				bodyBuf = bytes.NewBufferString(tc.body)
			} else {
				bodyBuf = &bytes.Buffer{}
			}
			req := httptest.NewRequest(tc.method, tc.path, bodyBuf)
			req.Header.Set("X-API-Key", apiKey)
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			srv.router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		})
	}
}

// TestHandleAddPin_ObservationVersionPin proves the happy path for a non-EID
// pin kind: observation-version requires no entity graph provider.
func TestHandleAddPin_ObservationVersionPin(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"kind":                "observation-version",
		"observation_version": "obs-v1-abc123",
		"annotation":          "pinned for investigation",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+c.ID+"/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, "add pin should return 201: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "response must have data field")
	assert.Equal(t, c.ID, data["case_id"])
	assert.NotEmpty(t, data["id"])
	ref, ok := data["ref"].(map[string]interface{})
	require.True(t, ok, "response must include ref")
	assert.Equal(t, "observation-version", ref["kind"])
	assert.Equal(t, "obs-v1-abc123", ref["observation_version"])

	// Verify the pin is persisted in the case.
	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	require.Len(t, stored.Pins, 1, "one pin must be persisted")
	assert.Equal(t, "observation-version", string(stored.Pins[0].Ref.Kind))
}

// TestHandleAddPin_DriftRecordPin exercises the drift-record kind (no egProvider needed).
func TestHandleAddPin_DriftRecordPin(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"kind":         "drift-record",
		"drift_record": "drift-abc-456",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+c.ID+"/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, "add pin should return 201: %s", rec.Body.String())

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	require.Len(t, stored.Pins, 1)
	assert.Equal(t, "drift-record", string(stored.Pins[0].Ref.Kind))
}

// TestHandleAddPin_EIDPin_WithinCaseTenant proves the happy path for eid kind:
// an entity that exists within the case's own tenant is successfully pinned.
func TestHandleAddPin_EIDPin_WithinCaseTenant(t *testing.T) {
	srv, egp := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	reportEntity(t, egp, "host:server-alpha", "tenant-alpha", "host")
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	body := map[string]interface{}{
		"kind": "eid",
		"eid":  "host:server-alpha",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+c.ID+"/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, "add eid pin should return 201: %s", rec.Body.String())

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	require.Len(t, stored.Pins, 1)
	assert.Equal(t, "eid", string(stored.Pins[0].Ref.Kind))
	assert.Equal(t, "host:server-alpha", stored.Pins[0].Ref.EID)
}

// TestHandleAddPin_CrossTenantEIDDenied is the REQUIRED TEST from AC:
// A case in tenant A attempts to pin an eid that exists but is owned by tenant B.
// The request must be rejected with 404 and no pin persisted — checked against
// the case's tenant, not the caller's ambient tenant.
func TestHandleAddPin_CrossTenantEIDDenied(t *testing.T) {
	srv, egp := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()

	// Case belongs to tenant-a.
	caseA := seedCase(t, cs, "tenant-a")

	// Entity exists but is owned by tenant-b — outside the case's tenant ceiling.
	reportEntity(t, egp, "host:server-beta", "tenant-b", "host")

	// Caller is scoped to tenant-a (can see the case).
	apiKey := newCasesTestKey(t, srv, "tenant-a")

	body := map[string]interface{}{
		"kind": "eid",
		"eid":  "host:server-beta",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+caseA.ID+"/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	// 404: indistinguishable from a nonexistent entity (existence-oracle prevention).
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant eid pin must be rejected with 404: %s", rec.Body.String())

	// No pin must be persisted.
	stored, err := cs.GetCase(context.Background(), caseA.ID)
	require.NoError(t, err)
	assert.Empty(t, stored.Pins, "a cross-tenant eid pin must not be persisted")
}

// TestHandleAddPin_CaseTenantIsEIDCeiling proves that even when the caller holds
// broader access than the case's own tenant, pins are verified against the case's
// (narrower) tenant ceiling, not the caller's ambient tenant.
//
// Case is in "msp-tenant/client-a". Caller is scoped to "msp-tenant" (broader).
// The entity is in "msp-tenant" — visible to the caller but outside the case's
// own subtree. The pin must be rejected.
func TestHandleAddPin_CaseTenantIsEIDCeiling(t *testing.T) {
	srv, egp := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()

	// Case is anchored to the client sub-tenant.
	caseClient := seedCase(t, cs, "msp-tenant/client-a")

	// Entity is in the parent MSP tenant — visible to an MSP-scoped caller,
	// but outside the case's own tenant subtree.
	reportEntity(t, egp, "host:msp-server", "msp-tenant", "host")

	// Caller is scoped to the parent "msp-tenant" — broader than the case's tenant.
	apiKey := newCasesTestKey(t, srv, "msp-tenant")

	body := map[string]interface{}{
		"kind": "eid",
		"eid":  "host:msp-server",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+caseClient.ID+"/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"entity outside case's tenant subtree must be rejected even when caller has broader access: %s", rec.Body.String())

	stored, err := cs.GetCase(context.Background(), caseClient.ID)
	require.NoError(t, err)
	assert.Empty(t, stored.Pins, "pin outside case's tenant ceiling must not be persisted")
}

func TestHandleAddPin_MalformedBodyReturns400(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+c.ID+"/pins", bytes.NewBufferString("not-json"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"malformed body must be rejected with 400: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "invalid request body")

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	assert.Empty(t, stored.Pins, "a rejected add must not persist a pin")
}

func TestHandleAddPin_MissingKindReturns400(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{"annotation": "no kind field"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+c.ID+"/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "kind is required")
}

func TestHandleAddPin_InvalidKindReturns400(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{"kind": "not-a-valid-kind"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+c.ID+"/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleAddPin_CaseNotFoundReturns404(t *testing.T) {
	srv := setupCasesTestServer(t)
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"kind":                "observation-version",
		"observation_version": "v1",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/does-not-exist/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleAddPin_CrossTenantCaseReturns404(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	keyBeta := NewEphemeralTestKey(t, srv,
		[]string{"case:create", "case:list", "case:read", "case:update"},
		"tenant-beta", 5*time.Minute)

	body := map[string]interface{}{
		"kind":                "observation-version",
		"observation_version": "v1",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+c.ID+"/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", keyBeta)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"add pin to another tenant's case must return 404")

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	assert.Empty(t, stored.Pins, "no pin must be added to another tenant's case")
}

func TestHandleAddPin_NoProviderForEIDKindReturns503(t *testing.T) {
	// No SetEntityGraphProvider — egProvider is nil.
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"kind": "eid",
		"eid":  "host:server-alpha",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+c.ID+"/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"eid pin with no entity graph provider must return 503: %s", rec.Body.String())
}

func TestHandleAddPin_NonLeaderRejects(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	srv.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	body := map[string]interface{}{
		"kind":                "observation-version",
		"observation_version": "v1",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+c.ID+"/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"non-leader must reject add pin with 503: %s", rec.Body.String())

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	assert.Empty(t, stored.Pins, "add pin rejected by leadership gate must not persist a pin")
}

// ── REMOVE PIN (DELETE /api/v1/cases/{id}/pins/{pin_id}) ────────────────────

func TestHandleRemovePin_RemovesPin(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	pin := seedPin(t, cs, c.ID, "observation-version", "obs-v1")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/cases/"+c.ID+"/pins/"+pin.ID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNoContent, rec.Code, "remove pin should return 204: %s", rec.Body.String())

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	assert.Empty(t, stored.Pins, "pin must be removed from the stored case")
}

func TestHandleRemovePin_PinNotFoundReturns404(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/cases/"+c.ID+"/pins/does-not-exist", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleRemovePin_CaseNotFoundReturns404(t *testing.T) {
	srv := setupCasesTestServer(t)
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/cases/does-not-exist/pins/some-pin-id", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleRemovePin_CrossTenantCaseReturns404(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	pin := seedPin(t, cs, c.ID, "observation-version", "obs-v1")
	keyBeta := NewEphemeralTestKey(t, srv,
		[]string{"case:create", "case:list", "case:read", "case:update"},
		"tenant-beta", 5*time.Minute)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/cases/"+c.ID+"/pins/"+pin.ID, nil)
	req.Header.Set("X-API-Key", keyBeta)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"remove pin from another tenant's case must return 404")

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	require.Len(t, stored.Pins, 1, "pin must not be removed from another tenant's case")
}

func TestHandleRemovePin_NonLeaderRejects(t *testing.T) {
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "test-tenant")
	pin := seedPin(t, cs, c.ID, "observation-version", "obs-v1")
	srv.registrationLeaderStatus = &stubRegistrationLeaderStatus{hasLeadership: false}
	apiKey := newCasesTestKey(t, srv, "test-tenant")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/cases/"+c.ID+"/pins/"+pin.ID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"non-leader must reject remove pin with 503: %s", rec.Body.String())

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	require.Len(t, stored.Pins, 1, "remove pin rejected by leadership gate must not remove the pin")
}

// ── ADD PIN: edge-identity and subject-time-range kinds ─────────────────────

// postPin issues POST /api/v1/cases/{id}/pins with the given JSON body.
func postPin(t *testing.T, srv *Server, apiKey, caseID string, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/"+caseID+"/pins", bytes.NewReader(bodyBytes))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)
	return rec
}

// requireNoPins asserts that the stored case carries no pins — the invariant for
// every rejected add.
func requireNoPins(t *testing.T, cs business.CaseStore, caseID string) {
	t.Helper()
	stored, err := cs.GetCase(context.Background(), caseID)
	require.NoError(t, err)
	assert.Empty(t, stored.Pins, "a rejected add must not persist a pin")
}

// TestHandleAddPin_EdgeIdentityPin_WithinCaseTenant is the edge-identity happy
// path: both endpoints resolve inside the case's tenant and the persisted
// identity is the canonical three-field subject.
func TestHandleAddPin_EdgeIdentityPin_WithinCaseTenant(t *testing.T) {
	srv, egp := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	reportEntity(t, egp, "host:server-from", "tenant-alpha", "host")
	reportEntity(t, egp, "host:server-to", "tenant-alpha", "host")
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	rec := postPin(t, srv, apiKey, c.ID, map[string]interface{}{
		"kind":      "edge-identity",
		"edge_type": "runs-on",
		"from_eid":  "host:server-from",
		"to_eid":    "host:server-to",
	})

	require.Equal(t, http.StatusCreated, rec.Code, "add edge-identity pin should return 201: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "response must have data field")
	ref, ok := data["ref"].(map[string]interface{})
	require.True(t, ok, "response must include ref")
	assert.Equal(t, "edge-identity", ref["kind"])
	assert.Equal(t, "runs-on|host:server-from|host:server-to", ref["edge_identity"])

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	require.Len(t, stored.Pins, 1)
	assert.Equal(t, "edge-identity", string(stored.Pins[0].Ref.Kind))
	assert.Equal(t, "runs-on|host:server-from|host:server-to", stored.Pins[0].Ref.EdgeIdentity)
}

// TestHandleAddPin_EdgeIdentityPin_RelatedEscapeAccepted proves the open
// related:<discriminator> subtype (ADR-022 §2) is a valid edge_type.
func TestHandleAddPin_EdgeIdentityPin_RelatedEscapeAccepted(t *testing.T) {
	srv, egp := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	reportEntity(t, egp, "host:server-from", "tenant-alpha", "host")
	reportEntity(t, egp, "host:server-to", "tenant-alpha", "host")
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	rec := postPin(t, srv, apiKey, c.ID, map[string]interface{}{
		"kind":      "edge-identity",
		"edge_type": "related:shares-subnet",
		"from_eid":  "host:server-from",
		"to_eid":    "host:server-to",
	})

	require.Equal(t, http.StatusCreated, rec.Code, "related: escape edge_type should be accepted: %s", rec.Body.String())

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	require.Len(t, stored.Pins, 1)
	assert.Equal(t, "related:shares-subnet|host:server-from|host:server-to", stored.Pins[0].Ref.EdgeIdentity)
}

func TestHandleAddPin_EdgeIdentityMissingEndpointsReturns400(t *testing.T) {
	srv, egp := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	reportEntity(t, egp, "host:server-from", "tenant-alpha", "host")
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	for name, body := range map[string]map[string]interface{}{
		"both missing": {"kind": "edge-identity", "edge_type": "runs-on"},
		"from missing": {"kind": "edge-identity", "edge_type": "runs-on", "to_eid": "host:server-from"},
		"to missing":   {"kind": "edge-identity", "edge_type": "runs-on", "from_eid": "host:server-from"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := postPin(t, srv, apiKey, c.ID, body)
			require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
			assert.Contains(t, rec.Body.String(), "from_eid and to_eid are required")
			requireNoPins(t, cs, c.ID)
		})
	}
}

// TestHandleAddPin_EdgeIdentityEndpointDelimiterRejected proves an endpoint that
// parses as an EID but carries the subject delimiter is rejected — otherwise it
// would shift the field boundaries of the stored three-field identity.
func TestHandleAddPin_EdgeIdentityEndpointDelimiterRejected(t *testing.T) {
	srv, egp := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	reportEntity(t, egp, "host:server-ok", "tenant-alpha", "host")
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	for name, tc := range map[string]struct {
		body    map[string]interface{}
		message string
	}{
		"from_eid carries delimiter": {
			body:    map[string]interface{}{"kind": "edge-identity", "edge_type": "runs-on", "from_eid": "host:evil|host:smuggled", "to_eid": "host:server-ok"},
			message: "invalid from_eid",
		},
		"to_eid carries delimiter": {
			body:    map[string]interface{}{"kind": "edge-identity", "edge_type": "runs-on", "from_eid": "host:server-ok", "to_eid": "host:evil|host:smuggled"},
			message: "invalid to_eid",
		},
		"from_eid unparseable": {
			body:    map[string]interface{}{"kind": "edge-identity", "edge_type": "runs-on", "from_eid": "not-an-eid", "to_eid": "host:server-ok"},
			message: "invalid from_eid",
		},
		"to_eid unparseable": {
			body:    map[string]interface{}{"kind": "edge-identity", "edge_type": "runs-on", "from_eid": "host:server-ok", "to_eid": "not-an-eid"},
			message: "invalid to_eid",
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := postPin(t, srv, apiKey, c.ID, tc.body)
			require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.message)
			requireNoPins(t, cs, c.ID)
		})
	}
}

// TestHandleAddPin_EdgeIdentityEdgeTypeValidated proves edge_type gets the same
// treatment as the endpoints it is concatenated with. A delimiter in edge_type
// would let a caller with two legitimate in-tenant endpoints persist an identity
// whose three-way split recovers an endpoint from another tenant that never
// passed verifyEntityAccess; an empty or unknown edge_type yields a malformed
// subject that no taxonomy consumer can interpret.
func TestHandleAddPin_EdgeIdentityEdgeTypeValidated(t *testing.T) {
	srv, egp := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	reportEntity(t, egp, "host:legit-from", "tenant-alpha", "host")
	reportEntity(t, egp, "host:legit-to", "tenant-alpha", "host")
	// The entity the injection attempts to name — owned by another tenant.
	reportEntity(t, egp, "host:victim", "tenant-beta", "host")
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	for name, tc := range map[string]struct {
		edgeType string
		message  string
	}{
		"delimiter injection smuggles a cross-tenant endpoint": {
			edgeType: "same-as|host:victim|host:x",
			message:  "edge_type must not contain '|'",
		},
		"empty": {
			edgeType: "",
			message:  "edge_type is required",
		},
		"absent from the taxonomy": {
			edgeType: "not-a-taxonomy-edge",
			message:  "edge_type must be a known edge type",
		},
		"bare related prefix with no discriminator": {
			edgeType: "related:",
			message:  "edge_type must be a known edge type",
		},
	} {
		t.Run(name, func(t *testing.T) {
			body := map[string]interface{}{
				"kind":     "edge-identity",
				"from_eid": "host:legit-from",
				"to_eid":   "host:legit-to",
			}
			if tc.edgeType != "" {
				body["edge_type"] = tc.edgeType
			}
			rec := postPin(t, srv, apiKey, c.ID, body)

			require.Equal(t, http.StatusBadRequest, rec.Code,
				"invalid edge_type must be rejected with 400: %s", rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.message)
			requireNoPins(t, cs, c.ID)
		})
	}
}

func TestHandleAddPin_NoProviderForEdgeIdentityKindReturns503(t *testing.T) {
	// No SetEntityGraphProvider — egProvider is nil.
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	rec := postPin(t, srv, apiKey, c.ID, map[string]interface{}{
		"kind":      "edge-identity",
		"edge_type": "runs-on",
		"from_eid":  "host:server-from",
		"to_eid":    "host:server-to",
	})

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"edge-identity pin with no entity graph provider must return 503: %s", rec.Body.String())
	requireNoPins(t, cs, c.ID)
}

// TestHandleAddPin_EdgeIdentityCrossTenantEndpointDenied proves both endpoints
// are checked against the case's tenant ceiling: an out-of-subtree endpoint on
// either side is a 404, indistinguishable from a nonexistent entity.
func TestHandleAddPin_EdgeIdentityCrossTenantEndpointDenied(t *testing.T) {
	for name, body := range map[string]map[string]interface{}{
		"from_eid outside the case tenant": {
			"kind": "edge-identity", "edge_type": "runs-on",
			"from_eid": "host:beta-server", "to_eid": "host:alpha-server",
		},
		"to_eid outside the case tenant": {
			"kind": "edge-identity", "edge_type": "runs-on",
			"from_eid": "host:alpha-server", "to_eid": "host:beta-server",
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv, egp := setupCasesWithEGTestServer(t)
			cs := srv.CasesStore()
			c := seedCase(t, cs, "tenant-a")
			reportEntity(t, egp, "host:alpha-server", "tenant-a", "host")
			reportEntity(t, egp, "host:beta-server", "tenant-b", "host")
			apiKey := newCasesTestKey(t, srv, "tenant-a")

			rec := postPin(t, srv, apiKey, c.ID, body)

			assert.Equal(t, http.StatusNotFound, rec.Code,
				"cross-tenant edge endpoint must be rejected with 404: %s", rec.Body.String())
			requireNoPins(t, cs, c.ID)
		})
	}
}

// TestHandleAddPin_SubjectTimeRangePin_WithinCaseTenant is the subject-time-range
// happy path: the subject resolves inside the case's tenant and both bounds are
// persisted.
func TestHandleAddPin_SubjectTimeRangePin_WithinCaseTenant(t *testing.T) {
	srv, egp := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	reportEntity(t, egp, "host:server-alpha", "tenant-alpha", "host")
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	start := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	end := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	rec := postPin(t, srv, apiKey, c.ID, map[string]interface{}{
		"kind":             "subject-time-range",
		"subject":          "host:server-alpha",
		"time_range_start": start.Format(time.RFC3339),
		"time_range_end":   end.Format(time.RFC3339),
	})

	require.Equal(t, http.StatusCreated, rec.Code, "add subject-time-range pin should return 201: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "response must have data field")
	ref, ok := data["ref"].(map[string]interface{})
	require.True(t, ok, "response must include ref")
	assert.Equal(t, "subject-time-range", ref["kind"])
	assert.Equal(t, "host:server-alpha", ref["subject"])

	stored, err := cs.GetCase(context.Background(), c.ID)
	require.NoError(t, err)
	require.Len(t, stored.Pins, 1)
	assert.Equal(t, "subject-time-range", string(stored.Pins[0].Ref.Kind))
	assert.Equal(t, "host:server-alpha", stored.Pins[0].Ref.Subject)
	assert.True(t, start.Equal(stored.Pins[0].Ref.TimeRangeStart),
		"time_range_start must round-trip: got %s", stored.Pins[0].Ref.TimeRangeStart)
	assert.True(t, end.Equal(stored.Pins[0].Ref.TimeRangeEnd),
		"time_range_end must round-trip: got %s", stored.Pins[0].Ref.TimeRangeEnd)
}

func TestHandleAddPin_SubjectTimeRangeValidationReturns400(t *testing.T) {
	srv, egp := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	reportEntity(t, egp, "host:server-alpha", "tenant-alpha", "host")
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	start := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC).Format(time.RFC3339)
	end := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)

	for name, tc := range map[string]struct {
		body    map[string]interface{}
		message string
	}{
		"subject missing": {
			body:    map[string]interface{}{"kind": "subject-time-range", "time_range_start": start, "time_range_end": end},
			message: "subject is required",
		},
		"both bounds missing": {
			body:    map[string]interface{}{"kind": "subject-time-range", "subject": "host:server-alpha"},
			message: "time_range_start and time_range_end are required",
		},
		"end bound missing": {
			body:    map[string]interface{}{"kind": "subject-time-range", "subject": "host:server-alpha", "time_range_start": start},
			message: "time_range_start and time_range_end are required",
		},
		"start bound missing": {
			body:    map[string]interface{}{"kind": "subject-time-range", "subject": "host:server-alpha", "time_range_end": end},
			message: "time_range_start and time_range_end are required",
		},
		"subject is not a parseable eid": {
			body:    map[string]interface{}{"kind": "subject-time-range", "subject": "not-an-eid", "time_range_start": start, "time_range_end": end},
			message: "invalid subject eid",
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := postPin(t, srv, apiKey, c.ID, tc.body)
			require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.message)
			requireNoPins(t, cs, c.ID)
		})
	}
}

func TestHandleAddPin_NoProviderForSubjectTimeRangeKindReturns503(t *testing.T) {
	// No SetEntityGraphProvider — egProvider is nil.
	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	rec := postPin(t, srv, apiKey, c.ID, map[string]interface{}{
		"kind":             "subject-time-range",
		"subject":          "host:server-alpha",
		"time_range_start": time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"time_range_end":   time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
	})

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"subject-time-range pin with no entity graph provider must return 503: %s", rec.Body.String())
	requireNoPins(t, cs, c.ID)
}

// TestHandleAddPin_SubjectTimeRangeCrossTenantSubjectDenied proves the subject
// EID is checked against the case's tenant ceiling, not the caller's ambient
// tenant: the caller here is scoped to the parent MSP tenant and can see the
// entity, but the case cannot.
func TestHandleAddPin_SubjectTimeRangeCrossTenantSubjectDenied(t *testing.T) {
	srv, egp := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "msp-tenant/client-a")
	reportEntity(t, egp, "host:msp-server", "msp-tenant", "host")
	apiKey := newCasesTestKey(t, srv, "msp-tenant")

	rec := postPin(t, srv, apiKey, c.ID, map[string]interface{}{
		"kind":             "subject-time-range",
		"subject":          "host:msp-server",
		"time_range_start": time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
		"time_range_end":   time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
	})

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"subject outside the case's tenant subtree must be rejected with 404: %s", rec.Body.String())
	requireNoPins(t, cs, c.ID)
}

// TestHandleAddPin_EntityAccessFailureReturns500 exercises the access-check error
// branch of each entity-referencing kind against a real closed SQLite provider,
// so the error comes from the driver rather than being synthesized. A failed
// check must never be reported as a 404 (which would read as "no such entity")
// and must not echo the provider error or the eid.
func TestHandleAddPin_EntityAccessFailureReturns500(t *testing.T) {
	start := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC).Format(time.RFC3339)
	end := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)

	for name, body := range map[string]map[string]interface{}{
		"eid": {"kind": "eid", "eid": "host:server-alpha"},
		"edge-identity": {
			"kind": "edge-identity", "edge_type": "runs-on",
			"from_eid": "host:server-alpha", "to_eid": "host:server-beta",
		},
		"subject-time-range": {
			"kind": "subject-time-range", "subject": "host:server-alpha",
			"time_range_start": start, "time_range_end": end,
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := setupCasesTestServer(t)
			cs := srv.CasesStore()
			c := seedCase(t, cs, "tenant-alpha")
			closed := newTestEntityGraphProvider(t)
			require.NoError(t, closed.Close(), "closing provider to induce a real GetEntity failure")
			srv.SetEntityGraphProvider(closed)
			apiKey := newCasesTestKey(t, srv, "tenant-alpha")

			rec := postPin(t, srv, apiKey, c.ID, body)

			require.Equal(t, http.StatusInternalServerError, rec.Code,
				"a provider failure in the tenant access check must surface as 500: %s", rec.Body.String())
			assert.NotContains(t, rec.Body.String(), "sql:",
				"the provider error must not be echoed to the caller")
			assert.NotContains(t, rec.Body.String(), "host:server-alpha",
				"no eid may be disclosed when the access check could not be completed")
			requireNoPins(t, cs, c.ID)
		})
	}
}

// eidRoutedEGProvider serves GetEntity for one named eid from a second entity
// graph provider and every other read from the first. Both halves are real
// *sqlite.SQLiteEntityGraphProvider values; pairing a live provider with a closed
// one is how the edge-identity from_eid check can succeed while the to_eid check
// fails, with the error produced by the real SQLite driver ("sql: database is
// closed") rather than synthesized.
type eidRoutedEGProvider struct {
	egReadProvider                // live provider serves every other eid
	routedEID      string         // the eid served by routedSrc
	routedSrc      egReadProvider // provider that serves routedEID
}

func (p eidRoutedEGProvider) GetEntity(ctx context.Context, eid eginterfaces.EIDRef, opts eginterfaces.GetEntityOpts) (*egtypes.EntityView, error) {
	if eid.String() == p.routedEID {
		return p.routedSrc.GetEntity(ctx, eid, opts)
	}
	return p.egReadProvider.GetEntity(ctx, eid, opts)
}

// TestHandleAddPin_EdgeIdentityToEIDAccessFailureReturns500 reaches the second
// (to_eid) access-check error branch independently: from_eid resolves against a
// live provider, to_eid against a closed one.
func TestHandleAddPin_EdgeIdentityToEIDAccessFailureReturns500(t *testing.T) {
	live := newTestEntityGraphProvider(t)
	closed := newTestEntityGraphProvider(t)
	require.NoError(t, closed.Close(), "closing provider to induce a real GetEntity failure")

	srv := setupCasesTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	reportEntity(t, live, "host:server-from", "tenant-alpha", "host")
	srv.SetEntityGraphProvider(eidRoutedEGProvider{
		egReadProvider: live,
		routedEID:      "host:server-to",
		routedSrc:      closed,
	})
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	rec := postPin(t, srv, apiKey, c.ID, map[string]interface{}{
		"kind":      "edge-identity",
		"edge_type": "runs-on",
		"from_eid":  "host:server-from",
		"to_eid":    "host:server-to",
	})

	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"a provider failure in the to_eid access check must surface as 500: %s", rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "sql:",
		"the provider error must not be echoed to the caller")
	requireNoPins(t, cs, c.ID)
}

// TestHandleAddPin_PerKindRequiredFieldsReturn400 covers the remaining
// per-kind required-field rejections so every buildPinRef validation branch is
// exercised.
func TestHandleAddPin_PerKindRequiredFieldsReturn400(t *testing.T) {
	srv, _ := setupCasesWithEGTestServer(t)
	cs := srv.CasesStore()
	c := seedCase(t, cs, "tenant-alpha")
	apiKey := newCasesTestKey(t, srv, "tenant-alpha")

	for name, tc := range map[string]struct {
		body    map[string]interface{}
		message string
	}{
		"eid missing": {
			body:    map[string]interface{}{"kind": "eid"},
			message: "eid is required",
		},
		"eid unparseable": {
			body:    map[string]interface{}{"kind": "eid", "eid": "not-an-eid"},
			message: "invalid eid",
		},
		"observation_version missing": {
			body:    map[string]interface{}{"kind": "observation-version"},
			message: "observation_version is required",
		},
		"drift_record missing": {
			body:    map[string]interface{}{"kind": "drift-record"},
			message: "drift_record is required",
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := postPin(t, srv, apiKey, c.ID, tc.body)
			require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())
			assert.Contains(t, rec.Body.String(), tc.message)
			requireNoPins(t, cs, c.ID)
		})
	}
}
