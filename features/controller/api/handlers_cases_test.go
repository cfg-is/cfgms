// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		ID:       "seed-case-" + tenantID + "-" + uuid.NewString(),
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
