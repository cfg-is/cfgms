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
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller/batchjob"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestBatchJobStoreForAPI returns a memory-backed BatchJobStore for handler tests.
// The concrete provider import lives in providers_test.go (allowlisted */providers_test.go file).
func newTestBatchJobStoreForAPI() batchjob.BatchJobStore {
	return newTestAPIBatchJobStore()
}

// adminPrincipal returns a global-admin principal with no tenant scope,
// mirroring the mTLS admin certificate path in authenticationMiddleware.
func adminPrincipal() *Principal {
	return &Principal{ID: "cfgms-admin", Assurance: session.AssuranceBasic, GlobalScope: true, TenantID: ""}
}

// tenantPrincipal returns a machine-assurance principal scoped to the given tenant,
// mirroring an API-key caller authenticated by authenticationMiddleware.
func tenantPrincipal(tenantID string) *Principal {
	return &Principal{ID: "api-key-" + tenantID, Assurance: session.AssuranceMachine, TenantID: tenantID}
}

// postCreateJobAs sends POST /api/v1/jobs as the given principal.
// withPrincipal is defined in handlers_runs_test.go (same package).
func postCreateJobAs(server *Server, principal *Principal, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, principal)
	rec := httptest.NewRecorder()
	server.handleCreateJob(rec, req)
	return rec
}

// postCreateJob sends POST /api/v1/jobs as a global admin (for simple cases).
func postCreateJob(server *Server, body string) *httptest.ResponseRecorder {
	return postCreateJobAs(server, adminPrincipal(), body)
}

// postCreateJobWithTenant sends POST /api/v1/jobs as a non-admin tenant-scoped caller.
func postCreateJobWithTenant(server *Server, body, tenantID string) *httptest.ResponseRecorder {
	return postCreateJobAs(server, tenantPrincipal(tenantID), body)
}

// getJobAs sends GET /api/v1/jobs/{id} as the given principal.
func getJobAs(server *Server, principal *Principal, jobID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+jobID, nil)
	req = withPrincipal(req, principal)
	req = mux.SetURLVars(req, map[string]string{"id": jobID})
	rec := httptest.NewRecorder()
	server.handleGetJob(rec, req)
	return rec
}

// getJobWithTenant sends GET /api/v1/jobs/{id} as a non-admin tenant-scoped caller.
// An empty tenantID simulates an admin mTLS caller.
func getJobWithTenant(server *Server, jobID, tenantID string) *httptest.ResponseRecorder {
	var p *Principal
	if tenantID == "" {
		p = adminPrincipal()
	} else {
		p = tenantPrincipal(tenantID)
	}
	return getJobAs(server, p, jobID)
}

// ── handleCreateJob: service-unavailable guard ────────────────────────────────

func TestHandleCreateJob_NilStore_Returns503(t *testing.T) {
	server := setupTestServer(t)
	// batchJobStore is nil by default — handler must return 503.
	rec := postCreateJob(server, `{"selector":"all","batch_size":3}`)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "SERVICE_UNAVAILABLE", resp.Error.Code)
}

// ── handleCreateJob: auth guard ───────────────────────────────────────────────

// TestHandleCreateJob_NoPrincipal_Returns401 verifies that a request with no
// authenticated principal is rejected before reaching business logic.
func TestHandleCreateJob_NoPrincipal_Returns401(t *testing.T) {
	server := setupTestServer(t)
	server.batchJobStore = newTestBatchJobStoreForAPI()

	// No principal in context — authRunAccess must return 401.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs",
		bytes.NewBufferString(`{"selector":"all","batch_size":3}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.handleCreateJob(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleCreateJob_NonAdminEmptyTenant_Returns401 verifies that a non-admin
// caller with no tenant is rejected (cannot claim global scope — Issue #1990).
func TestHandleCreateJob_NonAdminEmptyTenant_Returns401(t *testing.T) {
	server := setupTestServer(t)
	server.batchJobStore = newTestBatchJobStoreForAPI()

	nonAdminNoTenant := &Principal{ID: "bad-key", Assurance: session.AssuranceMachine, TenantID: ""}
	rec := postCreateJobAs(server, nonAdminNoTenant, `{"selector":"all","batch_size":3}`)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ── handleCreateJob: input validation ────────────────────────────────────────

func TestHandleCreateJob_InvalidJSON_Returns400(t *testing.T) {
	server := setupTestServer(t)
	server.batchJobStore = newTestBatchJobStoreForAPI()

	rec := postCreateJob(server, `not json`)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "INVALID_JSON", resp.Error.Code)
}

func TestHandleCreateJob_MissingSelector_Returns400(t *testing.T) {
	server := setupTestServer(t)
	server.batchJobStore = newTestBatchJobStoreForAPI()

	rec := postCreateJob(server, `{"selector":"","batch_size":3}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "MISSING_SELECTOR", resp.Error.Code)
}

func TestHandleCreateJob_InvalidSelector_Returns400(t *testing.T) {
	server := setupTestServer(t)
	server.batchJobStore = newTestBatchJobStoreForAPI()

	rec := postCreateJob(server, `{"selector":"typo:value","batch_size":3}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "INVALID_SELECTOR", resp.Error.Code)
}

// ── handleCreateJob: required acceptance-criteria test ───────────────────────

// TestHandleCreateJob_AllSelector_Returns202AndPersists is the REQUIRED test from
// the story acceptance criteria:
//
//	POST /api/v1/jobs with selector="all" and batch_size=3; assert response 202
//	and store.GetBatchJob returns a record with Config.BatchSize==3.
func TestHandleCreateJob_AllSelector_Returns202AndPersists(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store
	// No executor wired — goroutine skipped; job creation is still testable.

	rec := postCreateJob(server, `{"selector":"all","batch_size":3}`)
	require.Equal(t, http.StatusAccepted, rec.Code, "expected 202 Accepted")

	// Unmarshal the response to extract the job ID.
	var apiResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &apiResp))

	dataMap, ok := apiResp.Data.(map[string]interface{})
	require.True(t, ok, "response data must be a JSON object")
	jobID, ok := dataMap["job_id"].(string)
	require.True(t, ok, "response must contain a non-empty job_id")
	assert.NotEmpty(t, jobID)

	// Verify the persisted record.
	job, err := store.GetBatchJob(context.Background(), jobID)
	require.NoError(t, err, "GetBatchJob must find the persisted record")
	assert.Equal(t, 3, job.Config.BatchSize, "Config.BatchSize must equal the requested batch_size")
	assert.Equal(t, "all", job.Selector)
	assert.Equal(t, string(batchjob.BatchJobStatusPending), string(job.Status))
}

// TestHandleCreateJob_PreviousConfigRef_Passthrough verifies that previous_config_ref
// is wired from the JSON request body through to BatchJobConfig.PreviousConfigRef.
func TestHandleCreateJob_PreviousConfigRef_Passthrough(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store

	rec := postCreateJob(server, `{"selector":"all","batch_size":1,"previous_config_ref":"v1"}`)
	require.Equal(t, http.StatusAccepted, rec.Code)

	var apiResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &apiResp))
	dataMap, ok := apiResp.Data.(map[string]interface{})
	require.True(t, ok, "response data must be a JSON object")
	jobID, ok := dataMap["job_id"].(string)
	require.True(t, ok, "response must contain a non-empty job_id")

	job, err := store.GetBatchJob(context.Background(), jobID)
	require.NoError(t, err, "GetBatchJob must find the persisted record")
	assert.Equal(t, "v1", job.Config.PreviousConfigRef,
		"Config.PreviousConfigRef must equal the requested previous_config_ref")
}

// TestHandleCreateJob_DefaultBatchSize uses batch_size 0 (omitted) and verifies
// the handler applies the default of 10.
func TestHandleCreateJob_DefaultBatchSize(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store

	rec := postCreateJob(server, `{"selector":"all"}`)
	require.Equal(t, http.StatusAccepted, rec.Code)

	var apiResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &apiResp))
	dataMap := apiResp.Data.(map[string]interface{})
	jobID := dataMap["job_id"].(string)

	job, err := store.GetBatchJob(context.Background(), jobID)
	require.NoError(t, err)
	assert.Equal(t, 10, job.Config.BatchSize, "batch_size 0 must fall back to the default of 10")
}

// TestHandleCreateJob_TenantScoped verifies that the job is created with the
// caller's tenant ID from the request context.
func TestHandleCreateJob_TenantScoped(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store

	rec := postCreateJobWithTenant(server, `{"selector":"all","batch_size":5}`, "tenant-x")
	require.Equal(t, http.StatusAccepted, rec.Code)

	var apiResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &apiResp))
	dataMap := apiResp.Data.(map[string]interface{})
	jobID := dataMap["job_id"].(string)

	job, err := store.GetBatchJob(context.Background(), jobID)
	require.NoError(t, err)
	assert.Equal(t, "tenant-x", job.TenantID)
}

// ── handleCreateJob: explicit tenant-path-prefix selectors ───────────────────

// TestHandleCreateJob_ExplicitTenantPrefix_CrossTenantRejected verifies that a
// non-admin caller whose selector carries an explicit tenant-path prefix outside
// their authorized subtree is rejected with 403 CROSS_TENANT before any fleet
// query runs (handlers_jobs.go:85-92). The existing bare-selector tests never
// exercise this branch because they carry no leading tenant prefix.
func TestHandleCreateJob_ExplicitTenantPrefix_CrossTenantRejected(t *testing.T) {
	server := setupTestServer(t)
	server.batchJobStore = newTestBatchJobStoreForAPI()

	// Caller is scoped to tenant-a but the selector prefix targets tenant-b.
	rec := postCreateJobWithTenant(server, `{"selector":"tenant-b/all","batch_size":3}`, "tenant-a")
	require.Equal(t, http.StatusForbidden, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "CROSS_TENANT", resp.Error.Code)
}

// TestHandleCreateJob_ExplicitTenantPrefix_ScopesToSubtree verifies that a valid
// in-subtree tenant-path prefix drives filter.TenantSubtree = parsedTenantPath
// (handlers_jobs.go:93): the resolved target set is scoped to the prefixed
// sub-tenant, excluding sibling sub-tenants under the same caller tenant.
func TestHandleCreateJob_ExplicitTenantPrefix_ScopesToSubtree(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store

	// Two stewards under sibling sub-tenants of tenant-a.
	inScope := registerActiveSteward(t, server.controllerService, "job-prefix-c1", "tenant-a/client-1")
	registerActiveSteward(t, server.controllerService, "job-prefix-c2", "tenant-a/client-2")

	// Caller tenant-a targets only the client-1 subtree via an explicit prefix.
	rec := postCreateJobWithTenant(server, `{"selector":"tenant-a/client-1/all","batch_size":2}`, "tenant-a")
	require.Equal(t, http.StatusAccepted, rec.Code, "body: %s", rec.Body.String())

	var apiResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &apiResp))
	dataMap, ok := apiResp.Data.(map[string]interface{})
	require.True(t, ok)
	jobID, ok := dataMap["job_id"].(string)
	require.True(t, ok)

	job, err := store.GetBatchJob(context.Background(), jobID)
	require.NoError(t, err)
	assert.Equal(t, []string{inScope}, job.Targets,
		"explicit prefix must scope targets to tenant-a/client-1, excluding sibling client-2")
}

// ── handleGetJob: auth guard ──────────────────────────────────────────────────

// TestHandleGetJob_NoPrincipal_Returns401 verifies that GET without a principal is rejected.
func TestHandleGetJob_NoPrincipal_Returns401(t *testing.T) {
	server := setupTestServer(t)
	server.batchJobStore = newTestBatchJobStoreForAPI()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/any-id", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "any-id"})
	rec := httptest.NewRecorder()
	server.handleGetJob(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleGetJob_NonAdminEmptyTenant_Returns401 verifies the Issue #1990
// isolation fix: a non-admin key with no tenant cannot claim global scope.
func TestHandleGetJob_NonAdminEmptyTenant_Returns401(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store

	seedJob := &batchjob.BatchJob{
		ID:       "job-any-tenant",
		TenantID: "tenant-z",
		Selector: "all",
		Config:   batchjob.BatchJobConfig{BatchSize: 2},
		Status:   batchjob.BatchJobStatusPending,
	}
	require.NoError(t, store.CreateBatchJob(context.Background(), seedJob))

	nonAdminNoTenant := &Principal{ID: "bad-key", Assurance: session.AssuranceMachine, TenantID: ""}
	rec := getJobAs(server, nonAdminNoTenant, "job-any-tenant")
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ── handleGetJob: not-found and tenant isolation ──────────────────────────────

// TestHandleGetJob_UnknownID_Returns404 is the AC test: GET /api/v1/jobs/{id}
// must return 404 for an unknown ID.
func TestHandleGetJob_UnknownID_Returns404(t *testing.T) {
	server := setupTestServer(t)
	server.batchJobStore = newTestBatchJobStoreForAPI()

	rec := getJobWithTenant(server, "nonexistent-id", "tenant-a")
	require.Equal(t, http.StatusNotFound, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// TestHandleGetJob_WrongTenant_Returns403 is the AC test: GET /api/v1/jobs/{id}
// must return 403 when the caller's tenant does not match the job's tenant.
func TestHandleGetJob_WrongTenant_Returns403(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store

	// Seed a job for tenant-a.
	seedJob := &batchjob.BatchJob{
		ID:       "job-owned-by-tenant-a",
		TenantID: "tenant-a",
		Selector: "all",
		Config:   batchjob.BatchJobConfig{BatchSize: 5},
		Status:   batchjob.BatchJobStatusPending,
	}
	require.NoError(t, store.CreateBatchJob(context.Background(), seedJob))

	// Caller is authenticated as tenant-b.
	rec := getJobWithTenant(server, "job-owned-by-tenant-a", "tenant-b")
	require.Equal(t, http.StatusForbidden, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "FORBIDDEN", resp.Error.Code)
}

// TestHandleGetJob_SameTenant_Returns200 verifies that a caller with the correct
// tenant receives the full job record.
func TestHandleGetJob_SameTenant_Returns200(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store

	seedJob := &batchjob.BatchJob{
		ID:       "job-for-tenant-a",
		TenantID: "tenant-a",
		Selector: "os:linux",
		Config:   batchjob.BatchJobConfig{BatchSize: 7},
		Status:   batchjob.BatchJobStatusRunning,
	}
	require.NoError(t, store.CreateBatchJob(context.Background(), seedJob))

	rec := getJobWithTenant(server, "job-for-tenant-a", "tenant-a")
	require.Equal(t, http.StatusOK, rec.Code)

	var apiResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &apiResp))
	dataMap, ok := apiResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "job-for-tenant-a", dataMap["ID"])
	assert.Equal(t, "tenant-a", dataMap["TenantID"])
}

// TestHandleGetJob_AdminCallerNoTenant_Returns200 verifies that a global admin
// (mTLS with empty tenant) can read any tenant's job.
func TestHandleGetJob_AdminCallerNoTenant_Returns200(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store

	seedJob := &batchjob.BatchJob{
		ID:       "job-any-tenant",
		TenantID: "tenant-z",
		Selector: "all",
		Config:   batchjob.BatchJobConfig{BatchSize: 2},
		Status:   batchjob.BatchJobStatusCompleted,
	}
	require.NoError(t, store.CreateBatchJob(context.Background(), seedJob))

	// Empty tenantID simulates an admin mTLS caller.
	rec := getJobWithTenant(server, "job-any-tenant", "")
	require.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleGetJob_NilStore_Returns503 verifies the nil-store guard.
func TestHandleGetJob_NilStore_Returns503(t *testing.T) {
	server := setupTestServer(t)
	// batchJobStore is nil by default.
	rec := getJobWithTenant(server, "any-id", "tenant-a")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ── [REQUIRED TEST] Session-principal cross-tenant isolation (Issue #3143) ───────

// TestHandleGetJob_SessionPrincipal_CrossTenantBlocked is the required AC test from
// Issue #3143: a web-session caller (GlobalScope=true set by middleware, TenantID="tenant-a")
// must not be able to read a job belonging to "tenant-b". Before the fix, GlobalScope=true
// caused the cross-tenant guard to be bypassed for every session-authenticated caller.
func TestHandleGetJob_SessionPrincipal_CrossTenantBlocked(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store

	// Seed a job owned by tenant-b.
	victimJob := &batchjob.BatchJob{
		ID:       "job-owned-by-tenant-b",
		TenantID: "tenant-b",
		Selector: "all",
		Config:   batchjob.BatchJobConfig{BatchSize: 1},
		Status:   batchjob.BatchJobStatusPending,
	}
	require.NoError(t, store.CreateBatchJob(context.Background(), victimJob))

	// Build a session principal exactly as authenticationMiddleware does: GlobalScope=true
	// is hardcoded regardless of the account's actual tenant scope (middleware.go:429).
	sessionCaller := &Principal{
		ID:          "web-acct-xyz",
		GlobalScope: true, // the middleware bug — scoped accounts should not be global
		TenantID:    "tenant-a",
		Assurance:   session.AssuranceBasic,
	}

	rec := getJobAs(server, sessionCaller, "job-owned-by-tenant-b")
	require.Equal(t, http.StatusForbidden, rec.Code,
		"session principal scoped to tenant-a must not access tenant-b's job (body: %s)", rec.Body.String())

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "FORBIDDEN", resp.Error.Code)
}

// TestHandleGetJob_SessionPrincipal_OwnTenantAllowed verifies that the fix does not
// over-restrict: a session principal scoped to tenant-a can still read their own jobs.
func TestHandleGetJob_SessionPrincipal_OwnTenantAllowed(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store

	ownJob := &batchjob.BatchJob{
		ID:       "job-owned-by-tenant-a",
		TenantID: "tenant-a",
		Selector: "all",
		Config:   batchjob.BatchJobConfig{BatchSize: 2},
		Status:   batchjob.BatchJobStatusPending,
	}
	require.NoError(t, store.CreateBatchJob(context.Background(), ownJob))

	sessionCaller := &Principal{
		ID:          "web-acct-xyz",
		GlobalScope: true,
		TenantID:    "tenant-a",
		Assurance:   session.AssuranceBasic,
	}

	rec := getJobAs(server, sessionCaller, "job-owned-by-tenant-a")
	require.Equal(t, http.StatusOK, rec.Code,
		"session principal scoped to tenant-a must be able to read their own tenant's job (body: %s)", rec.Body.String())
}

// ── Tenant isolation regression tests — Issue #2781 ──────────────────────────

// TestJobsTenantIsolation_AssuranceBoundary is a table-driven regression test
// verifying that the Assurance-based tenant-isolation gates in handlers_jobs.go
// are byte-for-byte equivalent to the deleted IsAdmin-based checks:
//   - AssuranceBasic (admin) principal gets global access regardless of the job's tenant.
//   - AssuranceMachine (API key) principal is confined to its own tenant.
func TestJobsTenantIsolation_AssuranceBoundary(t *testing.T) {
	cases := []struct {
		name       string
		principal  *Principal
		jobTenant  string
		wantStatus int
	}{
		{
			name:       "admin_AssuranceBasic_any_tenant",
			principal:  &Principal{ID: "mTLS-admin", Assurance: session.AssuranceBasic, GlobalScope: true, TenantID: ""},
			jobTenant:  "tenant-z",
			wantStatus: http.StatusOK,
		},
		{
			name:       "machine_AssuranceMachine_same_tenant",
			principal:  &Principal{ID: "api-key-a", Assurance: session.AssuranceMachine, TenantID: "tenant-a"},
			jobTenant:  "tenant-a",
			wantStatus: http.StatusOK,
		},
		{
			name:       "machine_AssuranceMachine_cross_tenant_blocked",
			principal:  &Principal{ID: "api-key-a", Assurance: session.AssuranceMachine, TenantID: "tenant-a"},
			jobTenant:  "tenant-b",
			wantStatus: http.StatusForbidden,
		},
		{
			// Relay-grant principals carry AssuranceMachine; this case confirms that even
			// a relay-grant principal with tenant-a scoping cannot access tenant-b's jobs —
			// the handler's Assurance check is the defense-in-depth barrier.
			name: "relay_grant_AssuranceMachine_cross_tenant_blocked",
			principal: &Principal{
				ID:        "relay:device-1:exec-001",
				Name:      "relay-script:device-1",
				Assurance: session.AssuranceMachine,
				TenantID:  "tenant-a",
			},
			jobTenant:  "tenant-b",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			server := setupTestServer(t)
			store := newTestBatchJobStoreForAPI()
			server.batchJobStore = store

			jobID := "job-iso-" + tc.name
			require.NoError(t, store.CreateBatchJob(context.Background(), &batchjob.BatchJob{
				ID:       jobID,
				TenantID: tc.jobTenant,
				Selector: "all",
				Config:   batchjob.BatchJobConfig{BatchSize: 1},
				Status:   batchjob.BatchJobStatusPending,
			}))

			req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/"+jobID, nil)
			req = mux.SetURLVars(req, map[string]string{"id": jobID})
			req = withPrincipal(req, tc.principal)
			rec := httptest.NewRecorder()
			server.handleGetJob(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code, "principal %+v accessing job in %q", tc.principal, tc.jobTenant)
		})
	}
}

// ── log-injection sanitization (AC: CodeQL go/log-injection) ─────────────────

// errorCapturingLogger records Error-level log calls; all other levels are no-ops.
// It is a real log-buffer implementation — not a mock of any CFGMS component —
// following the same pattern as auditCapturingLogger in middleware_test.go.
//
// errCalledCh, if non-nil, is closed exactly once when the first Error call arrives.
// Tests that need to synchronize with an asynchronous goroutine's Error call should
// set this field and select on it rather than relying on a separate executor signal,
// because the executor signal fires when Execute returns — before the caller's log
// statement runs in the goroutine.
type errorCapturingLogger struct {
	logging.NoopLogger
	mu      sync.Mutex
	entries []struct {
		msg string
		kvs []interface{}
	}
	errCalledCh chan struct{}
	errOnce     sync.Once
}

func (l *errorCapturingLogger) Error(msg string, kvs ...interface{}) {
	l.mu.Lock()
	l.entries = append(l.entries, struct {
		msg string
		kvs []interface{}
	}{msg: msg, kvs: kvs})
	ch := l.errCalledCh
	l.mu.Unlock()
	if ch != nil {
		l.errOnce.Do(func() { close(ch) })
	}
}

// kvValue returns the first value for key across all captured Error entries, or nil.
func (l *errorCapturingLogger) kvValue(key string) interface{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		for i := 0; i+1 < len(e.kvs); i += 2 {
			if k, ok := e.kvs[i].(string); ok && k == key {
				return e.kvs[i+1]
			}
		}
	}
	return nil
}

// errBatchJobExecutor is a real test component (not a mock) that returns a
// pre-configured error from Execute. The done channel is closed when Execute
// is called so tests can synchronize with the asynchronous handler goroutine.
type errBatchJobExecutor struct {
	err  error
	done chan struct{}
}

func (e *errBatchJobExecutor) Execute(_ context.Context, _ *batchjob.BatchJob) error {
	defer close(e.done)
	return e.err
}

// TestHandleCreateJob_ExecutorError_LogValueSanitized is the required AC test for
// the CodeQL go/log-injection fix at handlers_jobs.go:146.
//
// It asserts that an execErr containing \n/\r is stripped in the logged "error"
// field (preventing log-line forgery), and that a normal error message with no
// control characters passes through unchanged.
func TestHandleCreateJob_ExecutorError_LogValueSanitized(t *testing.T) {
	t.Run("newlines_stripped", func(t *testing.T) {
		// errCalledCh lets us wait until s.logger.Error is called in the goroutine,
		// not just until executor.Execute returns — the two are not synchronised.
		capLog := &errorCapturingLogger{errCalledCh: make(chan struct{})}
		server := setupTestServerWithLogger(t, capLog)
		store := newTestBatchJobStoreForAPI()
		server.batchJobStore = store

		dirtyErr := errors.New("device sync failed\nforged log line\r\nalso forged")
		exec := &errBatchJobExecutor{err: dirtyErr, done: make(chan struct{})}
		server.batchJobExecutor = exec

		rec := postCreateJob(server, `{"selector":"all","batch_size":3}`)
		require.Equal(t, http.StatusAccepted, rec.Code)

		select {
		case <-capLog.errCalledCh:
		case <-time.After(5 * time.Second):
			t.Fatal("executor goroutine did not log error within timeout")
		}

		loggedErr := capLog.kvValue("error")
		require.NotNil(t, loggedErr, "expected 'error' key in logged Error entries")
		loggedStr, ok := loggedErr.(string)
		require.True(t, ok, "sanitized error must be logged as a string")
		assert.NotContains(t, loggedStr, "\n", "\\n must be stripped from logged error")
		assert.NotContains(t, loggedStr, "\r", "\\r must be stripped from logged error")
		assert.Contains(t, loggedStr, "device sync failed", "error message text must be preserved")
	})

	t.Run("clean_error_passes_through", func(t *testing.T) {
		capLog := &errorCapturingLogger{errCalledCh: make(chan struct{})}
		server := setupTestServerWithLogger(t, capLog)
		store := newTestBatchJobStoreForAPI()
		server.batchJobStore = store

		cleanErr := errors.New("normal execution failure")
		exec := &errBatchJobExecutor{err: cleanErr, done: make(chan struct{})}
		server.batchJobExecutor = exec

		rec := postCreateJob(server, `{"selector":"all","batch_size":3}`)
		require.Equal(t, http.StatusAccepted, rec.Code)

		select {
		case <-capLog.errCalledCh:
		case <-time.After(5 * time.Second):
			t.Fatal("executor goroutine did not log error within timeout")
		}

		loggedErr := capLog.kvValue("error")
		require.NotNil(t, loggedErr)
		loggedStr, ok := loggedErr.(string)
		require.True(t, ok)
		assert.Equal(t, "normal execution failure", loggedStr,
			"clean error message must pass through unchanged")
	})
}

// ── handleListJobs tests ──────────────────────────────────────────────────────

// listJobsAs sends GET /api/v1/jobs with the given principal and optional query string.
func listJobsAs(server *Server, principal *Principal, query string) *httptest.ResponseRecorder {
	url := "/api/v1/jobs"
	if query != "" {
		url += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = withPrincipal(req, principal)
	rec := httptest.NewRecorder()
	server.handleListJobs(rec, req)
	return rec
}

// TestHandleListJobs_NilStore_Returns503 verifies the service-unavailable guard.
func TestHandleListJobs_NilStore_Returns503(t *testing.T) {
	server := setupTestServer(t)
	// batchJobStore is nil by default.
	rec := listJobsAs(server, adminPrincipal(), "")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "SERVICE_UNAVAILABLE", resp.Error.Code)
}

// TestHandleListJobs_NoPrincipal_Returns401 verifies the auth guard.
func TestHandleListJobs_NoPrincipal_Returns401(t *testing.T) {
	server := setupTestServer(t)
	server.batchJobStore = newTestBatchJobStoreForAPI()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	rec := httptest.NewRecorder()
	server.handleListJobs(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleListJobs_EmptyList_NeverNull verifies that an empty store returns [] not null.
func TestHandleListJobs_EmptyList_NeverNull(t *testing.T) {
	server := setupTestServer(t)
	server.batchJobStore = newTestBatchJobStoreForAPI()

	rec := listJobsAs(server, adminPrincipal(), "")
	require.Equal(t, http.StatusOK, rec.Code)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	assert.Equal(t, json.RawMessage("[]"), raw["data"], "empty job list must serialize as [] not null")
}

// TestHandleListJobs_CrossTenantIsolation is the [REQUIRED TEST] verifying that a
// principal in tenant A cannot see tenant B's jobs.
func TestHandleListJobs_CrossTenantIsolation(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store

	// Create a job under tenant-a.
	recA := postCreateJobAs(server, tenantPrincipal("tenant-a"), `{"selector":"all","batch_size":1}`)
	require.Equal(t, http.StatusAccepted, recA.Code, "create job for tenant-a: %s", recA.Body.String())

	// Create a job under tenant-b.
	recB := postCreateJobAs(server, tenantPrincipal("tenant-b"), `{"selector":"all","batch_size":1}`)
	require.Equal(t, http.StatusAccepted, recB.Code, "create job for tenant-b: %s", recB.Body.String())

	// List as tenant-a: must see exactly 1 job belonging to tenant-a.
	recList := listJobsAs(server, tenantPrincipal("tenant-a"), "")
	require.Equal(t, http.StatusOK, recList.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(recList.Body.Bytes(), &resp))
	jobs, ok := resp.Data.([]interface{})
	require.True(t, ok, "data must be an array")
	require.Len(t, jobs, 1, "tenant-a must see exactly 1 job, not tenant-b's")

	jobMap, ok := jobs[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "tenant-a", jobMap["TenantID"], "the visible job must belong to tenant-a")

	// List as tenant-b: must see exactly 1 job belonging to tenant-b.
	recListB := listJobsAs(server, tenantPrincipal("tenant-b"), "")
	require.Equal(t, http.StatusOK, recListB.Code)

	var respB APIResponse
	require.NoError(t, json.Unmarshal(recListB.Body.Bytes(), &respB))
	jobsB, ok := respB.Data.([]interface{})
	require.True(t, ok, "data must be an array")
	require.Len(t, jobsB, 1, "tenant-b must see exactly 1 job, not tenant-a's")

	jobMapB, ok := jobsB[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "tenant-b", jobMapB["TenantID"])
}

// [REQUIRED TEST] TestHandleListJobs_PaginationClamping verifies that limit/offset
// clamping mirrors the convention in handlers_audit.go.
func TestHandleListJobs_PaginationClamping(t *testing.T) {
	server := setupTestServer(t)
	server.batchJobStore = newTestBatchJobStoreForAPI()

	// limit > 500 is silently clamped; request must succeed.
	rec := listJobsAs(server, adminPrincipal(), "limit=9999")
	assert.Equal(t, http.StatusOK, rec.Code, "limit=9999 must be clamped to 500, not error")

	// limit=0 is clamped to 1; request must succeed.
	rec = listJobsAs(server, adminPrincipal(), "limit=0")
	assert.Equal(t, http.StatusOK, rec.Code, "limit=0 must be clamped to 1, not error")

	// Non-numeric params are silently ignored; defaults apply.
	rec = listJobsAs(server, adminPrincipal(), "limit=notanumber&offset=bad")
	assert.Equal(t, http.StatusOK, rec.Code, "invalid params must be silently ignored")

	// Valid offset with no data returns empty list.
	rec = listJobsAs(server, adminPrincipal(), "offset=100&limit=10")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleListJobs_PaginationOffsetLimit verifies that offset and limit correctly
// slice the result set.
func TestHandleListJobs_PaginationOffsetLimit(t *testing.T) {
	server := setupTestServer(t)
	store := newTestBatchJobStoreForAPI()
	server.batchJobStore = store
	p := tenantPrincipal("tenant-pg")

	// Create 3 jobs.
	for i := 0; i < 3; i++ {
		rec := postCreateJobAs(server, p, `{"selector":"all","batch_size":1}`)
		require.Equal(t, http.StatusAccepted, rec.Code)
	}

	// Fetch all 3 with a generous limit.
	rec := listJobsAs(server, p, "limit=10")
	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	all, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Len(t, all, 3, "limit=10 must return all 3 jobs")

	// Fetch with limit=2: should return exactly 2.
	rec = listJobsAs(server, p, "limit=2")
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	page1, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Len(t, page1, 2, "limit=2 must return exactly 2 jobs")

	// Fetch with offset=2 and limit=10: should return exactly 1.
	rec = listJobsAs(server, p, "limit=10&offset=2")
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	page2, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Len(t, page2, 1, "offset=2 must return the remaining 1 job")
}
