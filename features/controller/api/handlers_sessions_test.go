// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
)

// testClock is a controllable clock for handler tests that need to advance time
// without sleeping. Separate from the session_test.fakeClock (different package).
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// setupTestServerWithSession returns a test server wired with a default-config
// in-memory session manager.
func setupTestServerWithSession(t *testing.T) (*Server, session.Manager, *session.MemStore) {
	t.Helper()
	srv := setupTestServer(t)
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)
	srv.SetSessionManager(mgr)
	return srv, mgr, store
}

// captureAllLogger records every log call at every level into a buffer so tests
// can assert that sensitive values (e.g. raw session tokens) never appear in logs.
type captureAllLogger struct {
	logging.NoopLogger
	mu  sync.Mutex
	buf strings.Builder
}

func (l *captureAllLogger) record(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.WriteString(msg)
	for _, v := range kvs {
		fmt.Fprintf(&l.buf, " %v", v)
	}
	l.buf.WriteByte('\n')
}

func (l *captureAllLogger) captured() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *captureAllLogger) Debug(msg string, kvs ...interface{}) { l.record(msg, kvs...) }
func (l *captureAllLogger) Info(msg string, kvs ...interface{})  { l.record(msg, kvs...) }
func (l *captureAllLogger) Warn(msg string, kvs ...interface{})  { l.record(msg, kvs...) }
func (l *captureAllLogger) Error(msg string, kvs ...interface{}) { l.record(msg, kvs...) }

func (l *captureAllLogger) DebugCtx(_ context.Context, msg string, kvs ...interface{}) {
	l.record(msg, kvs...)
}
func (l *captureAllLogger) InfoCtx(_ context.Context, msg string, kvs ...interface{}) {
	l.record(msg, kvs...)
}
func (l *captureAllLogger) WarnCtx(_ context.Context, msg string, kvs ...interface{}) {
	l.record(msg, kvs...)
}
func (l *captureAllLogger) ErrorCtx(_ context.Context, msg string, kvs ...interface{}) {
	l.record(msg, kvs...)
}

// injectAdminPrincipal returns a copy of r with a Strong-assurance admin Principal set
// in context (mTLS admin cert — AssuranceStrong, Issue #2780).
func injectAdminPrincipal(r *http.Request, principalID string) *http.Request {
	p := &Principal{
		ID:        principalID,
		Name:      "mtls-admin:" + principalID,
		Assurance: session.AssuranceStrong,
	}
	return r.WithContext(context.WithValue(r.Context(), principalContextKey, p))
}

// injectNonAdminPrincipal returns a copy of r with a Machine-assurance API-key Principal.
func injectNonAdminPrincipal(r *http.Request) *http.Request {
	p := &Principal{
		ID:          "api-key-user",
		Name:        "apikey",
		Assurance:   session.AssuranceMachine,
		Permissions: []string{"steward:list"},
		TenantID:    "default",
	}
	return r.WithContext(context.WithValue(r.Context(), principalContextKey, p))
}

// injectSessionMuxVars sets gorilla/mux route variables directly on the request
// so handler unit tests bypass the router without losing URL variables.
func injectSessionMuxVars(r *http.Request, vars map[string]string) *http.Request {
	return mux.SetURLVars(r, vars)
}

// TestHandleSessionCreate_AdminReturns201 verifies that an admin principal can create
// a session and receives the expected response fields including a 43-char bearer token
// (32 random bytes, base64url no-padding, 256 bits of entropy).
func TestHandleSessionCreate_AdminReturns201(t *testing.T) {
	srv, _, _ := setupTestServerWithSession(t)

	body := `{"connection_name":"test-ctrl"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(body))
	req = injectAdminPrincipal(req, "alice")
	rec := httptest.NewRecorder()

	srv.handleSessionCreate(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}

	var resp sessionCreateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.SessionID == "" {
		t.Error("session_id must not be empty")
	}
	if len(resp.Token) != 43 {
		t.Errorf("token length = %d, want 43 (256-bit base64url no-padding)", len(resp.Token))
	}
	if resp.IssuedAt.IsZero() {
		t.Error("issued_at must be set")
	}
	if resp.IdleTTLSeconds != int64(15*time.Minute/time.Second) {
		t.Errorf("idle_ttl = %d, want %d (15 min)", resp.IdleTTLSeconds, int64(15*time.Minute/time.Second))
	}
	if resp.AbsoluteExpiry.IsZero() {
		t.Error("absolute_expiry must be set")
	}
}

// TestRouterSessionCreate_BasicAssuranceReturns401 is a REQUIRED TEST (F3, Issue #2780):
// a Basic-assurance (cfg-CLI Bearer session) principal calling POST /api/v1/sessions must
// receive 401 step-up, not a silently-minted new Bearer session — closing the
// self-perpetuating-compromise gap where a Basic-assurance session could previously mint
// fresh long-lived credentials.
//
// Uses a real Bearer session token (not context injection) so the request goes through the
// auth middleware and the assurance gate fires on the authenticated principal.
func TestRouterSessionCreate_BasicAssuranceReturns401(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)

	// Issue a real session token — the auth middleware will validate it and create a
	// Basic-assurance principal (session.AssuranceBasic), matching the cfg-CLI Bearer path.
	_, token, err := mgr.Issue(context.Background(), "web-user", "test-conn", "")
	require.NoError(t, err, "must be able to issue a session token for the test")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(`{"connection_name":"test"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Basic-assurance principal: status = %d, want 401 step-up; body: %s", rec.Code, rec.Body.String())
	}
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "CFGMS-StepUp") {
		t.Errorf("WWW-Authenticate = %q, want contains CFGMS-StepUp", wwwAuth)
	}

	var body struct {
		Error             string `json:"error"`
		RequiredAssurance string `json:"required_assurance"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error != "step_up_required" {
		t.Errorf("body.error = %q, want step_up_required", body.Error)
	}
	if body.RequiredAssurance == "" {
		t.Error("body.required_assurance must not be empty")
	}
}

// TestRouterSessionCreate_MachineAssuranceReturns403 verifies that an API-key principal
// (AssuranceMachine) holding session:create gets a plain 403 — never the step-up challenge
// that it cannot satisfy (F2 REQUIRED TEST, Issue #2780).
//
// Uses a real API key credential through the router so the auth middleware authenticates
// the request and the assurance gate sees a genuine Machine-assurance principal.
func TestRouterSessionCreate_MachineAssuranceReturns403(t *testing.T) {
	srv, _, _ := setupTestServerWithSession(t)
	apiKey := NewTestKey(t, srv, []string{"session:create"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(`{}`))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("Machine-assurance principal: status = %d, want 403; body: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Errorf("API-key principal must not receive WWW-Authenticate step-up challenge")
	}
}

// TestHandleSessionCreate_InvalidJSON verifies HTTP 400 when the request body is not valid JSON.
func TestHandleSessionCreate_InvalidJSON(t *testing.T) {
	srv, _, _ := setupTestServerWithSession(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(`not-json`))
	req = injectAdminPrincipal(req, "alice")
	rec := httptest.NewRecorder()

	srv.handleSessionCreate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for invalid JSON body", rec.Code)
	}
}

// TestHandleSessionCreate_RootScopedPrincipal_IssuesRootScopedSession verifies that
// handleSessionCreate mints a session via sessionManager.IssueRootScoped (not the
// ordinary Issue) when the authenticated principal carries RootScoped==true — a cfg-CLI
// session inherits its scope from the authenticating credential (ADR-025 Amendment 1
// A1.3, founder decision 2026-08-09, PR #3215), never from a request field. Before this
// change, session.Manager.IssueRootScoped had zero non-test callers.
func TestHandleSessionCreate_RootScopedPrincipal_IssuesRootScopedSession(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)

	body := `{"connection_name":"root-op-ctrl"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(body))
	p := &Principal{
		ID:         "root-operator-1",
		Name:       "mtls-admin:root-operator-1",
		Assurance:  session.AssuranceStrong,
		RootScoped: true,
	}
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, p))
	rec := httptest.NewRecorder()

	srv.handleSessionCreate(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var resp sessionCreateResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	got, err := mgr.Validate(context.Background(), resp.Token)
	require.NoError(t, err)
	assert.True(t, got.RootScoped, "session minted for a RootScoped principal must itself be RootScoped")
	assert.Empty(t, got.TenantID, "a root-scoped session stays unscoped, same as IssueRootScoped's own contract")

	// No-regression companion: an ordinary (non-root-scoped) principal still gets an
	// ordinary session via Issue, not IssueRootScoped.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(body))
	req2 = injectAdminPrincipal(req2, "ordinary-admin")
	rec2 := httptest.NewRecorder()
	srv.handleSessionCreate(rec2, req2)
	require.Equal(t, http.StatusCreated, rec2.Code, rec2.Body.String())

	var resp2 sessionCreateResponse
	require.NoError(t, json.NewDecoder(rec2.Body).Decode(&resp2))
	got2, err := mgr.Validate(context.Background(), resp2.Token)
	require.NoError(t, err)
	assert.False(t, got2.RootScoped, "an ordinary admin principal must not produce a RootScoped session")
}

// TestHandleSessionRevoke_ImmediateRevocation verifies DELETE /api/v1/sessions/{id}
// revokes immediately; a subsequent request with the revoked token returns 401.
func TestHandleSessionRevoke_ImmediateRevocation(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)

	sess, token, err := mgr.Issue(context.Background(), "bob", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Revoke via handler.
	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sess.ID, nil)
	revokeReq = injectAdminPrincipal(revokeReq, "bob")
	revokeReq = injectSessionMuxVars(revokeReq, map[string]string{"id": sess.ID})
	revokeRec := httptest.NewRecorder()
	srv.handleSessionRevoke(revokeRec, revokeReq)

	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200; body: %s", revokeRec.Code, revokeRec.Body.String())
	}

	// A subsequent request with the revoked token must receive 401 from the middleware.
	authReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	authReq.Header.Set("Authorization", "Bearer "+token)
	authRec := httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK) // should never be reached
	})).ServeHTTP(authRec, authReq)

	if authRec.Code != http.StatusUnauthorized {
		t.Errorf("revoked token: status = %d, want 401", authRec.Code)
	}
}

// TestHandleSessionRevoke_NotFound verifies HTTP 404 when the session ID does not exist.
func TestHandleSessionRevoke_NotFound(t *testing.T) {
	srv, _, _ := setupTestServerWithSession(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/no-such-id", nil)
	req = injectAdminPrincipal(req, "admin")
	req = injectSessionMuxVars(req, map[string]string{"id": "no-such-id"})
	rec := httptest.NewRecorder()

	srv.handleSessionRevoke(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// TestHandleSessionRevoke_AnyPrincipalCanReachHandler verifies that the in-handler
// IsAdmin check has been removed (Issue #2780): authorization is now enforced at
// the router level via requirePermission("session", "revoke"). A principal with the
// session:revoke permission that reaches the handler will be able to revoke sessions
// in their own tenant.
func TestHandleSessionRevoke_AnyPrincipalCanReachHandler(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)

	// Issue the session in the same tenant as the non-admin principal ("default").
	sess, _, err := mgr.Issue(context.Background(), "alice", "ctrl", "default")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Non-admin principal (TenantID="default") can reach the revoke handler and revoke
	// a session in their own tenant.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sess.ID, nil)
	req = injectNonAdminPrincipal(req)
	req = injectSessionMuxVars(req, map[string]string{"id": sess.ID})
	rec := httptest.NewRecorder()

	srv.handleSessionRevoke(rec, req)

	// Handler succeeds — revocation is a safety action, not blocked by IsAdmin.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (handler reached, in-tenant revoke succeeded)", rec.Code)
	}
}

// TestHandleSessionRevoke_CrossTenantDenied is a REQUIRED TEST (Issue #3429):
// a tenant-scoped principal in tenant-a attempts to revoke a live session belonging
// to tenant-b. The request must return the same not-found response as a genuinely
// absent session, and the tenant-b session must remain live and usable afterwards.
func TestHandleSessionRevoke_CrossTenantDenied(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)
	ctx := context.Background()

	// Issue a session in tenant-b.
	_, tokenB, err := mgr.Issue(ctx, "bob", "ctrl-b", "tenant-b")
	if err != nil {
		t.Fatalf("Issue tenant-b session: %v", err)
	}
	// Validate so we have the session ID.
	sessB, err := mgr.Validate(ctx, tokenB)
	if err != nil {
		t.Fatalf("Validate tenant-b session: %v", err)
	}

	// Tenant-a scoped admin attempts to revoke the tenant-b session.
	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sessB.ID, nil)
	revokeReq = injectAdminPrincipalWithTenant(revokeReq, "alice-admin", "tenant-a")
	revokeReq = injectSessionMuxVars(revokeReq, map[string]string{"id": sessB.ID})
	revokeRec := httptest.NewRecorder()
	srv.handleSessionRevoke(revokeRec, revokeReq)

	// Must return 404 — identical to a genuinely absent session, disclosing nothing.
	if revokeRec.Code != http.StatusNotFound {
		t.Errorf("cross-tenant revoke: status = %d, want 404", revokeRec.Code)
	}
	var body struct {
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(revokeRec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error == nil || body.Error.Code != "SESSION_NOT_FOUND" {
		t.Errorf("cross-tenant revoke: error code = %v, want SESSION_NOT_FOUND", body.Error)
	}

	// The tenant-b session must still be valid — the cross-tenant attempt must not
	// have revoked it.
	if _, err := mgr.Validate(ctx, tokenB); err != nil {
		t.Errorf("tenant-b session invalidated by cross-tenant revoke attempt: %v", err)
	}
}

// TestHandleSessionRevoke_InTenantSucceeds verifies that a scoped admin can revoke
// a session in their own tenant (positive path for tenant-scoped revoke).
func TestHandleSessionRevoke_InTenantSucceeds(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)
	ctx := context.Background()

	_, tokenA, err := mgr.Issue(ctx, "alice", "ctrl-a", "tenant-a")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	sessA, err := mgr.Validate(ctx, tokenA)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sessA.ID, nil)
	revokeReq = injectAdminPrincipalWithTenant(revokeReq, "alice-admin", "tenant-a")
	revokeReq = injectSessionMuxVars(revokeReq, map[string]string{"id": sessA.ID})
	revokeRec := httptest.NewRecorder()
	srv.handleSessionRevoke(revokeRec, revokeReq)

	if revokeRec.Code != http.StatusOK {
		t.Errorf("in-tenant revoke: status = %d, want 200; body: %s", revokeRec.Code, revokeRec.Body.String())
	}
	// Token must now be invalid.
	if _, err := mgr.Validate(ctx, tokenA); err == nil {
		t.Error("in-tenant revoke: token still validates after revoke")
	}
}

// TestHandleSessionRevoke_UnscopedCanRevokeCrossTenant verifies that an unscoped
// (global) admin retains cross-tenant reach — matching the rule handleSessionList applies.
func TestHandleSessionRevoke_UnscopedCanRevokeCrossTenant(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)
	ctx := context.Background()

	_, tokenB, err := mgr.Issue(ctx, "bob", "ctrl-b", "tenant-b")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	sessB, err := mgr.Validate(ctx, tokenB)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Unscoped admin (TenantID == "") — cross-tenant reach allowed.
	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sessB.ID, nil)
	revokeReq = injectAdminPrincipal(revokeReq, "global-admin")
	revokeReq = injectSessionMuxVars(revokeReq, map[string]string{"id": sessB.ID})
	revokeRec := httptest.NewRecorder()
	srv.handleSessionRevoke(revokeRec, revokeReq)

	if revokeRec.Code != http.StatusOK {
		t.Errorf("unscoped cross-tenant revoke: status = %d, want 200; body: %s", revokeRec.Code, revokeRec.Body.String())
	}
	if _, err := mgr.Validate(ctx, tokenB); err == nil {
		t.Error("unscoped cross-tenant revoke: token still validates after revoke")
	}
}

// TestSessionTokenAuthMiddleware_ValidToken verifies that a 43-char Bearer token
// resolves to an admin Principal and sets X-Session-Token on the response.
func TestSessionTokenAuthMiddleware_ValidToken(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)

	_, token, err := mgr.Issue(context.Background(), "carol", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	var capturedPrincipal *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if capturedPrincipal == nil {
		t.Fatal("principal not set in context")
	}
	if capturedPrincipal.Assurance < session.AssuranceBasic {
		t.Error("session-token principal must have Assurance >= AssuranceBasic")
	}
	if capturedPrincipal.ID != "carol" {
		t.Errorf("principal ID = %q, want %q", capturedPrincipal.ID, "carol")
	}
	if rec.Header().Get("X-Session-Token") == "" {
		t.Error("X-Session-Token response header must be set after session-token auth")
	}
}

// TestSessionTokenAuthMiddleware_ExpiredToken verifies 401 for expired session tokens.
// Uses an injectable clock to avoid time.Sleep.
func TestSessionTokenAuthMiddleware_ExpiredToken(t *testing.T) {
	srv := setupTestServer(t)
	cfg := session.Config{
		IdleTimeout:     100 * time.Millisecond,
		AbsoluteTimeout: 100 * time.Millisecond,
		GraceWindow:     10 * time.Millisecond,
	}
	clock := &testClock{t: time.Now()}
	store := session.NewMemStore(cfg, clock.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, clock.Now)
	srv.SetSessionManager(mgr)

	_, token, err := mgr.Issue(context.Background(), "dave", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Advance clock past both idle TTL and absolute timeout — no sleep needed.
	clock.advance(200 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expired token: status = %d, want 401", rec.Code)
	}
}

// TestSessionTokenAuthMiddleware_FallsThrough_NonSessionToken verifies that a
// non-43-char Bearer token falls through to the API-key auth path (not rejected
// as an invalid session token), because API keys are 44 chars (base64url+padding).
func TestSessionTokenAuthMiddleware_FallsThrough_NonSessionToken(t *testing.T) {
	srv, _, _ := setupTestServerWithSession(t)

	// 44-char key (standard base64url with padding, len == 44 ≠ 43).
	apiKey44 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 44 chars
	injectAPIKey(srv, &APIKey{
		ID:          "k1",
		Key:         apiKey44,
		Name:        "test-key",
		Permissions: []string{"steward:list"},
		TenantID:    "default",
	})

	var reached bool
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey44)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !reached {
		t.Errorf("44-char Bearer token should fall through to API-key path, got status %d", rec.Code)
	}
}

// TestSessionTokenNotInLogs verifies that raw token values never appear in any
// controller log line across a full connect/renew/revoke cycle.  It wires a
// buffer-backed logger (captureAllLogger) so every Info/Error/Warn/Debug call is
// recorded, then asserts that neither the original token nor the renewed token is
// present in the captured output.
func TestSessionTokenNotInLogs(t *testing.T) {
	// Wire a capture logger so we can inspect every log line produced during
	// the connect/renew/revoke cycle.
	clog := &captureAllLogger{}
	srv := setupTestServerWithLogger(t, clog)
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)
	srv.SetSessionManager(mgr)

	// Connect: issue session via the handler so "Session issued" is logged.
	createBody := `{"connection_name":"log-test-ctrl"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(createBody))
	createReq = injectAdminPrincipal(createReq, "log-user")
	createRec := httptest.NewRecorder()
	srv.handleSessionCreate(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("handleSessionCreate: status = %d, want 201; body: %s", createRec.Code, createRec.Body.String())
	}
	var createResp sessionCreateResponse
	if err := json.NewDecoder(createRec.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	token := createResp.Token
	sessID := createResp.SessionID

	// Renew: trigger the middleware path that calls Renew internally.
	// Per the middleware comment, the raw new token is never logged.
	renewHandler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	renewReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	renewReq.Header.Set("Authorization", "Bearer "+token)
	renewRec := httptest.NewRecorder()
	renewHandler.ServeHTTP(renewRec, renewReq)
	newToken := renewRec.Header().Get("X-Session-Token")

	// Revoke: revoke via handler so "Session revoked" is logged.
	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sessID, nil)
	revokeReq = injectAdminPrincipal(revokeReq, "log-user")
	revokeReq = injectSessionMuxVars(revokeReq, map[string]string{"id": sessID})
	revokeRec := httptest.NewRecorder()
	srv.handleSessionRevoke(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("handleSessionRevoke: status = %d, want 200", revokeRec.Code)
	}

	// Assert: inspect every captured log line for raw token values.
	logOutput := clog.captured()
	if strings.Contains(logOutput, token) {
		t.Errorf("log output contains raw session token — tokens must not be logged\nlog:\n%s", logOutput)
	}
	if newToken != "" && strings.Contains(logOutput, newToken) {
		t.Errorf("log output contains renewed token value — tokens must not be logged\nlog:\n%s", logOutput)
	}
}

// TestHandleSessionCreate_NoSessionManager returns 503 when no manager is wired.
func TestHandleSessionCreate_NoSessionManager(t *testing.T) {
	srv := setupTestServer(t) // no SetSessionManager call

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(`{}`))
	req = injectAdminPrincipal(req, "alice")
	rec := httptest.NewRecorder()

	srv.handleSessionCreate(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when sessionManager is nil", rec.Code)
	}
}

// injectAdminPrincipalWithTenant returns a request with a Strong-assurance admin Principal
// scoped to a specific tenant (mTLS admin cert — AssuranceStrong, Issue #2780).
func injectAdminPrincipalWithTenant(r *http.Request, principalID, tenantID string) *http.Request {
	p := &Principal{
		ID:        principalID,
		Name:      "mtls-admin:" + principalID,
		Assurance: session.AssuranceStrong,
		TenantID:  tenantID,
	}
	return r.WithContext(context.WithValue(r.Context(), principalContextKey, p))
}

// TestHandleSessionList_AnyPrincipalCanReachHandler verifies that the in-handler
// IsAdmin check has been removed (Issue #2780): authorization is now enforced at
// the router level via requirePermission("session", "list"). A principal with the
// session:list permission that reaches the handler will receive 503 (no session manager).
func TestHandleSessionList_AnyPrincipalCanReachHandler(t *testing.T) {
	srv := setupTestServer(t) // no session manager wired

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req = injectNonAdminPrincipal(req)
	rec := httptest.NewRecorder()

	srv.handleSessionList(rec, req)

	// Handler no longer checks IsAdmin — it returns 503 when sessionManager is nil.
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (handler reached, no session manager)", rec.Code)
	}
}

// TestHandleSessionList_TenantIsolation verifies that a tenant-scoped admin sees only
// sessions belonging to their tenant, while a global admin sees all tenants' sessions.
func TestHandleSessionList_TenantIsolation(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)
	ctx := context.Background()

	// Issue sessions in two different tenants and one without a tenant.
	_, _, err := mgr.Issue(ctx, "alice", "ctrl-a", "tenant-x")
	if err != nil {
		t.Fatalf("Issue tenant-x: %v", err)
	}
	_, _, err = mgr.Issue(ctx, "bob", "ctrl-b", "tenant-y")
	if err != nil {
		t.Fatalf("Issue tenant-y: %v", err)
	}
	_, _, err = mgr.Issue(ctx, "carol", "ctrl-c", "tenant-x")
	if err != nil {
		t.Fatalf("Issue tenant-x second: %v", err)
	}

	// Tenant-scoped admin for tenant-x: must see only tenant-x sessions (alice + carol).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req = injectAdminPrincipalWithTenant(req, "alice", "tenant-x")
	rec := httptest.NewRecorder()
	srv.handleSessionList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("tenant-x admin: status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var tenantResp struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&tenantResp); err != nil {
		t.Fatalf("decode tenant-x response: %v", err)
	}
	if len(tenantResp.Sessions) != 2 {
		t.Errorf("tenant-x admin: got %d sessions, want 2 (alice + carol)", len(tenantResp.Sessions))
	}

	// Global admin (TenantID == ""): must see all three sessions.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req2 = injectAdminPrincipal(req2, "global-admin") // no TenantID → global
	rec2 := httptest.NewRecorder()
	srv.handleSessionList(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("global admin: status = %d, want 200; body: %s", rec2.Code, rec2.Body.String())
	}
	var globalResp struct {
		Sessions []struct {
			SessionID string `json:"session_id"`
		} `json:"sessions"`
	}
	if err := json.NewDecoder(rec2.Body).Decode(&globalResp); err != nil {
		t.Fatalf("decode global response: %v", err)
	}
	if len(globalResp.Sessions) != 3 {
		t.Errorf("global admin: got %d sessions, want 3 (all tenants)", len(globalResp.Sessions))
	}
}

// TestHandleSessionList_NoTokenDisclosure verifies that the raw bearer token, its SHA-256
// hash, and any other secret-equivalent value are absent from the GET /api/v1/sessions
// response body. The assertion is against raw response bytes, not the response struct.
func TestHandleSessionList_NoTokenDisclosure(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)
	ctx := context.Background()

	_, token, err := mgr.Issue(ctx, "dave", "ctrl-d", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tokenHash := session.HashToken(token)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req = injectAdminPrincipal(req, "dave")
	rec := httptest.NewRecorder()
	srv.handleSessionList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	if strings.Contains(body, token) {
		t.Errorf("response body contains raw bearer token — must not be disclosed\nbody:\n%s", body)
	}
	if strings.Contains(body, tokenHash) {
		t.Errorf("response body contains token hash — must not be disclosed\nbody:\n%s", body)
	}
}

// TestHandleSessionList_IdleExpiredExcluded verifies that a session that has gone
// idle-expired (per Validate's IdleTimeout rule) is excluded from the listing, even
// if the store record has not yet been physically reaped.
func TestHandleSessionList_IdleExpiredExcluded(t *testing.T) {
	srv := setupTestServer(t)
	cfg := session.Config{
		IdleTimeout:     100 * time.Millisecond,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     10 * time.Millisecond,
	}
	clock := &testClock{t: time.Now()}
	store := session.NewMemStore(cfg, clock.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, clock.Now)
	srv.SetSessionManager(mgr)

	ctx := context.Background()
	// Issue a session; it will become idle-expired when the clock advances past IdleTimeout.
	_, _, err := mgr.Issue(ctx, "eve", "ctrl-e", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Advance past idle TTL; the MemStore sweep has not yet reaped the record.
	clock.advance(200 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req = injectAdminPrincipal(req, "eve")
	rec := httptest.NewRecorder()
	srv.handleSessionList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Sessions []interface{} `json:"sessions"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Sessions) != 0 {
		t.Errorf("idle-expired session still in listing: got %d sessions, want 0", len(resp.Sessions))
	}
}

// TestHandleSessionList_ResponseFields verifies the response contains exactly the
// allow-listed fields and no extras.
func TestHandleSessionList_ResponseFields(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)
	ctx := context.Background()

	_, _, err := mgr.Issue(ctx, "frank", "ctrl-f", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req = injectAdminPrincipal(req, "frank")
	rec := httptest.NewRecorder()
	srv.handleSessionList(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	// Decode as a generic map to inspect raw field names.
	var raw struct {
		Sessions []map[string]interface{} `json:"sessions"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw.Sessions) != 1 {
		t.Fatalf("want 1 session, got %d", len(raw.Sessions))
	}
	item := raw.Sessions[0]
	allowed := map[string]bool{
		"session_id":      true,
		"principal_id":    true,
		"connection_name": true,
		"issued_at":       true,
		"last_activity":   true,
		"absolute_expiry": true,
	}
	for k := range item {
		if !allowed[k] {
			t.Errorf("unexpected field %q in session list item", k)
		}
	}
	for k := range allowed {
		if _, ok := item[k]; !ok {
			t.Errorf("required field %q missing from session list item", k)
		}
	}
}

// TestHandleSessionList_NoSessionManager returns 503 when no manager is wired.
func TestHandleSessionList_NoSessionManager(t *testing.T) {
	srv := setupTestServer(t) // no SetSessionManager call

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	req = injectAdminPrincipal(req, "alice")
	rec := httptest.NewRecorder()

	srv.handleSessionList(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when sessionManager is nil", rec.Code)
	}
}

// setupTwoChannelServer wires a server with separate CLI and web session managers
// sharing a MemStore. Returns the server, CLI manager, and web manager.
func setupTwoChannelServer(t *testing.T) (*Server, session.Manager, session.Manager) {
	t.Helper()
	srv := setupTestServer(t)
	cliCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "web",
	}
	store := session.NewMemStore(cliCfg, time.Now)
	t.Cleanup(store.Close)
	cliMgr := session.NewManager(cliCfg, store, time.Now)
	webMgr := session.NewManager(webCfg, store, time.Now)
	srv.SetSessionManager(cliMgr)
	srv.SetWebSessionManager(webMgr)
	return srv, cliMgr, webMgr
}

// TestCrossChannelValidation_InMemoryCachePath verifies that a CLI session token
// is rejected when presented via the cookie path (web manager), and vice versa —
// covering the in-memory-cache path where the session was just issued (Issue #3310).
//
// This is a REQUIRED TEST per the story acceptance criteria.
func TestCrossChannelValidation_InMemoryCachePath(t *testing.T) {
	srv, cliMgr, webMgr := setupTwoChannelServer(t)
	ctx := context.Background()

	// Issue a CLI session — it is in the CLI manager's memory but not the web manager's.
	_, cliToken, err := cliMgr.Issue(ctx, "alice", "cli-ctrl", "")
	require.NoError(t, err)

	// Issue a web session.
	_, webToken, err := webMgr.Issue(ctx, "alice", "web-ctrl", "")
	require.NoError(t, err)

	// CLI token as Bearer → uses CLI manager → validates OK (same channel, in-memory).
	cliReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	cliReq.Header.Set("Authorization", "Bearer "+cliToken)
	cliRec := httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(cliRec, cliReq)
	assert.Equal(t, http.StatusOK, cliRec.Code, "CLI token on Bearer path must succeed")

	// CLI token as cookie → uses web manager → rejected (cross-channel).
	crossReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	crossReq.AddCookie(&http.Cookie{Name: "cfgms_session", Value: cliToken})
	crossRec := httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(crossRec, crossReq)
	assert.Equal(t, http.StatusUnauthorized, crossRec.Code,
		"CLI token on cookie path must be rejected with 401")

	// Assert the response is byte-for-byte identical to an invalid session token
	// (no disclosure that the session exists on another channel).
	var crossBody ErrorResponse
	require.NoError(t, json.NewDecoder(crossRec.Body).Decode(&crossBody))
	require.NotNil(t, crossBody.Error)
	assert.Equal(t, "INVALID_SESSION_TOKEN", crossBody.Error.Code,
		"cross-channel rejection must be indistinguishable from an invalid token")

	// Web token as cookie → uses web manager → validates OK (same channel).
	webReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	webReq.AddCookie(&http.Cookie{Name: "cfgms_session", Value: webToken})
	webRec := httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(webRec, webReq)
	assert.Equal(t, http.StatusOK, webRec.Code, "web token on cookie path must succeed")
}

// TestCrossChannelValidation_PostRestartStoreRehydrationPath verifies cross-channel
// rejection on the store-rehydration path: after a simulated restart, a fresh manager
// loads sessions from the durable store and rejects sessions from the other channel
// (Issue #3310 REQUIRED TEST).
func TestCrossChannelValidation_PostRestartStoreRehydrationPath(t *testing.T) {
	cliCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "web",
	}
	store := session.NewMemStore(cliCfg, time.Now)
	t.Cleanup(store.Close)
	ctx := context.Background()

	// Issue sessions with both managers.
	cliMgr := session.NewManager(cliCfg, store, time.Now)
	webMgr := session.NewManager(webCfg, store, time.Now)
	_, cliToken, err := cliMgr.Issue(ctx, "alice", "cli-ctrl", "")
	require.NoError(t, err)
	_, webToken, err := webMgr.Issue(ctx, "bob", "web-ctrl", "")
	require.NoError(t, err)

	// Simulate restart: fresh managers with empty in-memory maps over the same store.
	freshCliMgr := session.NewManager(cliCfg, store, time.Now)
	freshWebMgr := session.NewManager(webCfg, store, time.Now)

	srv := setupTestServer(t)
	srv.SetSessionManager(freshCliMgr)
	srv.SetWebSessionManager(freshWebMgr)

	// CLI token as Bearer (CLI manager, store-rehydration path) → 200.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req1.Header.Set("Authorization", "Bearer "+cliToken)
	rec1 := httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusOK, rec1.Code, "CLI token must validate on CLI manager after restart")

	// CLI token as cookie (web manager, store-rehydration path) → 401.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req2.AddCookie(&http.Cookie{Name: "cfgms_session", Value: cliToken})
	rec2 := httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusUnauthorized, rec2.Code,
		"CLI token must be rejected by web manager on store-rehydration path")

	var body2 ErrorResponse
	require.NoError(t, json.NewDecoder(rec2.Body).Decode(&body2))
	require.NotNil(t, body2.Error)
	assert.Equal(t, "INVALID_SESSION_TOKEN", body2.Error.Code,
		"cross-channel rejection must be indistinguishable from an invalid token")

	// Web token as cookie (web manager, store-rehydration path) → 200.
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req3.AddCookie(&http.Cookie{Name: "cfgms_session", Value: webToken})
	rec3 := httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusOK, rec3.Code, "web token must validate on web manager after restart")

	// Web token as Bearer (CLI manager, store-rehydration path) → 401.
	req4 := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req4.Header.Set("Authorization", "Bearer "+webToken)
	rec4 := httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec4, req4)
	assert.Equal(t, http.StatusUnauthorized, rec4.Code,
		"web token must be rejected by CLI manager on store-rehydration path")
}

// TestCrossChannelListAndRevoke_PostRestartPath verifies that List returns only the
// calling manager's channel sessions on the store fallback path, and that Revoke
// refuses to revoke a session belonging to another channel (REQUIRED TEST, Issue #3310).
func TestCrossChannelListAndRevoke_PostRestartPath(t *testing.T) {
	cliCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "web",
	}
	store := session.NewMemStore(cliCfg, time.Now)
	t.Cleanup(store.Close)
	ctx := context.Background()

	// Issue one CLI and one web session.
	cliMgr := session.NewManager(cliCfg, store, time.Now)
	webMgr := session.NewManager(webCfg, store, time.Now)
	cliSess, _, err := cliMgr.Issue(ctx, "alice", "cli-ctrl", "")
	require.NoError(t, err)
	_, _, err = webMgr.Issue(ctx, "bob", "web-ctrl", "")
	require.NoError(t, err)

	// Simulate restart: fresh managers with empty in-memory maps over the same store.
	freshCliMgr := session.NewManager(cliCfg, store, time.Now)
	freshWebMgr := session.NewManager(webCfg, store, time.Now)

	// CLI manager List on store fallback → must see only its own channel's session.
	cliList, err := freshCliMgr.List(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, len(cliList), "CLI List must return exactly one session")
	if len(cliList) == 1 {
		assert.Equal(t, cliSess.ID, cliList[0].ID)
	}

	// Web manager List on store fallback → must see only its own channel's session.
	webList, err := freshWebMgr.List(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, len(webList), "web List must return exactly one session")

	// Cross-channel Revoke (cache-miss branch): web manager cannot revoke CLI session by ID.
	// The cache-miss path loads the record via GetByID, checks channel="cli" != "web", returns not-found.
	err = freshWebMgr.Revoke(ctx, cliSess.ID)
	assert.True(t, errors.Is(err, session.ErrSessionNotFound),
		"cross-channel Revoke must return ErrSessionNotFound, got: %v", err)

	// Cross-channel revoke via handleSessionRevoke handler → 404.
	srv := setupTestServer(t)
	srv.SetSessionManager(freshCliMgr)
	srv.SetWebSessionManager(freshWebMgr)
	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+cliSess.ID, nil)
	revokeReq = injectAdminPrincipal(revokeReq, "admin")
	revokeReq = injectSessionMuxVars(revokeReq, map[string]string{"id": cliSess.ID})
	// Override the session manager to the web manager (simulating a web-channel revoke attempt on a CLI session).
	srv.SetSessionManager(freshWebMgr)
	revokeRec := httptest.NewRecorder()
	srv.handleSessionRevoke(revokeRec, revokeReq)
	assert.Equal(t, http.StatusNotFound, revokeRec.Code,
		"cross-channel revoke must return 404 (session not found on this channel)")
}

// TestSessionCreate_GrantedAccount_ConfinedToAccountPermissions is a REQUIRED TEST
// (Issue #3584, AC): a tenant-scoped account granted session:create can mint a CLI
// Bearer session, but that session is confined to the account's permission grants —
// it is NOT implicitly admin. The test proves confinement by verifying that the minted
// session is denied a permission the account does not hold (steward:list).
//
// Safety depends on #3576: authenticationMiddleware re-derives the principal from the
// bound account on every Bearer request, so the session carries only the account's
// Permissions and never falls back to implicit admin.
func TestSessionCreate_GrantedAccount_ConfinedToAccountPermissions(t *testing.T) {
	srv, _, _ := setupTestServerWithSession(t)

	// Inject a tenant-scoped account that holds only session:create.
	// cacheAccount keys by Username; getAccountByID scans by ID.
	acct := &account{
		ID:          "tenant-admin-confinement-001",
		Username:    "tenant-admin-confinement",
		TenantID:    "acme-corp",
		RootScope:   false,
		Permissions: []string{"session:create"},
	}
	srv.cacheAccount(acct)

	// Build a Strong-assurance principal for this account — simulating the passkey
	// step-up that session:create requires. ImplicitAdmin is false: this is a
	// tenant-scoped account principal, not an mTLS-admin bootstrap principal.
	p := &Principal{
		ID:            acct.ID,
		Name:          "session:" + acct.Username,
		Assurance:     session.AssuranceStrong,
		TenantID:      acct.TenantID,
		Permissions:   []string{"session:create"},
		ImplicitAdmin: false,
	}
	body := `{"connection_name":"confinement-test-ctrl"}`
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(body))
	createReq = createReq.WithContext(context.WithValue(createReq.Context(), principalContextKey, p))
	createRec := httptest.NewRecorder()

	// Mint the session directly via the handler (permission gate is at router level;
	// we are testing confinement of the *resulting* session, not the issuance gate).
	srv.handleSessionCreate(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code, "granted account must be able to mint a CLI session: %s", createRec.Body.String())

	var createResp sessionCreateResponse
	require.NoError(t, json.NewDecoder(createRec.Body).Decode(&createResp))
	token := createResp.Token
	require.NotEmpty(t, token, "session token must not be empty")

	// Use the minted Bearer token on the router for a route that needs steward:list.
	// The middleware will re-derive the principal from the bound account (Issue #3576):
	// acct.RootScope == false → ImplicitAdmin = false; Permissions = ["session:create"].
	// steward:list is absent from that list → 403 INSUFFICIENT_PERMISSIONS.
	stewardReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	stewardReq.Header.Set("Authorization", "Bearer "+token)
	stewardRec := httptest.NewRecorder()
	srv.router.ServeHTTP(stewardRec, stewardReq)

	if stewardRec.Code != http.StatusForbidden {
		t.Errorf("confined session: GET /api/v1/stewards status = %d, want 403 "+
			"(session must be confined to account's grants, not implicit admin); body: %s",
			stewardRec.Code, stewardRec.Body.String())
	}
}

// TestRouterSessionCreate_NoGrantReturns403 is a REQUIRED TEST (Issue #3584, AC):
// an account that has NOT been granted session:create must still be refused by
// POST /api/v1/sessions with 403 INSUFFICIENT_PERMISSIONS.
//
// Uses a real API key (Machine assurance) with steward:list but not session:create,
// so requirePermission("session","create") fires on the permission check before the
// assurance check.
func TestRouterSessionCreate_NoGrantReturns403(t *testing.T) {
	srv, _, _ := setupTestServerWithSession(t)

	// API key with steward:list only — no session:create grant.
	apiKey := NewTestKey(t, srv, []string{"steward:list"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(`{"connection_name":"no-grant-test"}`))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("no session:create grant: status = %d, want 403; body: %s", rec.Code, rec.Body.String())
	}
}
