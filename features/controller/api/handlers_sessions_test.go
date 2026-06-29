// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

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

// injectAdminPrincipal returns a copy of r with an admin Principal set in context.
func injectAdminPrincipal(r *http.Request, principalID string) *http.Request {
	p := &Principal{
		ID:      principalID,
		Name:    "mtls-admin:" + principalID,
		IsAdmin: true,
	}
	return r.WithContext(context.WithValue(r.Context(), principalContextKey, p))
}

// injectNonAdminPrincipal returns a copy of r with a non-admin API-key Principal.
func injectNonAdminPrincipal(r *http.Request) *http.Request {
	p := &Principal{
		ID:          "api-key-user",
		Name:        "apikey",
		IsAdmin:     false,
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

// TestHandleSessionCreate_NonAdminReturns403 verifies non-admin principals are rejected.
func TestHandleSessionCreate_NonAdminReturns403(t *testing.T) {
	srv, _, _ := setupTestServerWithSession(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(`{}`))
	req = injectNonAdminPrincipal(req)
	rec := httptest.NewRecorder()

	srv.handleSessionCreate(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
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

// TestHandleSessionRevoke_NonAdminReturns403 verifies non-admin principals cannot revoke sessions.
func TestHandleSessionRevoke_NonAdminReturns403(t *testing.T) {
	srv, mgr, _ := setupTestServerWithSession(t)

	sess, _, err := mgr.Issue(context.Background(), "alice", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/"+sess.ID, nil)
	req = injectNonAdminPrincipal(req)
	req = injectSessionMuxVars(req, map[string]string{"id": sess.ID})
	rec := httptest.NewRecorder()

	srv.handleSessionRevoke(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
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
	if !capturedPrincipal.IsAdmin {
		t.Error("session-token principal must have IsAdmin=true")
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
