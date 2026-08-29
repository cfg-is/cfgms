// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// ---- test helpers -----------------------------------------------------------------

// setupCliLoginTestServer returns a server wired with a real in-memory session manager —
// the cli-login handlers are the one place in this file that mints sessions.
func setupCliLoginTestServer(t *testing.T) (*Server, session.Manager) {
	t.Helper()
	server, mgr, _ := setupTestServerWithSession(t)
	return server, mgr
}

// setupCliLoginTestServerWithLogger is setupCliLoginTestServer with the logger installed
// at construction time. New() starts background goroutines (startAPIKeyCleanup,
// startCredentialRequestSweep, startCliLoginRequestSweep) that read s.logger from the
// moment it returns, so a test must never assign server.logger afterwards — that plain
// field write races those readers under -race.
func setupCliLoginTestServerWithLogger(t *testing.T, logger logging.Logger) (*Server, session.Manager) {
	t.Helper()
	srv := setupTestServerWithLogger(t, logger)
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)
	srv.SetSessionManager(mgr)
	return srv, mgr
}

// newTestVerifier generates a random raw verifier and its SHA-256 hex hash, mirroring
// what the CLI does locally: the raw value is never sent at lodge time, only the hash.
func newTestVerifier(t *testing.T) (raw, hash string) {
	t.Helper()
	raw = "test-verifier-" + uuid.New().String()
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:])
}

func lodgeCliLogin(t *testing.T, server *Server, verifierHash string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(LodgeCliLoginRequestBody{VerifierHash: verifierHash})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli-login/lodge", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleLodgeCliLoginRequest(rec, req)
	return rec
}

func decodeLodgeCliLoginResponse(t *testing.T, rec *httptest.ResponseRecorder) LodgeCliLoginResponse {
	t.Helper()
	var resp struct {
		Data LodgeCliLoginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func approveCliLogin(t *testing.T, server *Server, principal *Principal, id string, body ApproveCliLoginRequestBody) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli-login/"+id+"/approve", bytes.NewReader(payload))
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"id": id})
	rec := httptest.NewRecorder()
	server.handleApproveCliLoginRequest(rec, req)
	return rec
}

func decodeApproveCliLoginResponse(t *testing.T, rec *httptest.ResponseRecorder) ApproveCliLoginResponse {
	t.Helper()
	var resp struct {
		Data ApproveCliLoginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

func collectCliLogin(t *testing.T, server *Server, id, verifier string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli-login/"+id+"/collect", nil)
	if verifier != "" {
		req.Header.Set("Authorization", "Bearer "+verifier)
	}
	req = withVars(req, map[string]string{"id": id})
	rec := httptest.NewRecorder()
	server.handleCollectCliLoginRequest(rec, req)
	return rec
}

func decodeCollectCliLoginResponse(t *testing.T, rec *httptest.ResponseRecorder) CollectCliLoginResponse {
	t.Helper()
	var resp struct {
		Data CollectCliLoginResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Data
}

// browserPrincipalAfterPasskeyLogin builds a Principal shaped exactly like
// authenticationMiddleware's web-cookie branch produces immediately after a successful
// passkey login: AssuranceStrong, RootScoped derived only from rootScopeFromAssertion.
func browserPrincipalAfterPasskeyLogin(id string, rootScope bool) *Principal {
	return &Principal{
		ID:            id,
		Name:          "session:" + id,
		Assurance:     session.AssuranceStrong,
		RootScoped:    rootScope,
		GlobalScope:   rootScope,
		ImplicitAdmin: rootScope,
	}
}

// lodgeAndApproveCliLogin lodges a request and approves it as principal, returning the
// request ID and the raw verifier the test needs for collect.
func lodgeAndApproveCliLogin(t *testing.T, server *Server, principal *Principal) (requestID, verifier string) {
	t.Helper()
	verifier, hash := newTestVerifier(t)
	lodgeRec := lodgeCliLogin(t, server, hash)
	require.Equal(t, http.StatusCreated, lodgeRec.Code, lodgeRec.Body.String())
	lodged := decodeLodgeCliLoginResponse(t, lodgeRec)

	approveRec := approveCliLogin(t, server, principal, lodged.RequestID, ApproveCliLoginRequestBody{UserCode: lodged.UserCode})
	require.Equal(t, http.StatusOK, approveRec.Code, approveRec.Body.String())
	return lodged.RequestID, verifier
}

// ---- lodge ----------------------------------------------------------------------------

func TestLodgeCliLoginRequest_Success(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	_, hash := newTestVerifier(t)

	rec := lodgeCliLogin(t, server, hash)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	resp := decodeLodgeCliLoginResponse(t, rec)
	assert.NotEmpty(t, resp.RequestID)
	assert.NotEmpty(t, resp.UserCode)
	assert.NotEmpty(t, resp.ExpiresAt)

	stored, err := server.getCliLoginRequestByID(context.Background(), resp.RequestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, cliLoginRequestStatusPending, stored.Status)
	assert.Equal(t, hash, stored.VerifierHash)
}

func TestLodgeCliLoginRequest_RejectsMalformedVerifierHash(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)

	rec := lodgeCliLogin(t, server, "not-a-hash")
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
}

// ---- approve ----------------------------------------------------------------------------

func TestApproveCliLoginRequest_MintsSessionForBrowserPrincipal(t *testing.T) {
	server, mgr := setupCliLoginTestServer(t)
	principal := browserPrincipalAfterPasskeyLogin("browser-op-1", false)
	principal.TenantID = "approver-tenant"

	_, hash := newTestVerifier(t)
	lodgeRec := lodgeCliLogin(t, server, hash)
	lodged := decodeLodgeCliLoginResponse(t, lodgeRec)

	rec := approveCliLogin(t, server, principal, lodged.RequestID, ApproveCliLoginRequestBody{UserCode: lodged.UserCode})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	resp := decodeApproveCliLoginResponse(t, rec)
	assert.Equal(t, cliLoginRequestStatusApproved, resp.Status)

	stored, err := server.getCliLoginRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, cliLoginRequestStatusApproved, stored.Status)
	assert.Equal(t, principal.ID, stored.ApprovedBy)
	require.NotEmpty(t, stored.SessionID)

	sess, err := mgr.Validate(context.Background(), func() string {
		withToken, err := server.getCliLoginRequestWithToken(context.Background(), lodged.RequestID)
		require.NoError(t, err)
		return withToken.SessionToken
	}())
	require.NoError(t, err)
	assert.Equal(t, principal.ID, sess.PrincipalID)
	assert.Equal(t, "approver-tenant", sess.TenantID)
	assert.False(t, sess.RootScoped)
}

func TestApproveCliLoginRequest_ResponseNeverCarriesToken(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	principal := browserPrincipalAfterPasskeyLogin("browser-op-2", false)

	_, hash := newTestVerifier(t)
	lodgeRec := lodgeCliLogin(t, server, hash)
	lodged := decodeLodgeCliLoginResponse(t, lodgeRec)

	rec := approveCliLogin(t, server, principal, lodged.RequestID, ApproveCliLoginRequestBody{UserCode: lodged.UserCode})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// The raw response body must never contain a 43-char base64url session token —
	// only the collect response, over the CLI's own connection, may ever carry it.
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	body, _ := raw["data"].(map[string]interface{})
	_, hasToken := body["token"]
	assert.False(t, hasToken, "approve response must never include a token field")
}

func TestApproveCliLoginRequest_CodeMismatchRejected(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	principal := browserPrincipalAfterPasskeyLogin("browser-op-3", false)

	_, hash := newTestVerifier(t)
	lodgeRec := lodgeCliLogin(t, server, hash)
	lodged := decodeLodgeCliLoginResponse(t, lodgeRec)

	rec := approveCliLogin(t, server, principal, lodged.RequestID, ApproveCliLoginRequestBody{UserCode: "WRON-GCDE"})
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())

	stored, err := server.getCliLoginRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	assert.Equal(t, cliLoginRequestStatusPending, stored.Status, "a mismatched code must not move the request out of pending")
}

func TestApproveCliLoginRequest_Deny(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	principal := browserPrincipalAfterPasskeyLogin("browser-op-4", false)

	_, hash := newTestVerifier(t)
	lodgeRec := lodgeCliLogin(t, server, hash)
	lodged := decodeLodgeCliLoginResponse(t, lodgeRec)

	rec := approveCliLogin(t, server, principal, lodged.RequestID, ApproveCliLoginRequestBody{UserCode: lodged.UserCode, Deny: true})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeApproveCliLoginResponse(t, rec)
	assert.Equal(t, cliLoginRequestStatusDenied, resp.Status)

	stored, err := server.getCliLoginRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	assert.Equal(t, cliLoginRequestStatusDenied, stored.Status)
	assert.Empty(t, stored.SessionID, "a denial must never mint a session")
}

// TestApproveCliLoginRequest_RequiresStrongAssurance is a [REQUIRED TEST]: the approve
// route requires strong assurance, and a session that has not completed a passkey login
// (stuck at Basic) cannot approve a login request — it receives the step-up challenge,
// never reaching the handler.
func TestApproveCliLoginRequest_RequiresStrongAssurance(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)

	_, hash := newTestVerifier(t)
	lodgeRec := lodgeCliLogin(t, server, hash)
	lodged := decodeLodgeCliLoginResponse(t, lodgeRec)

	basicPrincipal := &Principal{ID: "basic-op", Assurance: session.AssuranceBasic, ImplicitAdmin: true}
	body, err := json.Marshal(ApproveCliLoginRequestBody{UserCode: lodged.UserCode})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli-login/"+lodged.RequestID+"/approve", bytes.NewReader(body))
	req = withVars(req, map[string]string{"id": lodged.RequestID})
	rec := httptest.NewRecorder()

	handler := server.requirePermission("cli-login", "approve")(http.HandlerFunc(server.handleApproveCliLoginRequest))
	req = withPrincipal(req, basicPrincipal)
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")

	stored, err := server.getCliLoginRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	assert.Equal(t, cliLoginRequestStatusPending, stored.Status, "a Basic-assurance caller must never reach the handler")
}

// ---- collect ----------------------------------------------------------------------------

func TestCollectCliLoginRequest_Success(t *testing.T) {
	server, mgr := setupCliLoginTestServer(t)
	principal := browserPrincipalAfterPasskeyLogin("browser-op-5", false)
	requestID, verifier := lodgeAndApproveCliLogin(t, server, principal)

	rec := collectCliLogin(t, server, requestID, verifier)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	resp := decodeCollectCliLoginResponse(t, rec)
	assert.Equal(t, cliLoginRequestStatusCollected, resp.Status)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.SessionID)

	sess, err := mgr.Validate(context.Background(), resp.Token)
	require.NoError(t, err)
	assert.Equal(t, principal.ID, sess.PrincipalID)

	stored, err := server.getCliLoginRequestByID(context.Background(), requestID)
	require.NoError(t, err)
	assert.Equal(t, cliLoginRequestStatusCollected, stored.Status)
}

// TestCollectCliLoginRequest_RequiresVerifier_WrongIDOnlyGets404 is part of the
// [REQUIRED TEST]: a caller holding only the request identifier (no verifier) receives
// not-found, never any signal that the ID exists.
func TestCollectCliLoginRequest_RequiresVerifier_WrongIDOnlyGets404(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	principal := browserPrincipalAfterPasskeyLogin("browser-op-6", false)
	requestID, _ := lodgeAndApproveCliLogin(t, server, principal)

	rec := collectCliLogin(t, server, requestID, "")
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())

	rec2 := collectCliLogin(t, server, requestID, "totally-wrong-verifier")
	assert.Equal(t, http.StatusNotFound, rec2.Code, rec2.Body.String())
}

// TestCollectCliLoginRequest_SecondCollectionIsGone is the other half of the
// [REQUIRED TEST]: a second collection, even with the correct verifier, receives 410 Gone
// — the compare-and-set makes collection single-use.
func TestCollectCliLoginRequest_SecondCollectionIsGone(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	principal := browserPrincipalAfterPasskeyLogin("browser-op-7", false)
	requestID, verifier := lodgeAndApproveCliLogin(t, server, principal)

	first := collectCliLogin(t, server, requestID, verifier)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())

	second := collectCliLogin(t, server, requestID, verifier)
	assert.Equal(t, http.StatusGone, second.Code, second.Body.String())
}

// TestCollectCliLoginRequest_ConcurrentCollectSingleWinner races two collectors against
// the same approved request and asserts exactly one receives the token.
func TestCollectCliLoginRequest_ConcurrentCollectSingleWinner(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	principal := browserPrincipalAfterPasskeyLogin("browser-op-8", false)
	requestID, verifier := lodgeAndApproveCliLogin(t, server, principal)

	results := make(chan int, 2)
	run := func() {
		rec := collectCliLogin(t, server, requestID, verifier)
		results <- rec.Code
	}
	go run()
	go run()

	codes := []int{<-results, <-results}
	successCount, goneCount := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			successCount++
		case http.StatusGone:
			goneCount++
		}
	}
	assert.Equal(t, 1, successCount, "exactly one concurrent collector must succeed")
	assert.Equal(t, 1, goneCount, "the race loser must receive 410 Gone")
}

func TestCollectCliLoginRequest_PendingReturnsStatusOnly(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	verifier, hash := newTestVerifier(t)
	lodgeRec := lodgeCliLogin(t, server, hash)
	lodged := decodeLodgeCliLoginResponse(t, lodgeRec)

	rec := collectCliLogin(t, server, lodged.RequestID, verifier)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeCollectCliLoginResponse(t, rec)
	assert.Equal(t, "pending", resp.Status)
	assert.Empty(t, resp.Token)
}

func TestCollectCliLoginRequest_DeniedReturnsStatusOnly(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	principal := browserPrincipalAfterPasskeyLogin("browser-op-9", false)
	verifier, hash := newTestVerifier(t)
	lodgeRec := lodgeCliLogin(t, server, hash)
	lodged := decodeLodgeCliLoginResponse(t, lodgeRec)

	denyRec := approveCliLogin(t, server, principal, lodged.RequestID, ApproveCliLoginRequestBody{UserCode: lodged.UserCode, Deny: true})
	require.Equal(t, http.StatusOK, denyRec.Code)

	rec := collectCliLogin(t, server, lodged.RequestID, verifier)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeCollectCliLoginResponse(t, rec)
	assert.Equal(t, "denied", resp.Status)
	assert.Empty(t, resp.Token)
}

func TestCollectCliLoginRequest_ExpiredReturnsStatusOnly(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	verifier, hash := newTestVerifier(t)
	lodgeRec := lodgeCliLogin(t, server, hash)
	lodged := decodeLodgeCliLoginResponse(t, lodgeRec)

	stored, err := server.getCliLoginRequestByID(context.Background(), lodged.RequestID)
	require.NoError(t, err)
	stored.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	require.NoError(t, server.persistCliLoginRequest(context.Background(), stored))

	rec := collectCliLogin(t, server, lodged.RequestID, verifier)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	resp := decodeCollectCliLoginResponse(t, rec)
	assert.Equal(t, "expired", resp.Status)
	assert.Empty(t, resp.Token)
}

// ---- [REQUIRED TEST] token never travels through URL/log/output ----------------------

// TestCliLoginToken_NeverAppearsOutsideCollectResponseBody is the [REQUIRED TEST]: the
// session token appears only in the collect response body. It asserts the token is
// absent from every logged line across the full lodge -> approve -> collect flow, and
// absent from the lodge/approve response bodies (which is also covered by the dedicated
// approve test, verified again here as part of the end-to-end sweep).
func TestCliLoginToken_NeverAppearsOutsideCollectResponseBody(t *testing.T) {
	logger := &captureAllLogger{}
	server, _ := setupCliLoginTestServerWithLogger(t, logger)

	principal := browserPrincipalAfterPasskeyLogin("browser-op-10", false)
	verifier, hash := newTestVerifier(t)

	lodgeRec := lodgeCliLogin(t, server, hash)
	lodged := decodeLodgeCliLoginResponse(t, lodgeRec)

	approveRec := approveCliLogin(t, server, principal, lodged.RequestID, ApproveCliLoginRequestBody{UserCode: lodged.UserCode})
	require.Equal(t, http.StatusOK, approveRec.Code)

	collectRec := collectCliLogin(t, server, lodged.RequestID, verifier)
	require.Equal(t, http.StatusOK, collectRec.Code)
	resp := decodeCollectCliLoginResponse(t, collectRec)
	require.NotEmpty(t, resp.Token)

	assert.NotContains(t, lodgeRec.Body.String(), resp.Token)
	assert.NotContains(t, approveRec.Body.String(), resp.Token)
	assert.NotContains(t, logger.captured(), resp.Token, "the session token must never appear in any log line")

	// The token must never appear in a URL, query string or fragment either — nothing
	// in this flow ever places it in r.URL, so asserting it is absent from both request
	// URLs used is a direct check of that invariant.
	assert.NotContains(t, "/api/v1/cli-login/"+lodged.RequestID+"/approve", resp.Token)
	assert.NotContains(t, "/api/v1/cli-login/"+lodged.RequestID+"/collect", resp.Token)
}

// ---- [REQUIRED TEST] no scope-bearing field on the request record ---------------------

// TestPendingCliLoginRequest_NoScopeBearingField is a [REQUIRED TEST] (Amendment 2): the
// login request record has no scope-bearing field that could be made to carry a
// root-scope indication. Enumerates the struct's fields via reflection so the test fails
// if such a field is ever added.
func TestPendingCliLoginRequest_NoScopeBearingField(t *testing.T) {
	typ := reflect.TypeOf(pendingCliLoginRequest{})
	disallowed := []string{"tenant", "rootscope", "root_scope", "scope", "globalscope"}
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, bad := range disallowed {
			assert.NotContains(t, name, bad,
				"pendingCliLoginRequest field %q looks scope-bearing — the login request record must carry no tenant/scope field", typ.Field(i).Name)
		}
	}
}

// ---- root-scope session behavior (Amendment 2) ------------------------------------------

// TestApproveCliLoginRequest_RootScopedPrincipal_SessionCarriesMarker is a revised-AC
// test: browser login succeeds for an account with the root-scope flag set, and the
// resulting CLI session carries the root-scope marker.
func TestApproveCliLoginRequest_RootScopedPrincipal_SessionCarriesMarker(t *testing.T) {
	server, mgr := setupCliLoginTestServer(t)
	principal := browserPrincipalAfterPasskeyLogin("root-op-1", true)

	requestID, verifier := lodgeAndApproveCliLogin(t, server, principal)
	collectRec := collectCliLogin(t, server, requestID, verifier)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	resp := decodeCollectCliLoginResponse(t, collectRec)

	sess, err := mgr.Validate(context.Background(), resp.Token)
	require.NoError(t, err)
	assert.True(t, sess.RootScoped, "a session minted for a root-scoped browser principal must itself be root-scoped")
	assert.Empty(t, sess.TenantID)
}

// TestApproveCliLoginRequest_OrdinaryPrincipal_SessionHasNoMarker is a [REQUIRED TEST]:
// an account without the root-scope flag receives a session without the marker, so the
// flag is never inferred from an empty tenant or from global scope.
func TestApproveCliLoginRequest_OrdinaryPrincipal_SessionHasNoMarker(t *testing.T) {
	server, mgr := setupCliLoginTestServer(t)
	// Unscoped-but-not-root-scoped: TenantID=="" and GlobalScope could be true for an
	// ordinary unscoped mTLS admin too — RootScoped must stay false regardless.
	principal := &Principal{
		ID:            "unscoped-admin-1",
		Name:          "mtls-admin:unscoped-admin-1",
		Assurance:     session.AssuranceStrong,
		TenantID:      "",
		GlobalScope:   true,
		RootScoped:    false,
		ImplicitAdmin: true,
	}

	requestID, verifier := lodgeAndApproveCliLogin(t, server, principal)
	collectRec := collectCliLogin(t, server, requestID, verifier)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	resp := decodeCollectCliLoginResponse(t, collectRec)

	sess, err := mgr.Validate(context.Background(), resp.Token)
	require.NoError(t, err)
	assert.False(t, sess.RootScoped, "an unscoped-but-not-root-scoped principal must never produce a RootScoped session")
}

// TestCliLoginSession_RootScoped_SubjectToTenantBoundary is a [REQUIRED TEST]: the
// session minted for a root-scoped account is subject to the Decision 1 tenant
// boundary — reaching a strict descendant tenant with no active grant is refused,
// asserted through the catch-all boundary gate (handleGetTenant).
func TestCliLoginSession_RootScoped_SubjectToTenantBoundary(t *testing.T) {
	server, mgr := setupCliLoginTestServer(t)
	sm := pkgtesting.SetupTestStorage(t)
	tcs := sm.GetTenantCrossingStore()
	require.NotNil(t, tcs)
	server.SetTenantCrossingStore(tcs)

	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "cli-login-root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "cli-login-msp-a", ParentID: "cli-login-root"})
	require.NoError(t, err)

	principal := browserPrincipalAfterPasskeyLogin("root-op-2", true)
	requestID, verifier := lodgeAndApproveCliLogin(t, server, principal)
	collectRec := collectCliLogin(t, server, requestID, verifier)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	resp := decodeCollectCliLoginResponse(t, collectRec)

	sess, err := mgr.Validate(context.Background(), resp.Token)
	require.NoError(t, err)
	require.True(t, sess.RootScoped)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/cli-login-msp-a", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"a root-scoped CLI-login session must not see a real descendant tenant without an active grant")
}

// TestCliLoginSession_CannotObtainRootScopeCertificate is a [REQUIRED TEST]: a session
// minted by this flow cannot be used to obtain a certificate carrying the root-scope
// extension. principalHasCertifiedRootScope (handlers_credential_requests_approve.go,
// unchanged by this story) requires CertSerial != "", which no bearer-session principal
// ever carries — this test proves that boundary holds for a session minted by our own
// approve handler specifically, not just in the abstract.
func TestCliLoginSession_CannotObtainRootScopeCertificate(t *testing.T) {
	server, mgr := setupCliLoginTestServer(t)
	rootPrincipal := browserPrincipalAfterPasskeyLogin("root-op-3", true)
	requestID, verifier := lodgeAndApproveCliLogin(t, server, rootPrincipal)
	collectRec := collectCliLogin(t, server, requestID, verifier)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	resp := decodeCollectCliLoginResponse(t, collectRec)

	sess, err := mgr.Validate(context.Background(), resp.Token)
	require.NoError(t, err)
	require.True(t, sess.RootScoped)

	// Reconstruct the bearer-derived Principal the way authenticationMiddleware would —
	// no bound account, so ImplicitAdmin: true, and critically CertSerial stays "".
	bearerPrincipal := &Principal{
		ID:            sess.PrincipalID,
		Assurance:     sess.Assurance,
		RootScoped:    sess.RootScoped,
		TenantID:      sess.TenantID,
		GlobalScope:   sess.TenantID == "",
		ImplicitAdmin: true,
	}
	assert.False(t, principalHasCertifiedRootScope(bearerPrincipal),
		"a session-derived principal must never satisfy the certified-root-scope gate, regardless of RootScoped")
	_ = mgr
}

// TestPendingCliLoginRequest_NoFieldConveysRootScope is a [REQUIRED TEST] companion: the
// login request record itself has no field that could be made to carry a root-scope
// indication, verified by confirming denial and collection never read or write any such
// value — already covered structurally by TestPendingCliLoginRequest_NoScopeBearingField.

// ---- refusal fires before ceremony / distinguishes revoked vs expired -----------------
// (Client-side behaviors — a timeout/denial/interrupt distinction and the revoked-vs-
// expired distinction — are covered in cmd/cfg/cmd/login_test.go.)

// ---- expiry sweep -----------------------------------------------------------------------

// TestSweepExpiredCliLoginRequests covers the sweep's security-relevant branch directly:
// an approved-but-uncollected request whose expiry has passed must have its record
// deleted AND the session minted at approval revoked — an uncollected token must never
// remain a live credential once its request expires. Mirrors
// TestSweepExpiredCredentialRequestsAndTokens (Issue #3717).
func TestSweepExpiredCliLoginRequests(t *testing.T) {
	server, mgr := setupCliLoginTestServer(t)
	ctx := context.Background()

	// Approved, never collected, now past its expiry.
	principal := browserPrincipalAfterPasskeyLogin("sweep-op-1", false)
	approvedID, _ := lodgeAndApproveCliLogin(t, server, principal)
	approved, err := server.getCliLoginRequestWithToken(ctx, approvedID)
	require.NoError(t, err)
	require.NotNil(t, approved)
	require.NotEmpty(t, approved.SessionToken, "approval must have minted a session token")
	require.NotEmpty(t, approved.SessionID)
	uncollectedToken := approved.SessionToken

	_, err = mgr.Validate(ctx, uncollectedToken)
	require.NoError(t, err, "the session minted at approval is live until it is collected or swept")

	approved.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	require.NoError(t, server.persistCliLoginRequest(ctx, approved))

	// Pending, never approved, now past its expiry — nothing to revoke.
	_, expiredHash := newTestVerifier(t)
	expiredRec := lodgeCliLogin(t, server, expiredHash)
	require.Equal(t, http.StatusCreated, expiredRec.Code, expiredRec.Body.String())
	expiredPendingID := decodeLodgeCliLoginResponse(t, expiredRec).RequestID
	expiredPending, err := server.getCliLoginRequestByID(ctx, expiredPendingID)
	require.NoError(t, err)
	require.NotNil(t, expiredPending)
	expiredPending.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	require.NoError(t, server.persistCliLoginRequest(ctx, expiredPending))

	// A live pending request must survive the sweep untouched.
	_, liveHash := newTestVerifier(t)
	liveRec := lodgeCliLogin(t, server, liveHash)
	require.Equal(t, http.StatusCreated, liveRec.Code, liveRec.Body.String())
	liveID := decodeLodgeCliLoginResponse(t, liveRec).RequestID

	server.sweepExpiredCliLoginRequests(ctx)

	goneApproved, err := server.getCliLoginRequestByID(ctx, approvedID)
	require.NoError(t, err)
	assert.Nil(t, goneApproved, "an expired approved request must be removed by the sweep")

	_, err = mgr.Validate(ctx, uncollectedToken)
	assert.Error(t, err, "the sweep must revoke the session minted for a request that expired uncollected")

	gonePending, err := server.getCliLoginRequestByID(ctx, expiredPendingID)
	require.NoError(t, err)
	assert.Nil(t, gonePending, "an expired pending request must be removed by the sweep")

	stillLive, err := server.getCliLoginRequestByID(ctx, liveID)
	require.NoError(t, err)
	require.NotNil(t, stillLive, "a live pending request must survive the sweep")
	assert.Equal(t, cliLoginRequestStatusPending, stillLive.Status)

	require.NoError(t, server.auditManager.Flush(ctx))
	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{
		ResourceTypes: []string{"cli_login_request"},
	})
	require.NoError(t, err)
	expiredEvents := map[string]*business.AuditEntry{}
	for _, e := range entries {
		if e.Action == "cli_login.expired" {
			expiredEvents[e.ResourceID] = e
		}
	}
	require.Contains(t, expiredEvents, approvedID, "the swept approved request must emit cli_login.expired")
	require.Contains(t, expiredEvents, expiredPendingID, "the swept pending request must emit cli_login.expired")
	assert.NotContains(t, expiredEvents, liveID, "a live request must not emit an expiry event")

	for _, e := range expiredEvents {
		serialized, err := json.Marshal(e)
		require.NoError(t, err)
		assert.NotContains(t, string(serialized), uncollectedToken,
			"an expiry audit event must never carry the session token")
	}
}

// TestSweepExpiredCliLoginRequests_TerminalRequestsUntouched asserts the sweep's status
// filter: a collected request is terminal, so the sweep must neither delete its record
// nor revoke the session already handed to the CLI — collection makes that session the
// operator's live credential, independent of the request's own expiry. A denied request
// is likewise left for its storage TTL to reap.
func TestSweepExpiredCliLoginRequests_TerminalRequestsUntouched(t *testing.T) {
	server, mgr := setupCliLoginTestServer(t)
	ctx := context.Background()

	// Collected: the CLI already holds this token.
	principal := browserPrincipalAfterPasskeyLogin("sweep-op-2", false)
	collectedID, verifier := lodgeAndApproveCliLogin(t, server, principal)
	collectRec := collectCliLogin(t, server, collectedID, verifier)
	require.Equal(t, http.StatusOK, collectRec.Code, collectRec.Body.String())
	collectedToken := decodeCollectCliLoginResponse(t, collectRec).Token
	require.NotEmpty(t, collectedToken)

	collected, err := server.getCliLoginRequestByID(ctx, collectedID)
	require.NoError(t, err)
	require.NotNil(t, collected)
	require.Equal(t, cliLoginRequestStatusCollected, collected.Status)
	collected.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	require.NoError(t, server.persistCliLoginRequest(ctx, collected))

	// Denied: never minted a session, and already resolved.
	_, deniedHash := newTestVerifier(t)
	deniedRec := lodgeCliLogin(t, server, deniedHash)
	require.Equal(t, http.StatusCreated, deniedRec.Code, deniedRec.Body.String())
	deniedLodged := decodeLodgeCliLoginResponse(t, deniedRec)
	denyRec := approveCliLogin(t, server, principal, deniedLodged.RequestID,
		ApproveCliLoginRequestBody{UserCode: deniedLodged.UserCode, Deny: true})
	require.Equal(t, http.StatusOK, denyRec.Code, denyRec.Body.String())
	denied, err := server.getCliLoginRequestByID(ctx, deniedLodged.RequestID)
	require.NoError(t, err)
	require.NotNil(t, denied)
	denied.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	require.NoError(t, server.persistCliLoginRequest(ctx, denied))

	server.sweepExpiredCliLoginRequests(ctx)

	stillCollected, err := server.getCliLoginRequestByID(ctx, collectedID)
	require.NoError(t, err)
	require.NotNil(t, stillCollected, "a collected request is terminal and must not be swept")
	assert.Equal(t, cliLoginRequestStatusCollected, stillCollected.Status)

	sess, err := mgr.Validate(ctx, collectedToken)
	require.NoError(t, err, "the sweep must never revoke a session that was already collected")
	assert.Equal(t, principal.ID, sess.PrincipalID)

	stillDenied, err := server.getCliLoginRequestByID(ctx, deniedLodged.RequestID)
	require.NoError(t, err)
	require.NotNil(t, stillDenied, "a denied request is terminal and must not be swept")
	assert.Equal(t, cliLoginRequestStatusDenied, stillDenied.Status)
}

// TestStartCliLoginRequestSweep_RunsAndStopsOnClose covers the goroutine wrapper: New()
// starts the sweep goroutine and Close() stops it, closing cliLoginSweepDone on exit.
func TestStartCliLoginRequestSweep_RunsAndStopsOnClose(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)

	select {
	case <-server.cliLoginSweepDone:
		t.Fatal("the cli-login sweep goroutine must still be running before Close")
	default:
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, server.Close(closeCtx))

	select {
	case <-server.cliLoginSweepDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the cli-login sweep goroutine did not exit after Close")
	}
}

// ---- audit -----------------------------------------------------------------------------

func TestCliLogin_EmitsAuditEventsWithoutToken(t *testing.T) {
	server, _ := setupCliLoginTestServer(t)
	require.NotNil(t, server.auditManager, "setupTestServer must wire a real audit manager")
	ctx := context.Background()

	principal := browserPrincipalAfterPasskeyLogin("browser-op-11", false)
	requestID, verifier := lodgeAndApproveCliLogin(t, server, principal)
	collectRec := collectCliLogin(t, server, requestID, verifier)
	require.Equal(t, http.StatusOK, collectRec.Code)
	resp := decodeCollectCliLoginResponse(t, collectRec)
	require.NotEmpty(t, resp.Token)

	require.NoError(t, server.auditManager.Flush(ctx))
	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{
		ResourceTypes: []string{"cli_login_request"},
	})
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(entries), 3, "lodge, approve and collect must each emit an audit event")
	actions := map[string]bool{}
	for _, e := range entries {
		actions[e.Action] = true
		serialized, err := json.Marshal(e)
		require.NoError(t, err)
		assert.NotContains(t, string(serialized), resp.Token, "no audit event may ever contain the session token")
		assert.Equal(t, requestID, e.ResourceID)
	}
	assert.True(t, actions["cli_login.lodged"])
	assert.True(t, actions["cli_login.approved"])
	assert.True(t, actions["cli_login.collected"])
}
