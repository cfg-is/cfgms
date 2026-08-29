// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── flag / browser override helpers ───────────────────────────────────────────────

// allowTLSInsecureSession satisfies the session-token TLS-insecure confirmation gate
// non-interactively, exactly as an operator who has read and accepted the warning does.
// Every login test below drives runLogin with --tls-insecure against an httptest
// server, so without this the gate — asserted directly by
// TestLogin_TLSInsecureRequiresTypedConfirmation — would stop each of them before the
// first HTTP call. It returns the sink the warning is written to.
func allowTLSInsecureSession(t *testing.T) *strings.Builder {
	t.Helper()
	var out strings.Builder
	origWriter := tlsInsecureWriter
	origTTY := isTTYFn
	tlsInsecureWriter = &out
	isTTYFn = func() bool { return false }
	t.Setenv("CFGMS_TLS_INSECURE_CONFIRM", "yes")
	t.Cleanup(func() {
		tlsInsecureWriter = origWriter
		isTTYFn = origTTY
	})
	return &out
}

func setLoginFlags(t *testing.T) {
	t.Helper()
	withTempConfigDir(t)
	allowTLSInsecureSession(t)
	origURL := loginURL
	origName := loginName
	origTLSInsecure := loginTLSInsecure
	origServerName := loginServerName
	origPollInterval := loginPollInterval
	origWaitTimeout := loginWaitTimeout
	origNoBrowser := loginNoBrowser
	t.Cleanup(func() {
		loginURL = origURL
		loginName = origName
		loginTLSInsecure = origTLSInsecure
		loginServerName = origServerName
		loginPollInterval = origPollInterval
		loginWaitTimeout = origWaitTimeout
		loginNoBrowser = origNoBrowser
	})
	loginURL = ""
	loginName = ""
	loginTLSInsecure = true
	loginServerName = ""
	loginPollInterval = 5 * time.Millisecond
	loginWaitTimeout = 2 * time.Second
	loginNoBrowser = false
}

// capturingBrowserOpener records every URL passed to it and never actually launches a
// browser — tests must never shell out.
type capturingBrowserOpener struct {
	mu   sync.Mutex
	urls []string
}

func (o *capturingBrowserOpener) open(url string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.urls = append(o.urls, url)
	return nil
}

func (o *capturingBrowserOpener) opened() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string{}, o.urls...)
}

func overrideLoginBrowserOpener(t *testing.T) *capturingBrowserOpener {
	t.Helper()
	opener := &capturingBrowserOpener{}
	orig := loginOpenBrowserFn
	loginOpenBrowserFn = opener.open
	t.Cleanup(func() { loginOpenBrowserFn = orig })
	return opener
}

// ── stub controller ────────────────────────────────────────────────────────────────

// loginFlowCapture records what the test controller observed during a login run.
type loginFlowCapture struct {
	mu           sync.Mutex
	lodgeBody    []byte
	collectAuths []string
}

func (c *loginFlowCapture) recordCollectAuth(auth string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectAuths = append(c.collectAuths, auth)
	return len(c.collectAuths) - 1
}

func (c *loginFlowCapture) getCollectAuths() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.collectAuths...)
}

// newLoginFlowServer builds a stub controller for the login command flow: lodge always
// succeeds with requestID/userCode, and collect responds with collectSequence in order
// (the last entry repeats for any call beyond its length).
func newLoginFlowServer(t *testing.T, requestID, userCode string, capt *loginFlowCapture, collectSequence []func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/cli-login/lodge", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		capt.mu.Lock()
		capt.lodgeBody = body
		capt.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"request_id": requestID,
				"user_code":  userCode,
				"expires_at": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
			},
		})
	})
	mux.HandleFunc("/api/v1/cli-login/"+requestID+"/collect", func(w http.ResponseWriter, r *http.Request) {
		idx := capt.recordCollectAuth(r.Header.Get("Authorization"))
		if idx >= len(collectSequence) {
			idx = len(collectSequence) - 1
		}
		collectSequence[idx](w)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func collectLoginPending(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"status": "pending"}})
}

func collectLoginDenied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"status": "denied"}})
}

func collectLoginExpired(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"status": "expired"}})
}

func collectLoginGone(w http.ResponseWriter) {
	w.WriteHeader(http.StatusGone)
}

func collectLoginSuccess(sessionID, token string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"status":          "collected",
				"token":           token,
				"session_id":      sessionID,
				"absolute_expiry": time.Now().Add(8 * time.Hour).UTC().Format(time.RFC3339),
			},
		})
	}
}

// ── TestLogin_HappyPath ────────────────────────────────────────────────────────────

func TestLogin_HappyPath(t *testing.T) {
	setLoginFlags(t)
	overrideSessionStore(t, newTestSessionStore())
	opener := overrideLoginBrowserOpener(t)

	const requestID = "cli-login-test-1"
	const userCode = "WJKD-7RTN"
	const sessionToken = "test-session-token-value-abcdef0123456789012"
	const sessionID = "sess-login-1"

	capt := &loginFlowCapture{}
	srv := newLoginFlowServer(t, requestID, userCode, capt, []func(w http.ResponseWriter){
		collectLoginPending, collectLoginPending, collectLoginSuccess(sessionID, sessionToken),
	})

	loginURL = srv.URL
	loginName = "test-login"

	out := captureStdout(t, func() {
		require.NoError(t, runLogin(loginCmd, nil))
	})

	assert.Contains(t, out, userCode)
	assert.Contains(t, out, "Logged in as")

	// The session token must never appear in command output, at any verbosity
	// (Issue #3721 [REQUIRED TEST] shape, mirrored from the credential-enrol command).
	assert.False(t, strings.Contains(out, sessionToken),
		"the session token must never appear in command output")

	// The verifier (sent only as the collect Authorization header) must never appear
	// in the printed confirmation URL.
	require.NotEmpty(t, opener.opened())
	confirmURL := opener.opened()[0]
	assert.Contains(t, confirmURL, requestID)
	assert.False(t, strings.Contains(out, confirmURL[strings.Index(confirmURL, "request_id="):]) &&
		strings.Contains(confirmURL, "verifier"), "confirmation URL must never carry the verifier")

	// Lodge must never send the raw verifier — only its hash.
	var lodgeReq map[string]string
	require.NoError(t, json.Unmarshal(capt.lodgeBody, &lodgeReq))
	verifierHash, ok := lodgeReq["verifier_hash"]
	require.True(t, ok)
	assert.Len(t, verifierHash, 64, "verifier_hash must be a SHA-256 hex digest")

	// Every collect poll must authenticate with the same bearer verifier.
	collectAuths := capt.getCollectAuths()
	require.Len(t, collectAuths, 3)
	for _, h := range collectAuths {
		assert.True(t, strings.HasPrefix(h, "Bearer "))
	}
	assert.Equal(t, collectAuths[0], collectAuths[1], "the same verifier must be presented on every poll")
	assert.Equal(t, collectAuths[1], collectAuths[2])

	rec, err := loadSessionToken()
	require.NoError(t, err)
	require.NotNil(t, rec, "a working session must be left behind so the next ordinary cfg command succeeds")
	assert.Equal(t, sessionToken, rec.Token)
	assert.Equal(t, sessionID, rec.SessionID)
	assert.Equal(t, srv.URL, rec.ControllerURL)
	assert.Equal(t, "test-login", rec.ConnectionName)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)
	entry, err := reg.Get("test-login")
	require.NoError(t, err)
	require.NotNil(t, entry, "a successful login must register the connection")
	assert.Equal(t, srv.URL, entry.ControllerURL)
	assert.Equal(t, "browser", entry.UnlockMethod)
}

// ── distinct terminal outcomes ────────────────────────────────────────────────────

func TestLogin_Denied(t *testing.T) {
	setLoginFlags(t)
	overrideSessionStore(t, newTestSessionStore())
	overrideLoginBrowserOpener(t)

	capt := &loginFlowCapture{}
	srv := newLoginFlowServer(t, "cli-login-test-2", "AAAA-BBBB", capt, []func(w http.ResponseWriter){collectLoginDenied})
	loginURL = srv.URL

	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errCliLoginDenied)

	rec, err := loadSessionToken()
	require.NoError(t, err)
	assert.Nil(t, rec, "a denied request must not leave a session behind")

	reg, err := newConnectionRegistry()
	require.NoError(t, err)
	entry, err := reg.Get(deriveConnectionName(srv.URL))
	require.NoError(t, err)
	assert.Nil(t, entry, "a denied request must not register a connection")
}

func TestLogin_ExpiredSurfacesAsTimeout(t *testing.T) {
	setLoginFlags(t)
	overrideSessionStore(t, newTestSessionStore())
	overrideLoginBrowserOpener(t)

	capt := &loginFlowCapture{}
	srv := newLoginFlowServer(t, "cli-login-test-3", "AAAA-BBBB", capt, []func(w http.ResponseWriter){collectLoginExpired})
	loginURL = srv.URL

	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errCliLoginTimedOut)
	assert.Contains(t, err.Error(), "cfg credential enrol", "the timeout message must name the headless enrolment command")

	rec, err := loadSessionToken()
	require.NoError(t, err)
	assert.Nil(t, rec)
}

func TestLogin_AlreadyGone(t *testing.T) {
	setLoginFlags(t)
	overrideSessionStore(t, newTestSessionStore())
	overrideLoginBrowserOpener(t)

	capt := &loginFlowCapture{}
	srv := newLoginFlowServer(t, "cli-login-test-4", "AAAA-BBBB", capt, []func(w http.ResponseWriter){collectLoginGone})
	loginURL = srv.URL

	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errCliLoginGone)
}

func TestLogin_OperatorInterrupt(t *testing.T) {
	setLoginFlags(t)
	overrideSessionStore(t, newTestSessionStore())
	overrideLoginBrowserOpener(t)

	capt := &loginFlowCapture{}
	srv := newLoginFlowServer(t, "cli-login-test-5", "AAAA-BBBB", capt, []func(w http.ResponseWriter){collectLoginPending})
	loginURL = srv.URL
	loginWaitTimeout = time.Minute // long enough that only the interrupt can end the wait

	ctx, cancel := context.WithCancel(context.Background())
	origSignalFn := loginSignalContextFn
	loginSignalContextFn = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	t.Cleanup(func() { loginSignalContextFn = origSignalFn })

	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errCliLoginInterrupted)

	rec, err := loadSessionToken()
	require.NoError(t, err)
	assert.Nil(t, rec, "an operator interrupt must not leave a session behind")
}

// TestPollForCliLoginCollection_WaitTimeout covers the client-side wait-timeout
// directly, independent of signal wiring: a context.WithTimeout deadline, not a server
// "expired" status, produces the exact same distinct errCliLoginTimedOut outcome
// (Issue #3721 AC).
func TestPollForCliLoginCollection_WaitTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		collectLoginPending(w)
	}))
	defer srv.Close()

	client, err := NewAPIClient(&APIClientConfig{BaseURL: srv.URL, BearerToken: "verifier", TLSInsecure: true})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err = pollForCliLoginCollection(ctx, client, "cli-login-x", 5*time.Millisecond, io.Discard)
	require.Error(t, err)
	assert.ErrorIs(t, err, errCliLoginTimedOut)
}

// ── validation ─────────────────────────────────────────────────────────────────────

func TestLogin_RequiresURL(t *testing.T) {
	setLoginFlags(t)
	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--url is required")
}

func TestLogin_RefusesNonHTTPS(t *testing.T) {
	setLoginFlags(t)
	loginURL = "http://controller.example.com:9443"

	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires HTTPS")
}

// ── --tls-insecure confirmation gate ──────────────────────────────────────────────

// TestLogin_TLSInsecureRequiresTypedConfirmation covers the session-token confirmation
// gate on this command (Story #396 shape, as enforced at connect.go and
// client_helpers.go). cfg login is the worst case of the three paths: with the server
// certificate unverified it presents the collect verifier as a bearer credential AND
// receives a freshly minted session token in the collect response body, so an
// interposing party harvests a live session outright. Nothing may reach the network
// before the confirmation is given.
func TestLogin_TLSInsecureRequiresTypedConfirmation(t *testing.T) {
	setLoginFlags(t)
	overrideSessionStore(t, newTestSessionStore())
	opener := overrideLoginBrowserOpener(t)

	capt := &loginFlowCapture{}
	srv := newLoginFlowServer(t, "cli-login-test-6", "AAAA-BBBB", capt,
		[]func(w http.ResponseWriter){collectLoginSuccess("sess-insecure", "token-insecure")})
	loginURL = srv.URL
	loginTLSInsecure = true

	// Withhold the confirmation for this run.
	isTTYFn = func() bool { return false }
	t.Setenv("CFGMS_TLS_INSECURE_CONFIRM", "")

	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CFGMS_TLS_INSECURE_CONFIRM=yes")

	capt.mu.Lock()
	lodgeBody := capt.lodgeBody
	capt.mu.Unlock()
	assert.Nil(t, lodgeBody, "no login request may be lodged before the confirmation is given")
	assert.Empty(t, capt.getCollectAuths(),
		"the verifier must never be sent over an unverified connection without confirmation")
	assert.Empty(t, opener.opened(), "no browser may be opened for a login that was refused")

	rec, err := loadSessionToken()
	require.NoError(t, err)
	assert.Nil(t, rec, "a refused confirmation must not leave a session behind")
}

// TestLogin_TLSInsecureViaEnvRequiresTypedConfirmation asserts CFGMS_TLS_INSECURE=true
// in the environment takes the same gate as the flag — the env var must never silently
// downgrade verification for a session-minting command.
func TestLogin_TLSInsecureViaEnvRequiresTypedConfirmation(t *testing.T) {
	setLoginFlags(t)
	overrideSessionStore(t, newTestSessionStore())
	overrideLoginBrowserOpener(t)

	capt := &loginFlowCapture{}
	srv := newLoginFlowServer(t, "cli-login-test-7", "AAAA-BBBB", capt,
		[]func(w http.ResponseWriter){collectLoginSuccess("sess-env", "token-env")})
	loginURL = srv.URL

	loginTLSInsecure = false                   // the flag is off ...
	t.Setenv("CFGMS_TLS_INSECURE", "true")     // ... and only the environment enables it
	isTTYFn = func() bool { return false }     //
	t.Setenv("CFGMS_TLS_INSECURE_CONFIRM", "") // confirmation withheld

	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CFGMS_TLS_INSECURE_CONFIRM=yes")

	capt.mu.Lock()
	lodgeBody := capt.lodgeBody
	capt.mu.Unlock()
	assert.Nil(t, lodgeBody, "the environment variable must not bypass the gate")
}

// TestLogin_TLSInsecureConfirmedProceedsWithWarning is the other half of the gate: once
// confirmed the login completes, and the operator has seen the warning rather than
// being downgraded silently.
func TestLogin_TLSInsecureConfirmedProceedsWithWarning(t *testing.T) {
	setLoginFlags(t)
	warnings := allowTLSInsecureSession(t)
	overrideSessionStore(t, newTestSessionStore())
	overrideLoginBrowserOpener(t)

	const token = "confirmed-session-token-value-0123456789abc"
	capt := &loginFlowCapture{}
	srv := newLoginFlowServer(t, "cli-login-test-8", "AAAA-BBBB", capt,
		[]func(w http.ResponseWriter){collectLoginSuccess("sess-confirmed", token)})
	loginURL = srv.URL
	loginTLSInsecure = true

	require.NoError(t, runLogin(loginCmd, nil))
	assert.Contains(t, warnings.String(), tlsInsecureSessionWarning,
		"the operator must see the warning even on a confirmed run")

	rec, err := loadSessionToken()
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, token, rec.Token)
}

// ── verifier / URL construction ───────────────────────────────────────────────────

func TestGenerateCliLoginVerifier_UniqueAndHashable(t *testing.T) {
	a, err := generateCliLoginVerifier()
	require.NoError(t, err)
	b, err := generateCliLoginVerifier()
	require.NoError(t, err)
	assert.NotEqual(t, a, b, "each verifier must be freshly random")

	hashA := hashCliLoginVerifier(a)
	assert.Len(t, hashA, 64)
	assert.Equal(t, hashA, hashCliLoginVerifier(a), "hashing must be deterministic")
	assert.NotEqual(t, hashA, hashCliLoginVerifier(b))
}

func TestBuildCliLoginConfirmURL_CarriesRequestIDOnly(t *testing.T) {
	u := buildCliLoginConfirmURL("https://controller.example.com:9443", "cli-login-abc123")
	assert.Contains(t, u, "cli-login-abc123")
	assert.Contains(t, u, "https://controller.example.com:9443")
	assert.False(t, strings.Contains(u, "verifier"), "the confirmation URL must never reference a verifier field")
}

// ── revoked-vs-expired existing-session distinction ───────────────────────────────

func newSessionErrorServer(t *testing.T, code string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]interface{}{"code": code, "message": "unauthorized"},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDescribeExistingCliSession_Revoked(t *testing.T) {
	srv := newSessionErrorServer(t, "SESSION_REVOKED")
	overrideSessionStore(t, newTestSessionStore())
	require.NoError(t, storeSessionToken(&sessionRecord{
		Token:          "prior-token",
		SessionID:      "sess-old",
		ControllerURL:  srv.URL,
		ConnectionName: "old",
		AbsoluteExpiry: time.Now().Add(time.Hour),
	}))

	note := describeExistingCliSession(context.Background(), true, "")
	assert.Contains(t, note, "revoked")
	assert.Contains(t, note, "administrator")
}

func TestDescribeExistingCliSession_Expired(t *testing.T) {
	srv := newSessionErrorServer(t, "SESSION_EXPIRED")
	overrideSessionStore(t, newTestSessionStore())
	require.NoError(t, storeSessionToken(&sessionRecord{
		Token:          "prior-token",
		SessionID:      "sess-old",
		ControllerURL:  srv.URL,
		ConnectionName: "old",
		AbsoluteExpiry: time.Now().Add(time.Hour),
	}))

	note := describeExistingCliSession(context.Background(), true, "")
	assert.Contains(t, note, "expired")
	assert.False(t, strings.Contains(note, "revoked"))
}

func TestDescribeExistingCliSession_NoStoredSession(t *testing.T) {
	overrideSessionStore(t, newTestSessionStore())
	note := describeExistingCliSession(context.Background(), true, "")
	assert.Empty(t, note)
}

func TestDescribeExistingCliSession_MessagesAreDistinct(t *testing.T) {
	revokedSrv := newSessionErrorServer(t, "SESSION_REVOKED")
	overrideSessionStore(t, newTestSessionStore())
	require.NoError(t, storeSessionToken(&sessionRecord{
		Token: "t", SessionID: "s", ControllerURL: revokedSrv.URL, AbsoluteExpiry: time.Now().Add(time.Hour),
	}))
	revokedNote := describeExistingCliSession(context.Background(), true, "")

	expiredSrv := newSessionErrorServer(t, "SESSION_EXPIRED")
	require.NoError(t, storeSessionToken(&sessionRecord{
		Token: "t", SessionID: "s", ControllerURL: expiredSrv.URL, AbsoluteExpiry: time.Now().Add(time.Hour),
	}))
	expiredNote := describeExistingCliSession(context.Background(), true, "")

	require.NotEmpty(t, revokedNote)
	require.NotEmpty(t, expiredNote)
	assert.NotEqual(t, revokedNote, expiredNote, "a revoked session and an expired one must render distinct messages")
}
