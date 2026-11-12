// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// webLoginUser is the account the test controller resolves a discoverable
// assertion's userHandle to.
type webLoginUser struct {
	id    []byte
	creds []webauthn.Credential
}

func (u *webLoginUser) WebAuthnID() []byte                         { return u.id }
func (u *webLoginUser) WebAuthnName() string                       { return "operator" }
func (u *webLoginUser) WebAuthnDisplayName() string                { return "Operator" }
func (u *webLoginUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// webLoginServer is a test controller that implements the passkey login, logout and
// session-or-CSRF rules of features/controller/api over TLS, and verifies the login
// assertion with the real go-webauthn discoverable-login verification.
type webLoginServer struct {
	srv  *httptest.Server
	url  string // https://localhost:<port>: go-webauthn requires a domain RP ID
	cert *x509.Certificate
	wa   *webauthn.WebAuthn
	user *webLoginUser

	mu         sync.Mutex
	ceremonies map[string]webauthn.SessionData
	live       map[string]string // session token -> csrf token
	revoked    map[string]bool
	issued     []string // every secret value this server handed out
	requests   int
	finishes   int
	logouts    int
	logoutCSRF []bool // whether each logout carried the session's CSRF token

	beginRPID     string // when set, the begin response names this rpId
	failLogout    bool   // logout answers 500 and revokes nothing
	commandStatus int    // status the command endpoint answers after auth (default 200)
	commandBody   string // body of a non-200 command answer
	finishMessage string // when set, finish answers 401 with this error text
}

const webLoginCommandPath = "/api/v1/things"

func newWebLoginServer(t *testing.T) *webLoginServer {
	t.Helper()
	s := &webLoginServer{
		ceremonies: map[string]webauthn.SessionData{},
		live:       map[string]string{},
		revoked:    map[string]bool{},
		user:       &webLoginUser{id: []byte("user-handle-0123456789")},
	}
	s.srv = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	tlsCert, leaf := newLocalhostTLSCert(t)
	s.cert = leaf
	s.srv.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12}
	s.srv.StartTLS()
	t.Cleanup(s.srv.Close)
	s.url = strings.Replace(s.srv.URL, "127.0.0.1", "localhost", 1)

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          "localhost",
		RPDisplayName: "CFGMS test",
		RPOrigins:     []string{s.url},
	})
	require.NoError(t, err)
	s.wa = wa
	return s
}

// newLocalhostTLSCert generates a self-signed certificate for localhost at test time.
func newLocalhostTLSCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

func (s *webLoginServer) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.cert.Raw}))
}

// httpClient returns a client that trusts the test controller's certificate.
func (s *webLoginServer) httpClient() *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(s.cert)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
}

func (s *webLoginServer) secret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	v := base64.RawURLEncoding.EncodeToString(b)
	s.issued = append(s.issued, v)
	return v
}

func (s *webLoginServer) setCookie(w http.ResponseWriter, name, value string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", Secure: true,
		HttpOnly: httpOnly, SameSite: http.SameSiteStrictMode,
	})
}

func (s *webLoginServer) reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (s *webLoginServer) fail(w http.ResponseWriter, status int, msg string) {
	s.reply(w, status, map[string]string{"error": msg})
}

func (s *webLoginServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	switch {
	case r.Method == http.MethodGet && r.URL.Path == webCSRFPath:
		s.setCookie(w, webPreCSRFCookieName, s.secret(), false)
		s.reply(w, http.StatusOK, map[string]any{"data": map[string]bool{"ok": true}})
	case r.Method == http.MethodPost && r.URL.Path == webLoginBeginPath:
		s.begin(w, r)
	case r.Method == http.MethodPost && r.URL.Path == webLoginFinishPath:
		s.finish(w, r)
	case r.Method == http.MethodPost && r.URL.Path == webLogoutPath:
		s.logout(w, r)
	case r.URL.Path == webLoginCommandPath:
		s.command(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *webLoginServer) begin(w http.ResponseWriter, r *http.Request) {
	pre, err := r.Cookie(webPreCSRFCookieName)
	hdr := r.Header.Get("X-CSRF-Token")
	if err != nil || pre.Value == "" || hdr == "" || subtle.ConstantTimeCompare([]byte(pre.Value), []byte(hdr)) != 1 {
		s.fail(w, http.StatusForbidden, "CSRF token missing or mismatched")
		return
	}
	assertion, sd, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "begin failed")
		return
	}
	id := s.secret()
	s.ceremonies[id] = *sd
	s.setCookie(w, "__Host-cfgms_passkey_ceremony", id, true)
	if s.beginRPID != "" {
		assertion.Response.RelyingPartyID = s.beginRPID
	}
	s.reply(w, http.StatusOK, map[string]any{"data": assertion})
}

func (s *webLoginServer) finish(w http.ResponseWriter, r *http.Request) {
	s.finishes++
	if s.finishMessage != "" {
		s.fail(w, http.StatusUnauthorized, s.finishMessage)
		return
	}
	c, err := r.Cookie("__Host-cfgms_passkey_ceremony")
	if err != nil {
		s.fail(w, http.StatusBadRequest, "no ceremony")
		return
	}
	sd, ok := s.ceremonies[c.Value]
	delete(s.ceremonies, c.Value)
	if !ok {
		s.fail(w, http.StatusBadRequest, "unknown ceremony")
		return
	}
	_, err = s.wa.FinishDiscoverableLogin(func(_, handle []byte) (webauthn.User, error) {
		if !bytes.Equal(handle, s.user.id) {
			return nil, fmt.Errorf("unknown user handle")
		}
		return s.user, nil
	}, sd, r)
	if err != nil {
		s.fail(w, http.StatusUnauthorized, "assertion rejected")
		return
	}
	session, csrf := s.secret(), s.secret()
	s.live[session] = csrf
	s.setCookie(w, webSessionCookieName, session, true)
	s.setCookie(w, webCSRFCookieName, csrf, false)
	s.reply(w, http.StatusOK, map[string]any{"data": map[string]bool{"ok": true}})
}

// session returns the live session token the request's cookie names.
func (s *webLoginServer) session(r *http.Request) (string, bool) {
	c, err := r.Cookie(webSessionCookieName)
	if err != nil || s.revoked[c.Value] {
		return "", false
	}
	_, ok := s.live[c.Value]
	return c.Value, ok
}

func (s *webLoginServer) csrfOK(r *http.Request, session string) bool {
	h := r.Header.Get("X-CSRF-Token")
	return h != "" && subtle.ConstantTimeCompare([]byte(h), []byte(s.live[session])) == 1
}

func (s *webLoginServer) logout(w http.ResponseWriter, r *http.Request) {
	s.logouts++
	session, ok := s.session(r)
	if !ok {
		s.fail(w, http.StatusUnauthorized, "Session expired or invalid")
		return
	}
	csrfOK := s.csrfOK(r, session)
	s.logoutCSRF = append(s.logoutCSRF, csrfOK)
	if !csrfOK {
		s.fail(w, http.StatusForbidden, "CSRF token mismatch")
		return
	}
	if s.failLogout {
		s.fail(w, http.StatusInternalServerError, "revocation failed")
		return
	}
	s.revoked[session] = true
	delete(s.live, session)
	s.reply(w, http.StatusOK, map[string]any{"data": map[string]bool{"ok": true}})
}

func (s *webLoginServer) command(w http.ResponseWriter, r *http.Request) {
	session, ok := s.session(r)
	if !ok {
		s.fail(w, http.StatusUnauthorized, "Session expired or invalid")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !s.csrfOK(r, session) {
		s.fail(w, http.StatusForbidden, "CSRF token mismatch")
		return
	}
	if s.commandStatus != 0 && s.commandStatus != http.StatusOK {
		s.reply(w, s.commandStatus, map[string]string{"error": s.commandBody})
		return
	}
	s.reply(w, http.StatusOK, map[string]any{"data": map[string]bool{"ok": true}})
}

// stats returns a consistent snapshot of the counters.
func (s *webLoginServer) stats() (requests, finishes, logouts int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests, s.finishes, s.logouts
}

func (s *webLoginServer) secrets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.issued...)
}

// webLoginFixture is a registered software authenticator bound to a webLoginServer,
// with the credential store, session store and command-line state isolated.
type webLoginFixture struct {
	*webLoginServer
	name      string
	configDir string
	sessions  *testSessionStore
}

// newWebLoginFixture creates and registers an authenticator named agent-1 against a
// fresh test controller. mutate edits the record before it is stored.
func newWebLoginFixture(t *testing.T, mutate func(rec *authenticatorRecord, srv *webLoginServer)) *webLoginFixture {
	t.Helper()
	srv := newWebLoginServer(t)

	configDir := t.TempDir()
	overrideCredentialsDir(t, filepath.Join(configDir, "credentials"))
	sessions := newTestSessionStore()
	overrideSessionStore(t, sessions)

	rec, err := newAuthenticatorRecord("agent-1")
	require.NoError(t, err)
	rec.RPID = "localhost"
	rec.Origin = srv.url
	rec.ControllerURL = srv.url
	rec.CACertPEM = srv.caPEM()
	rec.UserHandle = srv.user.id
	rec.Registered = true
	if mutate != nil {
		mutate(rec, srv)
	}

	// Register the credential with the controller through the real ceremony.
	a, err := rec.authenticator()
	require.NoError(t, err)
	creation, sd, err := srv.wa.BeginRegistration(srv.user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification:   protocol.VerificationRequired,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		}))
	require.NoError(t, err)
	opts, err := json.Marshal(creation)
	require.NoError(t, err)
	body, err := a.Register(opts)
	require.NoError(t, err)
	cred, err := srv.wa.FinishRegistration(srv.user, *sd, httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body)))
	require.NoError(t, err)
	srv.user.creds = []webauthn.Credential{*cred}

	store, err := newCredentialStore()
	require.NoError(t, err)
	require.NoError(t, saveAuthenticatorRecord(context.Background(), store, rec))

	// Command-line state is global: restore it after the test.
	origSel, origBundle, origNoBundle, origVerbose := authenticatorSelection, bundlePath, noBundle, verbose
	t.Cleanup(func() {
		authenticatorSelection, bundlePath, noBundle, verbose = origSel, origBundle, origNoBundle, origVerbose
		closeWebSessions()
	})
	authenticatorSelection = "agent-1"
	t.Setenv("CFGMS_API_URL", "")
	t.Setenv("CFGMS_TLS_INSECURE", "")
	t.Setenv(authenticatorEnvVar, "")

	return &webLoginFixture{webLoginServer: srv, name: "agent-1", configDir: configDir, sessions: sessions}
}

// captured is everything a command run printed.
type captured struct {
	stdout, stderr, warn string
}

func (c captured) all() string { return c.stdout + "\n" + c.stderr + "\n" + c.warn }

// runProbeCommand runs a cobra command that resolves a client the way every cfg
// command does (requireSessionOrBundleClient), then POSTs to the test controller's
// command endpoint. Output through cobra, os.Stdout, os.Stderr and the logout
// warning writer is captured. Cobra's finalizers run, as they do for cfg.
func runProbeCommand(t *testing.T, apiURL string) (captured, error) {
	t.Helper()
	outDir := t.TempDir()
	stdoutF, err := os.Create(filepath.Join(outDir, "stdout"))
	require.NoError(t, err)
	stderrF, err := os.Create(filepath.Join(outDir, "stderr"))
	require.NoError(t, err)
	origOut, origErr, origWarn := os.Stdout, os.Stderr, webSessionWarnWriter
	os.Stdout, os.Stderr = stdoutF, stderrF
	var warn bytes.Buffer
	webSessionWarnWriter = &warn

	var cobraOut bytes.Buffer
	probe := &cobra.Command{
		Use:           "probe",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := requireSessionOrBundleClient(apiURL, false, "")
			if err != nil {
				return err
			}
			resp, err := client.doRequest(context.Background(), http.MethodPost, webLoginCommandPath, strings.NewReader(`{"name":"x"}`))
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				return client.parseError(resp)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "command ok")
			return nil
		},
	}
	probe.SetOut(&cobraOut)
	probe.SetErr(&cobraOut)
	probe.SetArgs(nil)
	runErr := probe.Execute()

	os.Stdout, os.Stderr, webSessionWarnWriter = origOut, origErr, origWarn
	require.NoError(t, stdoutF.Close())
	require.NoError(t, stderrF.Close())
	so, err := os.ReadFile(filepath.Join(outDir, "stdout"))
	require.NoError(t, err)
	se, err := os.ReadFile(filepath.Join(outDir, "stderr"))
	require.NoError(t, err)
	out := captured{stdout: string(so) + cobraOut.String(), stderr: string(se), warn: warn.String()}
	if runErr != nil {
		out.stderr += "\nError: " + runErr.Error() // what main prints for a failed command
	}
	return out, runErr
}

// replay sends a request carrying only the given session cookie, as an attacker who
// captured it would.
func (f *webLoginFixture) replay(t *testing.T, session string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.url+webLoginCommandPath, nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: webSessionCookieName, Value: session})
	resp, err := f.httpClient().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// sessionTokens returns the session cookie values the server issued (live or revoked).
func (f *webLoginFixture) sessionTokens() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for tok := range f.live {
		out = append(out, tok)
	}
	for tok := range f.revoked {
		out = append(out, tok)
	}
	return out
}

func TestAuthenticatorFlag_RegisteredOnRoot(t *testing.T) {
	f := rootCmd.PersistentFlags().Lookup("authenticator")
	require.NotNil(t, f, "--authenticator must be a persistent flag on the root command")
	assert.Contains(t, f.Usage, authenticatorEnvVar)
	assert.Empty(t, f.DefValue)
}

func TestSelectedAuthenticator_FlagThenEnv(t *testing.T) {
	orig := authenticatorSelection
	t.Cleanup(func() { authenticatorSelection = orig })

	authenticatorSelection = ""
	t.Setenv(authenticatorEnvVar, "")
	assert.Empty(t, selectedAuthenticator())

	t.Setenv(authenticatorEnvVar, "from-env")
	assert.Equal(t, "from-env", selectedAuthenticator())

	authenticatorSelection = "from-flag"
	assert.Equal(t, "from-flag", selectedAuthenticator(), "the flag wins over the environment")
}

// Required: the login succeeds against a controller that performs the real
// go-webauthn discoverable-login verification, a following unsafe request carries the
// session cookie and a matching X-CSRF-Token, and the same request without the header
// is refused by that server.
func TestAuthenticatorLogin_SessionCookieAndCSRFHeader(t *testing.T) {
	f := newWebLoginFixture(t, nil)

	out, err := runProbeCommand(t, "")
	require.NoError(t, err, out.all())
	assert.Contains(t, out.stdout, "command ok", "the command's request carried the cookie and a matching X-CSRF-Token")
	_, finishes, _ := f.stats()
	assert.Equal(t, 1, finishes)

	// Same request, no CSRF header: refused by the controller.
	client, closeFn, err := loginWithAuthenticator(context.Background(), f.name, "", false, "")
	require.NoError(t, err)
	defer closeFn()
	resp, err := client.httpClient.Post(f.url+webLoginCommandPath, "application/json", strings.NewReader(`{}`))
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "the cookie alone must not authorise an unsafe request")

	// And the client's own request, which adds the header, is accepted.
	resp, err = client.doRequest(context.Background(), http.MethodPost, webLoginCommandPath, strings.NewReader(`{}`))
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Required: after a command that succeeds, and after one that fails, the
// server-side session is gone: it was revoked via POST /api/v1/web/logout (with the
// CSRF header) and replaying the captured cookie is refused.
func TestAuthenticatorLogin_SessionEndedAfterSuccessAndFailure(t *testing.T) {
	cases := map[string]struct {
		status  int
		wantErr bool
	}{
		"command succeeds": {status: http.StatusOK},
		"command fails":    {status: http.StatusInternalServerError, wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newWebLoginFixture(t, nil)
			f.commandStatus = tc.status
			f.commandBody = "boom"

			out, err := runProbeCommand(t, "")
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err, out.all())
			}

			_, _, logouts := f.stats()
			assert.Equal(t, 1, logouts, "exactly one POST /api/v1/web/logout")
			assert.Equal(t, []bool{true}, f.logoutCSRF, "logout carried the session CSRF token")
			tokens := f.sessionTokens()
			require.Len(t, tokens, 1)
			assert.True(t, f.revoked[tokens[0]], "the server shows the session revoked")
			assert.Equal(t, http.StatusUnauthorized, f.replay(t, tokens[0]), "the captured cookie is refused")
			assert.Empty(t, out.warn, "a clean logout prints no warning")
		})
	}
}

// Required: a failing logout does not change the command's result and prints only a
// warning that names no cookie or token value.
func TestAuthenticatorLogin_FailingLogoutOnlyWarns(t *testing.T) {
	t.Run("command succeeds", func(t *testing.T) {
		f := newWebLoginFixture(t, nil)
		f.failLogout = true

		out, err := runProbeCommand(t, "")
		require.NoError(t, err, "a failed logout must not fail a successful command")
		assert.Contains(t, out.stdout, "command ok")
		assert.Contains(t, out.warn, "Warning")
		assert.Contains(t, out.warn, "500")
		assertNoSecrets(t, f.secrets(), out.all())
	})
	t.Run("command fails", func(t *testing.T) {
		f := newWebLoginFixture(t, nil)
		f.failLogout = true
		f.commandStatus = http.StatusBadRequest
		f.commandBody = "bad request"

		out, err := runProbeCommand(t, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bad request", "the command's own error is not replaced by the logout warning")
		assert.NotContains(t, err.Error(), "logout")
		assert.Contains(t, out.warn, "Warning")
	})
	t.Run("controller unreachable", func(t *testing.T) {
		f := newWebLoginFixture(t, nil)
		client, closeFn, err := loginWithAuthenticator(context.Background(), f.name, "", false, "")
		require.NoError(t, err)
		require.NotNil(t, client)
		f.srv.CloseClientConnections()
		f.srv.Close()

		var warn bytes.Buffer
		orig := webSessionWarnWriter
		webSessionWarnWriter = &warn
		t.Cleanup(func() { webSessionWarnWriter = orig })
		closeFn()
		assert.Contains(t, warn.String(), "Warning")
		assertNoSecrets(t, f.secrets(), warn.String())
	})
}

// The close function is idempotent: a second call makes no second logout request.
func TestAuthenticatorLogin_CloseIsIdempotent(t *testing.T) {
	f := newWebLoginFixture(t, nil)
	_, closeFn, err := loginWithAuthenticator(context.Background(), f.name, "", false, "")
	require.NoError(t, err)
	closeFn()
	closeFn()
	_, _, logouts := f.stats()
	assert.Equal(t, 1, logouts)
}

// Required: an http:// controller URL in the record is refused before any network
// call, no TLS-skip is offered, and certificate verification is on.
func TestAuthenticatorLogin_RefusesHTTPAndNeverSkipsTLSVerification(t *testing.T) {
	t.Run("http controller url in the record", func(t *testing.T) {
		f := newWebLoginFixture(t, func(rec *authenticatorRecord, srv *webLoginServer) {
			rec.ControllerURL = strings.Replace(srv.url, "https://", "http://", 1)
		})
		_, err := runProbeCommand(t, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
		requests, _, _ := f.stats()
		assert.Zero(t, requests, "no network call before the refusal")
	})

	t.Run("tls-insecure flag or env is refused", func(t *testing.T) {
		f := newWebLoginFixture(t, nil)
		_, closeFn, err := loginWithAuthenticator(context.Background(), f.name, "", true, "")
		require.Error(t, err)
		assert.Nil(t, closeFn)
		assert.Contains(t, err.Error(), "--tls-insecure")

		t.Setenv("CFGMS_TLS_INSECURE", "true")
		_, err = requireSessionOrBundleClient("", true, "")
		require.Error(t, err)
		requests, _, _ := f.stats()
		assert.Zero(t, requests)
	})

	t.Run("an untrusted controller certificate fails the login", func(t *testing.T) {
		f := newWebLoginFixture(t, func(rec *authenticatorRecord, _ *webLoginServer) {
			rec.CACertPEM = "" // system pool: the test controller's certificate is not in it
		})
		_, err := runProbeCommand(t, "")
		require.Error(t, err)
		assert.Contains(t, strings.ToLower(err.Error()), "certificate")
		_, finishes, _ := f.stats()
		assert.Zero(t, finishes, "nothing is signed for an unverified controller")
	})

	t.Run("no cfg flag skips verification with an authenticator", func(t *testing.T) {
		_, err := NewAPIClient(&APIClientConfig{BaseURL: "https://controller.example.test", WebSession: true, TLSInsecure: true})
		require.Error(t, err)
	})
}

// Required: the cookie value and CSRF token never appear in stdout, stderr or
// verbose output, on success or failure.
func TestAuthenticatorLogin_SecretsNeverPrinted(t *testing.T) {
	cases := map[string]func(f *webLoginFixture){
		"success": func(f *webLoginFixture) {},
		"command fails": func(f *webLoginFixture) {
			f.commandStatus = http.StatusInternalServerError
			f.commandBody = "command failed"
		},
		"logout fails": func(f *webLoginFixture) { f.failLogout = true },
		"command and logout": func(f *webLoginFixture) {
			f.commandStatus = http.StatusBadGateway
			f.commandBody = "bad"
			f.failLogout = true
		},
		"login finish refused": func(f *webLoginFixture) { f.finishMessage = "denied" },
	}
	for name, setup := range cases {
		for _, isVerbose := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/verbose=%t", name, isVerbose), func(t *testing.T) {
				f := newWebLoginFixture(t, nil)
				setup(f)
				verbose = isVerbose
				out, _ := runProbeCommand(t, "")
				secrets := f.secrets()
				require.NotEmpty(t, secrets)
				assertNoSecrets(t, secrets, out.all())
			})
		}
	}
}

// assertNoSecrets fails when any value the controller issued appears in text.
func assertNoSecrets(t *testing.T, secrets []string, texts ...string) {
	t.Helper()
	for _, text := range texts {
		for _, s := range secrets {
			assert.NotContains(t, text, s, "a cookie or CSRF value leaked")
		}
	}
}

// Required: after the command finishes, no session token, cookie value or CSRF value
// exists in the credentials directory, the session-token store or any file under the
// test config dir.
func TestAuthenticatorLogin_NothingPersisted(t *testing.T) {
	for _, failCommand := range []bool{false, true} {
		t.Run(fmt.Sprintf("command fails=%t", failCommand), func(t *testing.T) {
			f := newWebLoginFixture(t, nil)
			if failCommand {
				f.commandStatus = http.StatusInternalServerError
			}
			before := listFiles(t, f.configDir)

			_, _ = runProbeCommand(t, "")
			secrets := f.secrets()
			require.NotEmpty(t, secrets)

			after := listFiles(t, f.configDir)
			assert.Equal(t, before, after, "the command writes no file")
			for _, p := range after {
				raw, err := os.ReadFile(p)
				require.NoError(t, err)
				for _, s := range secrets {
					assert.False(t, bytes.Contains(raw, []byte(s)), "secret value found in %s", p)
				}
			}

			rec, err := loadSessionToken()
			require.NoError(t, err)
			assert.Nil(t, rec, "no session record in the session-token store")
			f.sessions.mu.Lock()
			assert.Empty(t, f.sessions.secrets, "the session-token store is untouched")
			f.sessions.mu.Unlock()
		})
	}
}

func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if !d.IsDir() {
			files = append(files, p)
		}
		return nil
	}))
	return files
}

// Required: --authenticator together with --bundle (or --no-bundle) fails with a clear
// error and makes no network call.
func TestAuthenticatorLogin_ConflictsWithBundleFlags(t *testing.T) {
	cases := map[string]func(){
		"--bundle":    func() { bundlePath = filepath.Join(t.TempDir(), "admin.bundle.yaml") },
		"--no-bundle": func() { noBundle = true },
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			f := newWebLoginFixture(t, nil)
			set()
			_, err := runProbeCommand(t, "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "provide exactly one credential")
			assert.Contains(t, err.Error(), "--authenticator")
			requests, _, _ := f.stats()
			assert.Zero(t, requests)
		})
	}
}

// Required: an unregistered record fails before any network call, naming the remedy.
func TestAuthenticatorLogin_UnregisteredRecordRefused(t *testing.T) {
	f := newWebLoginFixture(t, func(rec *authenticatorRecord, _ *webLoginServer) { rec.Registered = false })
	_, err := runProbeCommand(t, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cfg authenticator enroll")
	requests, _, _ := f.stats()
	assert.Zero(t, requests)
}

func TestAuthenticatorLogin_MissingAuthenticatorRefused(t *testing.T) {
	f := newWebLoginFixture(t, nil)
	authenticatorSelection = "no-such"
	_, err := runProbeCommand(t, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, errAuthenticatorNotFound)
	authenticatorSelection = "bad/name"
	_, err = runProbeCommand(t, "")
	require.Error(t, err)
	requests, _, _ := f.stats()
	assert.Zero(t, requests)
}

// Required: a login assertion is refused client-side when the controller's begin
// response names an rpId different from the record's: nothing is signed or sent.
func TestAuthenticatorLogin_RPIDMismatchRefusedClientSide(t *testing.T) {
	f := newWebLoginFixture(t, nil)
	f.beginRPID = "evil.example"

	out, err := runProbeCommand(t, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rpId")
	_, finishes, _ := f.stats()
	assert.Zero(t, finishes, "no assertion is sent to the controller")
	assert.Empty(t, f.sessionTokens())
	assertNoSecrets(t, f.secrets(), out.all())
}

// A login the controller rejects fails the command; the server's text is sanitised
// and no session is left behind.
func TestAuthenticatorLogin_FinishRejectedSanitisesServerText(t *testing.T) {
	f := newWebLoginFixture(t, nil)
	f.finishMessage = "denied\nINJECTED line\r\x1b[31m"

	_, err := runProbeCommand(t, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.Contains(t, err.Error(), "denied")
	assert.NotContains(t, err.Error(), "\n")
	assert.NotContains(t, err.Error(), "\r")
	assert.NotContains(t, err.Error(), "\x1b")
	_, _, logouts := f.stats()
	assert.Zero(t, logouts, "no session was issued, so nothing is logged out")
}

// The authenticator is bound to one controller: a different --url / CFGMS_API_URL is
// refused before any network call, the same URL is accepted.
func TestAuthenticatorLogin_APIURLMustMatchRecord(t *testing.T) {
	f := newWebLoginFixture(t, nil)
	_, err := runProbeCommand(t, "https://other.example.test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bound to")
	requests, _, _ := f.stats()
	assert.Zero(t, requests)

	out, err := runProbeCommand(t, f.url+"/")
	require.NoError(t, err, out.all())
}

// CFGMS_AUTHENTICATOR selects the authenticator when --authenticator is not given.
func TestAuthenticatorLogin_EnvSelectsAuthenticator(t *testing.T) {
	f := newWebLoginFixture(t, nil)
	authenticatorSelection = ""
	t.Setenv(authenticatorEnvVar, f.name)

	out, err := runProbeCommand(t, "")
	require.NoError(t, err, out.all())
	assert.Contains(t, out.stdout, "command ok")
	_, _, logouts := f.stats()
	assert.Equal(t, 1, logouts)
}

// Every command that resolves a client through resolveSessionOrBundleClient is
// covered: here the real `cfg token list` runs through the root command with the
// persistent flag and uses the web session for its (safe-method) request.
func TestAuthenticatorFlag_DrivesRealCommandThroughRoot(t *testing.T) {
	f := newWebLoginFixture(t, nil)
	authenticatorSelection = ""

	rootCmd.SetArgs([]string{"token", "list", "--authenticator", f.name})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})
	// The test controller only serves its own endpoints, so the list request itself
	// is answered 404; what matters is that the login ran and the session was ended.
	err := rootCmd.Execute()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "bundle lookup failed")

	_, finishes, logouts := f.stats()
	assert.Equal(t, 1, finishes, "the persistent flag selected the authenticator")
	assert.Equal(t, 1, logouts, "the session ended with the command")
	assertNoSecrets(t, f.secrets(), out.String(), err.Error())
}
