// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/softauthn"
)

// testEnrollToken is generated per test process, so no token-shaped literal is committed.
var testEnrollToken = func() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}()

// enrollTestServer is a TLS test server for the enrollment routes. It runs the real
// go-webauthn registration verification, keyed by the X-Enrollment-Token header, the
// way the controller's base-router routes do.
type enrollTestServer struct {
	srv *httptest.Server
	wa  *webauthn.WebAuthn
	// origin is the WebAuthn origin the records are bound to. The connection URL is the
	// test server's IP address, which is not a valid RP ID, so the RP ID and origin use a
	// name and the record's controller URL (srv.URL) is what the client connects to.
	origin string

	mu         sync.Mutex
	requests   int
	tokens     []string
	sessions   map[string]webauthn.SessionData
	finishRaw  []byte
	finishURL  string
	refuse     bool // finish answers the software-authenticator policy refusal
	registered *webauthn.Credential
}

func newEnrollTestServer(t *testing.T) *enrollTestServer {
	t.Helper()
	es := &enrollTestServer{sessions: map[string]webauthn.SessionData{}}
	es.srv = httptest.NewTLSServer(http.HandlerFunc(es.handle))
	t.Cleanup(es.srv.Close)

	u, err := url.Parse(es.srv.URL)
	require.NoError(t, err)
	es.origin = "https://" + testAuthRPID + ":" + u.Port()
	es.wa, err = webauthn.New(&webauthn.Config{
		RPID:          testAuthRPID,
		RPDisplayName: "CFGMS test",
		RPOrigins:     []string{es.origin},
	})
	require.NoError(t, err)
	return es
}

func (es *enrollTestServer) requestCount() int {
	es.mu.Lock()
	defer es.mu.Unlock()
	return es.requests
}

func writeTestAPIError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (es *enrollTestServer) handle(w http.ResponseWriter, r *http.Request) {
	es.mu.Lock()
	defer es.mu.Unlock()
	es.requests++
	token := r.Header.Get("X-Enrollment-Token")
	es.tokens = append(es.tokens, token)
	if r.Method != http.MethodPost || token != testEnrollToken {
		writeTestAPIError(w, http.StatusUnauthorized, "TOKEN_INVALID", "Invalid or expired enrollment token")
		return
	}
	user := &authTestUser{}
	switch r.URL.Path {
	case enrollBeginPath:
		creation, session, err := es.wa.BeginRegistration(user,
			webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				UserVerification:   protocol.VerificationRequired,
				ResidentKey:        protocol.ResidentKeyRequirementRequired,
				RequireResidentKey: protocol.ResidentKeyRequired(),
			}))
		if err != nil {
			writeTestAPIError(w, http.StatusInternalServerError, "WEBAUTHN_BEGIN_ERROR", "begin failed")
			return
		}
		es.sessions[token] = *session
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": creation})
	case enrollFinishPath:
		session, ok := es.sessions[token]
		delete(es.sessions, token)
		if !ok {
			writeTestAPIError(w, http.StatusBadRequest, "NO_ACTIVE_ENROLLMENT", "No active enrollment session")
			return
		}
		raw := new(bytes.Buffer)
		_, _ = raw.ReadFrom(r.Body)
		es.finishRaw = raw.Bytes()
		es.finishURL = r.URL.String()
		r.Body = readCloser{bytes.NewReader(es.finishRaw)}
		cred, err := es.wa.FinishRegistration(user, session, r)
		if err != nil {
			writeTestAPIError(w, http.StatusBadRequest, "WEBAUTHN_VERIFY_ERROR", "WebAuthn verification failed")
			return
		}
		if es.refuse {
			writeTestAPIError(w, http.StatusForbidden, "SOFTWARE_AUTHENTICATOR_NOT_ALLOWED",
				"A software authenticator is not permitted for this account")
			return
		}
		es.registered = cred
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"credential_id": cred.ID}})
	default:
		http.NotFound(w, r)
	}
}

type readCloser struct{ *bytes.Reader }

func (readCloser) Close() error { return nil }

// enrollTestRecord creates authenticator name bound to es (connection URL, origin and
// RP ID of the test server, its certificate pinned as the CA).
func enrollTestRecord(t *testing.T, es *enrollTestServer, name string) *CredentialStore {
	t.Helper()
	_, store := authTestStore(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: es.srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))
	out, err := runAuthenticator(t, "", "create", "--key-provider", "store", name, "--url", es.srv.URL,
		"--rp-id", testAuthRPID, "--origin", es.origin, "--ca-cert", caPath)
	require.NoError(t, err, out)
	return store
}

// runEnroll executes `authenticator enroll <args...>` on a fresh tree that includes
// the enroll subcommand.
func runEnroll(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	root := newAuthenticatorCmd()
	root.AddCommand(newAuthenticatorEnrollCmd())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append([]string{"enroll"}, args...))
	err := root.Execute()
	return out.String(), err
}

func writeLinkFile(t *testing.T, link string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "link.txt")
	require.NoError(t, os.WriteFile(p, []byte(link+"\n"), 0o600))
	return p
}

func enrollLink(es *enrollTestServer) string {
	return es.origin + "/enroll/" + testEnrollToken
}

func TestAuthenticatorEnroll_RegisteredOnRootCommand(t *testing.T) {
	verbs := map[string]bool{}
	for _, c := range authenticatorCmd.Commands() {
		verbs[c.Name()] = true
	}
	assert.True(t, verbs["enroll"], "enroll must be registered on authenticatorCmd by its init")
}

// Required: against real go-webauthn registration verification, enroll succeeds and
// the record becomes registered with a user handle. Both calls carry the token header.
func TestAuthenticatorEnroll_SucceedsAndRecordsRegistered(t *testing.T) {
	es := newEnrollTestServer(t)
	store := enrollTestRecord(t, es, "agent-1")
	link := writeLinkFile(t, enrollLink(es))

	out, err := runEnroll(t, "", "agent-1", "--link-file", link)
	require.NoError(t, err, out)
	assert.Contains(t, out, "enrolled")

	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.True(t, rec.Registered)
	assert.Equal(t, (&authTestUser{}).WebAuthnID(), rec.UserHandle)

	es.mu.Lock()
	defer es.mu.Unlock()
	require.NotNil(t, es.registered, "the server's real verification accepted the registration")
	assert.Equal(t, rec.CredentialID, es.registered.ID)
	assert.Equal(t, softauthn.AAGUID[:], es.registered.Authenticator.AAGUID)
	assert.Equal(t, []string{testEnrollToken, testEnrollToken}, es.tokens, "begin and finish both carry X-Enrollment-Token")

	// The stored record can sign a later assertion with the recorded handle.
	a, err := rec.authenticator()
	require.NoError(t, err)
	assert.NotNil(t, a)
}

func TestAuthenticatorEnroll_PassesRecordLabelToFinish(t *testing.T) {
	es := newEnrollTestServer(t)
	authTestStore(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: es.srv.Certificate().Raw}), 0o600))
	out, err := runAuthenticator(t, "", "create", "--key-provider", "store", "labelled", "--url", es.srv.URL,
		"--rp-id", testAuthRPID, "--origin", es.origin, "--ca-cert", caPath, "--label", "agent one")
	require.NoError(t, err, out)

	out, err = runEnroll(t, "", "labelled", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.NoError(t, err, out)
	es.mu.Lock()
	defer es.mu.Unlock()
	assert.Contains(t, es.finishURL, "label=agent+one")
}

// Required: a link whose host differs from the record's origin is refused before any
// network call.
func TestAuthenticatorEnroll_LinkHostMismatchRefusedBeforeNetwork(t *testing.T) {
	es := newEnrollTestServer(t)
	store := enrollTestRecord(t, es, "agent-1")

	for _, link := range []string{
		"https://other.example.test/enroll/" + testEnrollToken,
		es.origin + ".evil.test/enroll/" + testEnrollToken,
		"https://" + testAuthRPID + ":1/enroll/" + testEnrollToken,
		"http://" + strings.TrimPrefix(es.origin, "https://") + "/enroll/" + testEnrollToken,
	} {
		out, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, link))
		require.Error(t, err, link)
		assert.NotContains(t, out+err.Error(), testEnrollToken)
	}
	_, err := runEnroll(t, "", "agent-1", "--link-file",
		writeLinkFile(t, "https://other.example.test/enroll/"+testEnrollToken))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "different controller")
	assert.Contains(t, err.Error(), "nothing was sent")

	assert.Zero(t, es.requestCount(), "no request may reach the server")
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.False(t, rec.Registered)
}

func TestAuthenticatorEnroll_MalformedLinksRefused(t *testing.T) {
	es := newEnrollTestServer(t)
	enrollTestRecord(t, es, "agent-1")

	for name, link := range map[string]string{
		"no-enroll-segment": es.origin + "/other/" + testEnrollToken,
		"short-token":       es.origin + "/enroll/abc",
		"bad-token-chars":   es.origin + "/enroll/" + strings.Repeat("a b", 10),
		"not-a-url":         "::::",
		"credentials":       strings.Replace(es.origin, "https://", "https://user:pw@", 1) + "/enroll/" + testEnrollToken,
		"empty":             "",
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, link))
			require.Error(t, err)
			assert.NotContains(t, out+err.Error(), testEnrollToken)
		})
	}
	assert.Zero(t, es.requestCount())
}

func TestAuthenticatorEnroll_UnknownAuthenticatorRefused(t *testing.T) {
	es := newEnrollTestServer(t)
	enrollTestRecord(t, es, "agent-1")
	_, err := runEnroll(t, "", "missing", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.Error(t, err)
	assert.Zero(t, es.requestCount())
}

// Required: a 403 policy refusal leaves the record unregistered and exits non-zero,
// and the server code is shown.
func TestAuthenticatorEnroll_PolicyRefusalLeavesRecordUnregistered(t *testing.T) {
	es := newEnrollTestServer(t)
	es.refuse = true
	store := enrollTestRecord(t, es, "agent-1")

	out, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.Contains(t, err.Error(), "SOFTWARE_AUTHENTICATOR_NOT_ALLOWED")
	assert.NotContains(t, out+err.Error(), testEnrollToken)

	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.False(t, rec.Registered)
	assert.Empty(t, rec.UserHandle)
}

func TestAuthenticatorEnroll_BadTokenRefusedByServer(t *testing.T) {
	es := newEnrollTestServer(t)
	store := enrollTestRecord(t, es, "agent-1")
	wrong := es.origin + "/enroll/" + strings.Repeat("f", 40)

	out, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, wrong))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.Contains(t, err.Error(), "TOKEN_INVALID")
	assert.NotContains(t, out+err.Error(), strings.Repeat("f", 40))
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.False(t, rec.Registered)
}

// The controller's TLS certificate is always verified: without the pinned CA the
// enrollment fails and the token is not sent in the clear to an untrusted peer.
func TestAuthenticatorEnroll_UntrustedControllerCertificateRefused(t *testing.T) {
	es := newEnrollTestServer(t)
	_, store := authTestStore(t)
	out, err := runAuthenticator(t, "", "create", "--key-provider", "store", "no-ca", "--url", es.srv.URL,
		"--rp-id", testAuthRPID, "--origin", es.origin)
	require.NoError(t, err, out)

	out, err = runEnroll(t, "", "no-ca", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.Error(t, err)
	assert.NotContains(t, out+err.Error(), testEnrollToken)
	assert.Zero(t, es.requestCount(), "the handshake fails before any request is served")
	rec, err := loadAuthenticatorRecord(context.Background(), store, "no-ca")
	require.NoError(t, err)
	assert.False(t, rec.Registered)
}

func TestAuthenticatorEnroll_DoesNotFollowRedirects(t *testing.T) {
	var leaked bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = true
	}))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	rec := &authenticatorRecord{Name: "r", ControllerURL: redirector.URL}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: redirector.Certificate().Raw})
	caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw})...)
	rec.CACertPEM = string(caPEM)
	c, err := newEnrollClient(rec)
	require.NoError(t, err)

	_, err = c.begin(context.Background(), testEnrollToken)
	require.Error(t, err)
	assert.False(t, leaked, "the token header must not follow a redirect")
}

// Required: the token never appears in stdout, stderr or the stored record, and no
// flag of enroll accepts the link or token as a value (flag list asserted).
func TestAuthenticatorEnroll_TokenNeverLeaksAndNoValueFlag(t *testing.T) {
	es := newEnrollTestServer(t)
	store := enrollTestRecord(t, es, "agent-1")

	out, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.NoError(t, err, out)
	assert.NotContains(t, out, testEnrollToken)
	assert.NotContains(t, out, "/enroll/")

	raw, err := store.Load(context.Background(), authenticatorCredentialName("agent-1"))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), testEnrollToken)

	entries, err := os.ReadDir(store.dir)
	require.NoError(t, err)
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(store.dir, e.Name()))
		require.NoError(t, err)
		assert.NotContains(t, string(data), testEnrollToken, e.Name())
	}

	enroll := newAuthenticatorEnrollCmd()
	var names []string
	enroll.Flags().VisitAll(func(f *pflag.Flag) { names = append(names, f.Name) })
	assert.ElementsMatch(t, []string{"link-file", "link-stdin"}, names,
		"enroll takes the link only from a file or stdin")
	for _, n := range names {
		assert.NotContains(t, n, "token")
		assert.NotEqual(t, "link", n)
	}
	// The link as a flag value is refused by the parser.
	_, err = runEnroll(t, "", "agent-1", "--link", enrollLink(es))
	require.Error(t, err)
	_, err = runEnroll(t, "", "agent-1", "--token", testEnrollToken)
	require.Error(t, err)
}

// Required: the link is read from a file, from stdin and from CFGMS_ENROLLMENT_LINK.
func TestAuthenticatorEnroll_LinkSources(t *testing.T) {
	cases := map[string]func(t *testing.T, es *enrollTestServer) (stdin string, args []string){
		"file": func(t *testing.T, es *enrollTestServer) (string, []string) {
			return "", []string{"--link-file", writeLinkFile(t, enrollLink(es))}
		},
		"stdin": func(t *testing.T, es *enrollTestServer) (string, []string) {
			return enrollLink(es) + "\n", []string{"--link-stdin"}
		},
		"env": func(t *testing.T, es *enrollTestServer) (string, []string) {
			t.Setenv(enrollmentLinkEnv, enrollLink(es))
			return "", nil
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			es := newEnrollTestServer(t)
			store := enrollTestRecord(t, es, "agent-1")
			stdin, extra := setup(t, es)
			out, err := runEnroll(t, stdin, append([]string{"agent-1"}, extra...)...)
			require.NoError(t, err, out)
			rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
			require.NoError(t, err)
			assert.True(t, rec.Registered)
		})
	}
}

func TestAuthenticatorEnroll_LinkSourceErrors(t *testing.T) {
	es := newEnrollTestServer(t)
	enrollTestRecord(t, es, "agent-1")
	t.Setenv(enrollmentLinkEnv, "")

	_, err := runEnroll(t, "", "agent-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no enrollment link")

	_, err = runEnroll(t, enrollLink(es), "agent-1", "--link-stdin", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one of")

	_, err = runEnroll(t, "", "agent-1", "--link-file", filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)

	_, err = runEnroll(t, "", "agent-1", "--link-file", t.TempDir())
	require.Error(t, err, "a directory is not a link file")

	_, err = runEnroll(t, strings.Repeat("a", maxEnrollmentLinkBytes+10), "agent-1", "--link-stdin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "longer than")

	assert.Zero(t, es.requestCount())
}

func TestAuthenticatorEnroll_RequiresOneName(t *testing.T) {
	_, err := runEnroll(t, "")
	require.Error(t, err)
	_, err = runEnroll(t, "", "../escape", "--link-stdin")
	require.Error(t, err)
}

func TestEnrollRefusal_SanitisesServerMessage(t *testing.T) {
	err := enrollRefusal("finish", &enrollResponse{
		status: 403,
		body:   []byte(`{"error":{"code":"BAD CODE\n","message":"line1\u001b[31m red"}}`),
	})
	assert.NotContains(t, err.Error(), "\x1b")
	assert.NotContains(t, err.Error(), "BAD CODE")
	assert.Contains(t, err.Error(), "HTTP 403")

	err = enrollRefusal("begin", &enrollResponse{status: 502, body: []byte("<html>")})
	assert.Contains(t, err.Error(), "HTTP 502")
}
