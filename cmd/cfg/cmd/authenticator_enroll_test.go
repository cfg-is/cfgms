// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
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
	legacytpm "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
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
	// tpm, when set, makes the begin route behave as the controller does for a
	// TPM-aware begin (see tpmPolicy); nil leaves begin as it always was.
	tpm *tpmPolicy
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
		reqBody, _ := io.ReadAll(r.Body)
		var challenge map[string]any
		if es.tpm != nil {
			var refusal *tpmRefusal
			if challenge, refusal = es.tpm.begin(reqBody); refusal != nil {
				writeTestAPIError(w, refusal.status, refusal.code, refusal.message)
				return
			}
		}
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
		_ = json.NewEncoder(w).Encode(map[string]any{"data": withTPMChallenge(creation, challenge)})
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
		if es.tpm != nil {
			es.tpm.finish(es.finishRaw)
		}
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

	_, err = c.begin(context.Background(), testEnrollToken, nil)
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

// tpmRefusal is a refusal the fake controller sends.
type tpmRefusal struct {
	status        int
	code, message string
}

// tpmPolicy is the controller half of the TPM wire contract, shared by the fake
// enrollment and admin register servers. It checks the begin body's shape, makes
// the credential challenge with credactivation.Generate for the offered AK and
// EK, and at finish records the attestation format and the cfgmsActivation the
// client returned. Real go-webauthn verification of the attestation itself runs
// in the servers' finish handlers.
type tpmPolicy struct {
	// require refuses a begin that carries no TPM body, as for a root agent account.
	require bool
	// noChallenge answers a TPM body with plain creation options.
	noChallenge bool
	// corruptChallenge makes the credential for an attestation key other than the
	// one offered, so no TPM can activate it.
	corruptChallenge bool
	// ca, when set, must have issued the offered EK certificate.
	ca *x509.Certificate

	mu         sync.Mutex
	bodies     [][]byte
	secret     []byte
	activation []byte
	format     string
	finishes   int
}

func (p *tpmPolicy) beginBodies() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][]byte(nil), p.bodies...)
}

func (p *tpmPolicy) finishResult() (format string, activation, secret []byte, finishes int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.format, p.activation, p.secret, p.finishes
}

// begin returns the cfgmsTpm member to add to the options, or a refusal.
func (p *tpmPolicy) begin(body []byte) (map[string]any, *tpmRefusal) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bodies = append(p.bodies, append([]byte(nil), body...))
	if len(body) == 0 {
		if p.require {
			return nil, &tpmRefusal{http.StatusForbidden, "TPM_ATTESTATION_REQUIRED",
				"This account requires a TPM-held authenticator key"}
		}
		return nil, nil
	}
	challenge, err := p.challenge(body)
	if err != nil {
		return nil, &tpmRefusal{http.StatusBadRequest, "TPM_PROOF_INVALID", err.Error()}
	}
	if p.noChallenge {
		return nil, nil
	}
	return challenge, nil
}

// challenge checks the wire shape of body and builds the cfgmsTpm member.
func (p *tpmPolicy) challenge(body []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req struct {
		TPM *struct {
			EKCertChain [][]byte `json:"ek_cert_chain"`
			AKPublic    []byte   `json:"ak_public"`
		} `json:"tpm"`
	}
	if err := dec.Decode(&req); err != nil || req.TPM == nil {
		return nil, errors.New("the begin body must be {\"tpm\":{\"ek_cert_chain\":[...],\"ak_public\":\"...\"}}")
	}
	if len(req.TPM.EKCertChain) == 0 || len(req.TPM.AKPublic) == 0 {
		return nil, errors.New("ek_cert_chain and ak_public are required")
	}
	ekCert, err := x509.ParseCertificate(req.TPM.EKCertChain[0])
	if err != nil {
		return nil, errors.New("ek_cert_chain[0] is not a DER certificate")
	}
	if p.ca != nil {
		if err := ekCert.CheckSignatureFrom(p.ca); err != nil {
			return nil, errors.New("the EK certificate does not chain to a trusted root")
		}
	}
	ak, err := tpm2.Unmarshal[tpm2.TPMTPublic](req.TPM.AKPublic)
	if err != nil {
		return nil, errors.New("ak_public is not a TPMT_PUBLIC")
	}
	a := ak.ObjectAttributes
	if ak.Type != tpm2.TPMAlgECC || !a.FixedTPM || !a.FixedParent || !a.SensitiveDataOrigin || !a.Restricted || !a.SignEncrypt {
		return nil, errors.New("ak_public is not a restricted, fixed ECC signing key")
	}
	name, err := tpm2.ObjectName(ak)
	if err != nil || len(name.Buffer) <= 2 {
		return nil, errors.New("ak_public has no name")
	}
	p.secret = make([]byte, 32)
	if _, err := rand.Read(p.secret); err != nil {
		return nil, err
	}
	akName := append([]byte(nil), name.Buffer[2:]...)
	if p.corruptChallenge {
		akName[0] ^= 0x01
	}
	blob, enc, err := credactivation.Generate(&legacytpm.HashValue{Alg: legacytpm.AlgSHA256, Value: akName},
		ekCert.PublicKey, 16, p.secret)
	if err != nil {
		return nil, errors.New("cannot make a credential for that EK")
	}
	return map[string]any{
		"credential_blob":  base64.StdEncoding.EncodeToString(blob),
		"encrypted_secret": base64.StdEncoding.EncodeToString(enc),
	}, nil
}

// finish records what the finish body carried.
func (p *tpmPolicy) finish(body []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.finishes++
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return
	}
	obj := parsed.Response.AttestationObject
	p.format = obj.Format
	p.activation, _ = obj.AttStatement["cfgmsActivation"].([]byte)
}

// withTPMChallenge adds the cfgmsTpm member to the creation options.
func withTPMChallenge(creation any, challenge map[string]any) any {
	if challenge == nil {
		return creation
	}
	raw, err := json.Marshal(creation)
	if err != nil {
		return creation
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return creation
	}
	m["cfgmsTpm"] = challenge
	return m
}

// tpmTestPublicBlob is a marshalled TPM2B_PUBLIC for a fresh P-256 signing key.
// It is valid to parse; no TPM holds the key. Tests that need a "tpm" record on a
// host with no TPM use it, since they never reach a TPM operation.
func tpmTestPublicBlob(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pt := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, SignEncrypt: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: key.X.FillBytes(make([]byte, 32))},
			Y: tpm2.TPM2BECCParameter{Buffer: key.Y.FillBytes(make([]byte, 32))},
		}),
	}
	return tpm2.Marshal(tpm2.New2B(pt))
}

// convertToTPMRecord turns the stored "store" record name into a "tpm" record whose
// blobs parse but belong to no TPM.
func convertToTPMRecord(t *testing.T, store *CredentialStore, name string) {
	t.Helper()
	rec, err := loadAuthenticatorRecord(context.Background(), store, name)
	require.NoError(t, err)
	rec.KeyPKCS8 = nil
	rec.KeyPublicBlob = tpmTestPublicBlob(t)
	rec.KeyPrivateBlob = []byte("not-a-real-private-blob")
	rec.Protection = authenticatorProtectionTPM
	require.NoError(t, saveAuthenticatorRecord(context.Background(), store, rec))
}

// useTPMOpener replaces the TPM opener for the test.
func useTPMOpener(t *testing.T, open func() (transport.TPMCloser, error)) {
	t.Helper()
	orig := openAuthenticatorTPM
	openAuthenticatorTPM = open
	t.Cleanup(func() { openAuthenticatorTPM = orig })
}

func noTPM() (transport.TPMCloser, error) { return nil, errors.New("no TPM device on this host") }

// With a "store" record and a controller that offers no TPM challenge, begin has no
// body and the finish carries attestation none: behaviour is unchanged.
func TestAuthenticatorEnroll_StoreRecordSendsNoBeginBodyAndFmtNone(t *testing.T) {
	es := newEnrollTestServer(t)
	es.tpm = &tpmPolicy{}
	store := enrollTestRecord(t, es, "agent-1")

	out, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.NoError(t, err, out)

	bodies := es.tpm.beginBodies()
	require.Len(t, bodies, 1)
	assert.Empty(t, bodies[0], "a store record sends no begin body")
	format, activation, _, finishes := es.tpm.finishResult()
	assert.Equal(t, 1, finishes)
	assert.Equal(t, "none", format)
	assert.Empty(t, activation)
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.True(t, rec.Registered)
}

// A TPM_ATTESTATION_REQUIRED refusal prints the remedy that names --key-provider tpm,
// and leaves the record unregistered.
func TestAuthenticatorEnroll_TPMAttestationRequiredNamesTheRemedy(t *testing.T) {
	es := newEnrollTestServer(t)
	es.tpm = &tpmPolicy{require: true}
	store := enrollTestRecord(t, es, "agent-1")

	_, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a TPM-held key")
	assert.Contains(t, err.Error(), "--key-provider tpm")
	assert.Contains(t, err.Error(), "TPM_ATTESTATION_REQUIRED")
	assert.NotContains(t, err.Error(), testEnrollToken)
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.False(t, rec.Registered)
}

// A "tpm" record on a host whose TPM cannot be opened is refused before any request.
func TestAuthenticatorEnroll_TPMRecordWithoutUsableTPMRefusedBeforeNetwork(t *testing.T) {
	es := newEnrollTestServer(t)
	store := enrollTestRecord(t, es, "agent-1")
	convertToTPMRecord(t, store, "agent-1")
	useTPMOpener(t, noTPM)

	_, err := runEnroll(t, "", "agent-1", "--link-file", writeLinkFile(t, enrollLink(es)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TPM")
	assert.Contains(t, err.Error(), "cannot be opened")
	assert.Zero(t, es.requestCount(), "no request may reach the server")
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.False(t, rec.Registered)
}

func TestParseTPMChallenge(t *testing.T) {
	c, err := parseTPMChallenge([]byte(`{"publicKey":{}}`))
	require.NoError(t, err)
	assert.Nil(t, c, "no cfgmsTpm member means no challenge")

	c, err = parseTPMChallenge([]byte(`{"cfgmsTpm":{"credential_blob":"AQI=","encrypted_secret":"AwQ="}}`))
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, []byte{1, 2}, c.CredentialBlob)
	assert.Equal(t, []byte{3, 4}, c.EncryptedSecret)

	for name, raw := range map[string]string{
		"empty member":   `{"cfgmsTpm":{}}`,
		"missing secret": `{"cfgmsTpm":{"credential_blob":"AQI="}}`,
		"not base64":     `{"cfgmsTpm":{"credential_blob":"!!","encrypted_secret":"AwQ="}}`,
		"not an object":  `{"cfgmsTpm":"x"}`,
		"malformed json": `{`,
	} {
		_, err := parseTPMChallenge([]byte(raw))
		assert.Error(t, err, name)
	}
}

func TestExplainTPMRefusal(t *testing.T) {
	base := errors.New("controller said TPM_ATTESTATION_REQUIRED")

	storeErr := explainTPMRefusal(&authenticatorRecord{Name: "a", Protection: authenticatorProtectionStore}, base)
	assert.Contains(t, storeErr.Error(), "--key-provider tpm")
	assert.ErrorIs(t, storeErr, base)

	tpmErr := explainTPMRefusal(&authenticatorRecord{Name: "a", Protection: authenticatorProtectionTPM}, base)
	assert.Contains(t, tpmErr.Error(), "did not accept the TPM attestation")
	assert.NotContains(t, tpmErr.Error(), "create a new authenticator")

	other := errors.New("some other failure")
	assert.Equal(t, other, explainTPMRefusal(&authenticatorRecord{Name: "a"}, other))
	assert.NoError(t, explainTPMRefusal(&authenticatorRecord{Name: "a"}, nil))
}
