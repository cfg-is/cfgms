// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2783: tests for cfg webauthn commands.
//
// Coverage:
//   - getWebAuthnClient: rejects Bearer-only auth (no bundle → error)
//   - runWebAuthnRevoke: last-credential guard without --force → error
//   - runWebAuthnRevoke: --force bypasses the guard
//   - runWebAuthnRevoke: non-last credential succeeds without --force
//   - No email/password recovery route: static source grep
package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	certbundle "github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

// generateWebAuthnBundle generates a real (self-signed) ECDSA client certificate
// and returns a Bundle populated with valid PEM material. The bundle is ready to
// be written to disk; ControllerURL must be set by the caller before writing.
func generateWebAuthnBundle(t *testing.T) *certbundle.Bundle {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)
	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})

	return &certbundle.Bundle{
		CertPEM:      string(clientCertPEM),
		KeyPEM:       string(clientKeyPEM),
		CAPEM:        string(caCertPEM),
		AuditSubject: "test:admin",
	}
}

// writeBundleFile writes b to a temp file and returns the path.
// b.ControllerURL is set to serverURL before writing.
func writeBundleFile(t *testing.T, b *certbundle.Bundle, serverURL string) string {
	t.Helper()
	b.ControllerURL = serverURL
	path := t.TempDir() + "/admin.bundle.yaml"
	require.NoError(t, certbundle.Write(path, b))
	return path
}

// newWebAuthnListServer creates a plain-HTTP test server that serves the credential
// list and revoke endpoints. lastOnly controls whether the list returns one credential
// (triggers the last-credential guard) or two.
//
// Plain HTTP is used intentionally: the client TLS config is constructed (exercising
// cert/key validation via tls.X509KeyPair) but no TLS handshake fires, so we test
// CLI logic without needing a matching server certificate chain.
func newWebAuthnListServer(t *testing.T, lastOnly bool) *httptest.Server {
	t.Helper()

	cred1 := APIWebAuthnCredentialInfo{
		ID:           "Y3JlZGVudGlhbC1pZC0x",
		Label:        "YubiKey 5C",
		RegisteredAt: "2026-07-01T00:00:00Z",
	}
	cred2 := APIWebAuthnCredentialInfo{
		ID:           "Y3JlZGVudGlhbC1pZC0y",
		RegisteredAt: "2026-07-02T00:00:00Z",
	}

	buildList := func(username string) APIWebAuthnListResponse {
		creds := []APIWebAuthnCredentialInfo{cred1}
		if !lastOnly {
			creds = append(creds, cred2)
		}
		return APIWebAuthnListResponse{Username: username, Credentials: creds}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/webauthn/credentials"):
			username := extractPathSegmentAfter(r.URL.Path, "accounts")
			resp := struct {
				Data APIWebAuthnListResponse `json:"data"`
			}{Data: buildList(username)}
			_ = json.NewEncoder(w).Encode(resp)

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/webauthn/revoke/"):
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"NOT_FOUND","message":"not found"}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// extractPathSegmentAfter returns the URL path segment immediately following marker.
func extractPathSegmentAfter(path, marker string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if p == marker && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return "unknown"
}

// saveWebAuthnFlags snapshots webauthn-related global flags and returns a restore func.
func saveWebAuthnFlags(t *testing.T) func() {
	t.Helper()
	origAPIURL := webAuthnAPIURL
	origUsername := webAuthnUsername
	origLabel := webAuthnLabel
	origAuthenticator := webAuthnAuthenticator
	origForce := webAuthnForce
	origJSON := webAuthnJSON
	origNoBundle := noBundle
	origBundlePath := bundlePath

	return func() {
		webAuthnAPIURL = origAPIURL
		webAuthnUsername = origUsername
		webAuthnLabel = origLabel
		webAuthnAuthenticator = origAuthenticator
		webAuthnForce = origForce
		webAuthnJSON = origJSON
		noBundle = origNoBundle
		bundlePath = origBundlePath
	}
}

// --- AC: Bearer session rejected; only mTLS cert path permitted ---

// TestWebAuthnRegisterRejectsBearerOnly verifies that cfg webauthn register fails
// immediately when no admin bundle is available. Enforces ADR-021 §7: the mTLS cert
// path is the only path for passkey bootstrap/recovery.
func TestWebAuthnRegisterRejectsBearerOnly(t *testing.T) {
	restore := saveWebAuthnFlags(t)
	defer restore()

	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	t.Cleanup(func() {
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
	})
	userConfigDirFn = func() (string, error) { return t.TempDir(), nil }
	systemBundlePathFn = func() string { return "/nonexistent/admin.bundle.yaml" }

	noBundle = true
	webAuthnUsername = "alice"

	err := runWebAuthnRegister(webAuthnRegisterCmd, nil)
	require.Error(t, err, "register must fail when no bundle is available")
	assert.Contains(t, err.Error(), "mTLS certificate",
		"error must mention mTLS certificate requirement")
}

// TestWebAuthnListRejectsBearerOnly verifies cfg webauthn list enforces the cert path.
func TestWebAuthnListRejectsBearerOnly(t *testing.T) {
	restore := saveWebAuthnFlags(t)
	defer restore()

	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	t.Cleanup(func() {
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
	})
	userConfigDirFn = func() (string, error) { return t.TempDir(), nil }
	systemBundlePathFn = func() string { return "/nonexistent/admin.bundle.yaml" }

	noBundle = true
	webAuthnUsername = "alice"

	err := runWebAuthnList(webAuthnListCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mTLS certificate")
}

// TestWebAuthnRevokeRejectsBearerOnly verifies cfg webauthn revoke enforces the cert path.
func TestWebAuthnRevokeRejectsBearerOnly(t *testing.T) {
	restore := saveWebAuthnFlags(t)
	defer restore()

	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	t.Cleanup(func() {
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
	})
	userConfigDirFn = func() (string, error) { return t.TempDir(), nil }
	systemBundlePathFn = func() string { return "/nonexistent/admin.bundle.yaml" }

	noBundle = true
	webAuthnUsername = "alice"

	err := runWebAuthnRevoke(webAuthnRevokeCmd, []string{"some-credential-id"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mTLS certificate")
}

// --- Required test: runWebAuthnRegister fails fast, without a controller round-trip ---
//
// AC: "cfg webauthn register fails fast: the real runWebAuthnRegister path returns the
// actionable error naming the web UI enrollment path, without contacting the
// controller's begin endpoint, starting any local listener, or opening a browser."

func TestWebAuthnRegisterFailsFast(t *testing.T) {
	beginCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/webauthn/register/begin") {
			beginCalled = true
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	restore := saveWebAuthnFlags(t)
	defer restore()

	b := generateWebAuthnBundle(t)
	bundlePath = writeBundleFile(t, b, srv.URL)
	webAuthnUsername = "alice"

	err := runWebAuthnRegister(webAuthnRegisterCmd, nil)
	require.Error(t, err, "registration must fail fast — no configuration lets the CLI ceremony complete")
	assert.False(t, beginCalled, "must not contact the controller's begin endpoint")
	assert.Contains(t, err.Error(), "web UI", "error must name the web UI as the alternative")
	assert.NotContains(t, strings.ToLower(err.Error()), "unsupported configuration",
		"error must name the alternative explicitly, not say \"unsupported configuration\"")
}

// --- cfg webauthn register --authenticator ---

// registerTestServer serves the admin register begin/finish routes with real
// go-webauthn registration verification, and records what the CLI sent.
type registerTestServer struct {
	srv *httptest.Server
	wa  *webauthn.WebAuthn

	mu         sync.Mutex
	session    *webauthn.SessionData
	begins     int
	beginBody  []byte
	finishes   int
	finishURL  string
	finishBody []byte
	registered *webauthn.Credential
	failBegin  bool
	// tpm, when set, makes begin and finish follow the TPM wire contract.
	tpm *tpmPolicy
}

func newRegisterTestServer(t *testing.T) *registerTestServer {
	t.Helper()
	rs := &registerTestServer{}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          testAuthRPID,
		RPDisplayName: "CFGMS test",
		RPOrigins:     []string{testAuthOrigin},
	})
	require.NoError(t, err)
	rs.wa = wa
	user := &authTestUser{}

	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/accounts/alice/webauthn/register/begin":
			rs.begins++
			rs.beginBody, _ = io.ReadAll(r.Body)
			var challenge map[string]any
			if rs.tpm != nil {
				var refusal *tpmRefusal
				if challenge, refusal = rs.tpm.begin(rs.beginBody); refusal != nil {
					w.WriteHeader(refusal.status)
					_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": refusal.code, "message": refusal.message}})
					return
				}
			}
			if rs.failBegin {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"code":"ACCOUNT_DISABLED","message":"Account is disabled"}}`))
				return
			}
			creation, session, err := wa.BeginRegistration(user,
				webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
					UserVerification:   protocol.VerificationRequired,
					ResidentKey:        protocol.ResidentKeyRequirementRequired,
					RequireResidentKey: protocol.ResidentKeyRequired(),
				}))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			rs.session = session
			_ = json.NewEncoder(w).Encode(map[string]any{"data": withTPMChallenge(creation, challenge)})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/accounts/alice/webauthn/register/finish":
			rs.finishes++
			rs.finishURL = r.URL.String()
			rs.finishBody, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(rs.finishBody))
			if rs.tpm != nil {
				rs.tpm.finish(rs.finishBody)
			}
			if rs.session == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			cred, err := wa.FinishRegistration(user, *rs.session, r)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"code":"WEBAUTHN_VERIFY_ERROR","message":"WebAuthn verification failed"}}`))
				return
			}
			rs.registered = cred
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"credential_id": cred.ID}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

// Required: with --authenticator, register runs begin, signs with softauthn and runs
// finish against real registration verification; the record then shows registered.
func TestWebAuthnRegisterAuthenticator_SucceedsAgainstRealVerification(t *testing.T) {
	rs := newRegisterTestServer(t)
	restore := saveWebAuthnFlags(t)
	defer restore()
	_, store := authTestStore(t)
	createAuth(t, "agent-1")

	bundlePath = writeBundleFile(t, generateWebAuthnBundle(t), rs.srv.URL)
	webAuthnUsername = "alice"
	webAuthnAuthenticator = "agent-1"
	webAuthnLabel = "agent one"

	var out bytes.Buffer
	webAuthnRegisterCmd.SetOut(&out)
	t.Cleanup(func() { webAuthnRegisterCmd.SetOut(nil) })

	require.NoError(t, runWebAuthnRegister(webAuthnRegisterCmd, nil))
	assert.Contains(t, out.String(), "agent-1")

	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.True(t, rec.Registered)
	assert.Equal(t, (&authTestUser{}).WebAuthnID(), rec.UserHandle)

	rs.mu.Lock()
	defer rs.mu.Unlock()
	require.NotNil(t, rs.registered, "the server's real verification accepted the registration")
	assert.Equal(t, rec.CredentialID, rs.registered.ID)
	assert.Equal(t, 1, rs.begins)
	assert.Empty(t, rs.beginBody, "begin carries no body")
	assert.Equal(t, 1, rs.finishes)
	assert.Contains(t, rs.finishURL, "label=agent+one", "--label passes through to finish")

	var finish struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rs.finishBody, &finish))
	assert.Equal(t, "public-key", finish.Type)
	assert.NotEmpty(t, finish.ID)
	assert.NotEmpty(t, finish.Response.ClientDataJSON)
	assert.NotEmpty(t, finish.Response.AttestationObject)
}

// Required: without --authenticator the explicit refusal stays, before any
// controller call; with a bearer-only client the mTLS error still wins, with or
// without --authenticator.
func TestWebAuthnRegister_WithoutAuthenticatorKeepsRefusalAndMTLSError(t *testing.T) {
	rs := newRegisterTestServer(t)
	restore := saveWebAuthnFlags(t)
	defer restore()

	bundlePath = writeBundleFile(t, generateWebAuthnBundle(t), rs.srv.URL)
	webAuthnUsername = "alice"
	webAuthnAuthenticator = ""
	err := runWebAuthnRegister(webAuthnRegisterCmd, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errWebAuthnRegisterUnsupported), "got %v", err)
	rs.mu.Lock()
	assert.Zero(t, rs.begins)
	rs.mu.Unlock()

	origUserConfigDirFn := userConfigDirFn
	origSystemBundlePathFn := systemBundlePathFn
	t.Cleanup(func() {
		userConfigDirFn = origUserConfigDirFn
		systemBundlePathFn = origSystemBundlePathFn
	})
	userConfigDirFn = func() (string, error) { return t.TempDir(), nil }
	systemBundlePathFn = func() string { return "/nonexistent/admin.bundle.yaml" }
	noBundle = true
	bundlePath = ""
	for _, name := range []string{"", "agent-1"} {
		webAuthnAuthenticator = name
		err := runWebAuthnRegister(webAuthnRegisterCmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mTLS certificate", "authenticator=%q", name)
	}
}

func TestWebAuthnRegisterAuthenticator_ControllerRefusalLeavesRecordUnregistered(t *testing.T) {
	rs := newRegisterTestServer(t)
	rs.failBegin = true
	restore := saveWebAuthnFlags(t)
	defer restore()
	_, store := authTestStore(t)
	createAuth(t, "agent-1")

	bundlePath = writeBundleFile(t, generateWebAuthnBundle(t), rs.srv.URL)
	webAuthnUsername = "alice"
	webAuthnAuthenticator = "agent-1"

	err := runWebAuthnRegister(webAuthnRegisterCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACCOUNT_DISABLED")
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.False(t, rec.Registered)
	assert.Empty(t, rec.UserHandle)
}

func TestWebAuthnRegisterAuthenticator_MissingAuthenticatorFailsBeforeBegin(t *testing.T) {
	rs := newRegisterTestServer(t)
	restore := saveWebAuthnFlags(t)
	defer restore()
	authTestStore(t)

	bundlePath = writeBundleFile(t, generateWebAuthnBundle(t), rs.srv.URL)
	webAuthnUsername = "alice"
	for _, name := range []string{"nope", "../escape"} {
		webAuthnAuthenticator = name
		require.Error(t, runWebAuthnRegister(webAuthnRegisterCmd, nil), name)
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	assert.Zero(t, rs.begins)
}

func TestWebAuthnRegister_AuthenticatorFlagDeclared(t *testing.T) {
	f := webAuthnRegisterCmd.Flags().Lookup("authenticator")
	require.NotNil(t, f)
	assert.Empty(t, f.DefValue)
}

// --- AC: last-credential guard ---

// TestWebAuthnRevokeLastCredentialRequiresForce verifies that revoking the last
// credential without --force returns an error with actionable guidance.
func TestWebAuthnRevokeLastCredentialRequiresForce(t *testing.T) {
	srv := newWebAuthnListServer(t, true /* single credential */)
	restore := saveWebAuthnFlags(t)
	defer restore()

	b := generateWebAuthnBundle(t)
	bundlePath = writeBundleFile(t, b, srv.URL)
	webAuthnUsername = "alice"
	webAuthnForce = false

	err := runWebAuthnRevoke(webAuthnRevokeCmd, []string{"Y3JlZGVudGlhbC1pZC0x"})
	require.Error(t, err, "revoke must fail without --force on last credential")
	assert.Contains(t, err.Error(), "--force", "error must mention --force")
	assert.Contains(t, err.Error(), "last", "error must describe last-credential scenario")
}

// TestWebAuthnRevokeLastCredentialWithForce verifies --force bypasses the guard.
func TestWebAuthnRevokeLastCredentialWithForce(t *testing.T) {
	srv := newWebAuthnListServer(t, true /* single credential */)
	restore := saveWebAuthnFlags(t)
	defer restore()

	b := generateWebAuthnBundle(t)
	bundlePath = writeBundleFile(t, b, srv.URL)
	webAuthnUsername = "alice"
	webAuthnForce = true

	var out bytes.Buffer
	webAuthnRevokeCmd.SetOut(&out)
	t.Cleanup(func() { webAuthnRevokeCmd.SetOut(nil) })

	err := runWebAuthnRevoke(webAuthnRevokeCmd, []string{"Y3JlZGVudGlhbC1pZC0x"})
	require.NoError(t, err, "revoke with --force must succeed")
	assert.Contains(t, out.String(), "revoked", "output must confirm revocation")
}

// TestWebAuthnRevokeNonLastCredential verifies that a non-last credential can be
// revoked without --force.
func TestWebAuthnRevokeNonLastCredential(t *testing.T) {
	srv := newWebAuthnListServer(t, false /* two credentials */)
	restore := saveWebAuthnFlags(t)
	defer restore()

	b := generateWebAuthnBundle(t)
	bundlePath = writeBundleFile(t, b, srv.URL)
	webAuthnUsername = "alice"
	webAuthnForce = false

	var out bytes.Buffer
	webAuthnRevokeCmd.SetOut(&out)
	t.Cleanup(func() { webAuthnRevokeCmd.SetOut(nil) })

	err := runWebAuthnRevoke(webAuthnRevokeCmd, []string{"Y3JlZGVudGlhbC1pZC0x"})
	require.NoError(t, err, "revoking a non-last credential must not require --force")
}

// --- AC: no email/password recovery route ---

// TestNoEmailPasswordRecoveryRoute asserts that no handler in the webauthn handler file
// introduces a credential-minting route below AssuranceStrong (ADR-021 §7).
//
// Password verification (verifyWebPassword) and email-based flows must not appear in
// handlers_webauthn.go; their presence would indicate a downgrade attack surface.
func TestNoEmailPasswordRecoveryRoute(t *testing.T) {
	webAuthnHandlers, err := os.ReadFile("../../../features/controller/api/handlers_webauthn.go")
	require.NoError(t, err, "handlers_webauthn.go must be readable")
	content := string(webAuthnHandlers)

	// Each pattern in handlers_webauthn.go would indicate a recovery path that bypasses
	// AssuranceStrong (a downgrade attack per ADR-021 §7).
	dangerousPatterns := []struct {
		pattern string
		reason  string
	}{
		{"verifyWebPassword", "password-based credential minting is a downgrade attack"},
		{"AssuranceBasic", "a Basic-assurance path in webauthn handlers is a downgrade"},
		{"AssuranceMachine", "a Machine-assurance path in webauthn handlers is a downgrade"},
	}
	for _, dp := range dangerousPatterns {
		assert.NotContains(t, content, dp.pattern,
			"handlers_webauthn.go must not contain %q: %s", dp.pattern, dp.reason)
	}
}

// With a "store" record the admin register begin has no body and the finish carries
// attestation none, even when the controller is TPM-aware but does not require one.
func TestWebAuthnRegisterAuthenticator_StoreRecordSendsNoBeginBodyAndFmtNone(t *testing.T) {
	rs := newRegisterTestServer(t)
	rs.tpm = &tpmPolicy{}
	restore := saveWebAuthnFlags(t)
	defer restore()
	authTestStore(t)
	createAuth(t, "agent-1")

	bundlePath = writeBundleFile(t, generateWebAuthnBundle(t), rs.srv.URL)
	webAuthnUsername = "alice"
	webAuthnAuthenticator = "agent-1"
	webAuthnLabel = ""

	var out bytes.Buffer
	webAuthnRegisterCmd.SetOut(&out)
	t.Cleanup(func() { webAuthnRegisterCmd.SetOut(nil) })
	require.NoError(t, runWebAuthnRegister(webAuthnRegisterCmd, nil))

	bodies := rs.tpm.beginBodies()
	require.Len(t, bodies, 1)
	assert.Empty(t, bodies[0], "a store record sends no begin body")
	format, activation, _, _ := rs.tpm.finishResult()
	assert.Equal(t, "none", format)
	assert.Empty(t, activation)
}

// A TPM_ATTESTATION_REQUIRED refusal of the admin begin prints the remedy that names
// --key-provider tpm and leaves the record unregistered.
func TestWebAuthnRegisterAuthenticator_TPMAttestationRequiredNamesTheRemedy(t *testing.T) {
	rs := newRegisterTestServer(t)
	rs.tpm = &tpmPolicy{require: true}
	restore := saveWebAuthnFlags(t)
	defer restore()
	_, store := authTestStore(t)
	createAuth(t, "agent-1")

	bundlePath = writeBundleFile(t, generateWebAuthnBundle(t), rs.srv.URL)
	webAuthnUsername = "alice"
	webAuthnAuthenticator = "agent-1"

	err := runWebAuthnRegister(webAuthnRegisterCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a TPM-held key")
	assert.Contains(t, err.Error(), "--key-provider tpm")
	rec, err := loadAuthenticatorRecord(context.Background(), store, "agent-1")
	require.NoError(t, err)
	assert.False(t, rec.Registered)
}

// APIClient.WebAuthnBeginRegistration sends the body it is given, and none when nil.
func TestAPIClientWebAuthnBeginRegistration_OptionalBody(t *testing.T) {
	var gotBodies [][]byte
	var gotTypes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBodies = append(gotBodies, b)
		gotTypes = append(gotTypes, r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"publicKey":{}}}`))
	}))
	defer srv.Close()
	client := &APIClient{baseURL: srv.URL, httpClient: srv.Client()}

	_, err := client.WebAuthnBeginRegistration(context.Background(), "alice", nil)
	require.NoError(t, err)
	_, err = client.WebAuthnBeginRegistration(context.Background(), "alice", []byte(`{"tpm":{}}`))
	require.NoError(t, err)

	assert.Empty(t, gotBodies[0])
	assert.Equal(t, `{"tpm":{}}`, string(gotBodies[1]))
	assert.Equal(t, "application/json", gotTypes[1])
}
