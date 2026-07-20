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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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
	origForce := webAuthnForce
	origJSON := webAuthnJSON
	origNoBundle := noBundle
	origBundlePath := bundlePath

	return func() {
		webAuthnAPIURL = origAPIURL
		webAuthnUsername = origUsername
		webAuthnLabel = origLabel
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
