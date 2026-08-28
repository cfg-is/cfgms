// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/session"
)

// generateSigningCredentialTestKey generates a fresh ECDSA P-256 keypair and returns
// both the private key (kept only in the test — never sent to the server) and the
// PEM-encoded PKIX SubjectPublicKeyInfo of the public half (the only thing the wire
// protocol carries).
func generateSigningCredentialTestKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return priv, string(pubPEM)
}

// issueSigningCredentialAdminCert issues an mTLS admin certificate (bootstrap-fallback
// principal — no bound account) usable to drive the full router path in tests, mirroring
// TestHandleRotateSigningCert_AdminSuccess in handlers_certificates_test.go.
func issueSigningCredentialAdminCert(t *testing.T, certMgr *cert.Manager, commonName string) *x509.Certificate {
	t.Helper()
	issued, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       commonName,
		Organization:     "CFGMS",
		ValidityDays:     1,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	x509Cert, err := cert.ParseCertificateFromPEM(issued.CertificatePEM)
	require.NoError(t, err)
	return x509Cert
}

func TestHandleRequestSigningCredential_Success(t *testing.T) {
	server, certMgr := setupCertTestServer(t)

	adminCert := issueSigningCredentialAdminCert(t, certMgr, "operator-admin")
	priv, pubPEM := generateSigningCredentialTestKey(t)

	body, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: pubPEM})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/signing-credential/request", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{adminCert}}
	// The bootstrap-fallback principal ID is the cert's CommonName (extractAdminPrincipal).
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, "operator-admin"))
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var resp struct {
		Data SigningCredentialResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotEmpty(t, resp.Data.CertificatePEM)
	require.NotEmpty(t, resp.Data.CACertificatePEM)
	require.NotEmpty(t, resp.Data.SerialNumber)

	issuedCert, err := cert.ParseCertificateFromPEM([]byte(resp.Data.CertificatePEM))
	require.NoError(t, err)

	// [REQUIRED TEST] the issued cert carries PayloadSigningMarkerOID and does NOT
	// carry AdminMarkerOID.
	assert.True(t, cert.HasPayloadSigningMarker(issuedCert), "issued cert must carry PayloadSigningMarkerOID")
	assert.False(t, cert.HasAdminMarker(issuedCert), "issued cert must NOT carry AdminMarkerOID — it must remain distinguishable from an admin transport bundle")

	// The issued cert's public key must be exactly the caller-supplied key — no
	// substitution or regeneration by the server.
	issuedPub, ok := issuedCert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok, "issued cert public key must be ECDSA")
	assert.True(t, issuedPub.Equal(&priv.PublicKey), "issued cert public key must equal the caller-supplied public key")

	// [REQUIRED TEST] the cert passes the same x509.Verify chain check used by
	// verifyOperatorCert — drop-in compatible, matching pkg/cert's TestCA_SignClientCertificateRequest.
	caCert, err := cert.ParseCertificateFromPEM([]byte(resp.Data.CACertificatePEM))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err = issuedCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	assert.NoError(t, err, "issued cert must chain-verify against the returned CA certificate")

	// [REQUIRED TEST] the credential is usable to sign an envelope end-to-end: the
	// private key that never left this test process produces a signature the issued
	// certificate's public key verifies. This is the cryptographic primitive
	// operatorpayload.Envelope signing (story S5b) builds on.
	digest := []byte("operatorpayload envelope digest placeholder")
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(issuedPub, digest, sig), "issued cert's public key must verify a signature made with the locally-held private key")
}

// TestHandleRequestSigningCredential_ResponseNeverCarriesPrivateKeyMaterial is a
// [REQUIRED TEST]: no private key ever crosses the wire in either direction. The
// request struct (SigningCredentialRequest) has no field capable of carrying one; this
// asserts the actual response bytes contain no PEM private-key block.
func TestHandleRequestSigningCredential_ResponseNeverCarriesPrivateKeyMaterial(t *testing.T) {
	server, certMgr := setupCertTestServer(t)

	adminCert := issueSigningCredentialAdminCert(t, certMgr, "operator-admin-2")
	_, pubPEM := generateSigningCredentialTestKey(t)

	body, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: pubPEM})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/signing-credential/request", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{adminCert}}
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, "operator-admin-2"))
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	respBody := rec.Body.String()
	assert.False(t, strings.Contains(respBody, "PRIVATE KEY"), "response must never contain a PEM private-key block")

	// Structural guarantee: the wire request type has exactly one field, and it is
	// the public key — there is no field a caller or server could (mis)use to carry
	// a private key.
	reqJSON, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: pubPEM})
	require.NoError(t, err)
	var asMap map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(reqJSON, &asMap))
	assert.Len(t, asMap, 1, "request wire format must carry exactly one field")
	_, hasPublicKey := asMap["public_key_pem"]
	assert.True(t, hasPublicKey, "request wire format must carry public_key_pem")
}

func TestHandleRequestSigningCredential_MachineAssurance403(t *testing.T) {
	server, _ := setupCertTestServer(t)
	apiKey := NewTestKey(t, server, []string{"signing-credential:request"})

	_, pubPEM := generateSigningCredentialTestKey(t)
	body, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: pubPEM})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/signing-credential/request", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INSUFFICIENT_PERMISSIONS", errResp.Error.Code)
}

func TestHandleRequestSigningCredential_BasicAssuranceGetsStepUp(t *testing.T) {
	server, _ := setupCertTestServer(t)

	basicPrincipal := &Principal{
		ID:            "web-admin",
		Name:          "web-session:web-admin",
		Assurance:     session.AssuranceBasic,
		ImplicitAdmin: true,
	}

	probe := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := server.requirePermission("signing-credential", "request")(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/signing-credential/request", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, basicPrincipal))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// The AssuranceStrong floor is checked before the RequireUserPresence check, so a
	// Basic-assurance caller (which already fails the floor) gets the plain step-up
	// challenge, not a presence-specific one — mirrors assertStepUpFromRequirePermission.
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
}

func TestHandleRequestSigningCredential_NoPresenceTokenRejected(t *testing.T) {
	server, certMgr := setupCertTestServer(t)

	adminCert := issueSigningCredentialAdminCert(t, certMgr, "operator-admin-3")
	_, pubPEM := generateSigningCredentialTestKey(t)
	body, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: pubPEM})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/signing-credential/request", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{adminCert}}
	// No X-Presence-Token header set.
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`)
}

func TestHandleRequestSigningCredential_MissingPublicKey_Returns400(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	adminCert := issueSigningCredentialAdminCert(t, certMgr, "operator-admin-4")

	body, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: ""})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/signing-credential/request", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{adminCert}}
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, "operator-admin-4"))
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "MISSING_PUBLIC_KEY", errResp.Error.Code)
}

func TestHandleRequestSigningCredential_InvalidJSON_Returns400(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	adminCert := issueSigningCredentialAdminCert(t, certMgr, "operator-admin-5")

	req := httptest.NewRequest("POST", "/api/v1/signing-credential/request", strings.NewReader("{not json"))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{adminCert}}
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, "operator-admin-5"))
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_JSON", errResp.Error.Code)
}

func TestHandleRequestSigningCredential_RSAKeyRejected(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	adminCert := issueSigningCredentialAdminCert(t, certMgr, "operator-admin-6")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	body, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: string(pubPEM)})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/signing-credential/request", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{adminCert}}
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, "operator-admin-6"))
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_PUBLIC_KEY", errResp.Error.Code)
}

func TestHandleRequestSigningCredential_WrongCurveRejected(t *testing.T) {
	server, certMgr := setupCertTestServer(t)
	adminCert := issueSigningCredentialAdminCert(t, certMgr, "operator-admin-7")

	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&p384Key.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	body, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: string(pubPEM)})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/signing-credential/request", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{adminCert}}
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, "operator-admin-7"))
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_PUBLIC_KEY", errResp.Error.Code)
}

func TestHandleRequestSigningCredential_NilCertManager_Returns503(t *testing.T) {
	server := setupTestServer(t) // no cert manager wired

	strongPrincipal := &Principal{
		ID:            "cert-admin",
		Name:          "mtls-cert:cert-admin",
		Assurance:     session.AssuranceStrong,
		CertSerial:    "abc123",
		ImplicitAdmin: true,
	}

	_, pubPEM := generateSigningCredentialTestKey(t)
	body, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: pubPEM})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/signing-credential/request", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, strongPrincipal))

	rec := httptest.NewRecorder()
	server.handleRequestSigningCredential(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleRequestSigningCredential_Unauthenticated_Returns401(t *testing.T) {
	server, _ := setupCertTestServer(t)

	req := httptest.NewRequest("POST", "/api/v1/signing-credential/request", nil)
	rec := httptest.NewRecorder()
	server.handleRequestSigningCredential(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleRequestSigningCredential_SubStrongPrincipalRejected verifies the handler's
// own defense-in-depth Assurance check (mirroring handleRotateSigningCert) fires even
// when called directly with a principal that bypassed requirePermission somehow.
func TestHandleRequestSigningCredential_SubStrongPrincipalRejected(t *testing.T) {
	server, _ := setupCertTestServer(t)

	basicPrincipal := &Principal{
		ID:            "web-admin",
		Assurance:     session.AssuranceBasic,
		ImplicitAdmin: true,
	}

	_, pubPEM := generateSigningCredentialTestKey(t)
	body, err := json.Marshal(SigningCredentialRequest{PublicKeyPEM: pubPEM})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/signing-credential/request", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, basicPrincipal))

	rec := httptest.NewRecorder()
	server.handleRequestSigningCredential(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}
