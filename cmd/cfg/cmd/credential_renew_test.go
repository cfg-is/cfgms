// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certbundle "github.com/cfgis/cfgms/pkg/cert/bundle"
)

// buildTestAdminBundleWithExpiry mirrors buildTestAdminBundle (token_test.go) but
// takes an explicit client-certificate NotAfter, so renewal-window tests can control
// whether the bundle's certificate is due for renewal.
func buildTestAdminBundleWithExpiry(t *testing.T, controllerURL string, notAfter time.Time) *certbundle.Bundle {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})

	return &certbundle.Bundle{
		CertPEM:       string(clientCertPEM),
		KeyPEM:        string(clientKeyPEM),
		CAPEM:         string(caCertPEM),
		ControllerURL: controllerURL,
		AuditSubject:  "admin:test-admin",
		CertSerial:    "2",
	}
}

// setCredentialRenewFlags wires the module-level flags for a test run, authenticated
// via an admin bundle whose client certificate expires at notAfter. Mirrors
// setCredentialRequestSigningCertFlags (credential_request_signing_cert_test.go).
// Returns the bundle file path and a cleanup func.
func setCredentialRenewFlags(t *testing.T, url string, notAfter time.Time) string {
	t.Helper()
	bundleFilePath := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	b := buildTestAdminBundleWithExpiry(t, "https://placeholder.local:9443", notAfter)
	require.NoError(t, certbundle.Write(bundleFilePath, b))

	origURL := credentialRenewAPIURL
	origInsecure := credentialRenewTLSInsecure
	origUnattended := credentialRenewUnattended
	origBundlePath := bundlePath
	origNoBundle := noBundle
	credentialRenewAPIURL = url
	credentialRenewTLSInsecure = true
	bundlePath = bundleFilePath
	noBundle = false
	t.Cleanup(func() {
		credentialRenewAPIURL = origURL
		credentialRenewTLSInsecure = origInsecure
		credentialRenewUnattended = origUnattended
		bundlePath = origBundlePath
		noBundle = origNoBundle
	})
	return bundleFilePath
}

func renewedCertResponse(t *testing.T) (certPEM, caPEM, serial string) {
	t.Helper()
	b := buildTestAdminBundleWithExpiry(t, "", time.Now().Add(365*24*time.Hour))
	return b.CertPEM, b.CAPEM, "renewed-serial-999"
}

// ---- happy path ---------------------------------------------------------------------

// TestCredentialRenewCmd_HappyPath is a [REQUIRED TEST]: it captures the exact wire
// body and asserts it carries only a CSR — no private key material crosses the wire —
// and that the CSR's public key differs from the bundle's own (a fresh keypair was
// generated). It also asserts the bundle file on disk is fully replaced.
func TestCredentialRenewCmd_HappyPath(t *testing.T) {
	certPEM, caPEM, serial := renewedCertResponse(t)
	expiresAt := time.Now().Add(365 * 24 * time.Hour).UTC()

	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/credential-renewal", r.URL.Path)
		var err error
		capturedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"certificate_pem":    certPEM,
				"ca_certificate_pem": caPEM,
				"serial_number":      serial,
				"account_id":         "acct-123",
				"granted_markers":    []string{"admin"},
				"expires_at":         expiresAt.Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	bundleFilePath := setCredentialRenewFlags(t, srv.URL, time.Now().Add(24*time.Hour))
	before, err := certbundle.Read(bundleFilePath)
	require.NoError(t, err)
	oldCert, err := parseBundleCertificate(before.CertPEM)
	require.NoError(t, err)

	output := captureStdout(t, func() {
		require.NoError(t, runCredentialRenew(credentialRenewCmd, nil))
	})

	// --- [REQUIRED TEST] wire format carries only a CSR; no private key material ---
	require.NotEmpty(t, capturedBody)
	var wireReq map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(capturedBody, &wireReq))
	assert.Len(t, wireReq, 1, "request body must carry exactly one field")
	csrRaw, hasCSR := wireReq["csr_pem"]
	require.True(t, hasCSR, "request body must carry csr_pem")
	assert.False(t, bytes.Contains(capturedBody, []byte("PRIVATE KEY")), "request body must never contain private key material")

	var csrPEM string
	require.NoError(t, json.Unmarshal(csrRaw, &csrPEM))
	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature(), "CSR must be self-signed by the key it carries the public half of")

	newPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.False(t, newPub.Equal(oldCert.PublicKey.(*ecdsa.PublicKey)),
		"the CSR's public key must differ from the current bundle certificate's — a fresh keypair must be generated")

	// --- bundle fully replaced on disk ---
	after, err := certbundle.Read(bundleFilePath)
	require.NoError(t, err)
	assert.Equal(t, certPEM, after.CertPEM)
	assert.Equal(t, caPEM, after.CAPEM)
	assert.Equal(t, serial, after.CertSerial)
	assert.NotEqual(t, before.KeyPEM, after.KeyPEM, "the private key in the bundle must be replaced with the freshly generated one")
	assert.Equal(t, before.ControllerURL, after.ControllerURL, "controller_url must be preserved")
	assert.Equal(t, before.AuditSubject, after.AuditSubject, "audit_subject must be preserved")

	assert.Contains(t, output, serial)
	assert.Contains(t, output, bundleFilePath)
}

// ---- unattended mode -----------------------------------------------------------------

// TestCredentialRenewCmd_Unattended_NotYetDue asserts --unattended makes no network
// call and exits 0 when the certificate is far from its renewal window.
func TestCredentialRenewCmd_Unattended_NotYetDue(t *testing.T) {
	var requested bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requested = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// 200 days from now is well outside the 30-day renewal window.
	setCredentialRenewFlags(t, srv.URL, time.Now().Add(200*24*time.Hour))
	credentialRenewUnattended = true

	output := captureStdout(t, func() {
		require.NoError(t, runCredentialRenew(credentialRenewCmd, nil))
	})

	assert.False(t, requested, "no renewal request may be made when the certificate is not yet due")
	assert.Contains(t, output, "not yet due")
}

// TestCredentialRenewCmd_Unattended_Due asserts --unattended proceeds normally once
// the certificate is within the renewal window.
func TestCredentialRenewCmd_Unattended_Due(t *testing.T) {
	certPEM, caPEM, serial := renewedCertResponse(t)
	var requested bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requested = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"certificate_pem":    certPEM,
				"ca_certificate_pem": caPEM,
				"serial_number":      serial,
				"expires_at":         time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	// 24h from now is inside the 30-day renewal window.
	setCredentialRenewFlags(t, srv.URL, time.Now().Add(24*time.Hour))
	credentialRenewUnattended = true

	require.NoError(t, runCredentialRenew(credentialRenewCmd, nil))
	assert.True(t, requested, "a renewal request must be made when the certificate is within its renewal window")
}

// ---- server error --------------------------------------------------------------------

func TestCredentialRenewCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"OUTSIDE_RENEWAL_WINDOW","message":"renewal window has not yet opened"}}`))
	}))
	defer srv.Close()

	bundleFilePath := setCredentialRenewFlags(t, srv.URL, time.Now().Add(24*time.Hour))
	before, err := certbundle.Read(bundleFilePath)
	require.NoError(t, err)

	err = runCredentialRenew(credentialRenewCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "renewal window has not yet opened")

	after, err := certbundle.Read(bundleFilePath)
	require.NoError(t, err)
	assert.Equal(t, before.CertPEM, after.CertPEM, "the bundle must not be modified when renewal fails")
	assert.Equal(t, before.KeyPEM, after.KeyPEM)
}

// ---- no credential --------------------------------------------------------------------

func TestCredentialRenewCmd_NoCredential(t *testing.T) {
	origURL := credentialRenewAPIURL
	origBundlePath := bundlePath
	origNoBundle := noBundle
	credentialRenewAPIURL = ""
	bundlePath = ""
	noBundle = true
	t.Cleanup(func() {
		credentialRenewAPIURL = origURL
		bundlePath = origBundlePath
		noBundle = origNoBundle
	})

	err := runCredentialRenew(credentialRenewCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--no-bundle")
}

// ---- resolveRenewalBundlePath unit tests ----------------------------------------------

func TestResolveRenewalBundlePath_NoBundleFlagSet(t *testing.T) {
	origNoBundle := noBundle
	noBundle = true
	t.Cleanup(func() { noBundle = origNoBundle })

	_, err := resolveRenewalBundlePath()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--no-bundle")
}

func TestResolveRenewalBundlePath_ExplicitEnvEmpty(t *testing.T) {
	origNoBundle := noBundle
	noBundle = false
	t.Cleanup(func() { noBundle = origNoBundle })
	t.Setenv("CFGMS_ADMIN_BUNDLE", "")

	_, err := resolveRenewalBundlePath()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CFGMS_ADMIN_BUNDLE")
}

func TestResolveRenewalBundlePath_ExplicitFlag(t *testing.T) {
	origBundlePath := bundlePath
	origNoBundle := noBundle
	noBundle = false
	t.Cleanup(func() {
		bundlePath = origBundlePath
		noBundle = origNoBundle
	})

	bundleFilePath := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	b := buildTestAdminBundleWithExpiry(t, "https://x.local", time.Now().Add(24*time.Hour))
	require.NoError(t, certbundle.Write(bundleFilePath, b))
	bundlePath = bundleFilePath

	got, err := resolveRenewalBundlePath()
	require.NoError(t, err)
	assert.Equal(t, bundleFilePath, got)
}

// ---- certificateWithinRenewalWindow unit tests -----------------------------------------

func TestCertificateWithinRenewalWindow(t *testing.T) {
	assert.True(t, certificateWithinRenewalWindow(time.Now().Add(24*time.Hour)))
	assert.True(t, certificateWithinRenewalWindow(time.Now().Add(-time.Hour)), "an already-expired certificate is trivially within the window")
	assert.False(t, certificateWithinRenewalWindow(time.Now().Add(200*24*time.Hour)))
}
