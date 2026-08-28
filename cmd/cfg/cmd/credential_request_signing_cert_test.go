// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setCredentialRequestSigningCertFlags wires the module-level flags for a test run,
// authenticated via a generated admin mTLS bundle (mirrors setRoleFlags in role_test.go —
// Issue #3688 removed API-key auth from the cfg CLI). Returns a cleanup func.
func setCredentialRequestSigningCertFlags(t *testing.T, url string) func() {
	t.Helper()
	bundleFilePath := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFilePath, "https://placeholder.local:9443")

	origURL := credentialRequestSigningCertAPIURL
	origInsecure := credentialRequestSigningCertTLSInsecure
	origBundlePath := bundlePath
	origNoBundle := noBundle
	credentialRequestSigningCertAPIURL = url
	credentialRequestSigningCertTLSInsecure = true
	bundlePath = bundleFilePath
	noBundle = false
	return func() {
		credentialRequestSigningCertAPIURL = origURL
		credentialRequestSigningCertTLSInsecure = origInsecure
		bundlePath = origBundlePath
		noBundle = origNoBundle
	}
}

// TestCredentialRequestSigningCertCmd_HappyPath is a [REQUIRED TEST]: it captures the
// exact bytes sent over the wire and asserts the request body contains only the
// public key — no private key material crosses the wire in either direction.
func TestCredentialRequestSigningCertCmd_HappyPath(t *testing.T) {
	var capturedBody []byte
	certPEM := "-----BEGIN CERTIFICATE-----\nZmFrZS1jZXJ0LWJvZHk=\n-----END CERTIFICATE-----\n"
	caPEM := "-----BEGIN CERTIFICATE-----\nZmFrZS1jYS1ib2R5\n-----END CERTIFICATE-----\n"
	expiresAt := time.Now().Add(365 * 24 * time.Hour).UTC()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/signing-credential/request", r.URL.Path)
		var err error
		capturedBody, err = io.ReadAll(r.Body)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"certificate_pem":    certPEM,
				"ca_certificate_pem": caPEM,
				"serial_number":      "1234567890",
				"expires_at":         expiresAt.Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	cleanup := setCredentialRequestSigningCertFlags(t, srv.URL)
	defer cleanup()

	tmpDir := t.TempDir()
	keyOut := filepath.Join(tmpDir, "signing-key.pem")
	certOut := filepath.Join(tmpDir, "signing-cert.pem")
	origKeyOut := credentialRequestSigningCertKeyOut
	origCertOut := credentialRequestSigningCertCertOut
	credentialRequestSigningCertKeyOut = keyOut
	credentialRequestSigningCertCertOut = certOut
	defer func() {
		credentialRequestSigningCertKeyOut = origKeyOut
		credentialRequestSigningCertCertOut = origCertOut
	}()

	output := captureStdout(t, func() {
		err := runCredentialRequestSigningCert(credentialRequestSigningCertCmd, nil)
		require.NoError(t, err)
	})

	// --- [REQUIRED TEST] wire format contains only the public key ---
	require.NotEmpty(t, capturedBody)
	var wireReq map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(capturedBody, &wireReq))
	assert.Len(t, wireReq, 1, "request body must carry exactly one field")
	pubKeyRaw, hasPublicKey := wireReq["public_key_pem"]
	require.True(t, hasPublicKey, "request body must carry public_key_pem")
	assert.False(t, strings.Contains(string(capturedBody), "PRIVATE KEY"),
		"request body must never contain a PEM private-key block")

	var pubKeyPEM string
	require.NoError(t, json.Unmarshal(pubKeyRaw, &pubKeyPEM))
	block, _ := pem.Decode([]byte(pubKeyPEM))
	require.NotNil(t, block, "public_key_pem must be a valid PEM block")
	assert.Equal(t, "PUBLIC KEY", block.Type)
	sentPub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ecdsaSentPub, ok := sentPub.(*ecdsa.PublicKey)
	require.True(t, ok, "public_key_pem must decode to an ECDSA public key")

	// --- local key file: written, private, and matches the key that was sent ---
	keyBytes, err := os.ReadFile(keyOut)
	require.NoError(t, err)
	keyBlock, _ := pem.Decode(keyBytes)
	require.NotNil(t, keyBlock)
	assert.Equal(t, "PRIVATE KEY", keyBlock.Type)
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	ecdsaPriv, ok := parsedKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "written key must be ECDSA")
	assert.True(t, ecdsaPriv.PublicKey.Equal(ecdsaSentPub),
		"local private key's public half must equal the public key that was transmitted")

	keyInfo, err := os.Stat(keyOut)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), keyInfo.Mode().Perm(), "private key file must be mode 0600")

	// --- cert file written with the server's response ---
	certBytes, err := os.ReadFile(certOut)
	require.NoError(t, err)
	assert.Equal(t, certPEM, string(certBytes))

	assert.Contains(t, output, "1234567890")
	assert.Contains(t, output, keyOut)
	assert.Contains(t, output, certOut)
}

func TestCredentialRequestSigningCertCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"FORBIDDEN","message":"strong assurance required"}}`))
	}))
	defer srv.Close()

	cleanup := setCredentialRequestSigningCertFlags(t, srv.URL)
	defer cleanup()

	tmpDir := t.TempDir()
	origKeyOut := credentialRequestSigningCertKeyOut
	origCertOut := credentialRequestSigningCertCertOut
	credentialRequestSigningCertKeyOut = filepath.Join(tmpDir, "signing-key.pem")
	credentialRequestSigningCertCertOut = filepath.Join(tmpDir, "signing-cert.pem")
	defer func() {
		credentialRequestSigningCertKeyOut = origKeyOut
		credentialRequestSigningCertCertOut = origCertOut
	}()

	err := runCredentialRequestSigningCert(credentialRequestSigningCertCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "strong assurance required")

	// No files must be written on failure.
	_, statErr := os.Stat(credentialRequestSigningCertKeyOut)
	assert.True(t, os.IsNotExist(statErr))
	_, statErr = os.Stat(credentialRequestSigningCertCertOut)
	assert.True(t, os.IsNotExist(statErr))
}

func TestCredentialRequestSigningCertCmd_NoCredential(t *testing.T) {
	origURL := credentialRequestSigningCertAPIURL
	origBundlePath := bundlePath
	origNoBundle := noBundle
	credentialRequestSigningCertAPIURL = ""
	bundlePath = ""
	noBundle = true // force no-credential path
	defer func() {
		credentialRequestSigningCertAPIURL = origURL
		bundlePath = origBundlePath
		noBundle = origNoBundle
	}()

	tmpDir := t.TempDir()
	origKeyOut := credentialRequestSigningCertKeyOut
	origCertOut := credentialRequestSigningCertCertOut
	credentialRequestSigningCertKeyOut = filepath.Join(tmpDir, "signing-key.pem")
	credentialRequestSigningCertCertOut = filepath.Join(tmpDir, "signing-cert.pem")
	defer func() {
		credentialRequestSigningCertKeyOut = origKeyOut
		credentialRequestSigningCertCertOut = origCertOut
	}()

	err := runCredentialRequestSigningCert(credentialRequestSigningCertCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credential found")
}

func TestResolveSigningCredentialOutputPaths_Defaults(t *testing.T) {
	tmpDir := t.TempDir()
	origFn := userConfigDirFn
	userConfigDirFn = func() (string, error) { return tmpDir, nil }
	defer func() { userConfigDirFn = origFn }()

	origKeyOut := credentialRequestSigningCertKeyOut
	origCertOut := credentialRequestSigningCertCertOut
	credentialRequestSigningCertKeyOut = ""
	credentialRequestSigningCertCertOut = ""
	defer func() {
		credentialRequestSigningCertKeyOut = origKeyOut
		credentialRequestSigningCertCertOut = origCertOut
	}()

	keyPath, certPath, err := resolveSigningCredentialOutputPaths()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(tmpDir, "cfgms", "signing-key.pem"), keyPath)
	assert.Equal(t, filepath.Join(tmpDir, "cfgms", "signing-cert.pem"), certPath)
}

func TestResolveSigningCredentialOutputPaths_ExplicitFlags(t *testing.T) {
	origKeyOut := credentialRequestSigningCertKeyOut
	origCertOut := credentialRequestSigningCertCertOut
	credentialRequestSigningCertKeyOut = "/tmp/explicit-key.pem"
	credentialRequestSigningCertCertOut = "/tmp/explicit-cert.pem"
	defer func() {
		credentialRequestSigningCertKeyOut = origKeyOut
		credentialRequestSigningCertCertOut = origCertOut
	}()

	keyPath, certPath, err := resolveSigningCredentialOutputPaths()
	require.NoError(t, err)
	assert.Equal(t, "/tmp/explicit-key.pem", keyPath)
	assert.Equal(t, "/tmp/explicit-cert.pem", certPath)
}
