// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setCredentialRequestSigningCertFlags wires the module-level flags for a test run,
// authenticated via a generated admin mTLS bundle (mirrors setRoleFlags in role_test.go —
// Issue #3688 removed API-key auth from the cfg CLI). The credential store is pointed
// at a temp directory so the encrypted signing key never lands in the real user config
// directory. Returns a cleanup func.
func setCredentialRequestSigningCertFlags(t *testing.T, url string) func() {
	t.Helper()
	bundleFilePath := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFilePath, "https://placeholder.local:9443")
	overrideCredentialsDir(t, t.TempDir())

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

// setSigningCertOutputFlags points --key-out/--cert-out/--export-plaintext-key at a
// temp directory and restores them on cleanup.
func setSigningCertOutputFlags(t *testing.T, keyOut, certOut string, exportPlain bool) {
	t.Helper()
	origKeyOut := credentialRequestSigningCertKeyOut
	origCertOut := credentialRequestSigningCertCertOut
	origExport := credentialRequestSigningCertExportPlain
	credentialRequestSigningCertKeyOut = keyOut
	credentialRequestSigningCertCertOut = certOut
	credentialRequestSigningCertExportPlain = exportPlain
	t.Cleanup(func() {
		credentialRequestSigningCertKeyOut = origKeyOut
		credentialRequestSigningCertCertOut = origCertOut
		credentialRequestSigningCertExportPlain = origExport
	})
}

// setSigningCredentialName overrides --credential-name for the duration of the test.
func setSigningCredentialName(t *testing.T, name string) {
	t.Helper()
	orig := credentialRequestSigningCertCredential
	credentialRequestSigningCertCredential = name
	t.Cleanup(func() { credentialRequestSigningCertCredential = orig })
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
	setSigningCertOutputFlags(t, "", certOut, false)
	setSigningCredentialName(t, signingCredentialName)

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

	// --- private key: encrypted at rest in the credential store, no cleartext file ---
	_, statErr := os.Stat(keyOut)
	assert.True(t, os.IsNotExist(statErr),
		"no cleartext private key file may be written without --export-plaintext-key")

	credDir, err := credentialsDirFn()
	require.NoError(t, err)
	encPath := filepath.Join(credDir, signingCredentialName+".enc")
	rawEnc, err := os.ReadFile(encPath)
	require.NoError(t, err, "signing key must be persisted as an encrypted credential")
	assert.False(t, bytes.Contains(rawEnc, []byte("-----BEGIN")),
		"stored signing key must not contain a plaintext PEM header")
	assert.False(t, bytes.Contains(rawEnc, []byte("PRIVATE KEY")),
		"stored signing key must not contain a plaintext PEM private-key label")

	store, err := newCredentialStore()
	require.NoError(t, err)
	storedKeyPEM, err := store.Load(context.Background(), signingCredentialName)
	require.NoError(t, err)
	keyBlock, _ := pem.Decode(storedKeyPEM)
	require.NotNil(t, keyBlock)
	assert.Equal(t, "PRIVATE KEY", keyBlock.Type)
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	require.NoError(t, err)
	ecdsaPriv, ok := parsedKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "stored key must be ECDSA")
	assert.True(t, ecdsaPriv.PublicKey.Equal(ecdsaSentPub),
		"stored private key's public half must equal the public key that was transmitted")

	encInfo, err := os.Stat(encPath)
	require.NoError(t, err)
	// POSIX permission bits are not meaningful on Windows (ACL-based); only
	// assert the mode where the underlying filesystem honors 0600.
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0600), encInfo.Mode().Perm(), "stored credential must be mode 0600")
	}

	// --- cert file written with the server's response ---
	certBytes, err := os.ReadFile(certOut)
	require.NoError(t, err)
	assert.Equal(t, certPEM, string(certBytes))

	assert.Contains(t, output, "1234567890")
	assert.Contains(t, output, signingCredentialName)
	assert.Contains(t, output, certOut)
}

// TestCredentialRequestSigningCertCmd_PlaintextExportRequiresOptIn asserts --key-out
// alone is refused: the cleartext export is opt-in, and the refusal happens before any
// key is generated or any request is made.
func TestCredentialRequestSigningCertCmd_PlaintextExportRequiresOptIn(t *testing.T) {
	var requested bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requested = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	cleanup := setCredentialRequestSigningCertFlags(t, srv.URL)
	defer cleanup()

	tmpDir := t.TempDir()
	keyOut := filepath.Join(tmpDir, "signing-key.pem")
	setSigningCertOutputFlags(t, keyOut, filepath.Join(tmpDir, "signing-cert.pem"), false)

	err := runCredentialRequestSigningCert(credentialRequestSigningCertCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--export-plaintext-key")
	assert.False(t, requested, "no certificate may be requested when the flags are refused")

	_, statErr := os.Stat(keyOut)
	assert.True(t, os.IsNotExist(statErr), "no key file may be written when the flags are refused")
}

// TestCredentialRequestSigningCertCmd_PlaintextExportOptIn asserts that the explicit
// opt-in exports the same key that was stored encrypted, at mode 0600, and that the
// encrypted copy is written regardless.
func TestCredentialRequestSigningCertCmd_PlaintextExportOptIn(t *testing.T) {
	certPEM := "-----BEGIN CERTIFICATE-----\nZmFrZS1jZXJ0LWJvZHk=\n-----END CERTIFICATE-----\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"certificate_pem": certPEM,
				"serial_number":   "42",
				"expires_at":      time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
			},
		})
	}))
	defer srv.Close()

	cleanup := setCredentialRequestSigningCertFlags(t, srv.URL)
	defer cleanup()

	tmpDir := t.TempDir()
	keyOut := filepath.Join(tmpDir, "signing-key.pem")
	setSigningCertOutputFlags(t, keyOut, filepath.Join(tmpDir, "signing-cert.pem"), true)
	setSigningCredentialName(t, signingCredentialName)

	output := captureStdout(t, func() {
		require.NoError(t, runCredentialRequestSigningCert(credentialRequestSigningCertCmd, nil))
	})
	assert.Contains(t, output, "WARNING")

	exported, err := os.ReadFile(keyOut)
	require.NoError(t, err)
	block, _ := pem.Decode(exported)
	require.NotNil(t, block)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(keyOut)
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "exported key file must be mode 0600")
	}

	store, err := newCredentialStore()
	require.NoError(t, err)
	stored, err := store.Load(context.Background(), signingCredentialName)
	require.NoError(t, err)
	assert.Equal(t, string(stored), string(exported),
		"exported key must be the same key held encrypted in the credential store")
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
	setSigningCertOutputFlags(t, "", filepath.Join(tmpDir, "signing-cert.pem"), false)
	setSigningCredentialName(t, signingCredentialName)

	err := runCredentialRequestSigningCert(credentialRequestSigningCertCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "strong assurance required")

	// No credential material must be persisted on failure.
	_, statErr := os.Stat(credentialRequestSigningCertCertOut)
	assert.True(t, os.IsNotExist(statErr))
	credDir, err := credentialsDirFn()
	require.NoError(t, err)
	_, statErr = os.Stat(filepath.Join(credDir, signingCredentialName+".enc"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestCredentialRequestSigningCertCmd_NoCredential(t *testing.T) {
	overrideCredentialsDir(t, t.TempDir())
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
	setSigningCertOutputFlags(t, "", filepath.Join(tmpDir, "signing-cert.pem"), false)

	err := runCredentialRequestSigningCert(credentialRequestSigningCertCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credential found")
}

func TestResolveSigningCredentialOutputPaths_Defaults(t *testing.T) {
	tmpDir := t.TempDir()
	origFn := userConfigDirFn
	userConfigDirFn = func() (string, error) { return tmpDir, nil }
	defer func() { userConfigDirFn = origFn }()

	setSigningCertOutputFlags(t, "", "", false)

	keyPath, certPath, err := resolveSigningCredentialOutputPaths()
	require.NoError(t, err)
	assert.Empty(t, keyPath, "no cleartext key path may be defaulted without the export opt-in")
	assert.Equal(t, filepath.Join(tmpDir, "cfgms", "signing-cert.pem"), certPath)
}

// TestResolveSigningCredentialOutputPaths_ExportDefaults covers --export-plaintext-key
// with no --key-out: the export falls back to the documented default path.
func TestResolveSigningCredentialOutputPaths_ExportDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	origFn := userConfigDirFn
	userConfigDirFn = func() (string, error) { return tmpDir, nil }
	defer func() { userConfigDirFn = origFn }()

	setSigningCertOutputFlags(t, "", "", true)

	keyPath, certPath, err := resolveSigningCredentialOutputPaths()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(tmpDir, "cfgms", "signing-key.pem"), keyPath)
	assert.Equal(t, filepath.Join(tmpDir, "cfgms", "signing-cert.pem"), certPath)
}

func TestResolveSigningCredentialOutputPaths_ExplicitFlags(t *testing.T) {
	setSigningCertOutputFlags(t, "/tmp/explicit-key.pem", "/tmp/explicit-cert.pem", true)

	keyPath, certPath, err := resolveSigningCredentialOutputPaths()
	require.NoError(t, err)
	assert.Equal(t, "/tmp/explicit-key.pem", keyPath)
	assert.Equal(t, "/tmp/explicit-cert.pem", certPath)
}

// TestResolveSigningCredentialOutputPaths_KeyOutWithoutOptIn asserts --key-out is
// rejected rather than silently honored: writing a cleartext key requires the opt-in.
func TestResolveSigningCredentialOutputPaths_KeyOutWithoutOptIn(t *testing.T) {
	setSigningCertOutputFlags(t, "/tmp/explicit-key.pem", "/tmp/explicit-cert.pem", false)

	_, _, err := resolveSigningCredentialOutputPaths()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--export-plaintext-key")
}
