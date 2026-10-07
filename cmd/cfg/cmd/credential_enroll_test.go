// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	certbundle "github.com/cfgis/cfgms/pkg/cert/bundle"
)

// ── enrolment-token mint/revoke test helpers ──────────────────────────────────────

// setCredentialEnrolmentTokenFlags wires an admin mTLS bundle for enrolment-token
// commands, mirroring setCredentialRequestSigningCertFlags (Issue #3693).
func setCredentialEnrolmentTokenFlags(t *testing.T, url string) {
	t.Helper()
	bundleFilePath := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFilePath, "https://placeholder.local:9443")
	overrideCredentialsDir(t, t.TempDir())

	origURL := credentialEnrolmentTokenAPIURL
	origInsecure := credentialEnrolmentTokenTLSInsecure
	origBundlePath := bundlePath
	origNoBundle := noBundle
	credentialEnrolmentTokenAPIURL = url
	credentialEnrolmentTokenTLSInsecure = true
	bundlePath = bundleFilePath
	noBundle = false
	t.Cleanup(func() {
		credentialEnrolmentTokenAPIURL = origURL
		credentialEnrolmentTokenTLSInsecure = origInsecure
		bundlePath = origBundlePath
		noBundle = origNoBundle
	})
}

func TestCredentialEnrolmentTokenMint_HappyPath(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/enrolment-tokens", r.URL.Path)
		buf := make([]byte, 256)
		n, _ := r.Body.Read(buf)
		capturedBody = string(buf[:n])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"id":           "et-1",
				"token":        "raw-secret-token-value",
				"token_prefix": "raw-se",
				"tenant_id":    "root/msp-a",
				"created_at":   time.Now().UTC().Format(time.RFC3339),
				"expires_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				"revoked":      false,
			},
		})
	}))
	defer srv.Close()

	setCredentialEnrolmentTokenFlags(t, srv.URL)
	origTenant := credentialEnrolmentTokenMintTenantID
	credentialEnrolmentTokenMintTenantID = "root/msp-a"
	t.Cleanup(func() { credentialEnrolmentTokenMintTenantID = origTenant })

	out := captureStdout(t, func() {
		require.NoError(t, runCredentialEnrolmentTokenMint(credentialEnrolmentTokenMintCmd, nil))
	})

	assert.Contains(t, capturedBody, "root/msp-a")
	assert.Contains(t, out, "raw-secret-token-value", "the raw token must be printed exactly once")
	assert.Contains(t, out, "et-1")
	assert.Contains(t, out, "cfg credential enrol")
}

func TestCredentialEnrolmentTokenMint_RequiresTenantID(t *testing.T) {
	origTenant := credentialEnrolmentTokenMintTenantID
	credentialEnrolmentTokenMintTenantID = ""
	t.Cleanup(func() { credentialEnrolmentTokenMintTenantID = origTenant })

	err := runCredentialEnrolmentTokenMint(credentialEnrolmentTokenMintCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--tenant-id")
}

func TestCredentialEnrolmentTokenRevoke_HappyPath(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"id": "et-1", "token_prefix": "raw-se", "revoked": true},
		})
	}))
	defer srv.Close()

	setCredentialEnrolmentTokenFlags(t, srv.URL)

	out := captureStdout(t, func() {
		require.NoError(t, runCredentialEnrolmentTokenRevoke(credentialEnrolmentTokenRevokeCmd, []string{"et-1"}))
	})
	assert.Equal(t, "/api/v1/enrolment-tokens/et-1/revoke", capturedPath)
	assert.Contains(t, out, "et-1")
	assert.Contains(t, out, "revoked")
}

func TestCredentialEnrolmentTokenRevoke_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"Enrolment token has already been spent"}`))
	}))
	defer srv.Close()

	setCredentialEnrolmentTokenFlags(t, srv.URL)

	err := runCredentialEnrolmentTokenRevoke(credentialEnrolmentTokenRevokeCmd, []string{"et-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already been spent")
}

// ── cfg credential enrol test helpers ─────────────────────────────────────────────

// setCredentialEnrolFlags saves and restores all `cfg credential enrol` flag vars, and
// sets a fast poll interval so tests don't wait on the real default.
func setCredentialEnrolFlags(t *testing.T) {
	t.Helper()
	origToken := credentialEnrolToken
	origURL := credentialEnrolURL
	origName := credentialEnrolName
	origHostname := credentialEnrolHostname
	origLabel := credentialEnrolLabel
	origPlatform := credentialEnrolPlatform
	origPurpose := credentialEnrolPurpose
	origTLSInsecure := credentialEnrolTLSInsecure
	origServerName := credentialEnrolServerName
	origPollInterval := credentialEnrolPollInterval
	t.Cleanup(func() {
		credentialEnrolToken = origToken
		credentialEnrolURL = origURL
		credentialEnrolName = origName
		credentialEnrolHostname = origHostname
		credentialEnrolLabel = origLabel
		credentialEnrolPlatform = origPlatform
		credentialEnrolPurpose = origPurpose
		credentialEnrolTLSInsecure = origTLSInsecure
		credentialEnrolServerName = origServerName
		credentialEnrolPollInterval = origPollInterval
	})
	credentialEnrolTLSInsecure = true
	credentialEnrolPollInterval = 5 * time.Millisecond
}

// enrolCapture records what the test controller observed during an enrol run.
type enrolCapture struct {
	mu              sync.Mutex
	lodgeAuth       string
	lodgeBody       []byte
	lodgedPublicKey *ecdsa.PublicKey
	collectAuths    []string
}

func (c *enrolCapture) recordCollectAuth(auth string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectAuths = append(c.collectAuths, auth)
	return len(c.collectAuths) - 1
}

func (c *enrolCapture) getCollectAuths() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.collectAuths...)
}

// newEnrolFlowServer builds a stub controller for the enrol command flow: lodge always
// succeeds with requestID/collectSecretValue, /sessions always issues a session, and
// collect responds with collectSequence in order (the last entry repeats for any call
// beyond its length).
func newEnrolFlowServer(t *testing.T, requestID, collectSecretValue string, capt *enrolCapture, collectSequence []func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/credential-requests/lodge", func(w http.ResponseWriter, r *http.Request) {
		capt.mu.Lock()
		capt.lodgeAuth = r.Header.Get("Authorization")
		capt.mu.Unlock()
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var lodgeReq map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(body, &lodgeReq))
		var csrPEM string
		require.NoError(t, json.Unmarshal(lodgeReq["csr_pem"], &csrPEM))
		block, _ := pem.Decode([]byte(csrPEM))
		require.NotNil(t, block, "lodged csr_pem must decode as PEM")
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		require.NoError(t, err)
		pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
		require.True(t, ok, "lodged CSR must carry an ECDSA public key")

		capt.mu.Lock()
		capt.lodgeBody = body
		capt.lodgedPublicKey = pub
		capt.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"request_id":                   requestID,
				"public_key_fingerprint":       "full-fingerprint-value",
				"public_key_fingerprint_short": "AB12-CD34-EF56-7890",
				"collect_secret":               collectSecretValue,
				"expires_at":                   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			},
		})
	})
	mux.HandleFunc("/api/v1/credential-requests/"+requestID+"/collect", func(w http.ResponseWriter, r *http.Request) {
		idx := capt.recordCollectAuth(r.Header.Get("Authorization"))
		if idx >= len(collectSequence) {
			idx = len(collectSequence) - 1
		}
		collectSequence[idx](w)
	})
	mux.HandleFunc("/api/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(sessionIssueResponse{
			SessionID:      "sess-enrol-1",
			Token:          strings.Repeat("Z", 43),
			IssuedAt:       time.Now(),
			IdleTTLSeconds: 900,
			AbsoluteExpiry: time.Now().Add(8 * time.Hour),
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func collectPending(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"status": "pending"}})
}

func collectDenied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"status": "denied"}})
}

func collectExpired(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"status": "expired"}})
}

// issueTestCertificateForPublicKey signs a throwaway client certificate embedding pub —
// mirroring what the real controller's collect endpoint does (sign the lodged CSR's own
// public key) so the resulting cert/key pair is one tls.X509KeyPair actually accepts.
func issueTestCertificateForPublicKey(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject:      pkix.Name{CommonName: "test-headless"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, caKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// collectSuccessForCapture returns a collect step that signs a fresh certificate around
// the public key captured at lodge time, so the returned certificate_pem is one the
// locally held private key (never sent over the wire) actually matches.
func collectSuccessForCapture(t *testing.T, capt *enrolCapture, caPEM string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		capt.mu.Lock()
		pub := capt.lodgedPublicKey
		capt.mu.Unlock()
		require.NotNil(t, pub, "collect must not be reached before lodge captured a public key")
		certPEM := issueTestCertificateForPublicKey(t, pub)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"certificate_pem":    certPEM,
				"ca_certificate_pem": caPEM,
				"serial_number":      "999",
				"account_id":         "acct-123",
				"granted_markers":    []string{"admin"},
				"expires_at":         time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
			},
		})
	}
}

// assertNoEncryptedCredentialFile asserts credDir contains no *.enc credential file.
// newCredentialStore's encryptor writes its own housekeeping (machine-id, salt) the
// moment the store is opened, regardless of whether any credential is ever stored, so
// an empty directory is the wrong assertion — only the absence of a *.enc file proves
// no credential was written (Issue #3720 AC: denied/expired/interrupted leave none).
func assertNoEncryptedCredentialFile(t *testing.T, credDir string) {
	t.Helper()
	entries, err := os.ReadDir(credDir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.False(t, strings.HasSuffix(e.Name(), ".enc"),
			"no encrypted credential file may exist: found %s", e.Name())
	}
}

// assertNoFileContains walks dir recursively and fails the test if any file's bytes
// contain needle. Used to assert a secret was never written to disk anywhere under a
// given root (Issue #3720 [REQUIRED TEST]).
func assertNoFileContains(t *testing.T, dir, needle string) {
	t.Helper()
	if needle == "" {
		return
	}
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, rErr := os.ReadFile(path)
		if rErr != nil {
			return nil
		}
		assert.False(t, bytes.Contains(data, []byte(needle)), "file %s must not contain the secret value", path)
		return nil
	})
}

// setupEnrolCredentialDirs points the credential store and connection registry at
// fresh temp directories, and injects an in-memory session store, so the test never
// touches the real user config directory. Returns the credential directory.
func setupEnrolCredentialDirs(t *testing.T) string {
	t.Helper()
	withTempConfigDir(t)
	credDir := t.TempDir()
	origCredDir := credentialsDirFn
	credentialsDirFn = func() (string, error) { return credDir, nil }
	t.Cleanup(func() { credentialsDirFn = origCredDir })

	store := newTestSessionStore()
	overrideSessionStore(t, store)
	return credDir
}

// ── TestCredentialEnrol_HappyPath ─────────────────────────────────────────────────

func TestCredentialEnrol_HappyPath(t *testing.T) {
	credDir := setupEnrolCredentialDirs(t)
	setCredentialEnrolFlags(t)

	const enrolmentToken = "test-enrolment-token-value"
	const collectSecretValue = "test-collect-secret-value"
	caPEM := "-----BEGIN CERTIFICATE-----\nZmFrZS1jYS1ib2R5\n-----END CERTIFICATE-----\n"

	capt := &enrolCapture{}
	srv := newEnrolFlowServer(t, "cr-test-1", collectSecretValue, capt, []func(w http.ResponseWriter){
		collectPending, collectPending, collectSuccessForCapture(t, capt, caPEM),
	})

	credentialEnrolToken = enrolmentToken
	credentialEnrolURL = srv.URL
	credentialEnrolName = "test-headless"

	out := captureStdout(t, func() {
		require.NoError(t, runCredentialEnrol(credentialEnrolCmd, nil))
	})

	assert.Contains(t, out, "AB12-CD34-EF56-7890")
	assert.Contains(t, out, "Enrolled as")

	// --- [REQUIRED TEST] the private key never leaves the machine ---
	capt.mu.Lock()
	lodgeBody, lodgeAuth := capt.lodgeBody, capt.lodgeAuth
	capt.mu.Unlock()
	require.NotEmpty(t, lodgeBody)
	assert.Equal(t, "Bearer "+enrolmentToken, lodgeAuth)
	assert.False(t, strings.Contains(string(lodgeBody), "PRIVATE KEY"),
		"lodge request body must never contain a PEM private-key block")

	var lodgeReq map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(lodgeBody, &lodgeReq))
	csrRaw, ok := lodgeReq["csr_pem"]
	require.True(t, ok, "lodge request body must carry csr_pem")
	var csrPEM string
	require.NoError(t, json.Unmarshal(csrRaw, &csrPEM))
	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block, "csr_pem must be a valid PEM block")
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature(), "the lodged CSR must self-verify")
	_, isECDSA := csr.PublicKey.(*ecdsa.PublicKey)
	assert.True(t, isECDSA, "the lodged public key must be the locally generated ECDSA key")

	collectAuths := capt.getCollectAuths()
	require.NotEmpty(t, collectAuths)
	for _, h := range collectAuths {
		assert.Equal(t, "Bearer "+collectSecretValue, h, "every collect poll must authenticate with the collect secret")
	}

	// --- [REQUIRED TEST] the collect secret is held only in memory ---
	assert.False(t, strings.Contains(out, collectSecretValue),
		"the collect secret must never appear in command output, at any verbosity")
	assertNoFileContains(t, credDir, collectSecretValue)
	configDir, err := userConfigDirFn()
	require.NoError(t, err)
	assertNoFileContains(t, configDir, collectSecretValue)

	// --- [REQUIRED TEST] the stored credential goes through the encrypted store; no
	// key material is written in cleartext to any path ---
	credStore, err := newCredentialStore()
	require.NoError(t, err)
	stored, err := credStore.Load(context.Background(), "test-headless")
	require.NoError(t, err)
	var b certbundle.Bundle
	require.NoError(t, yaml.Unmarshal(stored, &b))
	assert.Contains(t, b.KeyPEM, "PRIVATE KEY")
	assert.Equal(t, caPEM, b.CAPEM)
	assert.Equal(t, srv.URL, b.ControllerURL)

	// The stored certificate and the stored private key must be a matching pair —
	// the certificate the server "signed" over the CSR's public key, paired with the
	// private key that CSR's key never left this machine to prove.
	storedTLSCert, err := tls.X509KeyPair([]byte(b.CertPEM), []byte(b.KeyPEM))
	require.NoError(t, err, "stored certificate and stored private key must match")
	parsedCert, err := x509.ParseCertificate(storedTLSCert.Certificate[0])
	require.NoError(t, err)
	storedPub, ok := parsedCert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, storedPub.Equal(capt.lodgedPublicKey),
		"the stored certificate's public key must equal the public key lodged in the CSR")

	rawEncBytes, err := os.ReadFile(filepath.Join(credDir, "test-headless.enc"))
	require.NoError(t, err)
	assert.False(t, bytes.Contains(rawEncBytes, []byte("BEGIN")),
		"stored credential must not contain a plaintext PEM header")
	assert.False(t, bytes.Contains(rawEncBytes, []byte("PRIVATE KEY")),
		"stored credential must not contain a plaintext PEM private-key label")
	assertNoFileContains(t, credDir, "PRIVATE KEY")

	// registered connection + a usable session, exactly as first-time connect leaves.
	reg, err := newConnectionRegistry()
	require.NoError(t, err)
	entry, err := reg.Get("test-headless")
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, srv.URL, entry.ControllerURL)

	rec, err := loadSessionToken()
	require.NoError(t, err)
	require.NotNil(t, rec, "a working session must be left behind so the next ordinary cfg command succeeds")
	assert.Equal(t, "sess-enrol-1", rec.SessionID)
	assert.Equal(t, srv.URL, rec.ControllerURL)
	assert.Equal(t, "test-headless", rec.ConnectionName)
}

// ── TestCredentialEnrol_Denied / Expired ──────────────────────────────────────────

func TestCredentialEnrol_Denied(t *testing.T) {
	credDir := setupEnrolCredentialDirs(t)
	setCredentialEnrolFlags(t)

	capt := &enrolCapture{}
	srv := newEnrolFlowServer(t, "cr-test-2", "collect-secret", capt, []func(w http.ResponseWriter){collectDenied})

	credentialEnrolToken = "tok"
	credentialEnrolURL = srv.URL
	credentialEnrolName = "denied-test"

	err := runCredentialEnrol(credentialEnrolCmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errCredentialRequestDenied)

	assertNoEncryptedCredentialFile(t, credDir)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)
	entry, err := reg.Get("denied-test")
	require.NoError(t, err)
	assert.Nil(t, entry, "a denied request must not register a connection")

	rec, err := loadSessionToken()
	require.NoError(t, err)
	assert.Nil(t, rec, "a denied request must not leave a session behind")
}

func TestCredentialEnrol_Expired(t *testing.T) {
	credDir := setupEnrolCredentialDirs(t)
	setCredentialEnrolFlags(t)

	capt := &enrolCapture{}
	srv := newEnrolFlowServer(t, "cr-test-3", "collect-secret", capt, []func(w http.ResponseWriter){collectExpired})

	credentialEnrolToken = "tok"
	credentialEnrolURL = srv.URL
	credentialEnrolName = "expired-test"

	err := runCredentialEnrol(credentialEnrolCmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errCredentialRequestExpired)

	assertNoEncryptedCredentialFile(t, credDir)
}

// ── TestCredentialEnrol_OperatorInterrupt ─────────────────────────────────────────

func TestCredentialEnrol_OperatorInterrupt(t *testing.T) {
	credDir := setupEnrolCredentialDirs(t)
	setCredentialEnrolFlags(t)

	capt := &enrolCapture{}
	srv := newEnrolFlowServer(t, "cr-test-4", "collect-secret", capt, []func(w http.ResponseWriter){collectPending})

	credentialEnrolToken = "tok"
	credentialEnrolURL = srv.URL
	credentialEnrolName = "interrupt-test"

	ctx, cancel := context.WithCancel(context.Background())
	origSignalFn := credentialEnrolSignalContextFn
	credentialEnrolSignalContextFn = func() (context.Context, context.CancelFunc) { return ctx, cancel }
	t.Cleanup(func() { credentialEnrolSignalContextFn = origSignalFn })

	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	err := runCredentialEnrol(credentialEnrolCmd, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errCredentialRequestInterrupted)

	assertNoEncryptedCredentialFile(t, credDir)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)
	entry, err := reg.Get("interrupt-test")
	require.NoError(t, err)
	assert.Nil(t, entry, "an operator interrupt must not register a connection")
}

// TestPollForCollection_Interrupted covers the poll loop directly, independent of
// signal wiring, so the interrupt path is tested without relying on real OS signals.
func TestPollForCollection_Interrupted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"status": "pending"}})
	}))
	defer srv.Close()

	client, err := NewAPIClient(&APIClientConfig{BaseURL: srv.URL, BearerToken: "secret", TLSInsecure: true})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, err = pollForCollection(ctx, client, "cr-1", 5*time.Millisecond, io.Discard)
	require.Error(t, err)
	assert.ErrorIs(t, err, errCredentialRequestInterrupted)
}

// ── TestCredentialEnrol_RefusesNonHTTPS / requires --token ────────────────────────

func TestCredentialEnrol_RefusesNonHTTPS(t *testing.T) {
	setCredentialEnrolFlags(t)
	credentialEnrolToken = "tok"
	credentialEnrolURL = "http://controller.example.com:9443"
	credentialEnrolName = "http-test"

	err := runCredentialEnrol(credentialEnrolCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires HTTPS")
}

func TestCredentialEnrol_RequiresToken(t *testing.T) {
	setCredentialEnrolFlags(t)
	credentialEnrolToken = ""
	credentialEnrolURL = "https://controller.example.com:9443"
	t.Setenv("CFGMS_ENROLMENT_TOKEN", "")

	err := runCredentialEnrol(credentialEnrolCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--token")
}

func TestCredentialEnrol_RequiresURL(t *testing.T) {
	setCredentialEnrolFlags(t)
	credentialEnrolToken = "tok"
	credentialEnrolURL = ""

	err := runCredentialEnrol(credentialEnrolCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--url")
}

// ── buildEnrolCSR unit coverage ────────────────────────────────────────────────────

func TestBuildEnrolCSR_NoPrivateKeyMaterial(t *testing.T) {
	priv, err := generateECDSAP256Keypair()
	require.NoError(t, err)

	csrPEM, err := buildEnrolCSR(priv, "my-host")
	require.NoError(t, err)
	assert.False(t, strings.Contains(csrPEM, "PRIVATE KEY"))

	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature())
	assert.Equal(t, "my-host", csr.Subject.CommonName)
}
