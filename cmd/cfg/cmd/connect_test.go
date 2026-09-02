// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certbundle "github.com/cfgis/cfgms/pkg/cert/bundle"
	"github.com/cfgis/cfgms/pkg/credential"
	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// ── in-memory SecretStore for tests ──────────────────────────────────────────

// testSessionStore is a thread-safe in-memory SecretStore for injecting via sessionStoreFn.
type testSessionStore struct {
	mu       sync.Mutex
	secrets  map[string]string
	versions map[string]int
}

func newTestSessionStore() *testSessionStore {
	return &testSessionStore{secrets: make(map[string]string)}
}

func (s *testSessionStore) StoreSecret(_ context.Context, req *interfaces.SecretRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[req.Key] = req.Value
	return nil
}

func (s *testSessionStore) CompareAndSwapSecret(_ context.Context, key string, expectedVersion int, req *interfaces.SecretRequest) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.versions == nil {
		s.versions = make(map[string]int)
	}
	if s.versions[key] != expectedVersion {
		return 0, false, nil
	}
	s.secrets[req.Key] = req.Value
	s.versions[key]++
	return s.versions[key], true, nil
}

func (s *testSessionStore) GetSecret(_ context.Context, key string) (*interfaces.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.secrets[key]
	if !ok {
		return nil, interfaces.ErrSecretNotFound
	}
	return &interfaces.Secret{Key: key, Value: v}, nil
}

func (s *testSessionStore) DeleteSecret(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.secrets[key]; !ok {
		return interfaces.ErrSecretNotFound
	}
	delete(s.secrets, key)
	return nil
}

func (s *testSessionStore) ListSecrets(_ context.Context, _ *interfaces.SecretFilter) ([]*interfaces.SecretMetadata, error) {
	return nil, errors.New("not implemented")
}
func (s *testSessionStore) GetSecrets(_ context.Context, _ []string) (map[string]*interfaces.Secret, error) {
	return nil, errors.New("not implemented")
}
func (s *testSessionStore) StoreSecrets(_ context.Context, _ map[string]*interfaces.SecretRequest) error {
	return errors.New("not implemented")
}
func (s *testSessionStore) GetSecretVersion(_ context.Context, _ string, _ int) (*interfaces.Secret, error) {
	return nil, errors.New("not implemented")
}
func (s *testSessionStore) ListSecretVersions(_ context.Context, _ string) ([]*interfaces.SecretVersion, error) {
	return nil, errors.New("not implemented")
}
func (s *testSessionStore) GetSecretMetadata(_ context.Context, _ string) (*interfaces.SecretMetadata, error) {
	return nil, errors.New("not implemented")
}
func (s *testSessionStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return errors.New("not implemented")
}
func (s *testSessionStore) RotateSecret(_ context.Context, _ string, _ string) error {
	return errors.New("not implemented")
}
func (s *testSessionStore) ExpireSecret(_ context.Context, _ string) error {
	return errors.New("not implemented")
}
func (s *testSessionStore) HealthCheck(_ context.Context) error { return nil }
func (s *testSessionStore) Close() error                        { return nil }

// ── counting CredentialUnlocker ───────────────────────────────────────────────

// countingUnlocker wraps a real MachineUnlocker and counts Unlock invocations.
type countingUnlocker struct {
	underlying credential.CredentialUnlocker
	count      *int64
}

func (u *countingUnlocker) Unlock(ctx context.Context, name string) ([]byte, error) {
	atomic.AddInt64(u.count, 1)
	return u.underlying.Unlock(ctx, name)
}

func (u *countingUnlocker) Lock(ctx context.Context, name string) error {
	return u.underlying.Lock(ctx, name)
}

// ── HTTPS session test server ─────────────────────────────────────────────────

// sessionStub is a minimal HTTPS server that handles /api/v1/sessions endpoints.
// It tracks issued and revoked sessions for the test assertions.
type sessionStub struct {
	mu       sync.Mutex
	sessions map[string]string // sessionID → token
	revoked  map[string]bool   // sessionID → revoked
	requests []string          // method+path log for assertions
}

func (s *sessionStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/sessions":
		s.mu.Lock()
		id := "sess-test-id"
		tok := strings.Repeat("A", 43) // exactly 43 chars
		s.sessions[id] = tok
		s.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(sessionIssueResponse{
			SessionID:      id,
			Token:          tok,
			IssuedAt:       time.Now(),
			IdleTTLSeconds: 900,
			AbsoluteExpiry: time.Now().Add(8 * time.Hour),
		})

	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/v1/sessions/"):
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/sessions/")
		s.mu.Lock()
		s.revoked[id] = true
		delete(s.sessions, id)
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": id, "revoked": true})

	default:
		// For other requests, check if the bearer token belongs to a live session.
		authHeader := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(authHeader, "Bearer ")
		s.mu.Lock()
		live := false
		for _, t := range s.sessions {
			if t == tok {
				live = true
				break
			}
		}
		s.mu.Unlock()
		if !live && authHeader != "" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "SESSION_REVOKED"})
			return
		}
		// Any other live-session request → 200 OK.
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

// ── certificate helpers ───────────────────────────────────────────────────────

type testCerts struct {
	caKey      *ecdsa.PrivateKey
	caCertDER  []byte
	caCert     *x509.Certificate
	caCertPEM  []byte
	serverCert tls.Certificate
	clientCert *certbundle.Bundle // ready to write
}

func generateConnectTestCerts(t *testing.T, serverURL string) *testCerts {
	t.Helper()

	// CA
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

	// Server cert (valid for 127.0.0.1 / localhost so the TLS client trusts it).
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	require.NoError(t, err)
	serverKeyBytes, err := x509.MarshalECPrivateKey(serverKey)
	require.NoError(t, err)
	serverTLSCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyBytes}),
	)
	require.NoError(t, err)

	// Client cert
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)
	clientKeyBytes, err := x509.MarshalECPrivateKey(clientKey)
	require.NoError(t, err)

	return &testCerts{
		caKey:      caKey,
		caCertDER:  caCertDER,
		caCert:     caCert,
		caCertPEM:  caCertPEM,
		serverCert: serverTLSCert,
		clientCert: &certbundle.Bundle{
			CertPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER})),
			KeyPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: clientKeyBytes})),
			CAPEM:        string(caCertPEM),
			AuditSubject: "test:admin",
		},
	}
}

// generateHostnameOnlyServerCert issues a server certificate signed by ca.caKey that is
// valid for dnsName only — deliberately no IP SANs — so a client connecting by IP fails
// hostname verification unless the TLS server name is overridden.
func generateHostnameOnlyServerCert(t *testing.T, ca *testCerts, dnsName string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.caCert, &key.PublicKey, ca.caKey)
	require.NoError(t, err)
	keyBytes, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}),
	)
	require.NoError(t, err)
	return tlsCert
}

// startTLSTestServer starts an HTTPS test server presenting serverCert.
// When clientCAs is non-nil the server requires and verifies a client certificate (mTLS).
func startTLSTestServer(t *testing.T, serverCert tls.Certificate, clientCAs *x509.CertPool, handler http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(handler)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}
	if clientCAs != nil {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = clientCAs
	}
	ts.TLS = cfg
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// startSessionServer creates and starts an HTTPS server backed by stub.
func startSessionServer(t *testing.T, certs *testCerts, stub *sessionStub) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(stub)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{certs.serverCert},
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// ── override helpers ──────────────────────────────────────────────────────────

// overrideSessionStore replaces sessionStoreFn with one that returns store.
func overrideSessionStore(t *testing.T, store interfaces.SecretStore) {
	t.Helper()
	orig := sessionStoreFn
	sessionStoreFn = func() (interfaces.SecretStore, error) { return store, nil }
	t.Cleanup(func() { sessionStoreFn = orig })
}

// overrideConnectFlags saves and restores all connect command-level flag vars.
func overrideConnectFlags(t *testing.T) {
	t.Helper()
	origBundle := connectBundlePath
	origURL := connectURL
	origName := connectName
	origGlobalBundle := bundlePath
	origNoBundle := noBundle
	t.Cleanup(func() {
		connectBundlePath = origBundle
		connectURL = origURL
		connectName = origName
		bundlePath = origGlobalBundle
		noBundle = origNoBundle
	})
}

// ── TestConnectReconnectDisconnect ────────────────────────────────────────────

func TestConnectReconnectDisconnect(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate CA, server, and client certificates.
	certs := generateConnectTestCerts(t, "")

	// Start the HTTPS session stub server.
	stub := &sessionStub{
		sessions: make(map[string]string),
		revoked:  make(map[string]bool),
	}
	srv := startSessionServer(t, certs, stub)

	// Set the bundle's ControllerURL to the actual server address.
	certs.clientCert.ControllerURL = srv.URL
	bundleFile := filepath.Join(tmpDir, "admin.bundle.yaml")
	require.NoError(t, certbundle.Write(bundleFile, certs.clientCert))

	// Inject in-memory session store (no disk writes for session token).
	store := newTestSessionStore()
	overrideSessionStore(t, store)

	// Override connection registry + credential dirs to temp dirs.
	withTempConfigDir(t)
	credDir := t.TempDir()
	origCredDir := credentialsDirFn
	credentialsDirFn = func() (string, error) { return credDir, nil }
	t.Cleanup(func() { credentialsDirFn = origCredDir })

	// Inject a counting unlocker so we can assert unlock call count.
	var unlockCount int64
	origUnlockerFn := credentialStoreUnlockerFn
	credentialStoreUnlockerFn = func(dir string) (credential.CredentialUnlocker, error) {
		real, err := credential.NewMachineUnlocker(dir)
		if err != nil {
			return nil, err
		}
		return &countingUnlocker{underlying: real, count: &unlockCount}, nil
	}
	t.Cleanup(func() { credentialStoreUnlockerFn = origUnlockerFn })

	overrideConnectFlags(t)

	// ── Phase 1: first-time connect ──────────────────────────────────────────
	connectBundlePath = bundleFile
	connectURL = srv.URL
	connectName = "test-ctrl"
	bundlePath = ""
	noBundle = false

	out := captureStdout(t, func() {
		require.NoError(t, runConnect(connectCmd, nil))
	})
	assert.Contains(t, out, "Connected as")
	assert.Contains(t, out, "test-ctrl")

	// Token must be in the in-memory store, not in any file.
	rec, err := loadSessionToken()
	require.NoError(t, err)
	require.NotNil(t, rec, "session token must be stored after connect")
	assert.Equal(t, "sess-test-id", rec.SessionID)
	assert.Equal(t, srv.URL, rec.ControllerURL)
	assert.False(t, rec.AbsoluteExpiry.IsZero())

	// Verify no token file exists anywhere in the credential directory.
	entries, err := os.ReadDir(credDir)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "token",
			"no token file must appear in the credential dir: %s", e.Name())
		assert.NotContains(t, e.Name(), "session",
			"no session file must appear in the credential dir: %s", e.Name())
	}

	// ── Phase 2: reconnect ───────────────────────────────────────────────────
	// Clear first-time flags; use the stored name.
	connectBundlePath = ""
	connectURL = ""
	connectName = ""

	out = captureStdout(t, func() {
		require.NoError(t, runConnect(connectCmd, []string{"test-ctrl"}))
	})
	assert.Contains(t, out, "Reconnected as")
	assert.Equal(t, int64(1), atomic.LoadInt64(&unlockCount),
		"unlocker must be invoked exactly once (during reconnect)")

	// ── Phase 3: N session-backed commands must NOT invoke the unlocker ──────
	// After reconnect the session token is stored; resolveSessionOrBundleClient
	// uses it without touching the credential store.
	bundlePath = ""
	noBundle = false

	const N = 3
	for i := range N {
		client, cErr := resolveSessionOrBundleClient("", false, "")
		require.NoError(t, cErr, "command %d: resolve client", i)
		require.NotNil(t, client, "command %d: session client must not be nil", i)

		// Simulate a command request against the stub.
		resp, rErr := client.doRequestWithContentType(
			context.Background(), http.MethodGet, "/api/v1/status", nil, "",
		)
		require.NoError(t, rErr, "command %d: request error", i)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"command %d: session Bearer token must be accepted by the controller", i)
	}

	assert.Equal(t, int64(1), atomic.LoadInt64(&unlockCount),
		"session-backed commands must not invoke the credential unlocker")

	// ── Phase 4: disconnect ──────────────────────────────────────────────────
	storedToken := store.secrets[sessionTokenKey] // capture before delete
	out = captureStdout(t, func() {
		require.NoError(t, runDisconnect(disconnectCmd, nil))
	})
	assert.Contains(t, out, "Disconnected")

	// Token must be removed from the in-memory store.
	rec, err = loadSessionToken()
	require.NoError(t, err)
	assert.Nil(t, rec, "session token must be removed from store after disconnect")

	// Verify the stub received a DELETE /api/v1/sessions/{id}.
	stub.mu.Lock()
	revokedOK := stub.revoked["sess-test-id"]
	stub.mu.Unlock()
	assert.True(t, revokedOK, "server must have recorded the session as revoked")

	// ── Phase 5: verify controller-side 401 after disconnect ─────────────────
	// Extract the raw session token from the stored JSON (it was valid before disconnect).
	var preRevoke sessionRecord
	require.NoError(t, json.Unmarshal([]byte(storedToken), &preRevoke))

	revokedClient, err := NewAPIClient(&APIClientConfig{
		BaseURL:     srv.URL,
		BearerToken: preRevoke.Token,
		TLSInsecure: true,
	})
	require.NoError(t, err)

	resp, err := revokedClient.doRequestWithContentType(
		context.Background(), http.MethodGet, "/api/v1/status", nil, "",
	)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"revoked session token must return 401 from the controller")
}

// ── TestBundleOverrideBypassesSession ────────────────────────────────────────

// TestBundleOverrideBypassesSession verifies that a --bundle invocation does not
// read the session token store and uses bundle auth even when a valid stored
// session exists.
func TestBundleOverrideBypassesSession(t *testing.T) {
	tmpDir := t.TempDir()

	// Plant a valid (non-expired) session token in the store.
	store := newTestSessionStore()
	overrideSessionStore(t, store)

	var storeReadCount int64
	orig := sessionStoreFn
	sessionStoreFn = func() (interfaces.SecretStore, error) {
		atomic.AddInt64(&storeReadCount, 1)
		return store, nil
	}
	t.Cleanup(func() { sessionStoreFn = orig })

	// Store a fake valid session.
	require.NoError(t, storeSessionToken(&sessionRecord{
		Token:          strings.Repeat("B", 43),
		SessionID:      "fake-session",
		ControllerURL:  "https://session-ctrl.example.com",
		ConnectionName: "session-conn",
		AbsoluteExpiry: time.Now().Add(8 * time.Hour),
	}))
	// Reset count after seed call.
	atomic.StoreInt64(&storeReadCount, 0)

	// Create a bundle that points to a test HTTP server.
	bundleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer bundleServer.Close()

	bundleFile := filepath.Join(tmpDir, "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFile, bundleServer.URL)

	// Call resolveSessionOrBundleClient with bundlePath set (simulates --bundle flag).
	origBundlePath := bundlePath
	t.Cleanup(func() { bundlePath = origBundlePath })
	bundlePath = bundleFile

	client, err := resolveSessionOrBundleClient("", false, "")
	require.NoError(t, err)
	require.NotNil(t, client, "bundle client must be returned when --bundle is set")

	// The client must use the bundle URL, not the session's ControllerURL.
	assert.Equal(t, bundleServer.URL, client.baseURL,
		"resolved client must use bundle URL, not session URL")

	// The session store must NOT have been queried for the bypass path.
	assert.Equal(t, int64(0), atomic.LoadInt64(&storeReadCount),
		"session store must not be read when --bundle flag is set")
}

// ── TestRequireHTTPS ──────────────────────────────────────────────────────────

func TestRequireHTTPS_RejectsHTTPNonLoopback(t *testing.T) {
	err := requireHTTPS("http://controller.example.com:9443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires HTTPS", "error message must mention HTTPS requirement")
}

func TestRequireHTTPS_AllowsHTTPSNonLoopback(t *testing.T) {
	assert.NoError(t, requireHTTPS("https://controller.example.com:9443"))
}

func TestRequireHTTPS_AllowsHTTPLoopback(t *testing.T) {
	assert.NoError(t, requireHTTPS("http://localhost:9080"))
	assert.NoError(t, requireHTTPS("http://127.0.0.1:9080"))
}

// ── TestDisconnect_NoActiveSession ────────────────────────────────────────────

func TestDisconnect_NoActiveSession(t *testing.T) {
	store := newTestSessionStore()
	overrideSessionStore(t, store)

	out := captureStdout(t, func() {
		require.NoError(t, runDisconnect(disconnectCmd, nil))
	})
	assert.Contains(t, out, "No active session")
}

// ── TestConnectionsCurrent ────────────────────────────────────────────────────

func TestConnectionsCurrent_ActiveSession(t *testing.T) {
	store := newTestSessionStore()
	overrideSessionStore(t, store)

	expiry := time.Now().Add(8 * time.Hour)
	require.NoError(t, storeSessionToken(&sessionRecord{
		Token:          strings.Repeat("C", 43),
		SessionID:      "sess-current-test",
		ControllerURL:  "https://ctrl.example.com",
		ConnectionName: "prod",
		AbsoluteExpiry: expiry,
	}))

	out := captureStdout(t, func() {
		require.NoError(t, runConnectionsCurrent(connectionsCurrentCmd, nil))
	})
	assert.Contains(t, out, "prod")
	assert.Contains(t, out, "https://ctrl.example.com")
	assert.Contains(t, out, "sess-current-test")
}

func TestConnectionsCurrent_NoSession(t *testing.T) {
	store := newTestSessionStore()
	overrideSessionStore(t, store)

	out := captureStdout(t, func() {
		require.NoError(t, runConnectionsCurrent(connectionsCurrentCmd, nil))
	})
	assert.Contains(t, out, "no active session")
}

func TestConnectionsCurrent_ExpiredSession(t *testing.T) {
	store := newTestSessionStore()
	overrideSessionStore(t, store)

	require.NoError(t, storeSessionToken(&sessionRecord{
		Token:          strings.Repeat("D", 43),
		SessionID:      "expired",
		ControllerURL:  "https://ctrl.example.com",
		ConnectionName: "old",
		AbsoluteExpiry: time.Now().Add(-time.Hour), // in the past
	}))

	out := captureStdout(t, func() {
		require.NoError(t, runConnectionsCurrent(connectionsCurrentCmd, nil))
	})
	assert.Contains(t, out, "no active session")
}

// ── TestDeriveConnectionName ──────────────────────────────────────────────────

func TestDeriveConnectionName(t *testing.T) {
	cases := []struct{ url, want string }{
		{"https://ctrl.example.com:9443", "ctrl.example.com"},
		{"https://ctrl.example.com", "ctrl.example.com"},
		{"http://localhost:9080", "localhost"},
		{"not-a-url", "default"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, deriveConnectionName(c.url), "url=%s", c.url)
	}
}

// ── TestSessionTokenRoundTrip ─────────────────────────────────────────────────

func TestSessionTokenRoundTrip(t *testing.T) {
	store := newTestSessionStore()
	overrideSessionStore(t, store)

	want := &sessionRecord{
		Token:          strings.Repeat("E", 43),
		SessionID:      "round-trip-id",
		ControllerURL:  "https://ctrl.local:9443",
		ConnectionName: "local",
		AbsoluteExpiry: time.Now().Add(8 * time.Hour).Truncate(time.Second),
	}
	require.NoError(t, storeSessionToken(want))

	got, err := loadSessionToken()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, want.Token, got.Token)
	assert.Equal(t, want.SessionID, got.SessionID)
	assert.Equal(t, want.ControllerURL, got.ControllerURL)
	assert.Equal(t, want.ConnectionName, got.ConnectionName)
	assert.WithinDuration(t, want.AbsoluteExpiry, got.AbsoluteExpiry, time.Second)

	require.NoError(t, deleteSessionToken())
	got, err = loadSessionToken()
	require.NoError(t, err)
	assert.Nil(t, got, "deleted token must not be loadable")
}

// ── TestUpdateSessionToken ────────────────────────────────────────────────────

func TestUpdateSessionToken(t *testing.T) {
	store := newTestSessionStore()
	overrideSessionStore(t, store)

	require.NoError(t, storeSessionToken(&sessionRecord{
		Token:          "old-token",
		SessionID:      "up-sid",
		ControllerURL:  "https://ctrl.local",
		ConnectionName: "upd",
		AbsoluteExpiry: time.Now().Add(time.Hour),
	}))

	require.NoError(t, updateSessionToken("new-token"))

	got, err := loadSessionToken()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "new-token", got.Token, "token must be updated")
	assert.Equal(t, "up-sid", got.SessionID, "session ID must be unchanged")
}

// ── TestResolveSessionOrBundleClient_Expiry ───────────────────────────────────

func TestResolveSessionOrBundleClient_ExpiredTokenFallsThrough(t *testing.T) {
	store := newTestSessionStore()
	overrideSessionStore(t, store)

	// Store an expired session.
	require.NoError(t, storeSessionToken(&sessionRecord{
		Token:          strings.Repeat("F", 43),
		SessionID:      "expired-sess",
		ControllerURL:  "https://ctrl.example.com",
		ConnectionName: "exp",
		AbsoluteExpiry: time.Now().Add(-time.Hour),
	}))

	origBundlePath := bundlePath
	origNoBundle := noBundle
	t.Cleanup(func() {
		bundlePath = origBundlePath
		noBundle = origNoBundle
	})
	bundlePath = ""
	noBundle = true // force nil return from resolveBundleClient

	client, err := resolveSessionOrBundleClient("", false, "")
	require.NoError(t, err)
	assert.Nil(t, client, "expired session must fall through to bundle client (nil when no bundle)")
}

// ── TestAPIClientOnTokenRenewed ───────────────────────────────────────────────

func TestAPIClientOnTokenRenewed(t *testing.T) {
	var capturedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Session-Token", "renewed-token-value")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client, err := NewAPIClient(&APIClientConfig{
		BaseURL: srv.URL,
		OnTokenRenewed: func(tok string) error {
			capturedToken = tok
			return nil
		},
	})
	require.NoError(t, err)

	resp, err := client.doRequestWithContentType(context.Background(), http.MethodGet, "/", nil, "")
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, "renewed-token-value", capturedToken,
		"OnTokenRenewed must be called with the header value")
}

// ── TestAPIClientOnUnauthorizedFallback ───────────────────────────────────────

func TestAPIClientOnUnauthorizedFallback(t *testing.T) {
	callCount := 0
	fallbackCalled := false

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"SESSION_REVOKED"}`))
	}))
	defer primary.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalled = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer fallback.Close()

	fallbackClient, err := NewAPIClient(&APIClientConfig{BaseURL: fallback.URL})
	require.NoError(t, err)

	client, err := NewAPIClient(&APIClientConfig{
		BaseURL: primary.URL,
		OnUnauthorized: func() (*APIClient, error) {
			return fallbackClient, nil
		},
	})
	require.NoError(t, err)

	resp, err := client.doRequestWithContentType(context.Background(), http.MethodGet, "/", nil, "")
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "fallback client response must be returned")
	assert.True(t, fallbackCalled, "fallback server must be called on 401")
	assert.Equal(t, 1, callCount, "primary server must be called exactly once")
}

// ── TestConnectFirstTime_HTTPSGuard ───────────────────────────────────────────

func TestConnectFirstTime_HTTPSGuard(t *testing.T) {
	origBundle := connectBundlePath
	origURL := connectURL
	origName := connectName
	t.Cleanup(func() {
		connectBundlePath = origBundle
		connectURL = origURL
		connectName = origName
	})

	// Write a dummy bundle file so the file read doesn't fail first.
	tmpDir := t.TempDir()
	bundleFile := filepath.Join(tmpDir, "admin.bundle.yaml")
	require.NoError(t, os.WriteFile(bundleFile, []byte("cert_pem: ''\nkey_pem: ''\nca_pem: ''\n"), 0600))

	connectBundlePath = bundleFile
	connectURL = "http://controller.example.com:9443" // non-loopback http://
	connectName = "guard-test"

	err := runConnect(connectCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires HTTPS")
}

// ── TestSessionTLSInsecureFallbackSkipsVerification ───────────────────────────

// TestSessionTLSInsecureFallbackSkipsVerification covers AC #5: a confirmed
// session-token --tls-insecure call skips certificate verification, and when that
// session 401s and falls back through OnUnauthorized to a bundle client the fallback
// client must also skip verification — gated by the mTLS banner, not by a second
// confirmation prompt.
func TestSessionTLSInsecureFallbackSkipsVerification(t *testing.T) {
	// Two independent CAs. The bundle trusts CA1 (its own CAPEM), while the fallback
	// server presents a CA2-signed certificate, so a fallback client that reverted to
	// verifying the server certificate could not complete the handshake at all.
	sessionCerts := generateConnectTestCerts(t, "")
	fallbackCerts := generateConnectTestCerts(t, "")

	var primaryHits, fallbackHits int64
	primary := startTLSTestServer(t, sessionCerts.serverCert, nil,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt64(&primaryHits, 1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"SESSION_REVOKED"}`))
		}))

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(sessionCerts.caCert)
	var peerCN atomic.Value
	fallback := startTLSTestServer(t, fallbackCerts.serverCert, clientCAs,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(&fallbackHits, 1)
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				peerCN.Store(r.TLS.PeerCertificates[0].Subject.CommonName)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))

	// Bundle: CA1 client credential, CA1 trust anchor, pointing at the fallback server.
	bundleFile := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	sessionCerts.clientCert.ControllerURL = fallback.URL
	require.NoError(t, certbundle.Write(bundleFile, sessionCerts.clientCert))
	t.Setenv("CFGMS_ADMIN_BUNDLE", bundleFile)

	// Session record with no stored CA → system pool, so the CA1-signed session
	// server is untrusted unless verification is genuinely skipped.
	store := newTestSessionStore()
	overrideSessionStore(t, store)
	require.NoError(t, storeSessionToken(&sessionRecord{
		Token:          strings.Repeat("G", 43),
		SessionID:      "insecure-fallback",
		ControllerURL:  primary.URL,
		ConnectionName: "insecure",
		AbsoluteExpiry: time.Now().Add(8 * time.Hour),
	}))

	origBundlePath, origNoBundle := bundlePath, noBundle
	t.Cleanup(func() { bundlePath, noBundle = origBundlePath, origNoBundle })
	bundlePath, noBundle = "", false

	// Confirmation gate: TTY with exactly one line of input available. A second prompt
	// would read EOF and fail the call, so this input also proves no re-prompt happens.
	var out strings.Builder
	origWriter, origReader, origTTY := tlsInsecureWriter, tlsInsecureReader, isTTYFn
	tlsInsecureWriter = &out
	tlsInsecureReader = strings.NewReader(tlsInsecureConfirmPhrase + "\n")
	isTTYFn = func() bool { return true }
	t.Cleanup(func() {
		tlsInsecureWriter, tlsInsecureReader, isTTYFn = origWriter, origReader, origTTY
	})

	client, err := resolveSessionOrBundleClient("", true, "")
	require.NoError(t, err)
	require.NotNil(t, client)

	primaryTLS := client.httpClient.Transport.(*http.Transport).TLSClientConfig
	require.True(t, primaryTLS.InsecureSkipVerify,
		"session client must skip verification under confirmed --tls-insecure")

	resp, err := client.doRequestWithContentType(context.Background(), http.MethodGet, "/", nil, "")
	require.NoError(t, err,
		"401 fallback to the bundle client must complete the handshake against an untrusted server cert")
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode, "fallback bundle client response must be returned")
	assert.Equal(t, int64(1), atomic.LoadInt64(&primaryHits), "session server must be called exactly once")
	assert.Equal(t, int64(1), atomic.LoadInt64(&fallbackHits), "fallback server must be called exactly once")
	assert.Equal(t, "test-admin", peerCN.Load(),
		"fallback must still present the bundle mTLS client certificate")

	// Banner gate, not a second confirmation prompt.
	assert.Contains(t, out.String(), tlsInsecureMTLSWarning,
		"fallback bundle client must print the mTLS banner")
	assert.Equal(t, 1, strings.Count(out.String(), tlsInsecureConfirmPrompt),
		"fallback must not issue a second confirmation prompt")
	assert.Equal(t, 1, strings.Count(out.String(), tlsInsecureSessionWarning),
		"session warning must be printed once, by the session client only")

	// The client produced by the OnUnauthorized closure itself carries InsecureSkipVerify.
	fallbackClient, err := client.onUnauthorized()
	require.NoError(t, err)
	require.NotNil(t, fallbackClient)
	fallbackTLS := fallbackClient.httpClient.Transport.(*http.Transport).TLSClientConfig
	assert.True(t, fallbackTLS.InsecureSkipVerify,
		"fallback bundle client must not silently revert to verifying")
	assert.Len(t, fallbackTLS.Certificates, 1,
		"fallback bundle client must keep its mTLS client certificate")

	// Control: with verification enabled the same bundle cannot reach the fallback
	// server, which is what makes the success above evidence of a skipped check.
	verifying, err := newClientFromBundle(bundleFile, "", false, "")
	require.NoError(t, err)
	_, err = verifying.Get(context.Background(), "/")
	require.Error(t, err, "fallback server certificate must be untrusted when verification is on")
	assert.Contains(t, err.Error(), "certificate")
}

// ── TestServerNameOverrideVerifiesWithoutDisablingVerification ────────────────

// TestServerNameOverrideVerifiesWithoutDisablingVerification covers AC #6:
// --server-name overrides the hostname used for certificate verification without
// disabling it. The server certificate is valid for a DNS name only (no IP SANs),
// so connecting by IP succeeds only when the server name is overridden to a name
// in the SAN — and still fails for any other name.
func TestServerNameOverrideVerifiesWithoutDisablingVerification(t *testing.T) {
	const sanHost = "controller.internal"

	certs := generateConnectTestCerts(t, "")
	serverCert := generateHostnameOnlyServerCert(t, certs, sanHost)

	srv := startTLSTestServer(t, serverCert, nil,
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
	// httptest listens on loopback, so srv.URL addresses the server by IP —
	// the same shape as connecting to a controller by its LAN IP.
	require.Contains(t, srv.URL, "127.0.0.1")

	bundleFile := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	certs.clientCert.ControllerURL = srv.URL
	require.NoError(t, certbundle.Write(bundleFile, certs.clientCert))

	t.Run("server name in SAN succeeds without tls-insecure", func(t *testing.T) {
		client, err := newClientFromBundle(bundleFile, "", false, sanHost)
		require.NoError(t, err)

		tlsCfg := client.httpClient.Transport.(*http.Transport).TLSClientConfig
		require.False(t, tlsCfg.InsecureSkipVerify, "--server-name must not disable verification")
		require.Equal(t, sanHost, tlsCfg.ServerName)

		resp, err := client.Get(context.Background(), "/")
		require.NoError(t, err, "IP connection with --server-name in the SAN must verify successfully")
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("session client with server name in SAN succeeds without tls-insecure", func(t *testing.T) {
		client, err := NewAPIClient(&APIClientConfig{
			BaseURL:     srv.URL,
			BearerToken: strings.Repeat("H", 43),
			CACertPEM:   certs.caCertPEM,
			ServerName:  sanHost,
		})
		require.NoError(t, err)

		tlsCfg := client.httpClient.Transport.(*http.Transport).TLSClientConfig
		require.False(t, tlsCfg.InsecureSkipVerify)

		resp, err := client.Get(context.Background(), "/")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("no server name override fails hostname verification", func(t *testing.T) {
		client, err := newClientFromBundle(bundleFile, "", false, "")
		require.NoError(t, err)

		_, err = client.Get(context.Background(), "/")
		require.Error(t, err, "connecting by IP without --server-name must fail verification")
		// The certificate carries no IP SAN, so verification against the IP fails.
		assert.Contains(t, err.Error(), "certificate")
		assert.Contains(t, err.Error(), "127.0.0.1")
	})

	t.Run("server name outside the SAN still fails", func(t *testing.T) {
		client, err := newClientFromBundle(bundleFile, "", false, "wrong.example.com")
		require.NoError(t, err)

		_, err = client.Get(context.Background(), "/")
		require.Error(t, err, "--server-name must not bypass verification for a name outside the SAN")
		assert.Contains(t, err.Error(), "certificate is valid for "+sanHost)
	})
}
