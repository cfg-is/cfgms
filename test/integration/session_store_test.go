// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller"
	controllerConfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
)

// sessionCapturingLogger records every log message (all levels) so the test can assert
// that raw session token values never appear in controller log output (ADR-014 security
// invariant: the controller stores and logs only SHA-256(token), never the raw token).
type sessionCapturingLogger struct {
	mu  sync.Mutex
	buf strings.Builder
}

func newSessionCapturingLogger() *sessionCapturingLogger { return &sessionCapturingLogger{} }

func (l *sessionCapturingLogger) record(msg string, kv ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.WriteString(msg)
	for i := 0; i+1 < len(kv); i += 2 {
		fmt.Fprintf(&l.buf, " %v=%v", kv[i], kv[i+1])
	}
	l.buf.WriteByte('\n')
}
func (l *sessionCapturingLogger) captured() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *sessionCapturingLogger) Debug(msg string, kv ...interface{}) { l.record(msg, kv...) }
func (l *sessionCapturingLogger) Info(msg string, kv ...interface{})  { l.record(msg, kv...) }
func (l *sessionCapturingLogger) Warn(msg string, kv ...interface{})  { l.record(msg, kv...) }
func (l *sessionCapturingLogger) Error(msg string, kv ...interface{}) { l.record(msg, kv...) }
func (l *sessionCapturingLogger) Fatal(msg string, kv ...interface{}) { l.record(msg, kv...) }
func (l *sessionCapturingLogger) DebugCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv...)
}
func (l *sessionCapturingLogger) InfoCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv...)
}
func (l *sessionCapturingLogger) WarnCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv...)
}
func (l *sessionCapturingLogger) ErrorCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv...)
}
func (l *sessionCapturingLogger) FatalCtx(_ context.Context, msg string, kv ...interface{}) {
	l.record(msg, kv...)
}

// sessionFreePort returns an available TCP port on localhost.
func sessionFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// sessionCreateResponse mirrors the JSON returned by POST /api/v1/sessions.
type sessionCreateResponse struct {
	SessionID string    `json:"session_id"`
	Token     string    `json:"token"`
	IssuedAt  time.Time `json:"issued_at"`
}

// sessionListResponse mirrors the JSON returned by GET /api/v1/sessions.
type sessionListResponse struct {
	Sessions []struct {
		SessionID string `json:"session_id"`
	} `json:"sessions"`
}

// newTestCertManager initialises a cert.Manager with a fresh CA at certPath.
func newTestCertManager(t *testing.T, certPath string) *cert.Manager {
	t.Helper()
	require.NoError(t, os.MkdirAll(certPath, 0755))
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: certPath,
		CAConfig: &cert.CAConfig{
			Organization: "CFGMS Session Store Integration Test CA",
			Country:      "US",
			ValidityDays: 1,
			KeySize:      2048,
		},
		LoadExistingCA:       false,
		RenewalThresholdDays: 1,
	})
	require.NoError(t, err, "cert.NewManager")
	return mgr
}

// newTestControllerConfig builds a minimal controller config for integration tests.
// httpPort must be a specific port (not 0) so GetHTTPListenAddr() returns a usable address.
func newTestControllerConfig(httpPort int, certPath, storageRoot, sqlitePath string) *controllerConfig.Config {
	return &controllerConfig.Config{
		ListenAddr: fmt.Sprintf("127.0.0.1:%d", httpPort),
		CertPath:   certPath,
		Storage: &controllerConfig.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: storageRoot,
			SQLitePath:   sqlitePath,
		},
		Certificate: &controllerConfig.CertificateConfig{
			EnableCertManagement:   true,
			CAPath:                 filepath.Join(certPath, "ca"),
			RenewalThresholdDays:   1,
			ServerCertValidityDays: 1,
			ClientCertValidityDays: 1,
			Server: &controllerConfig.ServerCertificateConfig{
				CommonName:   "localhost",
				DNSNames:     []string{"localhost", "127.0.0.1"},
				IPAddresses:  []string{"127.0.0.1", "::1"},
				Organization: "Test Organization",
			},
		},
	}
}

// adminHTTPClient builds an *http.Client that presents the given admin mTLS cert and
// trusts the CA from certMgr.
func adminHTTPClient(t *testing.T, certMgr *cert.Manager, adminTLSCert tls.Certificate) *http.Client {
	t.Helper()
	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM), "CA pool append")

	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{adminTLSCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
}

// noAuthHTTPClient builds an *http.Client that trusts the CA but presents no client cert.
func noAuthHTTPClient(t *testing.T, certMgr *cert.Manager) *http.Client {
	t.Helper()
	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM), "CA pool append")

	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// waitForHTTPReady polls GET /api/v1/health until the controller answers or times out.
func waitForHTTPReady(t *testing.T, httpClient *http.Client, base string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(base + "/api/v1/health")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("controller HTTP not ready at %s within %v", base, timeout)
}

// startController boots a controller, waits for it to be ready, and registers cleanup.
// Returns the running controller and the HTTPS base URL.
func startController(t *testing.T, cfg *controllerConfig.Config, logger logging.Logger, httpClient *http.Client) (*controller.Controller, string) {
	t.Helper()
	ctrl, err := controller.New(cfg, logger)
	require.NoError(t, err, "controller.New")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() { errCh <- ctrl.Start(ctx) }()

	base := fmt.Sprintf("https://%s", cfg.ListenAddr)
	waitForHTTPReady(t, httpClient, base, 30*time.Second)

	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		if err := ctrl.Stop(stopCtx); err != nil && !strings.Contains(err.Error(), "not running") {
			t.Logf("controller Stop: %v", err)
		}
	})

	return ctrl, base
}

// issueSession calls POST /api/v1/sessions with the given HTTP client (must carry admin
// mTLS cert) and returns the session token.
func issueSession(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"connection_name": "integ-test"})
	require.NoError(t, err)

	resp, err := client.Post(base+"/api/v1/sessions", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"POST /api/v1/sessions must return 201; body: %s", string(bodyBytes))

	var respData sessionCreateResponse
	require.NoError(t, json.Unmarshal(bodyBytes, &respData))
	require.NotEmpty(t, respData.Token, "response must contain a token")
	return respData.Token
}

// validateSession calls GET /api/v1/sessions using the given Bearer token.
// Returns (statusCode, response body).
func validateSession(t *testing.T, client *http.Client, base, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, base+"/api/v1/sessions", nil)
	require.NoError(t, err)
	// Use the session token as a Bearer credential; middleware validates it.
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(bodyBytes)
}

// TestSessionStore_SQLite_PersistenceAcrossRestart verifies the full session store
// bootstrap path (Issue #2774, epic #2735):
//
//  1. A real controller boots via server.New() + server.Start() with SQLite configured.
//  2. A real POST /api/v1/sessions issues a token via mTLS admin cert.
//  3. The controller is stopped (simulating a restart).
//  4. A second controller opens the same SQLite path.
//  5. The original token validates against the new controller — proving session durability.
//  6. The raw token value never appears in controller log output or the SQLite file bytes.
func TestSessionStore_SQLite_PersistenceAcrossRestart(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "certs")
	sqlitePath := filepath.Join(tempDir, "cfgms.db")
	storageRoot := filepath.Join(tempDir, "storage")

	certMgr := newTestCertManager(t, certPath)

	// Issue admin mTLS client cert (carries the CFGMS admin marker extension).
	adminCertBundle, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "integ-session-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		KeySize:          2048,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err, "generate admin cert")

	adminTLSCert, err := tls.X509KeyPair(adminCertBundle.CertificatePEM, adminCertBundle.PrivateKeyPEM)
	require.NoError(t, err)

	adminClient := adminHTTPClient(t, certMgr, adminTLSCert)
	healthClient := noAuthHTTPClient(t, certMgr)

	// ── Phase 1: first controller ──────────────────────────────────────────────
	httpPort1 := sessionFreePort(t)
	cfg1 := newTestControllerConfig(httpPort1, certPath, storageRoot, sqlitePath)

	logger1 := newSessionCapturingLogger()
	ctrl1, base1 := startController(t, cfg1, logger1, healthClient)
	_ = ctrl1

	token := issueSession(t, adminClient, base1)
	t.Logf("issued session token (length=%d)", len(token))

	// Immediately validate: proves the token works on the issuing controller.
	code, _ := validateSession(t, adminClient, base1, token)
	assert.Equal(t, http.StatusOK, code, "token must validate on issuing controller")

	// Assert raw token never appears in log output from the issuing controller.
	log1 := logger1.captured()
	assert.NotContains(t, log1, token,
		"raw session token must not appear in controller log output (ADR-014 security invariant)")

	// Stop the first controller (simulates a process restart).
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	err = ctrl1.Stop(stopCtx)
	if err != nil && !strings.Contains(err.Error(), "not running") {
		t.Logf("ctrl1.Stop: %v", err)
	}
	// Remove the cleanup registered by startController so we don't double-stop.
	// (t.Cleanup callbacks run in reverse order — the registered one fires last; it
	// checks "not running" so a second Stop is safe.)

	// ── Phase 2: second controller against the same SQLite ─────────────────────
	httpPort2 := sessionFreePort(t)
	cfg2 := newTestControllerConfig(httpPort2, certPath, storageRoot, sqlitePath)

	logger2 := newSessionCapturingLogger()
	ctrl2, base2 := startController(t, cfg2, logger2, healthClient)
	_ = ctrl2

	// The token issued by controller-1 must still validate on controller-2.
	// The manager's loadFromStore path queries SQLite to rebuild the in-memory state.
	code2, body2 := validateSession(t, adminClient, base2, token)
	assert.Equal(t, http.StatusOK, code2,
		"session token must survive controller restart when SQLite is configured; body: %s", body2)

	// Assert raw token never appears in log output from the second controller either.
	log2 := logger2.captured()
	assert.NotContains(t, log2, token,
		"raw session token must not appear in second controller log output")

	// Assert raw token is not present in the SQLite file bytes.
	// Only session.HashToken(token) output may appear as the stored key.
	dbBytes, err := os.ReadFile(sqlitePath)
	require.NoError(t, err, "SQLite file must be readable for byte-level assertion")
	assert.NotContains(t, string(dbBytes), token,
		"raw session token must not appear in SQLite file bytes; only its SHA-256 hash may be stored")

	// Verify the hash IS present in the file (proving the record was written).
	tokenHash := session.HashToken(token)
	assert.Contains(t, string(dbBytes), tokenHash,
		"SHA-256 hash of session token must appear in SQLite file (proves the record was written)")
}

// TestSessionStore_InMemoryFallback_SessionsWorkAndAreNonDurable verifies:
//
//   - When no SQLitePath is configured, POST /api/v1/sessions returns 201 (not 503),
//     proving sessionManager is never nil even on the in-memory fallback path (Issue #2774).
//   - A session token issued by controller-1 is rejected by a fresh controller-2
//     started against the same config (no shared durable store), proving the fallback
//     store is genuinely non-durable.
func TestSessionStore_InMemoryFallback_SessionsWorkAndAreNonDurable(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "certs")
	storageRoot := filepath.Join(tempDir, "storage")

	certMgr := newTestCertManager(t, certPath)

	adminCertBundle, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "integ-session-inmem-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		KeySize:          2048,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err, "generate admin cert")

	adminTLSCert, err := tls.X509KeyPair(adminCertBundle.CertificatePEM, adminCertBundle.PrivateKeyPEM)
	require.NoError(t, err)

	adminClient := adminHTTPClient(t, certMgr, adminTLSCert)
	healthClient := noAuthHTTPClient(t, certMgr)

	// ── Phase 1: controller with NO SQLitePath ─────────────────────────────────
	httpPort1 := sessionFreePort(t)
	// No SQLitePath — triggers in-memory fallback path in initializeSessionStore.
	cfg1 := newTestControllerConfig(httpPort1, certPath, storageRoot, "")

	ctrl1, base1 := startController(t, cfg1, logging.NewNoopLogger(), healthClient)
	_ = ctrl1

	// POST /api/v1/sessions must return 201 (not 503 SESSION_UNAVAILABLE).
	// This is the direct AC for the nil-manager gap at handlers_sessions.go:42.
	token := issueSession(t, adminClient, base1)
	t.Logf("in-memory session token issued (length=%d)", len(token))

	// Validate it works on the same controller (proves the manager is wired correctly).
	code, _ := validateSession(t, adminClient, base1, token)
	assert.Equal(t, http.StatusOK, code, "session must validate on issuing in-memory controller")

	// Stop controller-1 (in-memory store is lost).
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()
	if err := ctrl1.Stop(stopCtx); err != nil && !strings.Contains(err.Error(), "not running") {
		t.Logf("ctrl1.Stop: %v", err)
	}

	// ── Phase 2: second controller with NO SQLitePath ──────────────────────────
	httpPort2 := sessionFreePort(t)
	cfg2 := newTestControllerConfig(httpPort2, certPath, storageRoot, "")

	ctrl2, base2 := startController(t, cfg2, logging.NewNoopLogger(), healthClient)
	_ = ctrl2

	// The token issued by controller-1 must NOT validate on controller-2 (no shared store).
	// A 401 proves that in-memory sessions are non-durable — the session is genuinely gone
	// after the restart, ruling out any accidental durable path.
	code2, body2 := validateSession(t, adminClient, base2, token)
	assert.Equal(t, http.StatusUnauthorized, code2,
		"in-memory session token must not survive restart (non-durable); body: %s", body2)
}
