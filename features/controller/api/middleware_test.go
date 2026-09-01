// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	tenantsecurity "github.com/cfgis/cfgms/features/tenant/security"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/session"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// auditCapturingLogger records Info and Warn calls for audit log assertions.
// It is a real implementation backed by a test buffer — not a mock of any
// CFGMS component (same pattern as the terminal log-redaction stories #979, #981).
type auditCapturingLogger struct {
	logging.NoopLogger
	mu      sync.Mutex
	entries []auditLogEntry
}

func TestSecurityHeadersMiddlewareCoversAPIErrorResponses(t *testing.T) {
	srv := setupTestServer(t)
	handler := srv.securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusUnauthorized)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, "max-age=31536000; includeSubDomains", rec.Header().Get("Strict-Transport-Security"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
	assert.Equal(t, "camera=(), microphone=(), geolocation=()", rec.Header().Get("Permissions-Policy"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
}

type auditLogEntry struct {
	level string
	msg   string
	kvs   []interface{}
}

func (l *auditCapturingLogger) Info(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, auditLogEntry{level: "INFO", msg: msg, kvs: kvs})
}

func (l *auditCapturingLogger) Warn(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, auditLogEntry{level: "WARN", msg: msg, kvs: kvs})
}

func (l *auditCapturingLogger) Error(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, auditLogEntry{level: "ERROR", msg: msg, kvs: kvs})
}

// formattedOutput renders all captured entries as "key=value" pairs for substring assertions.
func (l *auditCapturingLogger) formattedOutput() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	for _, e := range l.entries {
		b.WriteString(e.level)
		b.WriteByte(' ')
		b.WriteString(e.msg)
		for i := 0; i+1 < len(e.kvs); i += 2 {
			fmt.Fprintf(&b, " %v=%v", e.kvs[i], e.kvs[i+1])
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// kvValue returns the value associated with key across all captured entries, or nil.
func (l *auditCapturingLogger) kvValue(key string) interface{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		for i := 0; i+1 < len(e.kvs); i += 2 {
			if k, ok := e.kvs[i].(string); ok && k == key {
				return e.kvs[i+1]
			}
		}
	}
	return nil
}

// hasLevel reports whether any entry was captured at the given level.
func (l *auditCapturingLogger) hasLevel(level string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if e.level == level {
			return true
		}
	}
	return false
}

func TestFlattenFieldsToKV_SortedDeterministic(t *testing.T) {
	fields := map[string]interface{}{
		"zebra":  "z",
		"apple":  "a",
		"mango":  "m",
		"banana": "b",
	}
	kv := flattenFieldsToKV(fields)
	require.Equal(t, 8, len(kv), "2 entries per field")

	// Keys must appear in alphabetical order.
	keys := make([]string, 0, 4)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		require.True(t, ok, "key at index %d must be string", i)
		keys = append(keys, k)
	}
	assert.Equal(t, []string{"apple", "banana", "mango", "zebra"}, keys)

	// Second call must return the same order.
	kv2 := flattenFieldsToKV(fields)
	for i := 0; i < len(kv); i++ {
		assert.Equal(t, kv[i], kv2[i], "index %d must be identical across calls", i)
	}
}

func TestFlattenFieldsToKV_EmptyMap(t *testing.T) {
	kv := flattenFieldsToKV(map[string]interface{}{})
	assert.Empty(t, kv)
}

func TestFlattenFieldsToKV_NilMap(t *testing.T) {
	kv := flattenFieldsToKV(nil)
	assert.Empty(t, kv)
}

func TestGenerateRequestID_UniqueUnderConcurrency(t *testing.T) {
	server := setupTestServer(t)

	const count = 1000
	ids := make([]string, count)
	var wg sync.WaitGroup
	wg.Add(count)

	for i := 0; i < count; i++ {
		i := i
		go func() {
			defer wg.Done()
			ids[i] = server.generateRequestID()
		}()
	}
	wg.Wait()

	seen := make(map[string]struct{}, count)
	for _, id := range ids {
		require.NotEmpty(t, id)
		_, duplicate := seen[id]
		assert.False(t, duplicate, "duplicate request ID: %s", id)
		seen[id] = struct{}{}
	}
	assert.Len(t, seen, count)
}

func TestGenerateRequestID_UUIDv4Format(t *testing.T) {
	server := setupTestServer(t)
	id := server.generateRequestID()
	// UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx (36 chars)
	require.Len(t, id, 36)
	assert.Equal(t, '4', rune(id[14]), "UUID version nibble must be 4")
	assert.Contains(t, "89ab", string(id[19]), "UUID variant nibble must be 8, 9, a, or b")
}

func TestAuditAuthorizationDecision_DoesNotPanic(t *testing.T) {
	server := setupTestServer(t)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	require.NoError(t, err)

	tests := []struct {
		name     string
		decision *AuthorizationDecision
	}{
		{
			name: "granted",
			decision: &AuthorizationDecision{
				Granted:      true,
				PermissionID: "steward:read",
				Resource:     "steward:test-id",
				Action:       "read",
				Decision:     "ALLOW",
				Reason:       "API key has required permission: steward:read",
				CheckedAt:    time.Now(),
				SubjectID:    "user-1",
				TenantID:     "tenant-1",
			},
		},
		{
			name: "denied",
			decision: &AuthorizationDecision{
				Granted:      false,
				PermissionID: "rbac:admin",
				Resource:     "rbac:*",
				Action:       "admin",
				Decision:     "DENY",
				Reason:       "API key lacks required permission: rbac:admin",
				CheckedAt:    time.Now(),
				SubjectID:    "user-1",
				TenantID:     "tenant-1",
			},
		},
		{
			name: "cross-tenant denial produces CRITICAL severity without panic",
			decision: &AuthorizationDecision{
				Granted:      false,
				PermissionID: "steward:read",
				Resource:     "steward:*",
				Action:       "read",
				Decision:     "DENY",
				Reason:       "Cross-tenant access attempt",
				CheckedAt:    time.Now(),
				SubjectID:    "user-1",
				TenantID:     "tenant-other",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				server.auditAuthorizationDecision(req, tc.decision)
			})
		})
	}
}

// TestAuditAuthorizationDecision_FieldsAppearInLogOutput verifies that after fixing
// the map-drop bug (passing a map as a single arg to a variadic logger), audit fields
// actually appear in the captured log output.
func TestAuditAuthorizationDecision_FieldsAppearInLogOutput(t *testing.T) {
	capLog := &auditCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	require.NoError(t, err)

	t.Run("granted path uses Info and fields appear", func(t *testing.T) {
		capLog.mu.Lock()
		capLog.entries = nil
		capLog.mu.Unlock()

		decision := &AuthorizationDecision{
			Granted:      true,
			PermissionID: "steward:read",
			Resource:     "steward:test-id",
			Action:       "read",
			Decision:     "ALLOW",
			Reason:       "API key has required permission: steward:read",
			CheckedAt:    time.Now(),
			SubjectID:    "subject-abc",
			TenantID:     "tenant-xyz",
		}
		server.auditAuthorizationDecision(req, decision)

		out := capLog.formattedOutput()
		assert.True(t, capLog.hasLevel("INFO"), "granted path must log at INFO")
		assert.Contains(t, out, "subject_id=subject-abc")
		assert.Contains(t, out, "tenant_id=tenant-xyz")
		assert.Contains(t, out, "resource=steward:test-id")
	})

	t.Run("denied path uses Warn and fields appear", func(t *testing.T) {
		capLog.mu.Lock()
		capLog.entries = nil
		capLog.mu.Unlock()

		decision := &AuthorizationDecision{
			Granted:      false,
			PermissionID: "rbac:admin",
			Resource:     "rbac:*",
			Action:       "admin",
			Decision:     "DENY",
			Reason:       "API key lacks required permission: rbac:admin",
			CheckedAt:    time.Now(),
			SubjectID:    "subject-abc",
			TenantID:     "tenant-xyz",
		}
		server.auditAuthorizationDecision(req, decision)

		out := capLog.formattedOutput()
		assert.True(t, capLog.hasLevel("WARN"), "denied path must log at WARN")
		assert.Contains(t, out, "subject_id=subject-abc")
		assert.Contains(t, out, "tenant_id=tenant-xyz")
		assert.Contains(t, out, "resource=rbac:*")
	})
}

// TestAuditAuthorizationDecision_SanitizesUserInput verifies that attacker-controlled
// fields (Reason, SubjectID, Resource, X-Request-ID header) are sanitized before
// reaching the logger — closing CodeQL go/log-injection alert #528 (CWE-117).
func TestAuditAuthorizationDecision_SanitizesUserInput(t *testing.T) {
	capLog := &auditCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	require.NoError(t, err)
	req = req.WithContext(context.Background())
	req.Header.Set("X-Request-ID", "rid\nFAKE")

	decision := &AuthorizationDecision{
		Granted:      false,
		PermissionID: "steward:read",
		Resource:     "res\x1b[31mevil\x1b[0m",
		Action:       "read",
		Decision:     "DENY",
		Reason:       "denied\n[FAKE LOG] admin granted access",
		CheckedAt:    time.Now(),
		SubjectID:    "user\x00inj",
		TenantID:     "tenant-1",
	}
	server.auditAuthorizationDecision(req, decision)

	// Assert the sanitized replacement char is present in the logged value — not just
	// absence of the bad char (absence-of-newline is insufficient because JSON encoding
	// masks newlines, but the replacement underscore is a positive signal).
	assert.Equal(t, "denied_[FAKE LOG] admin granted access", capLog.kvValue("reason"),
		"newline in Reason must be replaced with underscore")
	assert.Equal(t, "user_inj", capLog.kvValue("subject_id"),
		"null byte in SubjectID must be replaced with underscore")
	assert.Equal(t, "res_[31mevil_[0m", capLog.kvValue("resource"),
		"ESC bytes in Resource must be replaced with underscore")
	assert.Equal(t, "rid_FAKE", capLog.kvValue("request_id"),
		"newline in X-Request-ID header must be replaced with underscore")

	// Check no raw control characters in the individual logged string values.
	for _, key := range []string{"reason", "subject_id", "resource", "request_id"} {
		if s, ok := capLog.kvValue(key).(string); ok {
			assert.NotContains(t, s, "\n", "key %q must not contain LF", key)
			assert.NotContains(t, s, "\r", "key %q must not contain CR", key)
			assert.NotContains(t, s, "\x00", "key %q must not contain NUL", key)
			assert.NotContains(t, s, "\x1b", "key %q must not contain ESC", key)
		}
	}
}

// TestAuditAuthorizationDecision_SanitizesNestedConditionalVars verifies that
// SanitizeFieldsRecursive is applied to ConditionalVars, recursing into nested
// maps and slices to neutralise injected control characters.
func TestAuditAuthorizationDecision_SanitizesNestedConditionalVars(t *testing.T) {
	capLog := &auditCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	require.NoError(t, err)

	decision := &AuthorizationDecision{
		Granted:      true,
		PermissionID: "steward:read",
		Resource:     "steward:*",
		Action:       "read",
		Decision:     "ALLOW",
		Reason:       "allowed",
		CheckedAt:    time.Now(),
		SubjectID:    "user-1",
		TenantID:     "tenant-1",
		ConditionalVars: map[string]interface{}{
			"k": []interface{}{"a\nb"},
			"m": map[string]interface{}{"deep": "v\x00x"},
		},
	}
	server.auditAuthorizationDecision(req, decision)

	// Retrieve the sanitized conditional_vars from the captured key/value pairs.
	cv := capLog.kvValue("conditional_vars")
	require.NotNil(t, cv, "conditional_vars must be present in log output")

	cvMap, ok := cv.(map[string]interface{})
	require.True(t, ok, "conditional_vars must be a map after sanitization")

	// Nested slice: "k" → ["a_b"] (newline replaced)
	kSlice, ok := cvMap["k"].([]interface{})
	require.True(t, ok, "conditional_vars[k] must be a slice")
	require.Len(t, kSlice, 1)
	assert.Equal(t, "a_b", kSlice[0], "newline in slice element must be replaced")

	// Nested map: "m" → {"deep": "v_x"} (null byte replaced)
	mMap, ok := cvMap["m"].(map[string]interface{})
	require.True(t, ok, "conditional_vars[m] must be a nested map")
	assert.Equal(t, "v_x", mMap["deep"], "null byte in nested map value must be replaced")
}

// --- mTLS auth middleware tests (Story #1415) ---

// makeSelfSignedAdminCert creates a self-signed cert with the CFGMS admin marker.
// The TLS chain verification is bypassed in middleware unit tests (done at TLS layer in prod).
func makeSelfSignedAdminCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return makeAdminTestCert(t, true)
}

// makeSelfSignedCert creates a self-signed cert WITHOUT the admin marker.
func makeSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return makeAdminTestCert(t, false)
}

// sharedTestRSAKey lazily generates a single 2048-bit RSA key for the whole
// package test run. RSA-2048 keygen is expensive (Miller-Rabin primality search,
// especially under the FIPS path), and this package builds admin/self-signed test
// certs at 60+ call sites. Regenerating a key per cert pushed the package past the
// 5m -timeout limit; generating it once keeps cert construction effectively free.
// The key material is irrelevant to these unit tests — only the cert fields and the
// admin marker matter — so a shared key is safe.
var sharedTestRSAKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("test setup: rsa.GenerateKey failed: %v", err))
	}
	return key
})

func makeAdminTestCert(t *testing.T, withMarker bool) *x509.Certificate {
	t.Helper()
	key := sharedTestRSAKey()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Subject:      pkix.Name{CommonName: "test-admin"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if withMarker {
		cert.SetAdminMarker(template)
	}

	// Self-signed for unit test purposes; chain verification is done at TLS layer in prod.
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return parsed
}

// requestWithTLSCert returns an httptest.Request with r.TLS set to present peerCert.
func requestWithTLSCert(method, path string, peerCert *x509.Certificate) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{peerCert},
	}
	return req
}

// makeAdminRequest creates an httptest.Request authenticated as an mTLS admin cert principal.
// Pass a non-nil body for requests that require a payload (json-encoded etc.).
// Use this helper in tests that call Tier-3 endpoints — those require IsAdmin: true which
// only an mTLS admin cert provides.
func makeAdminRequest(t *testing.T, method, path string, body io.Reader) *http.Request {
	t.Helper()
	adminCert := makeSelfSignedAdminCert(t)
	req := httptest.NewRequest(method, path, body)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{adminCert},
	}
	return req
}

// wrapWithAuth wraps handler with authenticationMiddleware then requirePermission.
func wrapWithAuth(s *Server, resourceType, action string, inner http.HandlerFunc) http.Handler {
	return s.authenticationMiddleware(
		s.requirePermission(resourceType, action)(inner),
	)
}

// TestMTLSAuth_AdminMarker_Granted verifies that a request presenting a cert with the
// CFGMS admin extension is authenticated as an admin principal and passes requirePermission.
func TestMTLSAuth_AdminMarker_Granted(t *testing.T) {
	server := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t)

	var capturedPrincipal *Principal
	handler := wrapWithAuth(server, "steward", "read",
		func(w http.ResponseWriter, r *http.Request) {
			capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
			w.WriteHeader(http.StatusOK)
		})

	req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards/test", adminCert)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "admin cert must be granted access")
	require.NotNil(t, capturedPrincipal)
	assert.Equal(t, session.AssuranceStrong, capturedPrincipal.Assurance, "principal from admin cert must have AssuranceStrong")
	assert.NotEmpty(t, capturedPrincipal.CertSerial)
	assert.NotEmpty(t, capturedPrincipal.CertFingerprint)
	assert.False(t, capturedPrincipal.CertNotAfter.IsZero())
}

// TestMTLSAuth_NoMarker_FallsThrough verifies that when a cert without the admin marker
// is presented alongside a valid API key, the API-key auth path handles the request normally.
func TestMTLSAuth_NoMarker_FallsThrough(t *testing.T) {
	server := setupTestServer(t)
	apiKeyStr := NewTestKey(t, server, []string{"steward:read"})

	regularCert := makeSelfSignedCert(t)

	var capturedPrincipal *Principal
	handler := wrapWithAuth(server, "steward", "read",
		func(w http.ResponseWriter, r *http.Request) {
			capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
			w.WriteHeader(http.StatusOK)
		})

	req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards/test", regularCert)
	req.Header.Set("X-API-Key", apiKeyStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "cert without marker + valid API key must succeed via API-key path")
	require.NotNil(t, capturedPrincipal)
	assert.Equal(t, session.AssuranceMachine, capturedPrincipal.Assurance, "principal from API-key path must have AssuranceMachine")
}

// TestMTLSAuth_ConflictingCredentials_Rejected verifies that presenting an admin cert AND
// an API-key header together returns 400 CONFLICTING_CREDENTIALS (H2/L5).
func TestMTLSAuth_ConflictingCredentials_Rejected(t *testing.T) {
	server := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t)
	apiKeyStr := NewTestKey(t, server, []string{"steward:read"})

	handler := server.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards/test", adminCert)
	req.Header.Set("X-API-Key", apiKeyStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "admin cert + API key header must return 400")
	assert.Contains(t, rec.Body.String(), "CONFLICTING_CREDENTIALS")
}

// TestMTLSAuth_ConflictingCredentials_BearerToken verifies that admin cert + Bearer token
// also returns 400 CONFLICTING_CREDENTIALS.
func TestMTLSAuth_ConflictingCredentials_BearerToken(t *testing.T) {
	server := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t)
	apiKeyStr := NewTestKey(t, server, []string{"steward:read"})

	handler := server.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards/test", adminCert)
	req.Header.Set("Authorization", "Bearer "+apiKeyStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "admin cert + Bearer token must return 400")
	assert.Contains(t, rec.Body.String(), "CONFLICTING_CREDENTIALS")
}

// TestMTLSAuth_NoCert_FallsBackToAPIKey verifies that when no cert is presented,
// the middleware falls back to API-key auth unchanged.
func TestMTLSAuth_NoCert_FallsBackToAPIKey(t *testing.T) {
	server := setupTestServer(t)
	apiKeyStr := NewTestKey(t, server, []string{"steward:read"})

	var capturedPrincipal *Principal
	handler := wrapWithAuth(server, "steward", "read",
		func(w http.ResponseWriter, r *http.Request) {
			capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
			w.WriteHeader(http.StatusOK)
		})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/test", nil)
	req.Header.Set("X-API-Key", apiKeyStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "no cert + valid API key must succeed")
	require.NotNil(t, capturedPrincipal)
	assert.Equal(t, session.AssuranceMachine, capturedPrincipal.Assurance)
}

// TestAPIKeyAuth_DoesNotSetImplicitAdmin verifies that a Principal constructed via
// the API-key auth path never carries ImplicitAdmin. Exactly three construction
// sites set ImplicitAdmin: true (mTLS admin certs, Bearer sessions, root-scope web
// accounts) — the API-key path must default to false like any other principal type.
func TestAPIKeyAuth_DoesNotSetImplicitAdmin(t *testing.T) {
	server := setupTestServer(t)
	apiKeyStr := NewTestKey(t, server, []string{"steward:read"})

	var capturedPrincipal *Principal
	handler := wrapWithAuth(server, "steward", "read",
		func(w http.ResponseWriter, r *http.Request) {
			capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
			w.WriteHeader(http.StatusOK)
		})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/test", nil)
	req.Header.Set("X-API-Key", apiKeyStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "valid API key with granted permission must succeed")
	require.NotNil(t, capturedPrincipal)
	assert.False(t, capturedPrincipal.ImplicitAdmin,
		"API-key-derived principal must never carry ImplicitAdmin")

	assert.False(t, server.hasPermission(capturedPrincipal, "rbac:delete-role"),
		"API-key principal must be denied a permission outside its explicit grant list")
}

// TestHasPermission_AdminPrincipal verifies that an administrator principal with
// ImplicitAdmin: true is authorized for every permission (ADR-025 Amendment 3).
func TestHasPermission_AdminPrincipal(t *testing.T) {
	server := setupTestServer(t)
	admin := &Principal{Assurance: session.AssuranceBasic, ImplicitAdmin: true}

	assert.True(t, server.hasPermission(admin, "steward:read"))
	assert.True(t, server.hasPermission(admin, "rbac:delete-role"))
	assert.True(t, server.hasPermission(admin, "some-future:permission"))
}

// TestHasPermission_ZeroValuedPrincipalIsDenied verifies that a zero-valued
// Principal{} is denied every named permission. Previously, Permissions==nil served
// as the implicit-admin marker, making a zero-valued principal unintentionally
// privileged. ADR-025 Amendment 3 removed that hazard: ImplicitAdmin must be set
// explicitly, and the zero value of bool is false.
func TestHasPermission_ZeroValuedPrincipalIsDenied(t *testing.T) {
	server := setupTestServer(t)
	zero := &Principal{}

	assert.False(t, server.hasPermission(zero, "steward:read"),
		"zero-valued principal must be denied any named permission")
	assert.False(t, server.hasPermission(zero, "rbac:delete-role"),
		"zero-valued principal must be denied any named permission")
	assert.False(t, server.hasPermission(zero, "certificate:provision"),
		"zero-valued principal must be denied any named permission")
}

// TestHasPermission_IncompletePrincipalIsDenied verifies that a partially-constructed
// principal with human assurance and nil Permissions but ImplicitAdmin==false is denied.
// This closes the hazard where Permissions==nil was the implicit-admin marker: a caller
// who forgets to set Permissions on a new Principal no longer gets an unintended
// superadmin by default.
func TestHasPermission_IncompletePrincipalIsDenied(t *testing.T) {
	server := setupTestServer(t)
	incomplete := &Principal{
		ID:          "some-principal",
		Assurance:   session.AssuranceBasic,
		Permissions: nil, // explicitly nil, but ImplicitAdmin is false (zero value)
	}

	assert.False(t, server.hasPermission(incomplete, "steward:read"),
		"nil Permissions without ImplicitAdmin must not grant any permission")
	assert.False(t, server.hasPermission(incomplete, "certificate:provision"),
		"nil Permissions without ImplicitAdmin must not grant any permission")
}

// TestHasPermission_AccountPermissions verifies that human assurance does not
// erase the explicit, least-privilege grants configured on a web account.
func TestHasPermission_AccountPermissions(t *testing.T) {
	server := setupTestServer(t)
	web := &Principal{
		Assurance:   session.AssuranceBasic,
		Permissions: []string{"steward:list"},
	}

	assert.True(t, server.hasPermission(web, "steward:list"))
	assert.False(t, server.hasPermission(web, "steward:write-config"))
	assert.False(t, server.hasPermission(web, "rbac:create-role"))
}

// TestHasPermission_WildcardStringRejected verifies that an API-key principal with
// Permissions: []string{"*"} does not short-circuit — "*" is treated as a literal
// permission name (C1: no wildcard in permission strings).
func TestHasPermission_WildcardStringRejected(t *testing.T) {
	server := setupTestServer(t)
	wildcardPrincipal := &Principal{
		Assurance:   session.AssuranceMachine,
		Permissions: []string{"*"},
	}

	// "*" must not match any real permissionID
	assert.False(t, server.hasPermission(wildcardPrincipal, "steward:read"),
		"wildcard string must not grant steward:read")
	assert.False(t, server.hasPermission(wildcardPrincipal, "rbac:admin"),
		"wildcard string must not grant rbac:admin")
}

// TestMTLSAuth_AuditFields_CertAuth verifies that audit log entries from cert-auth
// requests carry auth_method=cert and cert detail fields (H3).
func TestMTLSAuth_AuditFields_CertAuth(t *testing.T) {
	capLog := &auditCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)
	adminCert := makeSelfSignedAdminCert(t)

	handler := wrapWithAuth(server, "steward", "read",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards/test", adminCert)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "cert", capLog.kvValue("auth_method"), "cert-auth must log auth_method=cert")
	assert.NotNil(t, capLog.kvValue("cert_serial"), "must log cert_serial")
	assert.NotNil(t, capLog.kvValue("cert_fingerprint"), "must log cert_fingerprint")
	assert.NotNil(t, capLog.kvValue("cert_not_after"), "must log cert_not_after")
}

// TestMTLSAuth_AuditFields_APIKeyAuth verifies that audit log entries from API-key
// auth requests carry auth_method=api_key (H3).
func TestMTLSAuth_AuditFields_APIKeyAuth(t *testing.T) {
	capLog := &auditCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)
	apiKeyStr := NewTestKey(t, server, []string{"steward:read"})

	handler := wrapWithAuth(server, "steward", "read",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/test", nil)
	req.Header.Set("X-API-Key", apiKeyStr)
	// Inject tenant context so requirePermission finds it.
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "test-tenant"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "api_key", capLog.kvValue("auth_method"), "API-key auth must log auth_method=api_key")
}

// setupTestServerWithCertMgr creates a test server wired with a real cert.Manager
// so that extractAdminPrincipal can check the revocation list.
func setupTestServerWithCertMgr(t *testing.T, certManager *cert.Manager) *Server {
	t.Helper()
	setTestSecretsEnv(t)

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	storageManager := pkgtesting.SetupTestStorage(t)
	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)
	controllerService := service.NewControllerService(logging.NewNoopLogger())
	configService := service.NewConfigurationServiceV2(logging.NewNoopLogger(), storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	server, err := New(
		cfg, logging.NewNoopLogger(),
		controllerService, configService,
		nil, rbacService, certManager, tenantManager, rbacManager,
		nil, nil, nil, "", nil, auditMgr, nil, nil, nil,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Close(closeCtx); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	})
	return server
}

// issueCertAndBuildRequest issues a cert via certManager (storing it so Revoke can find it),
// applies the admin marker, and builds a TLS request presenting that cert.
// Returns the request and the cert serial number for revocation tests.
func issueCertAndBuildRequest(t *testing.T, method, path string, certManager *cert.Manager) (*http.Request, string) {
	t.Helper()

	issuedCert, err := certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "test-admin-revoke",
		Organization:     "CFGMS",
		ValidityDays:     1,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)

	certBlock, _ := pem.Decode(issuedCert.CertificatePEM)
	require.NotNil(t, certBlock)
	x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
	require.NoError(t, err)

	req := httptest.NewRequest(method, path, nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{x509Cert},
	}
	return req, issuedCert.SerialNumber
}

// TestExtractAdminPrincipal_ChecksRevocation verifies that a chain-valid admin-marked
// cert whose serial is in the revoked-serials list returns nil (request rejected).
// This is the Story D C2 fix: the revocation check must occur on every cert-auth request.
func TestExtractAdminPrincipal_ChecksRevocation(t *testing.T) {
	tempDir := t.TempDir()
	certManager, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	server := setupTestServerWithCertMgr(t, certManager)

	// Issue an admin-marked cert via the Manager (stored in certManager for Revoke lookup)
	req, serial := issueCertAndBuildRequest(t, http.MethodGet, "/api/v1/test", certManager)

	// Before revocation: extractAdminPrincipal must return a non-nil principal
	principal := server.extractAdminPrincipal(req)
	require.NotNil(t, principal, "admin-marked cert must be accepted before revocation")
	assert.Equal(t, session.AssuranceStrong, principal.Assurance)

	// Revoke the cert
	require.NoError(t, certManager.Revoke(serial))

	// After revocation: extractAdminPrincipal must return nil (CERT_REVOKED)
	principal = server.extractAdminPrincipal(req)
	assert.Nil(t, principal, "revoked admin cert must be rejected by extractAdminPrincipal")
}

// TestExtractAdminPrincipal_NilCertManager_AllowsUnrevoked verifies that when
// certManager is nil (disabled cert management), certs are accepted without
// revocation checking (graceful degradation).
func TestExtractAdminPrincipal_NilCertManager_AllowsUnrevoked(t *testing.T) {
	server := setupTestServer(t) // no certManager set
	adminCert := makeSelfSignedAdminCert(t)

	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", adminCert)
	principal := server.extractAdminPrincipal(req)
	require.NotNil(t, principal, "admin cert must be accepted when certManager is nil (no revocation checking)")
	assert.Equal(t, session.AssuranceStrong, principal.Assurance)
}

// TestAuthMiddleware_SetsUserIDKey_APIKey verifies that the API-key auth path writes
// the authenticated user ID under ctxkeys.UserIDKey so downstream readers in
// features/config/rollback and features/config/diff/approval can find it.
func TestAuthMiddleware_SetsUserIDKey_APIKey(t *testing.T) {
	server := setupTestServer(t)
	apiKeyStr := NewTestKey(t, server, []string{"steward:read"})

	var capturedUserID string
	handler := server.authenticationMiddleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedUserID, _ = r.Context().Value(ctxkeys.UserIDKey).(string)
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKeyStr)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, capturedUserID, "ctxkeys.UserIDKey must be set after API-key auth")
}

// TestAuthMiddleware_SetsUserIDKey_CertAuth verifies that the mTLS admin-cert auth
// path writes the authenticated user ID under ctxkeys.UserIDKey.
func TestAuthMiddleware_SetsUserIDKey_CertAuth(t *testing.T) {
	server := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t)

	var capturedUserID string
	handler := server.authenticationMiddleware(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedUserID, _ = r.Context().Value(ctxkeys.UserIDKey).(string)
			w.WriteHeader(http.StatusOK)
		}),
	)

	req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards", adminCert)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, capturedUserID, "ctxkeys.UserIDKey must be set after mTLS cert auth")
	assert.Equal(t, "test-admin", capturedUserID, "UserIDKey must equal the cert CN (sanitized)")
}

// setupTestServerWithIsolationEngine builds a test server wired with a real
// TenantIsolationEngine. Uses real CFGMS components — no mocks.
func setupTestServerWithIsolationEngine(t *testing.T) *Server {
	t.Helper()
	setTestSecretsEnv(t)

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	storageManager := pkgtesting.SetupTestStorage(t)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)
	controllerService := service.NewControllerService(logging.NewNoopLogger())
	configService := service.NewConfigurationServiceV2(logging.NewNoopLogger(), storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	server, err := New(
		cfg, logging.NewNoopLogger(),
		controllerService, configService,
		nil, rbacService, nil, tenantManager, rbacManager,
		nil, nil, nil, "", nil, auditMgr, nil, nil, nil,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Close(closeCtx); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	})

	// Wire a real TenantIsolationEngine using the same audit manager.
	// The engine uses default isolation rules (cross-tenant access denied by default).
	isolationAuditMgr, isoErr := audit.NewManager(storageManager.GetAuditStore(), "isolation")
	require.NoError(t, isoErr)
	t.Cleanup(func() { _ = isolationAuditMgr.Stop(context.Background()) })

	engine := tenantsecurity.NewTenantIsolationEngine(tenantManager, isolationAuditMgr)
	server.SetIsolationEngine(engine)

	return server
}

// newAgentTestKey creates an API key with agent.dev permissions bound to tenantID.
func newAgentTestKey(t *testing.T, server *Server, tenantID string) string {
	t.Helper()
	key, err := server.generateEphemeralKey(
		"agent-dev-test",
		agentDevAPIPermissions,
		5*time.Minute,
		tenantID,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		server.mu.Lock()
		delete(server.apiKeys, key.Key)
		server.mu.Unlock()
	})
	return key.Key
}

// requestWithTargetTenant builds a test request that signals a specific target tenant
// to the isolation engine via the targetTenantContextKey context value.
func requestWithTargetTenant(method, path, targetTenant, apiKey string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-API-Key", apiKey)
	return req.WithContext(context.WithValue(req.Context(), targetTenantContextKey, targetTenant))
}

func TestTenantIsolation_SubtreeBoundaryEnforcedWithoutIsolationEngine(t *testing.T) {
	server := setupTestServer(t) // isolation engine is deliberately not wired
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:list"}, "msp-a/client-1", 5*time.Minute)
	handler := server.authenticationMiddleware(
		server.requirePermission("steward", "list")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})))

	for _, tc := range []struct {
		name         string
		targetTenant string
		wantStatus   int
	}{
		{name: "same tenant", targetTenant: "msp-a/client-1", wantStatus: http.StatusOK},
		{name: "child tenant", targetTenant: "msp-a/client-1/group-a", wantStatus: http.StatusOK},
		{name: "sibling tenant", targetTenant: "msp-a/client-2", wantStatus: http.StatusForbidden},
		{name: "parent tenant", targetTenant: "msp-a", wantStatus: http.StatusForbidden},
		{name: "prefix collision", targetTenant: "msp-a/client-10", wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := requestWithTargetTenant(http.MethodGet, "/api/v1/stewards", tc.targetTenant, apiKey)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, tc.wantStatus, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

// TestTenantIsolation_AgentDevKey verifies that requirePermission enforces tenant
// isolation for scoped API-key principals using the real TenantIsolationEngine.
//
// [REQUIRED TEST] real TenantIsolationEngine (no mocks):
//   - agent-test/1 key is allowed on agent-test/1 (same-tenant)
//   - agent-test/1 key gets 403 on agent-test/2 (sibling tenant)
//   - agent-test/1 key gets 403 on team-root/ (unrelated tenant)
//   - agent-test/1 key gets 403 on infra-hyperv/ (unrelated tenant)
//   - full-admin mTLS key passes all tenants
func TestTenantIsolation_AgentDevKey(t *testing.T) {
	server := setupTestServerWithIsolationEngine(t)

	const ownTenant = "agent-test/1"
	agentKey := newAgentTestKey(t, server, ownTenant)

	handler := wrapWithAuth(server, "steward", "read",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	tests := []struct {
		name         string
		targetTenant string
		wantStatus   int
	}{
		{name: "same-tenant allowed", targetTenant: ownTenant, wantStatus: http.StatusOK},
		{name: "sibling agent-test/2 denied", targetTenant: "agent-test/2", wantStatus: http.StatusForbidden},
		{name: "team-root/ denied", targetTenant: "team-root/", wantStatus: http.StatusForbidden},
		{name: "infra-hyperv/ denied", targetTenant: "infra-hyperv/", wantStatus: http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := requestWithTargetTenant(http.MethodGet, "/api/v1/stewards", tc.targetTenant, agentKey)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, tc.wantStatus, rec.Code,
				"agent-test/1 key targeting %q: expected %d", tc.targetTenant, tc.wantStatus)
			if tc.wantStatus == http.StatusForbidden {
				assert.Contains(t, rec.Body.String(), "CROSS_TENANT_ACCESS_DENIED",
					"denied response must carry CROSS_TENANT_ACCESS_DENIED code")
			}
		})
	}

	// Full-admin mTLS key must pass ALL tenants (TenantID == "" skips isolation check).
	adminCert := makeSelfSignedAdminCert(t)
	for _, target := range []string{ownTenant, "agent-test/2", "team-root/", "infra-hyperv/"} {
		t.Run("admin passes "+target, func(t *testing.T) {
			req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards", adminCert)
			req = req.WithContext(context.WithValue(req.Context(), targetTenantContextKey, target))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code, "admin key must pass tenant %q", target)
		})
	}
}

// TestLeastPrivilege_AgentDevKey verifies that a key with agent.dev permissions
// cannot perform write operations on its own tenant.
//
// [REQUIRED TEST] agent.dev key attempting config.create/config.delete/steward.manage
// on its own tenant gets 403. This is a distinct least-privilege gate — even within
// the correct tenant, writes must be blocked by missing permissions.
func TestLeastPrivilege_AgentDevKey(t *testing.T) {
	server := setupTestServer(t)

	const ownTenant = "agent-test/1"
	agentKey := newAgentTestKey(t, server, ownTenant)

	// Write operations that agent.dev must NOT have.
	writeOps := []struct {
		name         string
		resourceType string
		action       string
	}{
		{name: "config.create (write-config)", resourceType: "steward", action: "write-config"},
		{name: "config.delete (delete-config)", resourceType: "steward", action: "delete-config"},
		{name: "steward.manage (auth-refresh)", resourceType: "steward", action: "auth-refresh"},
	}

	for _, op := range writeOps {
		t.Run("agent.dev denied for "+op.name, func(t *testing.T) {
			handler := wrapWithAuth(server, op.resourceType, op.action,
				func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

			req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/test", nil)
			req.Header.Set("X-API-Key", agentKey)
			// Set the principal's own tenant — isolation is NOT the gate here,
			// least-privilege permission check is.
			req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, ownTenant))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusForbidden, rec.Code,
				"agent.dev key must be denied %s on own tenant", op.name)
			assert.Contains(t, rec.Body.String(), "INSUFFICIENT_PERMISSIONS")
		})
	}

	// Sanity-check: read operations that agent.dev DOES have must succeed.
	readOps := []struct {
		resourceType string
		action       string
	}{
		{resourceType: "steward", action: "read"},
		{resourceType: "steward", action: "list"},
		{resourceType: "steward", action: "validate-config"},
	}
	for _, op := range readOps {
		t.Run("agent.dev allowed for "+op.resourceType+":"+op.action, func(t *testing.T) {
			handler := wrapWithAuth(server, op.resourceType, op.action,
				func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

			req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/test", nil)
			req.Header.Set("X-API-Key", agentKey)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code,
				"agent.dev key must be allowed %s:%s", op.resourceType, op.action)
		})
	}
}

// --- Web session cookie path tests (Issue #2492, ADR-018 §1,2) ---

// webSessionTestClock is a simple controllable clock for expiry tests.
type webSessionTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newWebSessionTestClock() *webSessionTestClock {
	return &webSessionTestClock{now: time.Now()}
}

func (c *webSessionTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *webSessionTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// setupTestServerWithWebSession creates a server wired with a second session.Manager
// configured for web sessions (ADR-018 §2: idle 60m / absolute 12h / grace 30s).
// The clockFn parameter allows clock injection for expiry tests.
func setupTestServerWithWebSession(t *testing.T, clockFn func() time.Time) (*Server, session.Manager, *session.MemStore) {
	t.Helper()
	srv := setupTestServer(t)
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	store := session.NewMemStore(webCfg, clockFn)
	t.Cleanup(store.Close)
	mgr := session.NewManager(webCfg, store, clockFn)
	srv.SetWebSessionManager(mgr)
	return srv, mgr, store
}

// issueWebSession is a test helper that mints a web session and returns the cookie.
func issueWebSession(t *testing.T, mgr session.Manager, principalID, tenantID string) *http.Cookie {
	t.Helper()
	_, tok, err := mgr.Issue(context.Background(), principalID, "web-login", tenantID)
	require.NoError(t, err)
	return &http.Cookie{Name: "cfgms_session", Value: tok}
}

// TestWebSessionCookie_ValidCookie_BuildsPrincipal verifies that a request carrying a
// valid cfgms_session cookie is authenticated and resolves the correct Principal.
func TestWebSessionCookie_ValidCookie_BuildsPrincipal(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	cookie := issueWebSession(t, mgr, "alice", "tenant-a")

	var capturedPrincipal *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "valid cookie must yield 200")
	require.NotNil(t, capturedPrincipal, "Principal must be set in context")
	assert.Equal(t, "alice", capturedPrincipal.ID)
	assert.Equal(t, "tenant-a", capturedPrincipal.TenantID)
	assert.Equal(t, session.AssuranceBasic, capturedPrincipal.Assurance, "web session principal must have AssuranceBasic")
	assert.Equal(t, "web-session:alice", capturedPrincipal.Name)
}

// TestWebSessionCookie_PrincipalNeverCarriesImplicitAdmin pins the fail-closed
// half of hasPermission's implicit-admin encoding (ADR-025 Amendment 3).
//
// hasPermission grants every permission to a principal with ImplicitAdmin: true.
// Web-session principals must never have ImplicitAdmin set unless the underlying
// account is root-scoped. A web account that cannot be resolved (no account record,
// or account lookup fails) must yield zero permissions and ImplicitAdmin: false.
//
// The account lookup deliberately misses here (no web account backs "alice"), which is the
// worst case: an unresolvable account must yield no permissions, never unbounded ones.
func TestWebSessionCookie_PrincipalNeverCarriesImplicitAdmin(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	cookie := issueWebSession(t, mgr, "alice", "tenant-a")

	var capturedPrincipal *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedPrincipal, "Principal must be set in context")
	require.Equal(t, session.AssuranceBasic, capturedPrincipal.Assurance,
		"precondition: a web principal carries AssuranceBasic")

	assert.False(t, capturedPrincipal.ImplicitAdmin,
		"an unresolvable-account web principal must not carry ImplicitAdmin: true")
	require.NotNil(t, capturedPrincipal.Permissions,
		"web-session principals MUST carry a non-nil Permissions slice")

	// The security property the explicit ImplicitAdmin gate exists to produce.
	assert.False(t, srv.hasPermission(capturedPrincipal, "rbac:create-role"),
		"a web principal with no resolvable account must not be granted permissions it was never assigned")
	assert.False(t, srv.hasPermission(capturedPrincipal, "steward:write-config"),
		"a web principal with no resolvable account must not be granted permissions it was never assigned")
	assert.False(t, capturedPrincipal.GlobalScope,
		"GlobalScope must reflect the account's explicit root grant, not be assumed for web sessions")
}

// TestWebSessionCookie_RootScopeAccountIsImplicitAdminAndStillStepsUp asserts the
// platform-administrator half of the web-account model.
//
// A root-scope web account is an administrator: it holds every permission, so a
// permission introduced after the account was created is usable immediately rather
// than silently 403-ing until someone re-enumerates all 87 IDs.
//
// Breadth is not proof. This test pins both halves together, because the breadth grant
// is only defensible while the assurance gate still bites: the same principal that
// sails through a non-gated permission must be challenged for an AssuranceStrong one.
func TestWebSessionCookie_RootScopeAccountIsImplicitAdminAndStillStepsUp(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	// Deliberately no Permissions: breadth must come from the root-scope grant.
	srv.cacheAccount(&account{
		ID:        "admin-principal-id",
		Username:  "root-admin",
		TenantID:  "",
		RootScope: true,
	})
	cookie := issueWebSession(t, mgr, "admin-principal-id", "")

	var capturedPrincipal *Principal
	capture := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	capture.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedPrincipal)
	assert.True(t, capturedPrincipal.ImplicitAdmin,
		"a resolved root-scope account must carry ImplicitAdmin: true (ADR-025 Amendment 3)")
	assert.NotNil(t, capturedPrincipal.Permissions,
		"Permissions must not be nil — the nil-sentinel is replaced by ImplicitAdmin")
	assert.True(t, capturedPrincipal.GlobalScope,
		"root scope grants cross-tenant visibility")
	assert.True(t, srv.hasPermission(capturedPrincipal, "workflow:execute"),
		"an administrator holds permissions that were never enumerated on the account")

	// Breadth: a permission absent from permissionAssurance is reachable directly.
	okHandler := srv.authenticationMiddleware(
		srv.requirePermission("steward", "list")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	req = httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	okHandler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code,
		"administrator must reach a non-assurance-gated permission without a challenge")

	// Proof: certificate:provision is AssuranceStrong; this session is AssuranceBasic.
	require.Equal(t, session.AssuranceStrong, permissionAssurance["certificate:provision"].Min,
		"precondition: certificate:provision is the AssuranceStrong permission under test")
	stepUpHandler := srv.authenticationMiddleware(
		srv.requirePermission("certificate", "provision")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	req = httptest.NewRequest(http.MethodPost, "/api/v1/certificates/provision", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	stepUpHandler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"implicit admin must still be challenged for an AssuranceStrong permission, not admitted")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp",
		"the challenge must be a step-up invitation, not a flat denial")
	assert.Contains(t, rec.Body.String(), "step_up_required")
}

// TestWebSessionCookie_TenantScopedAccountIsEnumerated asserts the least-privilege half:
// a non-root web account is held to exactly the grants configured on it. This is the
// persona the Principal doc comment anticipates (Assurance=AssuranceBasic,
// GlobalScope=false) and the one whose permissions must never be widened by assurance.
func TestWebSessionCookie_TenantScopedAccountIsEnumerated(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	srv.cacheAccount(&account{
		ID:          "operator-principal-id",
		Username:    "tenant-operator",
		TenantID:    "tenant-a",
		RootScope:   false,
		Permissions: []string{"steward:list"},
	})
	cookie := issueWebSession(t, mgr, "operator-principal-id", "tenant-a")

	var capturedPrincipal *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedPrincipal)
	require.NotNil(t, capturedPrincipal.Permissions,
		"a tenant-scoped account must carry a non-nil Permissions slice")
	assert.False(t, capturedPrincipal.ImplicitAdmin,
		"a tenant-scoped account must never carry ImplicitAdmin: true")
	assert.False(t, capturedPrincipal.GlobalScope,
		"a tenant-scoped account is confined to its tenant subtree")
	assert.True(t, srv.hasPermission(capturedPrincipal, "steward:list"),
		"configured grants are honoured")
	assert.False(t, srv.hasPermission(capturedPrincipal, "steward:write-config"),
		"human assurance must not widen a tenant-scoped account beyond its grants")
	assert.False(t, srv.hasPermission(capturedPrincipal, "rbac:create-role"),
		"human assurance must not widen a tenant-scoped account beyond its grants")
}

// TestWebSessionCookie_RenewalCookieFlags verifies that the refreshed Set-Cookie header
// carries exactly HttpOnly; Secure; SameSite=Strict; Path=/ (ADR-018 §1).
func TestWebSessionCookie_RenewalCookieFlags(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
	cookie := issueWebSession(t, mgr, "alice", "tenant-a")

	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	setCookie := rec.Header().Get("Set-Cookie")
	require.NotEmpty(t, setCookie, "a valid cookie request must produce a refreshed Set-Cookie")

	assert.Contains(t, setCookie, "cfgms_session=", "Set-Cookie must use name cfgms_session")
	assert.Contains(t, setCookie, "HttpOnly", "cookie must be HttpOnly")
	assert.Contains(t, setCookie, "Secure", "cookie must be Secure")
	assert.Contains(t, setCookie, "SameSite=Strict", "cookie must be SameSite=Strict")
	assert.Contains(t, setCookie, "Path=/", "cookie must have Path=/")

	// Verify no Max-Age is present: server-side expiry is authoritative (ADR-018 §2).
	assert.NotContains(t, setCookie, "Max-Age", "cookie must NOT carry Max-Age — server-side expiry is authoritative")
}

// TestWebSessionCookie_IdleExpiry_Returns401 verifies that after the idle timeout
// elapses, subsequent cookie requests receive 401 SESSION_EXPIRED.
func TestWebSessionCookie_IdleExpiry_Returns401(t *testing.T) {
	clk := newWebSessionTestClock()
	srv, mgr, _ := setupTestServerWithWebSession(t, clk.Now)

	cookie := issueWebSession(t, mgr, "alice", "tenant-a")

	// Advance past web session idle timeout (60m).
	clk.Advance(61 * time.Minute)

	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "idle-expired cookie must return 401")
	assert.Contains(t, rec.Body.String(), "SESSION_EXPIRED")
	assert.Empty(t, rec.Header().Get("Set-Cookie"), "no Set-Cookie must be emitted for an expired session")
}

// TestWebSessionCookie_AbsoluteExpiry_Returns401 verifies that after the absolute timeout
// elapses (even with recent activity), cookie requests receive 401 SESSION_EXPIRED.
func TestWebSessionCookie_AbsoluteExpiry_Returns401(t *testing.T) {
	clk := newWebSessionTestClock()
	srv, mgr, _ := setupTestServerWithWebSession(t, clk.Now)

	cookie := issueWebSession(t, mgr, "alice", "tenant-a")

	// Advance past web session absolute timeout (12h).
	clk.Advance(13 * time.Hour)

	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "absolute-expired cookie must return 401")
	assert.Contains(t, rec.Body.String(), "SESSION_EXPIRED")
	assert.Empty(t, rec.Header().Get("Set-Cookie"), "no Set-Cookie must be emitted for an absolute-expired session")
}

// TestWebSessionCookie_Revoked_Returns401 verifies that a revoked web session cookie
// returns 401 SESSION_REVOKED (drives the SPA "session expired" state).
func TestWebSessionCookie_Revoked_Returns401(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	cookie := issueWebSession(t, mgr, "alice", "tenant-a")

	// Validate once to obtain the session ID, then revoke.
	sess, err := mgr.Validate(context.Background(), cookie.Value)
	require.NoError(t, err)
	require.NoError(t, mgr.Revoke(context.Background(), sess.ID))

	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "revoked cookie must return 401")
	assert.Contains(t, rec.Body.String(), "SESSION_REVOKED")
}

// TestWebSessionCookie_CoexistenceMatrix verifies the credential-precedence rule:
// when a header credential (Bearer or API key) or admin mTLS is present alongside a
// valid cfgms_session cookie, the header/mTLS credential wins and the cookie is
// ignored entirely — not validated, not renewed, no Set-Cookie emitted.
func TestWebSessionCookie_CoexistenceMatrix(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	webCookie := issueWebSession(t, mgr, "alice", "tenant-a")
	apiKeyStr := NewTestKey(t, srv, []string{"steward:read"})

	// Issue a Bearer session token via the cfg sessionManager (ADR-014 path).
	bearerCfg := session.DefaultConfig()
	bearerStore := session.NewMemStore(bearerCfg, time.Now)
	t.Cleanup(bearerStore.Close)
	bearerMgr := session.NewManager(bearerCfg, bearerStore, time.Now)
	srv.SetSessionManager(bearerMgr)
	_, bearerToken, err := bearerMgr.Issue(context.Background(), "admin", "cfg-cli", "")
	require.NoError(t, err)

	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := r.Context().Value(principalContextKey).(*Principal)
		if p != nil {
			w.Header().Set("X-Test-Auth-Method", p.Name)
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("cookie+Bearer → Bearer wins, no Set-Cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(webCookie)
		req.Header.Set("Authorization", "Bearer "+bearerToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		// Bearer session path identifies itself as "session:<principalID>", NOT "web-session:..."
		assert.Contains(t, rec.Header().Get("X-Test-Auth-Method"), "session:",
			"Bearer session must win over cookie")
		assert.NotContains(t, rec.Header().Get("X-Test-Auth-Method"), "web-session:")
		assert.Empty(t, rec.Header().Get("Set-Cookie"), "no Set-Cookie when Bearer credential wins")
	})

	t.Run("cookie+API-key → API-key wins, no Set-Cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(webCookie)
		req.Header.Set("X-API-Key", apiKeyStr)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		// API-key principal must win: auth-method must be non-empty and must NOT be "web-session:".
		authMethod := rec.Header().Get("X-Test-Auth-Method")
		assert.NotEmpty(t, authMethod, "API-key path must produce a principal")
		assert.NotContains(t, authMethod, "web-session:", "web session must NOT win when API-key is present")
		assert.Empty(t, rec.Header().Get("Set-Cookie"), "no Set-Cookie when API-key credential wins")
	})

	t.Run("cookie+mTLS → mTLS wins, no Set-Cookie", func(t *testing.T) {
		adminCert := makeSelfSignedAdminCert(t)
		req := requestWithTLSCert(http.MethodGet, "/api/v1/stewards", adminCert)
		req.AddCookie(webCookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		// mTLS path sets Name = "mtls-admin:<cn>"
		assert.Contains(t, rec.Header().Get("X-Test-Auth-Method"), "mtls-admin:",
			"mTLS must win over cookie")
		assert.Empty(t, rec.Header().Get("Set-Cookie"), "no Set-Cookie when mTLS credential wins")
	})

	t.Run("cookie only → web session wins", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(webCookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("X-Test-Auth-Method"), "web-session:",
			"only cookie present → web session path must fire")
		assert.NotEmpty(t, rec.Header().Get("Set-Cookie"), "renewal cookie must be set after web-session auth")
	})
}

// TestWebSessionCookie_BearerPathUnchanged_Regression verifies that the ADR-014 Bearer
// session path (X-Session-Token renewal, not Set-Cookie) is byte-identical after the
// web session cookie branch was added.
func TestWebSessionCookie_BearerPathUnchanged_Regression(t *testing.T) {
	srv, _, _ := setupTestServerWithWebSession(t, time.Now)

	// Wire the cfg-CLI session manager (ADR-014 defaults: idle 15m / absolute 8h).
	bearerCfg := session.DefaultConfig()
	bearerStore := session.NewMemStore(bearerCfg, time.Now)
	t.Cleanup(bearerStore.Close)
	bearerMgr := session.NewManager(bearerCfg, bearerStore, time.Now)
	srv.SetSessionManager(bearerMgr)

	_, bearerToken, err := bearerMgr.Issue(context.Background(), "admin", "cfg-cli", "")
	require.NoError(t, err)

	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "Bearer session path must still work")
	// ADR-014: renewal is expressed as X-Session-Token header, NOT Set-Cookie.
	assert.NotEmpty(t, rec.Header().Get("X-Session-Token"),
		"Bearer path must renew via X-Session-Token header (ADR-014)")
	assert.Empty(t, rec.Header().Get("Set-Cookie"),
		"Bearer path must NOT emit Set-Cookie (cookie transport is web-session only)")
}

// TestWebSessionManager_Issue_UniqueTokensPerCall verifies the session-fixation posture
// (ADR-018 §1, founder condition 4): webSessionManager.Issue mints a fresh 32-byte
// cryptographically random token on every call — no token reuse across invocations.
// The login endpoint (#2493) calls Issue on every successful authentication.
func TestWebSessionManager_Issue_UniqueTokensPerCall(t *testing.T) {
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	store := session.NewMemStore(webCfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(webCfg, store, time.Now)

	seen := make(map[string]bool, 20)
	for i := 0; i < 20; i++ {
		_, tok, err := mgr.Issue(context.Background(), "admin", "web-login", "default")
		require.NoError(t, err)
		require.NotEmpty(t, tok)
		require.False(t, seen[tok],
			"Issue must mint a unique token on each call (session-fixation posture); duplicate at iteration %d", i)
		seen[tok] = true
		// 43 chars = base64url of 32 bytes without padding.
		assert.Len(t, tok, 43, "web session token must be 43 characters (32 bytes base64url)")
	}
}

// TestWebSessionCookie_InvalidToken_Returns401 verifies that a cfgms_session cookie
// carrying an unrecognised token (not in manager's store) returns 401.
func TestWebSessionCookie_InvalidToken_Returns401(t *testing.T) {
	srv, _, _ := setupTestServerWithWebSession(t, time.Now)

	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	// Use a well-formed 43-char base64url string that was never issued.
	req.AddCookie(&http.Cookie{Name: "cfgms_session", Value: strings.Repeat("a", 43)})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code, "unknown cookie token must return 401")
	assert.Contains(t, rec.Body.String(), "INVALID_SESSION_TOKEN")
}

// --- Session assurance propagation tests (ADR-021 Decision 3/5, Issue #2788) ---
// The Bearer and cookie paths read sess.Assurance from the session returned by Manager.Validate
// instead of hardcoding AssuranceBasic. These tests verify that both the upgrade path
// (AssuranceStrong propagated to Principal) and the downgrade path (IP-change downgrade
// reflected in Principal) are correctly wired through the middleware.

// setupBearerSessionWithAssurance issues a session via mgrWrite, writes AssuranceStrong state
// directly to the shared store (simulating a WebAuthn assertion handler), and returns the token.
// mgrRead (cold cache) must be set as the server's sessionManager before making requests.
func setupBearerSessionWithAssurance(t *testing.T, store *session.MemStore, mgrWrite session.Manager, boundIP string) string {
	t.Helper()
	sess, token, err := mgrWrite.Issue(context.Background(), "admin", "cfg-cli", "tenant-1")
	require.NoError(t, err)
	sess.Assurance = session.AssuranceStrong
	sess.BoundIP = boundIP
	sess.LastProvenAt = time.Now()
	require.NoError(t, store.Set(context.Background(), session.HashToken(token), sess))
	return token
}

// TestBearerSession_AssurancePropagatedToPrincipal verifies that authenticationMiddleware reads
// sess.Assurance from Manager.Validate (ADR-021 Decision 3/5) and not a hardcoded value.
//
// (a) An AssuranceStrong session with a matching source IP must yield a Principal
// with Assurance == AssuranceStrong.
// (b) An AssuranceStrong session whose BoundIP differs from the request source IP is
// downgraded by Manager.Validate to AssuranceBasic; the Principal must reflect that downgrade.
func TestBearerSession_AssurancePropagatedToPrincipal(t *testing.T) {
	// httptest.NewRequest sets RemoteAddr = "192.0.2.1:1234"; SplitHostPort → "192.0.2.1".
	const httptestIP = "192.0.2.1"

	t.Run("AssuranceStrong propagated when source IP matches bound IP", func(t *testing.T) {
		cfg := session.DefaultConfig()
		store := session.NewMemStore(cfg, time.Now)
		t.Cleanup(store.Close)
		mgrWrite := session.NewManager(cfg, store, time.Now)
		mgrRead := session.NewManager(cfg, store, time.Now)

		srv := setupTestServer(t)
		srv.SetSessionManager(mgrRead)

		token := setupBearerSessionWithAssurance(t, store, mgrWrite, httptestIP)

		var capturedPrincipal *Principal
		handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.NotNil(t, capturedPrincipal)
		assert.Equal(t, session.AssuranceStrong, capturedPrincipal.Assurance,
			"AssuranceStrong session with matching IP must yield Principal with AssuranceStrong")
	})

	t.Run("IP-change downgrade reflected as AssuranceBasic in Principal", func(t *testing.T) {
		cfg := session.DefaultConfig()
		store := session.NewMemStore(cfg, time.Now)
		t.Cleanup(store.Close)
		mgrWrite := session.NewManager(cfg, store, time.Now)
		mgrRead := session.NewManager(cfg, store, time.Now)

		srv := setupTestServer(t)
		srv.SetSessionManager(mgrRead)

		// BoundIP differs from httptest.NewRequest RemoteAddr so Manager.Validate downgrades.
		token := setupBearerSessionWithAssurance(t, store, mgrWrite, "10.0.0.1")

		var capturedPrincipal *Principal
		handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		// RemoteAddr = "192.0.2.1:1234" → sourceIP "192.0.2.1" ≠ BoundIP "10.0.0.1"
		// → Manager.Validate downgrades session to AssuranceBasic (ADR-021 Decision 5).
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code,
			"downgraded session must remain valid — not killed (ADR-021 Decision 5)")
		require.NotNil(t, capturedPrincipal)
		assert.Equal(t, session.AssuranceBasic, capturedPrincipal.Assurance,
			"IP-change downgrade must be reflected in Principal Assurance")
	})
}

// TestBearerSession_RootScopedPropagatedToPrincipal verifies that authenticationMiddleware
// carries Session.RootScoped (ADR-025 Amendment 1 A1.3, set only by Manager.IssueRootScoped)
// onto the Principal it builds for the Bearer/session path. This is the session-issued half
// of the same control the mTLS path covers via cert.HasRootScopeMarker
// (TestExtractAdminPrincipal_RootScopeMarker): without propagation, a root-scoped operator's
// cfg-CLI session would authenticate as an ordinary unscoped superadmin and skip the
// root<->MSP boundary check in authorizeTenantAccess entirely.
func TestBearerSession_RootScopedPropagatedToPrincipal(t *testing.T) {
	captureBearerPrincipal := func(t *testing.T, issue func(session.Manager) string) *Principal {
		t.Helper()
		cfg := session.DefaultConfig()
		store := session.NewMemStore(cfg, time.Now)
		t.Cleanup(store.Close)
		mgrWrite := session.NewManager(cfg, store, time.Now)
		// A separate manager instance for the read side: its in-memory index is empty, so
		// Validate must reload the session from the shared store — the same path a session
		// takes across a controller restart or a sibling cluster node.
		mgrRead := session.NewManager(cfg, store, time.Now)

		srv := setupTestServer(t)
		srv.SetSessionManager(mgrRead)

		token := issue(mgrWrite)

		var captured *Principal
		handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured, _ = r.Context().Value(principalContextKey).(*Principal)
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.NotNil(t, captured)
		return captured
	}

	t.Run("root-scoped session yields RootScoped principal", func(t *testing.T) {
		principal := captureBearerPrincipal(t, func(mgr session.Manager) string {
			_, token, err := mgr.IssueRootScoped(context.Background(), "root-operator-1", "cfg-cli")
			require.NoError(t, err)
			return token
		})

		assert.True(t, principal.RootScoped,
			"a session issued via IssueRootScoped must produce a RootScoped Principal")
		assert.Equal(t, "", principal.TenantID,
			"a root-scoped session stays unscoped — RootScoped must not synthesise a TenantID")
		assert.Equal(t, "root-operator-1", principal.ID)
	})

	t.Run("ordinary unscoped session is not RootScoped", func(t *testing.T) {
		principal := captureBearerPrincipal(t, func(mgr session.Manager) string {
			_, token, err := mgr.Issue(context.Background(), "admin-1", "cfg-cli", "")
			require.NoError(t, err)
			return token
		})

		assert.False(t, principal.RootScoped,
			"RootScoped must come from the session's explicit marker, never from an empty TenantID")
		assert.True(t, principal.GlobalScope,
			"an unscoped session keeps today's cross-tenant visibility (Issue #3194)")
	})

	t.Run("tenant-scoped session is not RootScoped", func(t *testing.T) {
		principal := captureBearerPrincipal(t, func(mgr session.Manager) string {
			_, token, err := mgr.Issue(context.Background(), "msp-a-admin", "cfg-cli", "msp-a")
			require.NoError(t, err)
			return token
		})

		assert.False(t, principal.RootScoped)
		assert.Equal(t, "msp-a", principal.TenantID)
	})
}

// mintPresenceToken injects a presence token directly into the server's presenceTokens map,
// bypassing the WebAuthn ceremony. For use in middleware tests only — the WebAuthn hardware
// ceremony is not available in unit tests; this creates the token that
// handlePresenceFinish would mint after a successful assertion.
func mintPresenceToken(t *testing.T, s *Server, principalID string) string {
	t.Helper()
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	require.NoError(t, err)
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenHash := hashPresenceToken(token)
	s.presenceTokens.Store(tokenHash, &presenceTokenRecord{
		principalID: principalID,
		expires:     time.Now().Add(presenceTokenTTL),
	})
	t.Cleanup(func() { s.presenceTokens.Delete(tokenHash) })
	return token
}

// --- User-presence enforcement tests (Issue #2784, ADR-021 Decision 4) ---
//
// Testing strategy: synthetic test-only route registered inline via wrapWithAuth, using a
// temporary "test:presence-required" entry in permissionAssurance. No server.go route is
// modified — the test exercises requirePermission directly, consistent with the F2 parity
// pattern used throughout this file. Real WebAuthn hardware is unavailable in unit tests;
// mintPresenceToken injects the token that handlePresenceFinish would otherwise mint.

// withPresencePermission temporarily adds "test:presence-required" to permissionAssurance
// with RequireUserPresence=true and removes it on test cleanup.
func withPresencePermission(t *testing.T) {
	t.Helper()
	const perm = "test:presence-required"
	permissionAssurance[perm] = Requirement{
		Min:                 session.AssuranceStrong,
		RequireUserPresence: true,
	}
	t.Cleanup(func() { delete(permissionAssurance, perm) })
}

// TestRequirePermission_UserPresence_NoToken verifies that an AssuranceStrong session
// WITHOUT a presence token is rejected with 401 and WWW-Authenticate carrying presence="required".
//
// [REQUIRED TEST] ADR-021 Decision 4: continuity alone is insufficient — a present human
// gesture is needed for catastrophic operations, regardless of session assurance level.
func TestRequirePermission_UserPresence_NoToken(t *testing.T) {
	withPresencePermission(t)

	server := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t) // AssuranceStrong via mTLS

	handler := wrapWithAuth(server, "test", "presence-required",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	req := requestWithTLSCert(http.MethodPost, "/api/v1/test/presence-action", adminCert)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"AssuranceStrong session without presence token must be rejected with 401")

	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `presence="required"`,
		`WWW-Authenticate must carry presence="required"`)
	assert.Contains(t, wwwAuth, "CFGMS-StepUp",
		"WWW-Authenticate must use CFGMS-StepUp scheme")
	assert.Contains(t, wwwAuth, `required="strong"`,
		`WWW-Authenticate must specify required="strong"`)

	assert.Contains(t, rec.Body.String(), "step_up_required",
		"response body must carry step_up_required error code")
	assert.Contains(t, rec.Body.String(), "true",
		"response body must indicate presence_required")
}

// TestRequirePermission_UserPresence_ValidTokenAdmitted verifies that an AssuranceStrong
// session WITH a valid, fresh, single-use presence token is admitted (200), and that
// presenting the same token a second time is rejected (single-use enforcement).
//
// [REQUIRED TEST] ADR-021 Decision 4: the presence token is consumed on first use.
func TestRequirePermission_UserPresence_ValidTokenAdmitted(t *testing.T) {
	withPresencePermission(t)

	server := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t) // AssuranceStrong via mTLS

	handler := wrapWithAuth(server, "test", "presence-required",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	token := mintPresenceToken(t, server, "test-admin")

	// First use: must be admitted.
	req := requestWithTLSCert(http.MethodPost, "/api/v1/test/presence-action", adminCert)
	req.Header.Set(presenceTokenHeader, token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "valid presence token must be admitted (first use)")

	// Second use of the SAME token: must be rejected — token was consumed on first use.
	req2 := requestWithTLSCert(http.MethodPost, "/api/v1/test/presence-action", adminCert)
	req2.Header.Set(presenceTokenHeader, token)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusUnauthorized, rec2.Code,
		"same presence token must be rejected on second use (single-use enforcement)")
	assert.Contains(t, rec2.Header().Get("WWW-Authenticate"), `presence="required"`,
		"second-use rejection must carry presence=\"required\" in WWW-Authenticate")
}

// TestRequirePermission_UserPresence_PrincipalMismatchRejected verifies that a presence
// token minted for principal A does NOT satisfy the presence gate for principal B's request.
// The token is bound to the principal that ran the WebAuthn ceremony (record.principalID),
// and requirePermission must reject a mismatched acting principal with a step-up 401.
//
// [REQUIRED TEST] ADR-021 Decision 4: the *acting* principal must have proved fresh presence.
// A presence proof by another principal must never satisfy a catastrophic action's gate.
func TestRequirePermission_UserPresence_PrincipalMismatchRejected(t *testing.T) {
	withPresencePermission(t)

	server := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t) // principal.ID == "test-admin"

	handler := wrapWithAuth(server, "test", "presence-required",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	// Token minted for a DIFFERENT principal ("other-admin") than the acting cert principal.
	token := mintPresenceToken(t, server, "other-admin")

	req := requestWithTLSCert(http.MethodPost, "/api/v1/test/presence-action", adminCert)
	req.Header.Set(presenceTokenHeader, token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"presence token bound to a different principal must be rejected with 401")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`,
		`principal-mismatch rejection must carry presence="required" in WWW-Authenticate`)
	assert.Contains(t, rec.Body.String(), "presence_token_principal_mismatch",
		"response body must carry presence_token_principal_mismatch error code")

	// The mismatched token must have been consumed (single-use) — the acting principal
	// cannot retry, and neither can the legitimate owner replay it.
	_, stillPresent := server.presenceTokens.Load(hashPresenceToken(token))
	assert.False(t, stillPresent, "mismatched token must be consumed on the rejected attempt")
}

// TestRequirePermission_UserPresence_MachinePrincipalGets403 verifies that an API-key
// principal (AssuranceMachine) against a RequireUserPresence permission receives a plain 403,
// not a step-up challenge. Automation cannot self-elevate (ADR-021 Decision 8).
//
// [REQUIRED TEST] ADR-021 Decision 8: machine principals are permanently excluded from
// presence-gated routes; the response must be 403 INSUFFICIENT_PERMISSIONS, never 401.
func TestRequirePermission_UserPresence_MachinePrincipalGets403(t *testing.T) {
	withPresencePermission(t)

	server := setupTestServer(t)

	// Grant the API key the permission explicitly so it clears hasPermission,
	// reaching the assurance check which then rejects it with 403.
	machineKey := NewTestKey(t, server, []string{"test:presence-required"})

	handler := wrapWithAuth(server, "test", "presence-required",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	req := httptest.NewRequest(http.MethodPost, "/api/v1/test/presence-action", nil)
	req.Header.Set("X-API-Key", machineKey)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"AssuranceMachine against RequireUserPresence permission must get 403, not 401 step-up")
	assert.Contains(t, rec.Body.String(), "INSUFFICIENT_PERMISSIONS",
		"response must carry INSUFFICIENT_PERMISSIONS, not a step-up error code")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
		"machine 403 must NOT carry a WWW-Authenticate step-up challenge")
}

// TestRequirePermission_UserPresence_ExpiredToken verifies that a presence token
// whose TTL has elapsed is rejected with 401 and error "presence_token_expired".
// The token hash is removed from presenceTokens on LoadAndDelete so no cleanup is needed.
func TestRequirePermission_UserPresence_ExpiredToken(t *testing.T) {
	withPresencePermission(t)

	server := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t)

	handler := wrapWithAuth(server, "test", "presence-required",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	// Inject a token whose TTL has already elapsed.
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	require.NoError(t, err)
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenHash := hashPresenceToken(token)
	server.presenceTokens.Store(tokenHash, &presenceTokenRecord{
		principalID: "test-admin",
		expires:     time.Now().Add(-1 * time.Second), // already elapsed
	})
	// LoadAndDelete in requirePermission will remove the entry on first access;
	// this cleanup handles the case where the test is skipped before that.
	t.Cleanup(func() { server.presenceTokens.Delete(tokenHash) })

	req := requestWithTLSCert(http.MethodPost, "/api/v1/test/presence-action", adminCert)
	req.Header.Set(presenceTokenHeader, token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code,
		"expired presence token must be rejected with 401")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`)
	assert.Contains(t, rec.Body.String(), "presence_token_expired",
		"response body must carry presence_token_expired error code")
}

// TestWebSessionCookie_AssurancePropagatedToPrincipal verifies that the cookie auth path
// reads sess.Assurance from Manager.Validate (ADR-021 Decision 3/5) and not a hardcoded value.
//
// (a) An AssuranceStrong web session with matching source IP must yield a Principal
// with Assurance == AssuranceStrong.
// (b) An AssuranceStrong web session whose BoundIP differs from the request source IP is
// downgraded by Manager.Validate; the Principal must reflect AssuranceBasic.
func TestWebSessionCookie_AssurancePropagatedToPrincipal(t *testing.T) {
	const httptestIP = "192.0.2.1"

	webCfg := session.Config{
		IdleTimeout:           60 * time.Minute,
		AbsoluteTimeout:       12 * time.Hour,
		GraceWindow:           30 * time.Second,
		SilentReproofInterval: 5 * time.Minute,
	}

	t.Run("AssuranceStrong propagated when source IP matches bound IP", func(t *testing.T) {
		store := session.NewMemStore(webCfg, time.Now)
		t.Cleanup(store.Close)
		mgrWrite := session.NewManager(webCfg, store, time.Now)
		mgrRead := session.NewManager(webCfg, store, time.Now)

		srv := setupTestServer(t)
		srv.SetWebSessionManager(mgrRead)

		// Issue via mgrWrite and elevate to AssuranceStrong in the shared store.
		webSess, token, err := mgrWrite.Issue(context.Background(), "alice", "web-login", "tenant-a")
		require.NoError(t, err)
		webSess.Assurance = session.AssuranceStrong
		webSess.BoundIP = httptestIP
		webSess.LastProvenAt = time.Now()
		require.NoError(t, store.Set(context.Background(), session.HashToken(token), webSess))

		var capturedPrincipal *Principal
		handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(&http.Cookie{Name: "cfgms_session", Value: token})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		require.NotNil(t, capturedPrincipal)
		assert.Equal(t, session.AssuranceStrong, capturedPrincipal.Assurance,
			"AssuranceStrong web session with matching IP must yield Principal with AssuranceStrong")
	})

	t.Run("IP-change downgrade reflected as AssuranceBasic in Principal", func(t *testing.T) {
		store := session.NewMemStore(webCfg, time.Now)
		t.Cleanup(store.Close)
		mgrWrite := session.NewManager(webCfg, store, time.Now)
		mgrRead := session.NewManager(webCfg, store, time.Now)

		srv := setupTestServer(t)
		srv.SetWebSessionManager(mgrRead)

		// BoundIP differs from httptest RemoteAddr so Validate downgrades.
		webSess, token, err := mgrWrite.Issue(context.Background(), "alice", "web-login", "tenant-a")
		require.NoError(t, err)
		webSess.Assurance = session.AssuranceStrong
		webSess.BoundIP = "10.0.0.1"
		webSess.LastProvenAt = time.Now()
		require.NoError(t, store.Set(context.Background(), session.HashToken(token), webSess))

		var capturedPrincipal *Principal
		handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.AddCookie(&http.Cookie{Name: "cfgms_session", Value: token})
		// RemoteAddr "192.0.2.1:1234" → sourceIP "192.0.2.1" ≠ BoundIP "10.0.0.1"
		// → Manager.Validate downgrades web session to AssuranceBasic.
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code,
			"downgraded web session must remain valid (ADR-021 Decision 5)")
		require.NotNil(t, capturedPrincipal)
		assert.Equal(t, session.AssuranceBasic, capturedPrincipal.Assurance,
			"IP-change downgrade must be reflected in web session Principal Assurance")
	})
}

// --- cfg-CLI Bearer session GlobalScope tests (Issue #3194) ---
// These tests verify that the cfg-CLI Bearer session principal's GlobalScope is derived
// from the session's actual tenant scope rather than hardcoded true.

// TestBearerSession_TenantScoped_GlobalScopeFalse verifies that a cfg-CLI session bound
// to a non-empty TenantID produces a principal with GlobalScope==false. Before Issue #3194,
// GlobalScope was hardcoded true on the Bearer session path, making tenant isolation
// checks dead code for this principal type.
func TestBearerSession_TenantScoped_GlobalScopeFalse(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)

	srv := setupTestServer(t)
	srv.SetSessionManager(mgr)

	_, token, err := mgr.Issue(context.Background(), "cli-admin", "cfg-cli", "msp-a")
	require.NoError(t, err)

	var capturedPrincipal *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedPrincipal)
	assert.False(t, capturedPrincipal.GlobalScope,
		"cfg-CLI session bound to TenantID='msp-a' must yield GlobalScope=false (Issue #3194)")
	assert.Equal(t, "msp-a", capturedPrincipal.TenantID)
}

// TestBearerSession_Unscoped_GlobalScopeTrue verifies that a cfg-CLI session with no
// tenant scope (TenantID=="") still receives cross-tenant visibility (GlobalScope==true),
// so existing platform-admin CLI workflows do not regress after Issue #3194.
func TestBearerSession_Unscoped_GlobalScopeTrue(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)

	srv := setupTestServer(t)
	srv.SetSessionManager(mgr)

	_, token, err := mgr.Issue(context.Background(), "platform-admin", "cfg-cli", "")
	require.NoError(t, err)

	var capturedPrincipal *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedPrincipal)
	assert.True(t, capturedPrincipal.GlobalScope,
		"cfg-CLI session with empty TenantID (platform admin) must yield GlobalScope=true (Issue #3194 regression guard)")
	assert.Empty(t, capturedPrincipal.TenantID)
}

// TestBearerSession_TenantScoped_CrossTenantAccessDenied verifies end-to-end that the
// corrected GlobalScope signal causes requirePermission to reject a cross-tenant request
// from a tenant-scoped cfg-CLI session. Before Issue #3194, GlobalScope was hardcoded
// true, making the !principal.GlobalScope guard a dead check for this principal type.
func TestBearerSession_TenantScoped_CrossTenantAccessDenied(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)

	// setupTestServer wires no isolation engine; the boundary check at middleware.go:818
	// fires before the engine check, so the simpler server is sufficient.
	srv := setupTestServer(t)
	srv.SetSessionManager(mgr)

	// Issue a tenant-scoped cfg-CLI session for "msp-a".
	_, token, err := mgr.Issue(context.Background(), "cli-admin", "cfg-cli", "msp-a")
	require.NoError(t, err)

	handler := srv.authenticationMiddleware(
		srv.requirePermission("steward", "list")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		),
	)

	t.Run("same tenant allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req = req.WithContext(context.WithValue(req.Context(), targetTenantContextKey, "msp-a"))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code,
			"tenant-scoped CLI session must access its own tenant")
	})

	t.Run("cross-tenant denied (GlobalScope now false)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req = req.WithContext(context.WithValue(req.Context(), targetTenantContextKey, "msp-b"))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code,
			"tenant-scoped CLI session must not access a sibling tenant (GlobalScope fix)")
		assert.Contains(t, rec.Body.String(), "CROSS_TENANT_ACCESS_DENIED",
			"cross-tenant denial must carry CROSS_TENANT_ACCESS_DENIED error code")
	})
}

// --- Bearer session + bound account tests (Issue #3576) ---
//
// These tests verify that authenticationMiddleware's Bearer-token branch resolves
// TenantID, GlobalScope, and Permissions fresh from the bound web account on every
// request, mirroring the web-cookie branch's per-request account recheck (Issue #3311).

// setupBearerSession issues a cfg-CLI Bearer session for the given principalID and
// tenantID, returning the token. Uses the manager already wired on srv.
func setupBearerSession(t *testing.T, mgr session.Manager, principalID, tenantID string) string {
	t.Helper()
	_, token, err := mgr.Issue(context.Background(), principalID, "cfg-cli", tenantID)
	require.NoError(t, err)
	return token
}

// TestBearerSession_BoundTenantScopedAccount_PermissionDenied is the [REQUIRED TEST]
// that a session bound to a tenant-scoped, non-root-scope account with an explicit
// permission list is DENIED a permission the account does not hold — proving the
// resolved principal is NOT implicit admin.
func TestBearerSession_BoundTenantScopedAccount_PermissionDenied(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)

	srv := setupTestServer(t)
	srv.SetSessionManager(mgr)

	// Cache a tenant-scoped account with a limited permission set.
	srv.cacheAccount(&account{
		ID:          "bounded-operator-id",
		Username:    "bounded-operator",
		TenantID:    "tenant-a",
		RootScope:   false,
		Permissions: []string{"steward:list"},
	})

	// Issue a Bearer session for this account's principal ID.
	token := setupBearerSession(t, mgr, "bounded-operator-id", "tenant-a")

	// steward:write-config is NOT in the account's permissions.
	handler := srv.authenticationMiddleware(
		srv.requirePermission("steward", "write-config")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		),
	)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/test/config", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"a tenant-scoped Bearer session must be confined to its account's grants — steward:write-config must be denied")
	assert.Contains(t, rec.Body.String(), "INSUFFICIENT_PERMISSIONS",
		"denied response must carry INSUFFICIENT_PERMISSIONS code")
}

// TestBearerSession_BoundAccountPermissionChangeLiveWithoutRelogin is the [REQUIRED TEST]
// that changing an account's permissions between two requests on the same, still-valid
// session token changes what the second request is allowed to do — no re-login required.
func TestBearerSession_BoundAccountPermissionChangeLiveWithoutRelogin(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)

	srv := setupTestServer(t)
	srv.SetSessionManager(mgr)

	// Cache the account with steward:list only.
	acct := &account{
		ID:          "live-perm-user-id",
		Username:    "live-perm-user",
		TenantID:    "tenant-b",
		RootScope:   false,
		Permissions: []string{"steward:list"},
	}
	srv.cacheAccount(acct)

	// Issue one session token that both requests will use.
	token := setupBearerSession(t, mgr, acct.ID, acct.TenantID)

	// steward:validate-config is used here (not steward:write-config) because it
	// carries no permissionAssurance entry — this test exercises live permission-
	// grant propagation, not assurance gating, and Bearer sessions are AssuranceBasic
	// so an AssuranceStrong-gated permission (Issue #3792) would 401 step-up rather
	// than the 403/200 pair this test asserts.
	handler := srv.authenticationMiddleware(
		srv.requirePermission("steward", "validate-config")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		),
	)

	// Request 1: steward:validate-config is not in the account's grants → 403.
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/test/config", nil)
	req1.Header.Set("Authorization", "Bearer "+token)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusForbidden, rec1.Code,
		"steward:validate-config must be denied before the permission is granted")

	// Simulate an admin granting steward:validate-config — update the cache without re-login.
	updated := *acct
	updated.Permissions = append([]string{}, acct.Permissions...)
	updated.Permissions = append(updated.Permissions, "steward:validate-config")
	srv.cacheAccount(&updated)

	// Request 2: same token, now steward:validate-config is in the account's grants → 200.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/test/config", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code,
		"steward:validate-config must be allowed after the account permission is updated — no re-login required")
}

// TestBearerSession_BoundDisabledAccount_Returns401Revoked verifies that a session
// whose PrincipalID matches a Disabled account is rejected with the same
// "Session has been revoked" 401 an ordinarily-revoked session gets (Issue #3576).
func TestBearerSession_BoundDisabledAccount_Returns401Revoked(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)

	srv := setupTestServer(t)
	srv.SetSessionManager(mgr)

	srv.cacheAccount(&account{
		ID:       "disabled-cli-id",
		Username: "disabled-cli-user",
		TenantID: "tenant-a",
		Disabled: true,
	})

	token := setupBearerSession(t, mgr, "disabled-cli-id", "tenant-a")

	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"a session bound to a disabled account must return 401")
	assert.Contains(t, rec.Body.String(), "SESSION_REVOKED",
		"disabled account must produce SESSION_REVOKED — indistinguishable from a revoked session")
}

// TestBearerSession_NoAccountFound_PreservesImplicitAdmin verifies that a session
// whose PrincipalID matches no account (e.g. a certificate-derived CLI session)
// sets ImplicitAdmin: true and TenantID from the session (ADR-025 Amendment 3).
func TestBearerSession_NoAccountFound_PreservesImplicitAdmin(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)

	srv := setupTestServer(t)
	srv.SetSessionManager(mgr)

	// No account cached — simulates a session issued from an mTLS admin cert path.
	token := setupBearerSession(t, mgr, "cert-admin-no-account", "")

	var capturedPrincipal *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "session with no matching account must still succeed")
	require.NotNil(t, capturedPrincipal)
	assert.True(t, capturedPrincipal.ImplicitAdmin,
		"no-account-found fallback must set ImplicitAdmin: true (ADR-025 Amendment 3)")
	assert.NotNil(t, capturedPrincipal.Permissions,
		"Permissions must not be nil — the nil-sentinel is replaced by ImplicitAdmin")
	assert.Empty(t, capturedPrincipal.TenantID,
		"no-account-found fallback must use the session's TenantID (empty for an unscoped session)")
}

// TestBearerSession_BoundRootScopeAccount_IsImplicitAdmin verifies that a session
// bound to a root-scope account resolves to ImplicitAdmin: true (ADR-025 Amendment 3),
// mirroring the web-cookie branch's root-scope rule.
func TestBearerSession_BoundRootScopeAccount_IsImplicitAdmin(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)

	srv := setupTestServer(t)
	srv.SetSessionManager(mgr)

	srv.cacheAccount(&account{
		ID:        "root-cli-admin-id",
		Username:  "root-cli-admin",
		TenantID:  "",
		RootScope: true,
	})

	token := setupBearerSession(t, mgr, "root-cli-admin-id", "")

	var capturedPrincipal *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedPrincipal)
	assert.True(t, capturedPrincipal.ImplicitAdmin,
		"a root-scope bound account must set ImplicitAdmin: true (ADR-025 Amendment 3)")
	assert.NotNil(t, capturedPrincipal.Permissions,
		"Permissions must not be nil — the nil-sentinel is replaced by ImplicitAdmin")
	assert.True(t, capturedPrincipal.GlobalScope,
		"a root-scope bound account must set GlobalScope=true")
}

// TestBearerSession_AccountLookupError_FailsClosed is the [REQUIRED TEST] for the
// fail-closed account-resolution property of the Bearer branch (Issue #3576 security
// review). getAccountByID returns a real error when the durable store is unhealthy
// (secret-store/SOPS failure, git storage error, ListSecrets failure, context deadline).
// Treating that error as "no account found" would set ImplicitAdmin: true — the
// implicit-admin gate hasPermission honours — skip the Issue #3126 disabled check,
// and restore session-derived tenant scope over the account's. The request must be
// rejected instead, and the downstream handler must never run.
func TestBearerSession_AccountLookupError_FailsClosed(t *testing.T) {
	capLog := &captureAllLogger{}
	srv := setupTestServerWithLogger(t, capLog)

	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, time.Now)
	srv.SetSessionManager(mgr)

	// Persist a real, tenant-scoped account holding a single grant, so the lookup
	// exercised below is the same one the middleware performs in production.
	const username = "failclosed-bearer-operator"
	rec := postAccount(t, srv, testAdminPrincipal(), AccountRequest{
		Username:    username,
		TenantID:    "tenant-a",
		Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "body: %s", rec.Body.String())

	acct := cachedAccount(srv, username)
	require.NotNil(t, acct, "account must be cached so the by-ID lookup hits the store re-verify")
	require.NotEmpty(t, acct.ID)

	token := setupBearerSession(t, mgr, acct.ID, acct.TenantID)

	// Break the durable store the account lookup depends on.
	listErr := errors.New("injected ListSecrets failure")
	srv.secretStore = &errListSecretStore{SecretStore: srv.secretStore, listErr: listErr}

	t.Run("authentication rejects the request", func(t *testing.T) {
		handlerRan := false
		handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerRan = true
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)

		assert.False(t, handlerRan,
			"the protected handler must not run when the bound account could not be resolved")
		assert.Equal(t, http.StatusServiceUnavailable, resp.Code,
			"an account-lookup failure must fail closed, not fall through to session-derived defaults")
		assert.Contains(t, resp.Body.String(), "SERVICE_UNAVAILABLE",
			"fail-closed rejection must carry the SERVICE_UNAVAILABLE code")
		assert.NotContains(t, resp.Body.String(), "injected ListSecrets failure",
			"the internal store error must not be disclosed in the response body")

		logged := capLog.captured()
		assert.Contains(t, logged, "Account lookup failed for session token",
			"the discarded error must now be logged")
		assert.Contains(t, logged, "injected ListSecrets failure",
			"the sanitized underlying error must appear in the log for operators")
	})

	t.Run("no implicit-admin escalation", func(t *testing.T) {
		// steward:write-config is not in the account's grants. Before the fix the
		// lookup error would set ImplicitAdmin: true (via the no-account-found path),
		// so this request was ALLOWED (200).
		handler := srv.authenticationMiddleware(
			srv.requirePermission("steward", "write-config")(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			),
		)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/test/config", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)

		assert.NotEqual(t, http.StatusOK, resp.Code,
			"a store failure must never promote a tenant-scoped operator to implicit admin")
		assert.Equal(t, http.StatusServiceUnavailable, resp.Code,
			"the request must be rejected at authentication with 503")
	})
}

// failingResponseWriter is a real http.ResponseWriter whose body writes always fail,
// reproducing a client that disconnects after the status line (the condition that makes
// json.Encoder.Encode return an error). It implements the stdlib interface directly —
// no mocking framework and no CFGMS component is stubbed.
type failingResponseWriter struct {
	header   http.Header
	status   int
	writeErr error
}

func newFailingResponseWriter(err error) *failingResponseWriter {
	return &failingResponseWriter{header: make(http.Header), writeErr: err}
}

func (w *failingResponseWriter) Header() http.Header       { return w.header }
func (w *failingResponseWriter) WriteHeader(code int)      { w.status = code }
func (w *failingResponseWriter) Write([]byte) (int, error) { return 0, w.writeErr }

// TestResponseEncodeFailuresAreLogged is the [REQUIRED TEST] that no response path in
// middleware.go silently discards a JSON encoding failure. Every security-rejection
// writer (writeErrorResponse, writeAuthorizationError, the step-up and presence-token
// branches of requirePermission) previously used `_ = json.NewEncoder(w).Encode(...)`,
// so a truncated rejection response left no trace at all. They now share
// encodeJSONBody with the success path, which logs at Error level.
func TestResponseEncodeFailuresAreLogged(t *testing.T) {
	writeErr := errors.New("client disconnected mid-response")

	t.Run("writeErrorResponse", func(t *testing.T) {
		capLog := &captureAllLogger{}
		srv := setupTestServerWithLogger(t, capLog)

		w := newFailingResponseWriter(writeErr)
		srv.writeErrorResponse(w, http.StatusUnauthorized, "Session has been revoked", "SESSION_REVOKED")

		assert.Equal(t, http.StatusUnauthorized, w.status, "status must still be written")
		assert.Contains(t, capLog.captured(), "Failed to encode response",
			"an encoding failure on a rejection response must be logged, not discarded")
		assert.Contains(t, capLog.captured(), "body_kind error",
			"the log must identify which response shape failed to encode")
	})

	t.Run("writeAuthorizationError", func(t *testing.T) {
		capLog := &captureAllLogger{}
		srv := setupTestServerWithLogger(t, capLog)

		w := newFailingResponseWriter(writeErr)
		srv.writeAuthorizationError(w, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS",
			&AuthorizationDecision{Granted: false, PermissionID: "steward:write-config"})

		assert.Equal(t, http.StatusForbidden, w.status, "status must still be written")
		assert.Contains(t, capLog.captured(), "Failed to encode response",
			"an encoding failure on an authorization denial must be logged, not discarded")
		assert.Contains(t, capLog.captured(), "body_kind authorization_error",
			"the log must identify which response shape failed to encode")
	})

	t.Run("requirePermission step-up challenge", func(t *testing.T) {
		capLog := &captureAllLogger{}
		srv := setupTestServerWithLogger(t, capLog)

		cfg := session.DefaultConfig()
		store := session.NewMemStore(cfg, time.Now)
		t.Cleanup(store.Close)
		mgr := session.NewManager(cfg, store, time.Now)
		srv.SetSessionManager(mgr)

		// steward:decommission requires AssuranceStrong; a CLI session is AssuranceBasic,
		// so requirePermission answers with the step-up challenge body.
		token := setupBearerSession(t, mgr, "stepup-encode-admin", "")
		handler := srv.authenticationMiddleware(
			srv.requirePermission("steward", "decommission")(
				http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
			),
		)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/stewards/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := newFailingResponseWriter(writeErr)
		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnauthorized, w.status,
			"an AssuranceBasic session must receive the step-up challenge")
		assert.Contains(t, capLog.captured(), "Failed to encode response",
			"an encoding failure on the step-up challenge must be logged, not discarded")
		assert.Contains(t, capLog.captured(), "body_kind step_up_required",
			"the log must identify the step-up challenge as the failed response shape")
	})
}

// makeAdminCertWithAttrs creates an admin-marked cert with specific serial, CN, and
// optionally the root-scope marker. Used by the extractAdminPrincipal cross-product tests.
func makeAdminCertWithAttrs(t *testing.T, serial int64, cn string, withRootScopeMarker bool) *x509.Certificate {
	t.Helper()
	key := sharedTestRSAKey()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cert.SetAdminMarker(template)
	if withRootScopeMarker {
		cert.SetRootScopeMarker(template)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return parsed
}

// TestExtractAdminPrincipal_BoundAccount_CrossProduct is the [REQUIRED TEST] covering the
// cross-product of {account.RootScope true/false} × {cert has root-scope marker true/false}
// for a bound (non-disabled) account. Asserts that GlobalScope, RootScoped, TenantID, and
// Permissions match the resolution rule in ADR-025 Amendment 3.
func TestExtractAdminPrincipal_BoundAccount_CrossProduct(t *testing.T) {
	type tc struct {
		name               string
		accountRootScope   bool
		accountTenantID    string
		accountPerms       []string
		certHasRootMarker  bool
		wantGlobalScope    bool
		wantRootScoped     bool
		wantTenantID       string
		wantPermissionsNil bool
		wantImplicitAdmin  bool
	}
	cases := []tc{
		{
			// Certificate carries root-scope marker but account is tenant-scoped.
			// ADR-025 A2.1/A2.2: RootScoped derives from cert, not account.
			// The marker is inert — TenantID non-empty means authorizeTenantAccess
			// uses the account's scope, not the marker.
			name:               "cert-with-root-marker bound to tenant-scoped account",
			accountRootScope:   false,
			accountTenantID:    "msp-a",
			accountPerms:       []string{"steward:read"},
			certHasRootMarker:  true,
			wantGlobalScope:    false,
			wantRootScoped:     true, // from cert, not account
			wantTenantID:       "msp-a",
			wantPermissionsNil: false,
			wantImplicitAdmin:  false,
		},
		{
			// Certificate without root-scope marker, bound to a root-scope account.
			// RootScoped must NOT be back-derived from account.RootScope (ADR-025 A2.2).
			name:               "cert-without-root-marker bound to root-scope account",
			accountRootScope:   true,
			accountTenantID:    "",
			accountPerms:       nil,
			certHasRootMarker:  false,
			wantGlobalScope:    true,  // from account.RootScope
			wantRootScoped:     false, // from cert (no marker)
			wantTenantID:       "",
			wantPermissionsNil: true, // nil for root-scope accounts (ImplicitAdmin gate)
			wantImplicitAdmin:  true,
		},
		{
			// Both root-scope marker and root-scope account.
			name:               "cert-with-root-marker bound to root-scope account",
			accountRootScope:   true,
			accountTenantID:    "",
			accountPerms:       nil,
			certHasRootMarker:  true,
			wantGlobalScope:    true,
			wantRootScoped:     true,
			wantTenantID:       "",
			wantPermissionsNil: true,
			wantImplicitAdmin:  true,
		},
		{
			// Neither marker: tenant-scoped account, no root-scope marker.
			name:               "cert-without-root-marker bound to tenant-scoped account",
			accountRootScope:   false,
			accountTenantID:    "msp-b",
			accountPerms:       []string{"steward:list", "steward:read"},
			certHasRootMarker:  false,
			wantGlobalScope:    false,
			wantRootScoped:     false,
			wantTenantID:       "msp-b",
			wantPermissionsNil: false,
			wantImplicitAdmin:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := setupTestServer(t)

			const serialNum = 9991
			peerCert := makeAdminCertWithAttrs(t, serialNum, "shared-cn", tc.certHasRootMarker)
			serial := peerCert.SerialNumber.String()

			acct := &account{
				ID:           "acct-" + tc.name,
				Username:     "test-operator",
				TenantID:     tc.accountTenantID,
				RootScope:    tc.accountRootScope,
				Permissions:  tc.accountPerms,
				CertBindings: []CertBinding{{Serial: serial}},
			}
			srv.cacheAccount(acct)

			req := requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert)
			p := srv.extractAdminPrincipal(req)

			require.NotNil(t, p, "bound, active account must yield a non-nil principal")
			assert.Equal(t, acct.ID, p.ID,
				"Principal.ID must be the account ID, never the certificate CN")
			assert.Equal(t, "mtls-admin:"+acct.Username, p.Name)
			assert.Equal(t, tc.wantGlobalScope, p.GlobalScope)
			assert.Equal(t, tc.wantRootScoped, p.RootScoped,
				"RootScoped derives from cert.HasRootScopeMarker alone, never from account.RootScope")
			assert.Equal(t, tc.wantTenantID, p.TenantID)
			assert.Equal(t, tc.wantImplicitAdmin, p.ImplicitAdmin)
			if tc.wantPermissionsNil {
				assert.Nil(t, p.Permissions,
					"root-scope account must have nil Permissions (ImplicitAdmin is the gate)")
			} else {
				require.NotNil(t, p.Permissions)
				assert.Equal(t, tc.accountPerms, p.Permissions)
			}
		})
	}
}

// TestExtractAdminPrincipal_Unbound_Bootstrap verifies that a cert with no bound account
// follows the bootstrap fallback path: GlobalScope=true, TenantID="", ImplicitAdmin=true,
// and Principal.ID equals the certificate CommonName (ADR-025 Amendment 3).
func TestExtractAdminPrincipal_Unbound_Bootstrap(t *testing.T) {
	srv := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t) // serial 1234, no bound account

	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", adminCert)
	p := srv.extractAdminPrincipal(req)

	require.NotNil(t, p)
	assert.Equal(t, "test-admin", p.ID, "bootstrap fallback: ID must be the cert CN")
	assert.True(t, p.GlobalScope)
	assert.Equal(t, "", p.TenantID)
	assert.True(t, p.ImplicitAdmin)
}

// TestExtractAdminPrincipal_DisabledAccount_RejectsWithNil verifies that a cert bound to
// a disabled account returns nil — not the bootstrap fallback (ADR-025 Amendment 3).
func TestExtractAdminPrincipal_DisabledAccount_RejectsWithNil(t *testing.T) {
	srv := setupTestServer(t)

	const serialNum = 9992
	peerCert := makeAdminCertWithAttrs(t, serialNum, "disabled-admin", false)
	serial := peerCert.SerialNumber.String()

	srv.cacheAccount(&account{
		ID:           "acct-disabled",
		Username:     "disabled-operator",
		TenantID:     "msp-a",
		Disabled:     true,
		CertBindings: []CertBinding{{Serial: serial}},
	})

	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert)
	p := srv.extractAdminPrincipal(req)

	assert.Nil(t, p,
		"a cert bound to a disabled account must be rejected; must not fall through to bootstrap")
}

// TestExtractAdminPrincipal_AccountLookupError_FailsClosed verifies that a store error
// during getAccountByCertSerial causes extractAdminPrincipal to return nil, not fall
// through to the bootstrap fallback (ADR-025 Amendment 3 fail-closed requirement).
func TestExtractAdminPrincipal_AccountLookupError_FailsClosed(t *testing.T) {
	capLog := &auditCapturingLogger{}
	srv := setupTestServerWithLogger(t, capLog)

	const serialNum = 9993
	peerCert := makeAdminCertWithAttrs(t, serialNum, "error-admin", false)
	serial := peerCert.SerialNumber.String()

	// Inject an account with the serial into the cache. The cache hit will trigger
	// loadAccountFromStore for re-verification, which will fail with the injected error.
	srv.cacheAccount(&account{
		ID:           "acct-error",
		Username:     "error-operator",
		TenantID:     "msp-a",
		CertBindings: []CertBinding{{Serial: serial}},
	})

	// Break the durable store so the re-verification fails.
	injected := errors.New("injected store failure")
	srv.secretStore = &errListSecretStore{SecretStore: srv.secretStore, listErr: injected}

	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert)
	p := srv.extractAdminPrincipal(req)

	assert.Nil(t, p,
		"account lookup error must fail closed — must not fall through to bootstrap fallback")

	// Verify the error was logged and the bootstrap audit was NOT emitted.
	out := capLog.formattedOutput()
	assert.Contains(t, out, "Cert serial account lookup failed",
		"store error must be logged")
	assert.NotContains(t, out, "admin.bootstrap_fallback_used",
		"bootstrap audit must NOT fire when lookup fails (fail closed)")
}

// TestExtractAdminPrincipal_BootstrapFallback_EmitsAudit verifies that an unbound
// admin cert emits the admin.bootstrap_fallback_used audit event with the required
// auth_path field (ADR-025 Amendment 3 audit requirement).
func TestExtractAdminPrincipal_BootstrapFallback_EmitsAudit(t *testing.T) {
	capLog := &auditCapturingLogger{}
	srv := setupTestServerWithLogger(t, capLog)

	// Unbound cert (no account in cache with matching serial).
	adminCert := makeSelfSignedAdminCert(t)

	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", adminCert)
	p := srv.extractAdminPrincipal(req)

	require.NotNil(t, p, "unbound cert must succeed via bootstrap fallback")

	out := capLog.formattedOutput()
	assert.Contains(t, out, "admin.bootstrap_fallback_used",
		"bootstrap fallback must emit the admin.bootstrap_fallback_used audit event")
	assert.Contains(t, out, "bootstrap-fallback",
		"audit event must include auth_path=bootstrap-fallback")
}

// TestExtractAdminPrincipal_BootstrapFallback_AnomalousWhenAccountsExist verifies that
// when accounts exist in the cache, the bootstrap audit event includes accounts_in_cache > 0,
// making the anomalous combination separately detectable in monitoring (ADR-025 Amendment 3).
func TestExtractAdminPrincipal_BootstrapFallback_AnomalousWhenAccountsExist(t *testing.T) {
	capLog := &auditCapturingLogger{}
	srv := setupTestServerWithLogger(t, capLog)

	// Inject an account with a DIFFERENT serial so the presented cert is unbound.
	srv.cacheAccount(&account{
		ID:           "existing-acct",
		Username:     "existing-operator",
		TenantID:     "msp-a",
		CertBindings: []CertBinding{{Serial: "99999"}}, // different serial
	})

	// Present a cert with serial 1234 (makeSelfSignedAdminCert's serial) — no binding.
	adminCert := makeSelfSignedAdminCert(t)
	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", adminCert)
	p := srv.extractAdminPrincipal(req)

	require.NotNil(t, p, "bootstrap fallback still applies")
	assert.True(t, p.ImplicitAdmin)

	// The audit log must include accounts_in_cache=1 so the anomaly is detectable.
	assert.Equal(t, 1, capLog.kvValue("accounts_in_cache"),
		"accounts_in_cache must be >0 when accounts exist, enabling anomaly detection")
}

// TestExtractAdminPrincipal_CNReuse_ResolvesToDistinctAccountIDs is the [REQUIRED TEST]
// for the CN-reuse case: two accounts, each bound to a separately-issued certificate that
// happens to share the same Subject.CommonName, must resolve to their own distinct
// Principal.ID (the respective account ID). Reusing a CN across two cert bundles must
// never cause one account's identity or permissions to apply to the other.
func TestExtractAdminPrincipal_CNReuse_ResolvesToDistinctAccountIDs(t *testing.T) {
	srv := setupTestServer(t)

	const sharedCN = "shared-cn-admin"

	// Two certs with the same CN but different serials.
	cert1 := makeAdminCertWithAttrs(t, 11001, sharedCN, false)
	cert2 := makeAdminCertWithAttrs(t, 11002, sharedCN, false)
	serial1 := cert1.SerialNumber.String()
	serial2 := cert2.SerialNumber.String()

	acct1 := &account{
		ID:           "account-id-1",
		Username:     "operator-one",
		TenantID:     "msp-a",
		Permissions:  []string{"steward:read"},
		CertBindings: []CertBinding{{Serial: serial1}},
	}
	acct2 := &account{
		ID:           "account-id-2",
		Username:     "operator-two",
		TenantID:     "msp-b",
		Permissions:  []string{"steward:list"},
		CertBindings: []CertBinding{{Serial: serial2}},
	}
	srv.cacheAccount(acct1)
	srv.cacheAccount(acct2)

	req1 := requestWithTLSCert(http.MethodGet, "/api/v1/test", cert1)
	p1 := srv.extractAdminPrincipal(req1)
	require.NotNil(t, p1)
	assert.Equal(t, "account-id-1", p1.ID,
		"cert1 must resolve to acct1's ID regardless of shared CN")
	assert.Equal(t, "msp-a", p1.TenantID)

	req2 := requestWithTLSCert(http.MethodGet, "/api/v1/test", cert2)
	p2 := srv.extractAdminPrincipal(req2)
	require.NotNil(t, p2)
	assert.Equal(t, "account-id-2", p2.ID,
		"cert2 must resolve to acct2's ID regardless of shared CN")
	assert.Equal(t, "msp-b", p2.TenantID)

	assert.NotEqual(t, p1.ID, p2.ID,
		"two certs with the same CN but different serials must never share the same Principal.ID")
}

// TestIsWithinTenantScope verifies the helper introduced by Issue #3147.
func TestIsWithinTenantScope(t *testing.T) {
	tests := []struct {
		callerTenant   string
		resourceTenant string
		want           bool
		desc           string
	}{
		{"", "any-tenant", true, "unscoped admin (empty caller) always allowed"},
		{"", "", true, "unscoped admin with empty resource tenant"},
		{"msp-a", "msp-a", true, "same-tenant match"},
		{"msp-a", "msp-a/client-1", true, "direct descendant allowed"},
		{"msp-a", "msp-a/client-1/server", true, "deep descendant allowed"},
		{"msp-a", "msp-b", false, "sibling tenant denied"},
		{"msp-a", "msp-alpha", false, "sibling with shared prefix denied (no slash separator)"},
		{"msp-a", "root/msp-a", false, "ancestor not in subtree denied"},
		{"root/msp-a", "root/msp-a", true, "hierarchical path same-tenant"},
		{"root/msp-a", "root/msp-a/client-1", true, "hierarchical path descendant"},
		{"root/msp-a", "root/msp-alpha", false, "hierarchical sibling-prefix denied"},
		{"root/msp-a", "root/msp-b", false, "hierarchical sibling denied"},
		{"client-1", "client-2", false, "flat sibling denied (required AC)"},
		{"client-1", "client-10", false, "flat sibling-prefix denied"},
		{"client-1", "client-1", true, "flat same-tenant"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := isWithinTenantScope(tc.callerTenant, tc.resourceTenant)
			assert.Equal(t, tc.want, got,
				"isWithinTenantScope(%q, %q)", tc.callerTenant, tc.resourceTenant)
		})
	}
}

// TestExtractAdminPrincipal_DeprovisioningCannotWidenBoundCert verifies that deleting the
// account a certificate is bound to cannot move that still-valid certificate back onto the
// unscoped-root bootstrap fallback.
//
// The offboarding cascade (Issue #3581) prevents the privilege escalation by disabling the
// account as its very first step. Even when certificate revocation cannot be completed (e.g.
// the serial is not registered in certManager's store), the account-disabled check fires
// before the bootstrap fallback in extractAdminPrincipal, so the certificate cannot resolve
// to GlobalScope=true. The cascade returns 500 (cert revoke failed) in that scenario, leaving
// the account disabled-but-not-deleted — still fail-closed.
func TestExtractAdminPrincipal_DeprovisioningCannotWidenBoundCert(t *testing.T) {
	server, _ := setupCertBindingServer(t)

	rec := postAccount(t, server, strongPrincipal(), AccountRequest{
		Username:    "tenant-operator",
		TenantID:    "msp-a",
		Permissions: []string{"account:delete"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "create account: %s", rec.Body.String())

	// Use a self-signed cert (serial 9995) that is NOT in certManager's store.
	// The cascade will attempt to revoke it, fail, and return 500 — leaving the
	// account disabled (but not deleted) as the fail-closed terminal state.
	peerCert := makeAdminCertWithAttrs(t, 9995, "tenant-operator", false)
	serial := peerCert.SerialNumber.String()

	bindRec := bindCertReq(t, server, strongPrincipal(), "tenant-operator", BindCertRequest{
		Serial: serial,
		Label:  "operator laptop",
	})
	require.Equal(t, http.StatusCreated, bindRec.Code, "bind: %s", bindRec.Body.String())

	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert)
	before := server.extractAdminPrincipal(req)
	require.NotNil(t, before)
	require.Equal(t, "msp-a", before.TenantID, "bound cert must resolve to the account's tenant")
	require.False(t, before.GlobalScope)
	require.False(t, before.ImplicitAdmin)

	// Delete returns 500 (cert revoke fails — serial not in certManager store).
	// Account is disabled (step 1 of the cascade always runs) but not deleted.
	delRec := deleteAccount(t, server, strongPrincipal(), "tenant-operator")
	require.Equal(t, http.StatusInternalServerError, delRec.Code,
		"cascade fails when cert revocation fails (cert not in certMgr store): %s", delRec.Body.String())
	assert.Contains(t, delRec.Body.String(), "CERT_REVOKE_FAILED")

	// The certificate must NOT widen to unscoped root. The account is disabled,
	// so extractAdminPrincipal returns nil — the disabled-account check fires before
	// the bootstrap fallback, preventing the escalation.
	after := server.extractAdminPrincipal(
		requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert))
	assert.Nil(t, after,
		"cert must not resolve: account is disabled (step 1 completed even though revocation failed)")
}

// TestExtractAdminPrincipal_AccountResetCannotWidenBoundCert verifies that the
// POST /api/v1/accounts reset (upsert) path cannot move a still-valid bound certificate
// back onto the unscoped-root bootstrap fallback.
//
// handleCreateAccount builds a fresh account record on every request and carries selected
// fields forward from the existing one. persistAccount rebuilds the metadata from the record
// it is handed and writes cert_bindings only when the slice is non-empty, and cacheAccount
// replaces the in-memory copy that getAccountByCertSerial scans — so an upsert that did not
// carry CertBindings forward would silently unbind every certificate on the account. A
// tenant-scoped admin holding account:create could then POST their own username and have
// their own unrevoked certificate resolve as GlobalScope=true / TenantID="" /
// ImplicitAdmin=true on the very next request.
func TestExtractAdminPrincipal_AccountResetCannotWidenBoundCert(t *testing.T) {
	server, _ := setupCertBindingServer(t)

	rec := postAccount(t, server, strongPrincipal(), AccountRequest{
		Username:    "tenant-operator",
		TenantID:    "msp-a",
		Permissions: []string{"account:create"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, "create account: %s", rec.Body.String())

	peerCert := makeAdminCertWithAttrs(t, 9994, "tenant-operator", false)
	serial := peerCert.SerialNumber.String()

	bindRec := bindCertReq(t, server, strongPrincipal(), "tenant-operator", BindCertRequest{
		Serial: serial,
		Label:  "operator laptop",
	})
	require.Equal(t, http.StatusCreated, bindRec.Code, "bind: %s", bindRec.Body.String())

	before := server.extractAdminPrincipal(
		requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert))
	require.NotNil(t, before)
	require.Equal(t, "msp-a", before.TenantID, "bound cert must resolve to the account's tenant")
	require.False(t, before.GlobalScope)
	require.False(t, before.ImplicitAdmin)

	// The escalation attempt: the tenant admin resets their own account, inside their own
	// subtree, with the grants they legitimately hold. The reset itself is allowed.
	resetReq := httptest.NewRequest(http.MethodPost, "/api/v1/accounts",
		bytes.NewReader([]byte(`{"username":"tenant-operator","tenant_id":"msp-a"}`)))
	resetReq = withPrincipal(resetReq, &Principal{
		ID:          before.ID,
		Name:        before.Name,
		Assurance:   session.AssuranceStrong,
		TenantID:    "msp-a",
		Permissions: []string{"account:create"},
	})
	resetReq = resetReq.WithContext(context.WithValue(resetReq.Context(), ctxkeys.TenantID, "msp-a"))
	resetRec := httptest.NewRecorder()
	server.handleCreateAccount(resetRec, resetReq)
	require.Equal(t, http.StatusOK, resetRec.Code, "reset: %s", resetRec.Body.String())

	after := server.extractAdminPrincipal(
		requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert))
	require.NotNil(t, after, "the binding must survive an account reset")
	assert.Equal(t, "msp-a", after.TenantID,
		"the certificate must still be tenant-scoped after a reset")
	assert.False(t, after.GlobalScope,
		"a reset must not widen the certificate to unscoped root")
	assert.False(t, after.ImplicitAdmin,
		"a reset must not put the certificate back on the bootstrap fallback")

	// The carry-forward must reach the durable record, not just the cache: a controller
	// restart after the reset must reload the binding.
	dropAccountCache(server)
	afterReload := server.extractAdminPrincipal(
		requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert))
	require.NotNil(t, afterReload)
	assert.Equal(t, "msp-a", afterReload.TenantID,
		"the binding must be persisted by the reset, not only cached")
	assert.False(t, afterReload.GlobalScope)
	assert.False(t, afterReload.ImplicitAdmin)
}

// --- Issue #3715: cert-binding last-used recording tests ---

// countingStoreSecretStore wraps a real SecretStore and counts StoreSecret (write) calls.
// Used to assert write-coalescing and zero-writes-on-rejection by counting, not by timing.
type countingStoreSecretStore struct {
	secretsif.SecretStore
	mu     sync.Mutex
	stores int
}

func (c *countingStoreSecretStore) StoreSecret(ctx context.Context, req *secretsif.SecretRequest) error {
	c.mu.Lock()
	c.stores++
	c.mu.Unlock()
	return c.SecretStore.StoreSecret(ctx, req)
}

func (c *countingStoreSecretStore) storeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stores
}

// TestRecordCertBindingUse_CoalescesRepeatedAuth is the [REQUIRED TEST] verifying that
// repeated authenticated requests against the same certificate serial, inside the
// coalescing window, produce at most one durable store write. Asserted by counting
// StoreSecret calls, not by timing: recordCertBindingUse updates its in-memory throttle
// synchronously before ever spawning a goroutine, so the 5 follow-up calls below are
// guaranteed not to schedule a second write — nothing here depends on goroutine scheduling.
func TestRecordCertBindingUse_CoalescesRepeatedAuth(t *testing.T) {
	srv := setupTestServer(t)

	const serialNum = 87001
	peerCert := makeAdminCertWithAttrs(t, serialNum, "coalesce-admin", false)
	serial := peerCert.SerialNumber.String()

	srv.cacheAccount(&account{
		ID:           "acct-coalesce",
		Username:     "coalesce-operator",
		TenantID:     "msp-a",
		Permissions:  []string{"steward:read"},
		CertBindings: []CertBinding{{Serial: serial}},
	})

	counting := &countingStoreSecretStore{SecretStore: srv.secretStore}
	srv.secretStore = counting

	persisted := make(chan error, 1)
	srv.onCertBindingLastUsedPersisted = func(_, _ string, err error) {
		persisted <- err
	}

	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert)

	require.NotNil(t, srv.extractAdminPrincipal(req), "first authenticated request")

	// 5 more authenticated requests for the same serial, still inside the coalescing
	// window. recordCertBindingUse's throttle check-and-set runs synchronously in the
	// caller's goroutine (this one), so by the time extractAdminPrincipal returns from
	// each of these calls, no second write has been scheduled.
	for i := 0; i < 5; i++ {
		require.NotNil(t, srv.extractAdminPrincipal(req), "repeated request #%d", i)
	}

	require.NoError(t, <-persisted, "the single async write from the first request")

	assert.Equal(t, 1, counting.storeCount(),
		"repeated requests inside the coalescing window must produce at most one store write")
}

// TestRecordCertBindingUse_RejectedOrUnboundAuthProducesZeroWrites is the [REQUIRED TEST]
// verifying that authentication paths which do not resolve to a bound, active-account
// principal — a revoked serial, an unbound serial (bootstrap fallback), and a disabled
// account — never trigger a durable store write. Asserted by counting StoreSecret calls.
func TestRecordCertBindingUse_RejectedOrUnboundAuthProducesZeroWrites(t *testing.T) {
	// assertZeroWrites gives any (incorrectly) spawned last-used-recording goroutine a
	// brief window to run, then asserts — by count, not by the wait itself — that it
	// produced no write. The wait only guards against a regression that schedules the
	// write asynchronously after extractAdminPrincipal has already returned.
	assertZeroWrites := func(t *testing.T, counting *countingStoreSecretStore) {
		t.Helper()
		time.Sleep(150 * time.Millisecond)
		assert.Equal(t, 0, counting.storeCount())
	}

	t.Run("revoked serial", func(t *testing.T) {
		tempDir := t.TempDir()
		certManager, err := cert.NewManager(&cert.ManagerConfig{
			StoragePath: tempDir,
			CAConfig: &cert.CAConfig{
				Organization: "Test",
				Country:      "US",
				ValidityDays: 365,
			},
		})
		require.NoError(t, err)
		srv := setupTestServerWithCertMgr(t, certManager)

		req, serial := issueCertAndBuildRequest(t, http.MethodGet, "/api/v1/test", certManager)
		require.NoError(t, certManager.Revoke(serial))

		counting := &countingStoreSecretStore{SecretStore: srv.secretStore}
		srv.secretStore = counting

		p := srv.extractAdminPrincipal(req)
		assert.Nil(t, p, "revoked cert must be rejected")
		assertZeroWrites(t, counting)
	})

	t.Run("unbound serial (bootstrap fallback)", func(t *testing.T) {
		srv := setupTestServer(t)
		adminCert := makeSelfSignedAdminCert(t)
		req := requestWithTLSCert(http.MethodGet, "/api/v1/test", adminCert)

		counting := &countingStoreSecretStore{SecretStore: srv.secretStore}
		srv.secretStore = counting

		p := srv.extractAdminPrincipal(req)
		require.NotNil(t, p, "an unbound cert is accepted via the bootstrap fallback")
		assertZeroWrites(t, counting)
	})

	t.Run("disabled account", func(t *testing.T) {
		srv := setupTestServer(t)

		const serialNum = 87002
		peerCert := makeAdminCertWithAttrs(t, serialNum, "disabled-coalesce-admin", false)
		serial := peerCert.SerialNumber.String()

		srv.cacheAccount(&account{
			ID:           "acct-disabled-coalesce",
			Username:     "disabled-coalesce-operator",
			TenantID:     "msp-a",
			Disabled:     true,
			CertBindings: []CertBinding{{Serial: serial}},
		})

		counting := &countingStoreSecretStore{SecretStore: srv.secretStore}
		srv.secretStore = counting

		req := requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert)
		p := srv.extractAdminPrincipal(req)
		assert.Nil(t, p, "a cert bound to a disabled account must be rejected")
		assertZeroWrites(t, counting)
	})
}

// TestRecordCertBindingUse_StoreFailureDoesNotFailAuth is the [REQUIRED TEST] verifying
// that a durable-store failure while recording certificate-binding use does not fail the
// authenticating request, and is logged (not silent) rather than swallowed.
func TestRecordCertBindingUse_StoreFailureDoesNotFailAuth(t *testing.T) {
	capLog := &auditCapturingLogger{}
	srv := setupTestServerWithLogger(t, capLog)

	const serialNum = 87003
	peerCert := makeAdminCertWithAttrs(t, serialNum, "store-fail-admin", false)
	serial := peerCert.SerialNumber.String()

	srv.cacheAccount(&account{
		ID:           "acct-store-fail",
		Username:     "store-fail-operator",
		TenantID:     "msp-a",
		Permissions:  []string{"steward:read"},
		CertBindings: []CertBinding{{Serial: serial}},
	})

	injected := errors.New("injected store failure")
	srv.secretStore = &errStoreSecretStore{SecretStore: srv.secretStore, storeErr: injected}

	persisted := make(chan error, 1)
	srv.onCertBindingLastUsedPersisted = func(_, _ string, err error) {
		persisted <- err
	}

	req := requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert)
	p := srv.extractAdminPrincipal(req)
	require.NotNil(t, p, "a store failure while recording use must not fail authentication")
	assert.Equal(t, "acct-store-fail", p.ID)
	assert.Equal(t, session.AssuranceStrong, p.Assurance)

	require.Error(t, <-persisted, "the injected failure must have reached the persist attempt")

	out := capLog.formattedOutput()
	assert.Contains(t, out, "Failed to persist certificate binding last-used timestamp",
		"a failed update must be logged, not silent")
}

// TestCertBindingLastUsed_MultiLevelTenantRoundTrip verifies that a last-used record
// written for a multi-level tenant ID (root/msp-a/client-1 — the documented CFGMS tenancy
// shape) is read back by the same tenant, and is not visible to the tenant that a
// first-slash key split would resolve to. Composing "tenant/key" for GetSecret resolved
// the read to TenantID "root" with the rest of the path folded into the name, so the read
// silently missed the written record: the listing reported "never used" for a certificate
// in daily use, and the merge below dropped the other serial's timestamp on each write.
func TestCertBindingLastUsed_MultiLevelTenantRoundTrip(t *testing.T) {
	srv := setupTestServer(t)
	ctx := context.Background()

	const tenantID = "root/msp-a/client-1"
	firstUse := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	secondUse := time.Now().UTC().Truncate(time.Second)

	require.NoError(t, srv.persistCertBindingLastUsed(ctx, "alice", tenantID, "serial-aaa", firstUse))

	uses, err := srv.loadCertBindingLastUsed(ctx, "alice", tenantID)
	require.NoError(t, err)
	require.Contains(t, uses, "serial-aaa", "record written for a multi-level tenant must be readable")
	assert.True(t, firstUse.Equal(uses["serial-aaa"]), "expected %s, got %s", firstUse, uses["serial-aaa"])

	// A second serial on the same account must merge, not clobber: the read side of the
	// read-merge-write has to resolve the record that the write side created.
	require.NoError(t, srv.persistCertBindingLastUsed(ctx, "alice", tenantID, "serial-bbb", secondUse))

	uses, err = srv.loadCertBindingLastUsed(ctx, "alice", tenantID)
	require.NoError(t, err)
	require.Len(t, uses, 2, "recording a second serial must preserve the first")
	assert.True(t, firstUse.Equal(uses["serial-aaa"]))
	assert.True(t, secondUse.Equal(uses["serial-bbb"]))

	// The record belongs to root/msp-a/client-1 only — the parent tenant a first-slash
	// split would land on must not resolve it.
	parentUses, err := srv.loadCertBindingLastUsed(ctx, "alice", "root")
	require.NoError(t, err)
	assert.Empty(t, parentUses, "another tenant must not resolve this account's record")
}

// TestCertBindingLastUsed_NoRecordReturnsEmpty verifies that an account which has never
// recorded a use reads back as empty without error (never-used, not an error condition).
func TestCertBindingLastUsed_NoRecordReturnsEmpty(t *testing.T) {
	srv := setupTestServer(t)

	uses, err := srv.loadCertBindingLastUsed(context.Background(), "never-authenticated", "root/msp-a")
	require.NoError(t, err)
	assert.Empty(t, uses)
}

// TestCertBindingLastUsedStoreKey_WindowsFilenameSafe guards against the regression
// diagnosed in the merge queue on 2026-08-28: certBindingLastUsedStoreKey used to
// separate its prefix from the username with ":", which is legal in a POSIX filename
// but illegal on Windows (NTFS reserves it as the alternate-data-stream separator).
// The flatfile-backed secret store writes this key straight to a filename, so every
// write of the record failed on Windows (rename ...cert-binding-last-used:alice.json:
// "The filename, directory name, or volume label syntax is incorrect") while passing
// on Linux — this test would have caught it without needing a Windows runner.
func TestCertBindingLastUsedStoreKey_WindowsFilenameSafe(t *testing.T) {
	const windowsReservedChars = `<>:"/\|?*`

	for _, username := range []string{"alice", "bob.smith", "svc-account"} {
		key := certBindingLastUsedStoreKey(username)
		for _, c := range windowsReservedChars {
			assert.False(t, strings.ContainsRune(key, c),
				"store key %q must not contain Windows-reserved filename character %q", key, c)
		}
	}
}

// ---- ADR-025 Amendment 4: session-derived root-scope marker ------------------------

// TestWebSessionCookie_PhishingResistantRootScopeAccount_CarriesMarker is the positive
// half of the [REQUIRED TEST] set for ADR-025 Amendment 4 A4.1: a web-cookie session
// established by a phishing-resistant assertion (AssuranceStrong, mirroring a passkey
// login which is issued at Strong directly per handlePasskeyLoginFinish) for an account
// whose RootScope flag is set must carry the explicit RootScoped marker. Before this
// story the web-session principal construction set no such marker at all.
func TestWebSessionCookie_PhishingResistantRootScopeAccount_CarriesMarker(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	srv.cacheAccount(&account{
		ID:        "web-root-op",
		Username:  "web-root-op",
		TenantID:  "",
		RootScope: true,
	})

	sess, _, err := mgr.Issue(context.Background(), "web-root-op", "web-login", "")
	require.NoError(t, err)
	// Elevate with an empty sourceIP: BoundIP stays "" so no source-IP-change downgrade
	// can fire against httptest's default RemoteAddr on the request below.
	_, elevatedTok, err := mgr.Elevate(context.Background(), sess.ID, []byte("cred-1"), "")
	require.NoError(t, err)

	var captured *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(&http.Cookie{Name: "cfgms_session", Value: elevatedTok})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, captured)
	require.Equal(t, session.AssuranceStrong, captured.Assurance, "precondition: session must be phishing-resistant")
	assert.True(t, captured.RootScoped,
		"a phishing-resistant web session for a root-scope account must carry the ADR-025 Amendment 4 A4.1 marker")
}

// TestBearerSession_PhishingResistantRootScopeAccount_CarriesMarker is the CLI-Bearer
// counterpart, pinning AC1's "on both the browser cookie path and the CLI bearer path."
func TestBearerSession_PhishingResistantRootScopeAccount_CarriesMarker(t *testing.T) {
	srv := setupTestServer(t)
	cliCfg := session.DefaultConfig()
	store := session.NewMemStore(cliCfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cliCfg, store, time.Now)
	srv.SetSessionManager(mgr)

	srv.cacheAccount(&account{
		ID:        "cli-root-op",
		Username:  "cli-root-op",
		TenantID:  "",
		RootScope: true,
	})

	sess, _, err := mgr.Issue(context.Background(), "cli-root-op", "cfg-cli", "")
	require.NoError(t, err)
	_, elevatedTok, err := mgr.Elevate(context.Background(), sess.ID, []byte("cred-1"), "")
	require.NoError(t, err)

	var captured *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+elevatedTok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, captured)
	require.Equal(t, session.AssuranceStrong, captured.Assurance, "precondition: session must be phishing-resistant")
	assert.True(t, captured.RootScoped,
		"a phishing-resistant cfg-CLI Bearer session for a root-scope account must carry the ADR-025 Amendment 4 A4.1 marker")
}

// TestWebSessionCookie_RootScopeAccount_BasicAssurance_NoMarker is the [REQUIRED TEST]
// for the acceptance criterion "a session whose assurance is below phishing-resistant
// does not carry the marker, even when the bound account's flag is set."
func TestWebSessionCookie_RootScopeAccount_BasicAssurance_NoMarker(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	srv.cacheAccount(&account{
		ID:        "web-root-op-basic",
		Username:  "web-root-op-basic",
		TenantID:  "",
		RootScope: true,
	})

	// Issue only — never elevated, so Assurance stays Basic.
	cookie := issueWebSession(t, mgr, "web-root-op-basic", "")

	var captured *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, captured)
	require.Equal(t, session.AssuranceBasic, captured.Assurance, "precondition: session must not be phishing-resistant")
	assert.False(t, captured.RootScoped,
		"a root-scope account's session must not carry the marker until its assurance is phishing-resistant")
	assert.True(t, captured.ImplicitAdmin,
		"permission breadth is unaffected: it is still granted from the account's RootScope flag alone")
}

// TestBearerSession_RootScopeAccount_BasicAssurance_NoMarker is the CLI-Bearer
// counterpart of the assurance-floor test above.
func TestBearerSession_RootScopeAccount_BasicAssurance_NoMarker(t *testing.T) {
	srv := setupTestServer(t)
	cliCfg := session.DefaultConfig()
	store := session.NewMemStore(cliCfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cliCfg, store, time.Now)
	srv.SetSessionManager(mgr)

	srv.cacheAccount(&account{
		ID:        "cli-root-op-basic",
		Username:  "cli-root-op-basic",
		TenantID:  "",
		RootScope: true,
	})

	_, tok, err := mgr.Issue(context.Background(), "cli-root-op-basic", "cfg-cli", "")
	require.NoError(t, err)

	var captured *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, captured)
	require.Equal(t, session.AssuranceBasic, captured.Assurance, "precondition: session must not be phishing-resistant")
	assert.False(t, captured.RootScoped,
		"a root-scope account's cfg-CLI Bearer session must not carry the marker until its assurance is phishing-resistant")
}

// TestWebSessionCookie_RootScopeMarker_RemovedOnAssuranceDowngrade pins A4.3: an
// assurance downgrade (ADR-021 Decision 5, source-IP change) removes the marker on the
// very next request rather than at session expiry.
func TestWebSessionCookie_RootScopeMarker_RemovedOnAssuranceDowngrade(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	srv.cacheAccount(&account{
		ID:        "web-root-op-downgrade",
		Username:  "web-root-op-downgrade",
		TenantID:  "",
		RootScope: true,
	})

	sess, _, err := mgr.Issue(context.Background(), "web-root-op-downgrade", "web-login", "")
	require.NoError(t, err)
	// Bind the elevation to an IP different from httptest's default RemoteAddr
	// (192.0.2.1) so the very next request is a source-IP-change downgrade.
	_, elevatedTok, err := mgr.Elevate(context.Background(), sess.ID, []byte("cred-1"), "10.0.0.9")
	require.NoError(t, err)

	var captured *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(&http.Cookie{Name: "cfgms_session", Value: elevatedTok})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, captured)
	require.Equal(t, session.AssuranceBasic, captured.Assurance,
		"precondition: the source-IP change must have downgraded this very request")
	assert.False(t, captured.RootScoped,
		"an assurance downgrade must remove the marker on the next request, not wait for session expiry")
}

// TestWebSessionCookie_RootScopeMarker_RemovedWhenAccountFlagCleared pins A4.3's other
// half: an administrative clearing of the account's RootScope flag removes the marker
// on the next request without waiting for session expiry.
func TestWebSessionCookie_RootScopeMarker_RemovedWhenAccountFlagCleared(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	srv.cacheAccount(&account{
		ID:        "web-root-op-cleared",
		Username:  "web-root-op-cleared",
		TenantID:  "",
		RootScope: true,
	})

	sess, _, err := mgr.Issue(context.Background(), "web-root-op-cleared", "web-login", "")
	require.NoError(t, err)
	_, elevatedTok, err := mgr.Elevate(context.Background(), sess.ID, []byte("cred-1"), "")
	require.NoError(t, err)
	cookie := &http.Cookie{Name: "cfgms_session", Value: elevatedTok}

	var captured *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req1.AddCookie(cookie)
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code, rec1.Body.String())
	require.NotNil(t, captured)
	require.True(t, captured.RootScoped, "precondition: the first request must carry the marker")

	// Administratively clear the account's RootScope flag — no session mutation at all.
	srv.cacheAccount(&account{
		ID:        "web-root-op-cleared",
		Username:  "web-root-op-cleared",
		TenantID:  "",
		RootScope: false,
	})

	captured = nil
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
	require.NotNil(t, captured)
	assert.False(t, captured.RootScoped,
		"clearing the account's RootScope flag must remove the marker on the very next request")
}

// TestWebSessionPhishingResistantRootScope_CannotGrantCertificateExtension is the
// [REQUIRED TEST]: a session-derived root scope (this story's new marker source) must
// never satisfy principalHasCertifiedRootScope, the sole gate on granting
// RootScopeMarkerOID to a new credential (ADR-025 Amendment 4 A4.4). Only a principal
// whose certificate authenticated the request — evidenced by a non-empty CertSerial —
// may do that; a session, however strongly asserted, never has CertSerial set.
func TestWebSessionPhishingResistantRootScope_CannotGrantCertificateExtension(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	srv.cacheAccount(&account{
		ID:        "web-root-op-cert-bound",
		Username:  "web-root-op-cert-bound",
		TenantID:  "",
		RootScope: true,
	})

	sess, _, err := mgr.Issue(context.Background(), "web-root-op-cert-bound", "web-login", "")
	require.NoError(t, err)
	_, elevatedTok, err := mgr.Elevate(context.Background(), sess.ID, []byte("cred-1"), "")
	require.NoError(t, err)

	var captured *Principal
	handler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credential-requests/x/approve", nil)
	req.AddCookie(&http.Cookie{Name: "cfgms_session", Value: elevatedTok})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, captured)
	require.True(t, captured.RootScoped, "sanity: this session must be genuinely root-scoped by Amendment 4")
	assert.Empty(t, captured.CertSerial)
	assert.False(t, principalHasCertifiedRootScope(captured),
		"a session-derived root scope, however phishing-resistant, must never satisfy the certified-root-scope gate")
}

// TestCertificateAuthPath_UnchangedByAmendment4 is the [REQUIRED TEST] pinning that
// this story's session-derived marker leaves the certificate authentication path
// byte-identical: a root-scope-marked certificate, an unmarked admin certificate, and a
// revoked certificate all behave exactly as before.
func TestCertificateAuthPath_UnchangedByAmendment4(t *testing.T) {
	t.Run("root-scope-marked certificate", func(t *testing.T) {
		server := setupTestServer(t)
		peerCert := makeRootScopedAdminTestCert(t)
		req := requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert)
		p := server.extractAdminPrincipal(req)
		require.NotNil(t, p)
		assert.True(t, p.RootScoped, "a root-scope-marked certificate must still derive RootScoped from the extension")
		assert.Equal(t, "", p.TenantID)
		assert.NotEmpty(t, p.CertSerial)
	})

	t.Run("unmarked admin certificate", func(t *testing.T) {
		server := setupTestServer(t)
		peerCert := makeSelfSignedAdminCert(t)
		req := requestWithTLSCert(http.MethodGet, "/api/v1/test", peerCert)
		p := server.extractAdminPrincipal(req)
		require.NotNil(t, p)
		assert.False(t, p.RootScoped, "an unmarked admin certificate must still derive RootScoped=false")
		assert.Equal(t, "", p.TenantID)
		assert.True(t, p.ImplicitAdmin, "the unbound bootstrap-fallback admin grant must be unaffected")
	})

	t.Run("revoked certificate is rejected outright", func(t *testing.T) {
		server := setupTestServer(t)
		tempDir := t.TempDir()
		certManager, err := cert.NewManager(&cert.ManagerConfig{
			StoragePath: tempDir,
			CAConfig:    &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365},
		})
		require.NoError(t, err)
		server.certManager = certManager

		issuedCert, err := certManager.GenerateClientCertificate(&cert.ClientCertConfig{
			CommonName:   "revoked-op",
			Organization: "CFGMS",
			ValidityDays: 1,
			TemplateModifier: func(template *x509.Certificate) {
				cert.SetAdminMarker(template)
				cert.SetRootScopeMarker(template)
			},
		})
		require.NoError(t, err)
		require.NoError(t, certManager.Revoke(issuedCert.SerialNumber))

		certBlock, _ := pem.Decode(issuedCert.CertificatePEM)
		require.NotNil(t, certBlock)
		x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
		require.NoError(t, err)

		req := requestWithTLSCert(http.MethodGet, "/api/v1/test", x509Cert)
		p := server.extractAdminPrincipal(req)
		assert.Nil(t, p, "a revoked certificate must still be rejected outright, never granted any scope")
	})
}

// TestWebSessionCookie_RootScopedAccount_ConfinedByCatchAllBoundaryGate is the
// [REQUIRED TEST]: a root-scope browser session (ADR-025 Amendment 4 A4.1) attempting a
// tenant-targeting action against a strict descendant of "root" with no active crossing
// is confined by requirePermission's catch-all ADR-025 Decision 1 boundary gate — not
// only by a single handler's own authorizeTenantAccess call. Before this story a
// root-scope web session carried no RootScoped marker at all and sailed through this
// exact gate unconfined (Amendment 4 A4.2).
func TestWebSessionCookie_RootScopedAccount_ConfinedByCatchAllBoundaryGate(t *testing.T) {
	server := boundaryTestServer(t)
	webCfg := session.DefaultConfig()
	store := session.NewMemStore(webCfg, time.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(webCfg, store, time.Now)
	server.SetWebSessionManager(mgr)

	server.cacheAccount(&account{
		ID:        "web-root-operator-1",
		Username:  "web-root-operator-1",
		TenantID:  "",
		RootScope: true,
	})

	sess, _, err := mgr.Issue(context.Background(), "web-root-operator-1", "web-login", "")
	require.NoError(t, err)
	_, elevatedTok, err := mgr.Elevate(context.Background(), sess.ID, []byte("cred-1"), "")
	require.NoError(t, err)

	reached := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	handler := server.authenticationMiddleware(server.requirePermission("tenant", "read")(probe))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/msp-a", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "msp-a"})
	req.AddCookie(&http.Cookie{Name: "cfgms_session", Value: elevatedTok})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.False(t, reached,
		"a root-scope web session without an active crossing must not reach the handler")
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`,
		"the catch-all boundary gate, not a bare 403/404, must respond")
}
