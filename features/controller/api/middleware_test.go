// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
	assert.True(t, capturedPrincipal.IsAdmin, "principal from admin cert must have IsAdmin == true")
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
	assert.False(t, capturedPrincipal.IsAdmin, "principal from API-key path must not be admin")
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
	assert.False(t, capturedPrincipal.IsAdmin)
}

// TestHasPermission_AdminPrincipal verifies that hasPermission returns true for any
// permissionID when the principal has IsAdmin == true.
func TestHasPermission_AdminPrincipal(t *testing.T) {
	server := setupTestServer(t)
	admin := &Principal{IsAdmin: true}

	assert.True(t, server.hasPermission(admin, "steward:read"))
	assert.True(t, server.hasPermission(admin, "rbac:delete-role"))
	assert.True(t, server.hasPermission(admin, "some-future:permission"))
}

// TestHasPermission_WildcardStringRejected verifies that an API-key principal with
// Permissions: []string{"*"} does not short-circuit — "*" is treated as a literal
// permission name (C1: no wildcard in permission strings).
func TestHasPermission_WildcardStringRejected(t *testing.T) {
	server := setupTestServer(t)
	wildcardPrincipal := &Principal{
		IsAdmin:     false,
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
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

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
	assert.True(t, principal.IsAdmin)

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
	assert.True(t, principal.IsAdmin)
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
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())

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
	assert.True(t, capturedPrincipal.IsAdmin, "web session principal must have IsAdmin == true")
	assert.Equal(t, "web-session:alice", capturedPrincipal.Name)
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
