// SPDX-License-Identifier: Apache-2.0
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
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
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

func makeAdminTestCert(t *testing.T, withMarker bool) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

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
		nil, nil, nil, "", nil, auditMgr, nil, nil,
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
