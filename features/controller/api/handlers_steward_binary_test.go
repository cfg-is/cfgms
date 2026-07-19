// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/session"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
)

// stewardBinaryTestFixture holds a generated Ed25519 key pair and the trust store
// wired to the server for signature tests.
type stewardBinaryTestFixture struct {
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	store *trust.InMemoryTrustStore
}

// newStewardBinaryFixture generates a fresh Ed25519 key pair and returns a fixture
// with an InMemoryTrustStore containing the corresponding publisher identity.
func newStewardBinaryFixture(t *testing.T) stewardBinaryTestFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	store := trust.NewInMemoryTrustStore()
	id := trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: []byte(pub),
		Algorithm: "ed25519",
	}
	require.NoError(t, store.AddPublisher(id))
	return stewardBinaryTestFixture{pub: pub, priv: priv, store: store}
}

// setupStewardBinaryServer creates a test server with a real BlobStore and an
// injectable test trust store so tests can produce valid Ed25519 signatures.
func setupStewardBinaryServer(t *testing.T) (*Server, stewardBinaryTestFixture) {
	t.Helper()
	fix := newStewardBinaryFixture(t)
	server, _ := setupTestServerWithBlobStore(t)
	server.stewardBinaryTrustStore = fix.store
	return server, fix
}

// signContent signs the SHA-256 hex of content with the fixture private key and returns
// URL-safe base64 (no padding) signature bytes, as expected by the endpoint.
func (f stewardBinaryTestFixture) signContent(content []byte) string {
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	sig := ed25519.Sign(f.priv, []byte(hash))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// doPublish calls handlePublishStewardBinary directly with the given body and signature.
// Pass sigBase64="" to omit the signature query param.
// Signature is URL-encoded so base64 '+' characters survive query-param parsing.
func doPublish(server *Server, version, platform, arch, tenantID, sigBase64 string, body []byte) *httptest.ResponseRecorder {
	rawURL := "/api/v1/installer/steward-binaries/" + version + "/" + platform + "/" + arch
	if sigBase64 != "" {
		q := url.Values{}
		q.Set("signature", sigBase64)
		rawURL += "?" + q.Encode()
	}
	req := httptest.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
	// A tenant-scoped (non-admin) caller carries both a principal and its tenant, exactly
	// as authenticationMiddleware injects them for an X-API-Key request (Issue #1999).
	req = withScopedPrincipal(req, tenantID)
	req = mux.SetURLVars(req, map[string]string{
		"version":  version,
		"platform": platform,
		"arch":     arch,
	})
	rec := httptest.NewRecorder()
	server.handlePublishStewardBinary(rec, req)
	return rec
}

// withScopedPrincipal injects a machine-assurance principal bound to tenantID plus the
// tenant context value, mirroring authenticationMiddleware for an API-key request. An
// empty tenantID models a non-human caller with no tenant (a genuine auth failure).
func withScopedPrincipal(req *http.Request, tenantID string) *http.Request {
	p := &Principal{ID: "api-key:" + tenantID, Assurance: session.AssuranceMachine, TenantID: tenantID}
	ctx := context.WithValue(req.Context(), principalContextKey, p)
	ctx = context.WithValue(ctx, ctxkeys.TenantID, tenantID)
	return req.WithContext(ctx)
}

// withAdminPrincipal injects an mTLS admin principal (AssuranceBasic, empty tenant) plus
// the empty tenant context value, mirroring authenticationMiddleware for an mTLS admin
// cert (middleware.go:173). This is the global-scope path that cannot be reached via an
// X-API-Key request (Issue #1999).
func withAdminPrincipal(req *http.Request) *http.Request {
	p := &Principal{ID: "mtls-admin:cn", Name: "mtls-admin:cn", Assurance: session.AssuranceBasic, TenantID: ""}
	ctx := context.WithValue(req.Context(), principalContextKey, p)
	ctx = context.WithValue(ctx, ctxkeys.TenantID, "")
	return req.WithContext(ctx)
}

// doGet calls handleGetStewardBinary directly.
func doGet(server *Server, version, platform, arch, tenantID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/installer/steward-binaries/"+version+"/"+platform+"/"+arch, nil)
	req = withScopedPrincipal(req, tenantID)
	req = mux.SetURLVars(req, map[string]string{
		"version":  version,
		"platform": platform,
		"arch":     arch,
	})
	rec := httptest.NewRecorder()
	server.handleGetStewardBinary(rec, req)
	return rec
}

// ---- Required tests (AC) ----

// TestPublishEndpoint_RejectsUnsignedUpload verifies that POST without a signature returns 400.
func TestPublishEndpoint_RejectsUnsignedUpload(t *testing.T) {
	server, _ := setupStewardBinaryServer(t)

	rec := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", "", []byte("binary content"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "SIGNATURE_REQUIRED")
}

// TestPublishEndpoint_RejectsInvalidSignature verifies that POST with wrong signature bytes returns 400.
func TestPublishEndpoint_RejectsInvalidSignature(t *testing.T) {
	server, _ := setupStewardBinaryServer(t)

	// 64 bytes of zeros is syntactically valid URL-safe base64 but cryptographically wrong.
	badSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	rec := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", badSig, []byte("binary content"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "SIGNATURE_VERIFICATION_FAILED")
}

// TestPublishEndpoint_RejectsCrossTenantPublish verifies that a caller without
// installer:publish:steward permission receives 403. This demonstrates tenant-namespace
// isolation: a key scoped to tenant-b (without the required permission) cannot publish
// steward binaries through the authenticated endpoint.
func TestPublishEndpoint_RejectsCrossTenantPublish(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)

	// Add an API key for tenant-b that only has installer:read, not installer:publish:steward.
	server.apiKeys["cross-tenant-key"] = &APIKey{
		ID:          "cross-tenant-key-id",
		Key:         "cross-tenant-key",
		Permissions: []string{"installer:read"},
		TenantID:    "tenant-b",
	}

	ts := httptest.NewServer(server.router)
	defer ts.Close()

	content := []byte("steward binary content for tenant-b test")
	sigBase64 := fix.signContent(content)

	q := url.Values{}
	q.Set("signature", sigBase64)
	reqURL := ts.URL + "/api/v1/installer/steward-binaries/v1.0.0/linux/amd64?" + q.Encode()
	req, err := http.NewRequestWithContext(context.Background(), "POST", reqURL, bytes.NewReader(content))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer cross-tenant-key")

	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestPublishEndpoint_DuplicatePublishReturns409 verifies that a second POST for the
// same version/platform/arch/tenant returns 409 Conflict.
func TestPublishEndpoint_DuplicatePublishReturns409(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)

	content := []byte("steward binary content")
	sigBase64 := fix.signContent(content)

	// First publish — must succeed.
	rec1 := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", sigBase64, content)
	require.Equal(t, http.StatusOK, rec1.Code, "first publish must succeed")

	// Second publish with the same coordinates — must return 409.
	rec2 := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", sigBase64, content)
	assert.Equal(t, http.StatusConflict, rec2.Code)
	body := rec2.Body.String()
	assert.Contains(t, body, "DUPLICATE_BINARY")
}

// TestPublishEndpoint_ValidatesPlatformAndArch verifies that the handler returns 400
// for unknown platform and arch values in the URL path.
func TestPublishEndpoint_ValidatesPlatformAndArch(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("binary")
	sig := fix.signContent(content)

	t.Run("rejects unknown platform", func(t *testing.T) {
		rec := doPublish(server, "v1.0.0", "solaris", "amd64", "test-tenant", sig, content)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "INVALID_PLATFORM")
	})

	t.Run("rejects unknown arch", func(t *testing.T) {
		rec := doPublish(server, "v1.0.0", "linux", "ppc64", "test-tenant", sig, content)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "INVALID_ARCH")
	})
}

// ---- Happy path tests ----

// TestHandlePublishStewardBinary_ValidInput verifies a successful publish and correct response fields.
func TestHandlePublishStewardBinary_ValidInput(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)

	content := []byte("cfgms-steward binary content")
	sigBase64 := fix.signContent(content)

	rec := doPublish(server, "v0.5.12", "linux", "amd64", "test-tenant", sigBase64, content)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "expected object in Data")
	assert.Equal(t, "v0.5.12", data["version"])
	assert.Equal(t, "linux", data["platform"])
	assert.Equal(t, "amd64", data["arch"])
	assert.NotEmpty(t, data["sha256"], "sha256 must be populated by the blob store")
	size, _ := data["size"].(float64)
	assert.Greater(t, size, float64(0), "size must be non-zero")
	assert.Equal(t, "cfgms", data["publisher"])
	assert.NotEmpty(t, data["signature_digest"])
}

// TestHandlePublishStewardBinary_ForceOverwrite verifies that ?force=true replaces an
// existing binary without returning 409.
func TestHandlePublishStewardBinary_ForceOverwrite(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)

	content := []byte("original binary")
	sigBase64 := fix.signContent(content)

	rec := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", sigBase64, content)
	require.Equal(t, http.StatusOK, rec.Code, "first publish must succeed")

	// Overwrite with --force.
	newContent := []byte("updated binary")
	newSig := fix.signContent(newContent)
	q := url.Values{}
	q.Set("signature", newSig)
	q.Set("force", "true")
	rawURL := "/api/v1/installer/steward-binaries/v1.0.0/linux/amd64?" + q.Encode()
	req := httptest.NewRequest(http.MethodPost, rawURL, bytes.NewReader(newContent))
	req = withScopedPrincipal(req, "test-tenant")
	req = mux.SetURLVars(req, map[string]string{"version": "v1.0.0", "platform": "linux", "arch": "amd64"})
	rec2 := httptest.NewRecorder()
	server.handlePublishStewardBinary(rec2, req)

	assert.Equal(t, http.StatusOK, rec2.Code)
}

// TestHandlePublishStewardBinary_InvalidVersion verifies that a version not matching
// ^v\d+\.\d+\.\d+ returns 400.
func TestHandlePublishStewardBinary_InvalidVersion(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("binary")
	sigBase64 := fix.signContent(content)

	rec := doPublish(server, "1.0.0", "linux", "amd64", "test-tenant", sigBase64, content)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_VERSION")
}

// TestHandlePublishStewardBinary_InvalidPlatform verifies unknown platform returns 400.
func TestHandlePublishStewardBinary_InvalidPlatform(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("binary")
	sigBase64 := fix.signContent(content)

	rec := doPublish(server, "v1.0.0", "solaris", "amd64", "test-tenant", sigBase64, content)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_PLATFORM")
}

// TestHandlePublishStewardBinary_NoTenant verifies missing auth context returns 401.
func TestHandlePublishStewardBinary_NoTenant(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("binary")
	sigBase64 := fix.signContent(content)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/installer/steward-binaries/v1.0.0/linux/amd64?signature="+sigBase64,
		bytes.NewReader(content))
	req = mux.SetURLVars(req, map[string]string{"version": "v1.0.0", "platform": "linux", "arch": "amd64"})
	rec := httptest.NewRecorder()
	server.handlePublishStewardBinary(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandlePublishStewardBinary_NoBlobStore verifies 503 when blob store is absent.
func TestHandlePublishStewardBinary_NoBlobStore(t *testing.T) {
	server := setupTestServer(t)
	// blobStore is nil by default in setupTestServer.

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/installer/steward-binaries/v1.0.0/linux/amd64", bytes.NewReader([]byte("content")))
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "test-tenant"))
	req = mux.SetURLVars(req, map[string]string{"version": "v1.0.0", "platform": "linux", "arch": "amd64"})
	rec := httptest.NewRecorder()
	server.handlePublishStewardBinary(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ---- GET handler tests ----

// TestHandleGetStewardBinary_ReturnsStream verifies GET returns the binary with 200.
func TestHandleGetStewardBinary_ReturnsStream(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)

	content := []byte("cfgms-steward-binary-content-for-get-test")
	sigBase64 := fix.signContent(content)

	// Publish first.
	rec := doPublish(server, "v1.2.3", "darwin", "arm64", "get-tenant", sigBase64, content)
	require.Equal(t, http.StatusOK, rec.Code, "publish must succeed before GET test")

	// GET must return the binary stream.
	getRec := doGet(server, "v1.2.3", "darwin", "arm64", "get-tenant")
	assert.Equal(t, http.StatusOK, getRec.Code)
	assert.Equal(t, content, getRec.Body.Bytes())
	assert.NotEmpty(t, getRec.Header().Get("X-CFGMS-SHA256"))
}

// TestHandleGetStewardBinary_Returns404WhenAbsent verifies GET returns 404 for missing binary.
func TestHandleGetStewardBinary_Returns404WhenAbsent(t *testing.T) {
	server, _ := setupStewardBinaryServer(t)

	rec := doGet(server, "v9.9.9", "linux", "amd64", "test-tenant")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "BINARY_NOT_FOUND")
}

// TestHandleGetStewardBinary_TenantIsolation verifies that a binary published under
// tenant A is not accessible under tenant B.
func TestHandleGetStewardBinary_TenantIsolation(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)

	content := []byte("tenant-a binary")
	sigBase64 := fix.signContent(content)

	// Publish under tenant-a.
	rec := doPublish(server, "v1.0.0", "linux", "amd64", "tenant-a", sigBase64, content)
	require.Equal(t, http.StatusOK, rec.Code)

	// GET from tenant-b must return 404 (different namespace).
	getRec := doGet(server, "v1.0.0", "linux", "amd64", "tenant-b")
	assert.Equal(t, http.StatusNotFound, getRec.Code)
}

// TestHandleGetStewardBinary_NoBlobStore verifies 503 when blob store is absent.
func TestHandleGetStewardBinary_NoBlobStore(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/installer/steward-binaries/v1.0.0/linux/amd64", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "test-tenant"))
	req = mux.SetURLVars(req, map[string]string{"version": "v1.0.0", "platform": "linux", "arch": "amd64"})
	rec := httptest.NewRecorder()
	server.handleGetStewardBinary(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleGetStewardBinary_ErrorPaths verifies the GET handler validation branches.
func TestHandleGetStewardBinary_ErrorPaths(t *testing.T) {
	server, _ := setupStewardBinaryServer(t)

	t.Run("missing tenant returns 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/installer/steward-binaries/v1.0.0/linux/amd64", nil)
		req = mux.SetURLVars(req, map[string]string{"version": "v1.0.0", "platform": "linux", "arch": "amd64"})
		rec := httptest.NewRecorder()
		server.handleGetStewardBinary(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("invalid version returns 400", func(t *testing.T) {
		rec := doGet(server, "1.0.0", "linux", "amd64", "test-tenant")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "INVALID_VERSION")
	})

	t.Run("invalid platform returns 400", func(t *testing.T) {
		rec := doGet(server, "v1.0.0", "solaris", "amd64", "test-tenant")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "INVALID_PLATFORM")
	})

	t.Run("invalid arch returns 400", func(t *testing.T) {
		rec := doGet(server, "v1.0.0", "linux", "ppc64", "test-tenant")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "INVALID_ARCH")
	})
}

// TestHandlePublishStewardBinary_LabelsStoredCorrectly verifies that BlobMeta.Labels
// are stored with the expected keys after a successful publish.
func TestHandlePublishStewardBinary_LabelsStoredCorrectly(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)

	content := []byte("binary for label test")
	sigBase64 := fix.signContent(content)

	// Inject an operator identity so published_by is non-empty.
	q2 := url.Values{}
	q2.Set("signature", sigBase64)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/installer/steward-binaries/v2.0.0/windows/amd64?"+q2.Encode(),
		bytes.NewReader(content))
	req = withScopedPrincipal(req, "label-tenant")
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.UserIDKey, "admin@example.com"))
	req = mux.SetURLVars(req, map[string]string{"version": "v2.0.0", "platform": "windows", "arch": "amd64"})
	rec := httptest.NewRecorder()
	server.handlePublishStewardBinary(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Verify labels via ListBlobs.
	blobs, err := server.blobStore.ListBlobs(context.Background(), blob.BlobKey{
		TenantID:  "label-tenant",
		Namespace: "steward-binaries",
	})
	require.NoError(t, err)
	require.Len(t, blobs, 1)

	labels := blobs[0].Meta.Labels
	assert.Equal(t, "v2.0.0", labels["version"])
	assert.Equal(t, "windows", labels["platform"])
	assert.Equal(t, "amd64", labels["arch"])
	assert.Equal(t, "admin@example.com", labels["published_by"])
	assert.Equal(t, "cfgms", labels["publisher"])
	assert.NotEmpty(t, labels["signature_digest"])
	assert.NotEmpty(t, labels["signature"])
	assert.Equal(t, "label-tenant", labels["publisher_tenant"])

	// Verify the response JSON reflects the correct sha256.
	var apiResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &apiResp))
	data, ok := apiResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "admin@example.com", data["published_by"])

	// Verify io.Reader body can be compared (sanity-check stream content).
	rc, _, getErr := server.blobStore.GetBlob(context.Background(), blob.BlobKey{
		TenantID:  "label-tenant",
		Namespace: "steward-binaries",
		Name:      "v2.0.0-windows-amd64",
	})
	require.NoError(t, getErr)
	defer func() { _ = rc.Close() }()
	got, readErr := io.ReadAll(rc)
	require.NoError(t, readErr)
	assert.Equal(t, content, got)
}

// --- Admin mTLS empty-tenant tests (Issue #1999) ---

// publishWithPrincipal calls handlePublishStewardBinary with the given principal injected
// into the request context (admin mTLS or scoped non-admin), exactly as the middleware does.
func publishWithPrincipal(server *Server, principalReq func(*http.Request) *http.Request, version, platform, arch, sigBase64 string, body []byte) *httptest.ResponseRecorder {
	q := url.Values{}
	q.Set("signature", sigBase64)
	rawURL := "/api/v1/installer/steward-binaries/" + version + "/" + platform + "/" + arch + "?" + q.Encode()
	req := httptest.NewRequest(http.MethodPost, rawURL, bytes.NewReader(body))
	req = principalReq(req)
	req = mux.SetURLVars(req, map[string]string{"version": version, "platform": platform, "arch": arch})
	rec := httptest.NewRecorder()
	server.handlePublishStewardBinary(rec, req)
	return rec
}

// getWithPrincipal calls handleGetStewardBinary with the given principal injected.
func getWithPrincipal(server *Server, principalReq func(*http.Request) *http.Request, version, platform, arch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/installer/steward-binaries/"+version+"/"+platform+"/"+arch, nil)
	req = principalReq(req)
	req = mux.SetURLVars(req, map[string]string{"version": version, "platform": platform, "arch": arch})
	rec := httptest.NewRecorder()
	server.handleGetStewardBinary(rec, req)
	return rec
}

// TestPublish_AdminEmptyTenant_NotUnauthorized verifies that an admin mTLS principal
// (IsAdmin=true, TenantID="") is NOT rejected with 401 on publish — it proceeds to the
// global (empty-tenant) namespace and succeeds (Issue #1999).
func TestPublish_AdminEmptyTenant_NotUnauthorized(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("admin-published steward binary")
	sigBase64 := fix.signContent(content)

	rec := publishWithPrincipal(server, withAdminPrincipal, "v1.0.0", "linux", "amd64", sigBase64, content)

	require.NotEqual(t, http.StatusUnauthorized, rec.Code,
		"admin mTLS principal with empty tenant must not be rejected with 401: %s", rec.Body.String())
	assert.Equal(t, http.StatusOK, rec.Code, "admin publish must succeed: %s", rec.Body.String())
}

// TestPublish_NonAdminEmptyTenant_Unauthorized verifies that a NON-admin principal with
// no tenant still gets 401 on publish (regression guard, Issue #1999).
func TestPublish_NonAdminEmptyTenant_Unauthorized(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("scoped-but-tenantless binary")
	sigBase64 := fix.signContent(content)

	emptyScoped := func(req *http.Request) *http.Request { return withScopedPrincipal(req, "") }
	rec := publishWithPrincipal(server, emptyScoped, "v1.0.0", "linux", "amd64", sigBase64, content)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "AUTHENTICATION_REQUIRED")
}

// TestGetStewardBinary_AdminEmptyTenant_NotUnauthorized verifies that an admin mTLS
// principal can GET from the global (empty-tenant) namespace it published into, without 401.
func TestGetStewardBinary_AdminEmptyTenant_NotUnauthorized(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("admin binary for get")
	sigBase64 := fix.signContent(content)

	pubRec := publishWithPrincipal(server, withAdminPrincipal, "v1.2.3", "darwin", "arm64", sigBase64, content)
	require.Equal(t, http.StatusOK, pubRec.Code, "admin publish must succeed: %s", pubRec.Body.String())

	getRec := getWithPrincipal(server, withAdminPrincipal, "v1.2.3", "darwin", "arm64")
	require.NotEqual(t, http.StatusUnauthorized, getRec.Code,
		"admin mTLS principal with empty tenant must not be rejected with 401 on GET")
	assert.Equal(t, http.StatusOK, getRec.Code)
	assert.Equal(t, content, getRec.Body.Bytes())
}

// TestGetStewardBinary_NonAdminEmptyTenant_Unauthorized verifies that a NON-admin caller
// with no tenant still gets 401 on the authenticated GET (regression guard, Issue #1999).
func TestGetStewardBinary_NonAdminEmptyTenant_Unauthorized(t *testing.T) {
	server, _ := setupStewardBinaryServer(t)

	emptyScoped := func(req *http.Request) *http.Request { return withScopedPrincipal(req, "") }
	getRec := getWithPrincipal(server, emptyScoped, "v1.0.0", "linux", "amd64")

	assert.Equal(t, http.StatusUnauthorized, getRec.Code)
	assert.Contains(t, getRec.Body.String(), "AUTHENTICATION_REQUIRED")
}
