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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/session"
	blob "github.com/cfgis/cfgms/pkg/storage/interfaces/blob"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
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
	wireTestStewardBinaryApprovalStore(t, server)
	return server, fix
}

// signContent signs the canonical (contentHash, version, platform, arch) composite with
// the fixture private key and returns URL-safe base64 (no padding) signature bytes, as
// expected by the endpoint. Binding the release coordinates means a signature minted for
// one version/platform/arch cannot be replayed to publish another (Issue #2834).
func (f stewardBinaryTestFixture) signContent(content []byte, version, platform, arch string) string {
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	msg, err := trust.StewardBinaryMessage(hash, version, platform, arch)
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(f.priv, []byte(msg))
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
// Also carries ctxkeys.TenantScope (Issue #4335), the value authenticationMiddleware
// sets alongside ctxkeys.TenantID — without it, a handler migrated to read TenantScope
// sees an unset scope and fails closed regardless of tenantID.
func withScopedPrincipal(req *http.Request, tenantID string) *http.Request {
	p := &Principal{ID: "api-key:" + tenantID, Assurance: session.AssuranceMachine, TenantID: tenantID}
	ctx := context.WithValue(req.Context(), principalContextKey, p)
	ctx = context.WithValue(ctx, ctxkeys.TenantID, tenantID)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scopeForVerifiedAdminCert(tenantID))
	return req.WithContext(ctx)
}

// withAdminPrincipal injects an mTLS admin principal (AssuranceBasic, GlobalScope=true,
// empty tenant) plus the empty tenant context value, mirroring authenticationMiddleware
// for an mTLS admin cert (middleware.go). This is the global-scope path that cannot be
// reached via an X-API-Key request (Issue #1999, #2787). Also carries ctxkeys.TenantScope
// (Issue #4335) as root scope, matching scopeForVerifiedAdminCert("").
func withAdminPrincipal(req *http.Request) *http.Request {
	p := &Principal{ID: "mtls-admin:cn", Name: "mtls-admin:cn", Assurance: session.AssuranceBasic, GlobalScope: true, TenantID: ""}
	ctx := context.WithValue(req.Context(), principalContextKey, p)
	ctx = context.WithValue(ctx, ctxkeys.TenantID, "")
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
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

// TestPublishEndpoint_RejectsVersionBindingMismatch verifies that a signature minted for
// one set of release coordinates cannot be replayed to publish a different version,
// platform, or arch. This is the publish-side half of the rollback defense (Issue #2834):
// the stored signature always covers the key the blob lands under, so a later GET cannot
// serve bytes whose signature was issued for some other release.
func TestPublishEndpoint_RejectsVersionBindingMismatch(t *testing.T) {
	content := []byte("steward binary signed for v1.0.0/linux/amd64")

	cases := map[string][3]string{
		"version substituted":  {"v2.0.0", "linux", "amd64"},
		"platform substituted": {"v1.0.0", "darwin", "amd64"},
		"arch substituted":     {"v1.0.0", "linux", "arm64"},
	}
	for name, coords := range cases {
		t.Run(name, func(t *testing.T) {
			server, fix := setupStewardBinaryServer(t)
			// Authentic signature, but bound to v1.0.0/linux/amd64.
			sigBase64 := fix.signContent(content, "v1.0.0", "linux", "amd64")

			rec := doPublish(server, coords[0], coords[1], coords[2], "test-tenant", sigBase64, content)

			assert.Equal(t, http.StatusBadRequest, rec.Code,
				"signature bound to different coordinates must be rejected")
			assert.Contains(t, rec.Body.String(), "SIGNATURE_VERIFICATION_FAILED")
		})
	}
}

// TestGetStewardBinaryPublic_ServesSignatureHeaders is the #2836 round-trip: publish a
// binary, GET it via the public endpoint, and assert the publisher signature and identity
// are served as headers alongside the SHA-256, equal to the persisted values — so a
// self-fetching steward (#2833) can verify the publisher independently.
func TestGetStewardBinaryPublic_ServesSignatureHeaders(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)

	content := []byte("steward binary for public-header round-trip")
	sigBase64 := fix.signContent(content, "v1.0.0", "linux", "amd64")

	pubRec := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", sigBase64, content)
	require.Equal(t, http.StatusOK, pubRec.Code, "publish must succeed: %s", pubRec.Body.String())
	approveStewardBinaryBytes(t, server, "test-tenant", "v1.0.0", "linux", "amd64", content)

	getRec := doGetStewardBinaryPublic(server, "v1.0.0", "linux", "amd64", "test-tenant")
	require.Equal(t, http.StatusOK, getRec.Code, "public GET must succeed: %s", getRec.Body.String())

	assert.Equal(t, sigBase64, getRec.Header().Get("X-CFGMS-Signature"),
		"X-CFGMS-Signature must equal the persisted (base64url) publisher signature")
	assert.Equal(t, "cfgms", getRec.Header().Get("X-CFGMS-Publisher"),
		"X-CFGMS-Publisher must equal the persisted publisher identity")
	assert.NotEmpty(t, getRec.Header().Get("X-CFGMS-SHA256"),
		"existing X-CFGMS-SHA256 header must still be served")
	assert.Equal(t, content, getRec.Body.Bytes(), "public GET must return the exact bytes")
}

func TestGetStewardBinaryPublic_CacheValidatorsRangesAndPublishInvalidation(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("0123456789-steward-binary")
	signature := fix.signContent(content, "v1.0.0", "linux", "amd64")
	pubRec := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", signature, content)
	require.Equal(t, http.StatusOK, pubRec.Code)
	approveStewardBinaryBytes(t, server, "test-tenant", "v1.0.0", "linux", "amd64", content)

	request := func(rangeHeader, etag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(
			http.MethodGet,
			"/api/v1/public/steward-binaries/v1.0.0/linux/amd64?tenant=test-tenant",
			nil,
		)
		req = mux.SetURLVars(req, map[string]string{
			"version": "v1.0.0", "platform": "linux", "arch": "amd64",
		})
		if rangeHeader != "" {
			req.Header.Set("Range", rangeHeader)
		}
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		rec := httptest.NewRecorder()
		server.handleGetStewardBinaryPublic(rec, req)
		return rec
	}

	full := request("", "")
	require.Equal(t, http.StatusOK, full.Code)
	assert.Equal(t, content, full.Body.Bytes())
	etag := full.Header().Get("ETag")
	require.NotEmpty(t, etag)
	assert.Equal(t, "bytes", full.Header().Get("Accept-Ranges"))

	partial := request("bytes=3-7", "")
	require.Equal(t, http.StatusPartialContent, partial.Code)
	assert.Equal(t, content[3:8], partial.Body.Bytes())
	assert.Equal(t, signature, partial.Header().Get("X-CFGMS-Signature"))

	notModified := request("", etag)
	assert.Equal(t, http.StatusNotModified, notModified.Code)
	assert.Zero(t, notModified.Body.Len())

	replacement := []byte("replacement-steward-binary")
	replacementSignature := fix.signContent(replacement, "v1.0.0", "linux", "amd64")
	q := url.Values{}
	q.Set("signature", replacementSignature)
	q.Set("force", "true")
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/installer/steward-binaries/v1.0.0/linux/amd64?"+q.Encode(),
		bytes.NewReader(replacement),
	)
	req = withScopedPrincipal(req, "test-tenant")
	req = mux.SetURLVars(req, map[string]string{
		"version": "v1.0.0", "platform": "linux", "arch": "amd64",
	})
	replaceRec := httptest.NewRecorder()
	server.handlePublishStewardBinary(replaceRec, req)
	require.Equal(t, http.StatusOK, replaceRec.Code)

	// Different bytes are not covered by the first approval: the replacement is
	// not served until it is approved itself.
	require.Equal(t, http.StatusNotFound, request("", "").Code)
	approveStewardBinaryBytes(t, server, "test-tenant", "v1.0.0", "linux", "amd64", replacement)

	updated := request("", "")
	require.Equal(t, http.StatusOK, updated.Code)
	assert.Equal(t, replacement, updated.Body.Bytes())
	assert.NotEqual(t, etag, updated.Header().Get("ETag"))
}

// TestGetStewardBinaryPublic_DoesNotLeakSensitiveLabels guards the security invariant that
// header emission reads the two signature keys individually and never ranges over the
// blob's Labels map. The same map on this UNAUTHENTICATED endpoint also holds the operator
// identity (published_by) and internal tenant IDs (publisher_tenant, signature_digest); a
// blanket label→header copy would disclose them to any anonymous caller.
func TestGetStewardBinaryPublic_DoesNotLeakSensitiveLabels(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)

	content := []byte("steward binary for label-leak guard")
	sigBase64 := fix.signContent(content, "v1.0.0", "linux", "amd64")

	pubRec := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", sigBase64, content)
	require.Equal(t, http.StatusOK, pubRec.Code, "publish must succeed: %s", pubRec.Body.String())
	approveStewardBinaryBytes(t, server, "test-tenant", "v1.0.0", "linux", "amd64", content)

	getRec := doGetStewardBinaryPublic(server, "v1.0.0", "linux", "amd64", "test-tenant")
	require.Equal(t, http.StatusOK, getRec.Code, "public GET must succeed: %s", getRec.Body.String())

	// None of the sensitive labels may surface as a response header, under any casing or the
	// hypothetical X-CFGMS-<label> form a range-over-Labels implementation would produce.
	for _, sensitive := range []string{"published_by", "publisher_tenant", "signature_digest"} {
		for _, name := range []string{
			sensitive,
			"X-CFGMS-" + sensitive,
			"X-Cfgms-" + sensitive,
		} {
			assert.Empty(t, getRec.Header().Get(name),
				"sensitive label %q must not be served as header %q", sensitive, name)
		}
	}
	// And the whole header set must not contain the operator identity value anywhere.
	for k, vals := range getRec.Header() {
		for _, v := range vals {
			assert.NotContains(t, v, "cfgms-admin",
				"operator identity must not leak via header %q", k)
		}
	}
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
	sigBase64 := fix.signContent(content, "v1.0.0", "linux", "amd64")

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
	sigBase64 := fix.signContent(content, "v1.0.0", "linux", "amd64")

	// First publish — must succeed.
	rec1 := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", sigBase64, content)
	require.Equal(t, http.StatusOK, rec1.Code, "first publish must succeed")

	// Second publish with the same coordinates — must return 409.
	rec2 := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", sigBase64, content)
	assert.Equal(t, http.StatusConflict, rec2.Code)
	body := rec2.Body.String()
	assert.Contains(t, body, "DUPLICATE_BINARY")
}

// TestPublishStewardBinary_ConcurrentPublishesExactlyOneWins is the [REQUIRED TEST]
// for Issue #3895: handlePublishStewardBinary's GetBlob-then-PutBlob duplicate check
// was a TOCTOU race — two concurrent publishes without force=true could both pass
// the not-found pre-check and both PutBlob, silently overwriting each other while
// both reported success. The fix routes the non-force path through
// blob.BlobStore.PutBlobIfAbsent, whose conditional-create is atomic at the storage
// layer, so exactly one concurrent publish for the same version/platform/arch key can
// ever succeed. Run under -race.
func TestPublishStewardBinary_ConcurrentPublishesExactlyOneWins(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)

	const attempts = 8
	type publishResult struct {
		code int
		body string
	}
	results := make(chan publishResult, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			content := []byte(fmt.Sprintf("attempt-%d", i))
			sig := fix.signContent(content, "v1.0.0", "linux", "amd64")
			rec := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", sig, content)
			results <- publishResult{code: rec.Code, body: rec.Body.String()}
		}(i)
	}
	wg.Wait()
	close(results)

	successes, conflicts := 0, 0
	for r := range results {
		switch r.code {
		case http.StatusOK:
			successes++
		case http.StatusConflict:
			conflicts++
			assert.Contains(t, r.body, "DUPLICATE_BINARY")
		default:
			t.Fatalf("unexpected status %d: %s", r.code, r.body)
		}
	}

	assert.Equal(t, 1, successes, "exactly one concurrent publish must succeed")
	assert.Equal(t, attempts-1, conflicts, "every other publish must be rejected with 409, never silently overwritten")
}

// TestPublishEndpoint_ValidatesPlatformAndArch verifies that the handler returns 400
// for unknown platform and arch values in the URL path.
func TestPublishEndpoint_ValidatesPlatformAndArch(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("binary")
	sig := fix.signContent(content, "v1.0.0", "solaris", "amd64")

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
	sigBase64 := fix.signContent(content, "v0.5.12", "linux", "amd64")

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
	sigBase64 := fix.signContent(content, "v1.0.0", "linux", "amd64")

	rec := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", sigBase64, content)
	require.Equal(t, http.StatusOK, rec.Code, "first publish must succeed")

	// Overwrite with --force.
	newContent := []byte("updated binary")
	newSig := fix.signContent(newContent, "v1.0.0", "linux", "amd64")
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
	sigBase64 := fix.signContent(content, "1.0.0", "linux", "amd64")

	rec := doPublish(server, "1.0.0", "linux", "amd64", "test-tenant", sigBase64, content)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_VERSION")
}

// TestHandlePublishStewardBinary_InvalidPlatform verifies unknown platform returns 400.
func TestHandlePublishStewardBinary_InvalidPlatform(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("binary")
	sigBase64 := fix.signContent(content, "v1.0.0", "solaris", "amd64")

	rec := doPublish(server, "v1.0.0", "solaris", "amd64", "test-tenant", sigBase64, content)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_PLATFORM")
}

// TestHandlePublishStewardBinary_NoTenant verifies missing auth context returns 401.
func TestHandlePublishStewardBinary_NoTenant(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("binary")
	sigBase64 := fix.signContent(content, "v1.0.0", "linux", "amd64")

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
	sigBase64 := fix.signContent(content, "v1.2.3", "darwin", "arm64")

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
	sigBase64 := fix.signContent(content, "v1.0.0", "linux", "amd64")

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
	sigBase64 := fix.signContent(content, "v2.0.0", "windows", "amd64")

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
	sigBase64 := fix.signContent(content, "v1.0.0", "linux", "amd64")

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
	sigBase64 := fix.signContent(content, "v1.0.0", "linux", "amd64")

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
	sigBase64 := fix.signContent(content, "v1.2.3", "darwin", "arm64")

	pubRec := publishWithPrincipal(server, withAdminPrincipal, "v1.2.3", "darwin", "arm64", sigBase64, content)
	require.Equal(t, http.StatusOK, pubRec.Code, "admin publish must succeed: %s", pubRec.Body.String())

	getRec := getWithPrincipal(server, withAdminPrincipal, "v1.2.3", "darwin", "arm64")
	require.NotEqual(t, http.StatusUnauthorized, getRec.Code,
		"admin mTLS principal with empty tenant must not be rejected with 401 on GET")
	assert.Equal(t, http.StatusOK, getRec.Code)
	assert.Equal(t, content, getRec.Body.Bytes())
}

// TestGetStewardBinary_UnsetTenantScope_Refused is the [REQUIRED TEST] for Issue
// #4335: a session-assurance principal with an empty ctxkeys.TenantID passes
// authRunAccess (it is not machine-assurance), but with no ctxkeys.TenantScope
// established at all — the plumbing-bug signature — must still be refused, not
// silently served from the "default" namespace a genuine root-scoped admin uses.
func TestGetStewardBinary_UnsetTenantScope_Refused(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	content := []byte("admin binary for unset-scope check")
	sigBase64 := fix.signContent(content, "v1.9.9", "linux", "amd64")

	pubRec := publishWithPrincipal(server, withAdminPrincipal, "v1.9.9", "linux", "amd64", sigBase64, content)
	require.Equal(t, http.StatusOK, pubRec.Code, "admin publish must succeed: %s", pubRec.Body.String())

	unsetScope := func(req *http.Request) *http.Request {
		p := &Principal{ID: "session-acct", Assurance: session.AssuranceBasic, GlobalScope: true, TenantID: ""}
		ctx := context.WithValue(req.Context(), principalContextKey, p)
		ctx = context.WithValue(ctx, ctxkeys.TenantID, p.TenantID)
		// Deliberately no ctxkeys.TenantScopeKey.
		return req.WithContext(ctx)
	}
	getRec := getWithPrincipal(server, unsetScope, "v1.9.9", "linux", "amd64")

	assert.Equal(t, http.StatusForbidden, getRec.Code,
		"an unset tenant scope must be refused, not served from the default namespace: %s", getRec.Body.String())
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

// ---- Leader-gate tests (Issue #3543) ----

// newNonAuthoritativeHAManager returns a real *ha.Manager — the production component the
// leader gate consults — in the state a partitioned controller is in: ClusterMode, holding
// no lease, so the real HasLeadership() implementation (backed by the shared database
// lease, ADR-031 Decision 5, the 0.8 × ElectionTimeout lease bound of ADR-029) reports
// false. The manager is constructed but never Started, so this node never acquires the
// lease and it stays permanently unheld — the same condition a leader that has lost
// quorum reaches once its lease ages out.
func newNonAuthoritativeHAManager(t *testing.T) *ha.Manager {
	t.Helper()

	certMgr := newTLSTestCertManager(t)
	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)
	caPath := filepath.Join(t.TempDir(), "ha-ca.pem")
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	manager := newClusterModeHAManager(t, caPath, certMgr)
	require.False(t, manager.HasLeadership(),
		"precondition: a cluster-mode node holding no lease must not claim leadership")
	return manager
}

// newAuthoritativeHAManager returns a real *ha.Manager in SingleServerMode, where the real
// HasLeadership() is unconditionally true (ADR-029 Decision 4: no quorum to lose, no peer
// to overlap with, so no lease is needed). This is the deployment shape every OSS
// single-controller install runs.
func newAuthoritativeHAManager(t *testing.T) *ha.Manager {
	t.Helper()

	cfg := ha.DefaultConfig()
	cfg.Mode = ha.SingleServerMode
	manager, err := ha.NewManager(cfg, logging.NewNoopLogger(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, manager.Stop(context.Background())) })
	require.True(t, manager.HasLeadership(),
		"precondition: a single-server node is always authoritative")
	return manager
}

// TestPublishStewardBinary_SucceedsOnNonAuthoritativeNode is the [REQUIRED TEST] for
// this file (Issue #3761, ADR-031 Decision 1): handlePublishStewardBinary used to
// return 503 and store nothing when the serving node held no lease-backed
// leadership (the former partition-scenario gate, Issue #3543). Any-node service
// means every cluster node now accepts this write — the shared store is the
// serialization point, not leadership — so publishing against a real, deliberately
// non-authoritative *ha.Manager (ClusterMode, no lease ever acquired) must succeed
// and the binary must land in the blob store exactly as it would on a leader.
func TestPublishStewardBinary_SucceedsOnNonAuthoritativeNode(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	server.haManager = newNonAuthoritativeHAManager(t)

	content := []byte("binary published from a non-authoritative node")
	sigBase64 := fix.signContent(content, "v1.0.0", "linux", "amd64")

	rec := doPublish(server, "v1.0.0", "linux", "amd64", "test-tenant", sigBase64, content)
	assert.Equal(t, http.StatusOK, rec.Code, "publish must succeed regardless of leadership: %s", rec.Body.String())

	blobs, err := server.blobStore.ListBlobs(context.Background(), blob.BlobKey{
		TenantID:  "test-tenant",
		Namespace: "steward-binaries",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, blobs, "blob store must contain the published binary")
}

// TestPublishStewardBinary_SucceedsOnAuthoritativeNode is the mirror case: a real,
// deliberately authoritative *ha.Manager (SingleServerMode) must also reach the
// existing publish logic unchanged — the removal of the leader gate must not have
// broken the leader path either.
func TestPublishStewardBinary_SucceedsOnAuthoritativeNode(t *testing.T) {
	server, fix := setupStewardBinaryServer(t)
	server.haManager = newAuthoritativeHAManager(t)
	content := []byte("binary content for authoritative-node path")
	sigBase64 := fix.signContent(content, "v1.2.0", "linux", "amd64")
	rec := doPublish(server, "v1.2.0", "linux", "amd64", "test-tenant", sigBase64, content)
	assert.Equal(t, http.StatusOK, rec.Code, "publish must succeed on an authoritative node: %s", rec.Body.String())
}

// ---- Steward binary approval (Issue #6053) ----

const approveTestTenant = "tenant-a"

// approveStewardBinaryBytes records an approval for the SHA-256 of content, as the
// approve route would after a reviewer confirmed those bytes.
func approveStewardBinaryBytes(t *testing.T, server *Server, tenantID, version, platform, arch string, content []byte) {
	t.Helper()
	_, err := server.approveStewardBinary(context.Background(), tenantID, version, platform, arch, hexSHA256(content), "approver@example.com")
	require.NoError(t, err)
}

// approveFixture serves the real approve route behind the real requirePermission
// middleware on a server with a real blob store, config store and audit manager.
type approveFixture struct {
	t      *testing.T
	srv    *Server
	fix    stewardBinaryTestFixture
	router *mux.Router
}

func newApproveFixture(t *testing.T) *approveFixture {
	t.Helper()
	srv, fix := setupStewardBinaryServer(t)
	return newApproveFixtureOn(t, srv, fix)
}

func newApproveFixtureOn(t *testing.T, srv *Server, fix stewardBinaryTestFixture) *approveFixture {
	t.Helper()
	srv.stewardBinaryTrustStore = fix.store
	r := mux.NewRouter()
	registerStewardBinaryRoutes(srv, r.PathPrefix("/api/v1").Subrouter())
	return &approveFixture{t: t, srv: srv, fix: fix, router: r}
}

func approverPrincipal(id string) *Principal {
	return &Principal{
		ID: id, Assurance: session.AssuranceStrong, TenantID: approveTestTenant,
		Permissions: []string{"installer:approve:steward"},
	}
}

// publish publishes content through the real publish handler and returns its SHA-256.
func (f *approveFixture) publish(version, platform, arch string, content []byte, force bool) string {
	f.t.Helper()
	sig := f.fix.signContent(content, version, platform, arch)
	q := url.Values{}
	q.Set("signature", sig)
	if force {
		q.Set("force", "true")
	}
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/installer/steward-binaries/"+version+"/"+platform+"/"+arch+"?"+q.Encode(), bytes.NewReader(content))
	req = withScopedPrincipal(req, approveTestTenant)
	req = mux.SetURLVars(req, map[string]string{"version": version, "platform": platform, "arch": arch})
	rec := httptest.NewRecorder()
	f.srv.handlePublishStewardBinary(rec, req)
	require.Equal(f.t, http.StatusOK, rec.Code, rec.Body.String())
	return hexSHA256(content)
}

func (f *approveFixture) approve(p *Principal, version, platform, arch, body string, presence bool) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/installer/steward-binaries/"+version+"/"+platform+"/"+arch+"/approve", strings.NewReader(body))
	req = withPrincipal(req, p)
	if presence {
		req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(f.t, f.srv, p.ID, req, "installer:approve:steward"))
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

func (f *approveFixture) approveHash(p *Principal, version, platform, arch, sha string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.approve(p, version, platform, arch, `{"sha256":"`+sha+`"}`, true)
}

func (f *approveFixture) approved(version, platform, arch, sha string) bool {
	f.t.Helper()
	ok, err := f.srv.stewardBinaryApproved(context.Background(), approveTestTenant, version, platform, arch, sha)
	require.NoError(f.t, err)
	return ok
}

type approveResponse struct {
	Data stewardBinaryApproveResponse `json:"data"`
}

func TestApproveThenDispatchSucceeds(t *testing.T) {
	stewards := []fleet.StewardData{{ID: "steward-1", TenantID: approveTestTenant, Status: "online"}}
	server, _ := setupUpgradeServer(t, approveTestTenant, stewards)
	require.False(t, server.testAutoApproveStewardBinaries, "the test auto-approve flag stays off")
	f := newApproveFixtureOn(t, server, newStewardBinaryFixture(t))
	sha := f.publish("v1.0.0", "linux", "amd64", []byte("dispatch me"), false)

	rec := doDispatchUpgrade(server, approveTestTenant, "id:steward-1", "v1.0.0", "linux", "amd64")
	require.Equal(t, http.StatusForbidden, rec.Code, "a published binary is not dispatchable")
	assert.Contains(t, rec.Body.String(), "NOT_APPROVED")

	rec = f.approveHash(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", sha)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp approveResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "alice", resp.Data.ApprovedBy)
	assert.Equal(t, sha, resp.Data.SHA256)
	assert.True(t, resp.Data.Created)
	assert.False(t, resp.Data.ApprovedAt.IsZero())

	rec = doDispatchUpgrade(server, approveTestTenant, "id:steward-1", "v1.0.0", "linux", "amd64")
	assert.Equal(t, http.StatusAccepted, rec.Code, rec.Body.String())
}

func TestApproveRequiresPresenceToken(t *testing.T) {
	f := newApproveFixture(t)
	sha := f.publish("v1.0.0", "linux", "amd64", []byte("presence"), false)

	// A basic-assurance human is challenged for step-up and nothing is recorded.
	basic := approverPrincipal("basic-user")
	basic.Assurance = session.AssuranceBasic
	rec := f.approveHash(basic, "v1.0.0", "linux", "amd64", sha)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
	assert.False(t, f.approved("v1.0.0", "linux", "amd64", sha))

	// A strong-assurance human without a tap is challenged for presence.
	rec = f.approve(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", `{"sha256":"`+sha+`"}`, false)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`)
	assert.False(t, f.approved("v1.0.0", "linux", "amd64", sha))

	// A strong-assurance human with a tap approves.
	rec = f.approveHash(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", sha)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, f.approved("v1.0.0", "linux", "amd64", sha))

	// The permission is gated at Strong, with a tap, and with no machine access.
	req := permissionAssurance["installer:approve:steward"]
	assert.Equal(t, session.AssuranceStrong, req.Min)
	assert.True(t, req.RequireUserPresence)
	assert.False(t, req.AllowMachine)
}

func TestApproveRefusesMachinePrincipal(t *testing.T) {
	f := newApproveFixture(t)
	sha := f.publish("v1.0.0", "linux", "amd64", []byte("machine"), false)

	machine := approverPrincipal("api-key:tenant-a")
	machine.Assurance = session.AssuranceMachine
	for _, presence := range []bool{false, true} {
		rec := f.approve(machine, "v1.0.0", "linux", "amd64", `{"sha256":"`+sha+`"}`, presence)
		assert.Equal(t, http.StatusForbidden, rec.Code, "presence=%v: %s", presence, rec.Body.String())
		assert.Empty(t, rec.Header().Get("WWW-Authenticate"), "a machine principal is refused, not challenged")
	}
	assert.False(t, f.approved("v1.0.0", "linux", "amd64", sha))
	assert.Empty(t, auditEntriesByAction(t, f.srv, auditActionStewardBinaryApprove))
}

func TestApproveUnknownBlob404(t *testing.T) {
	f := newApproveFixture(t)
	rec := f.approveHash(approverPrincipal("alice"), "v9.9.9", "linux", "amd64", hexSHA256([]byte("nothing")))
	assert.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "BINARY_NOT_FOUND")
	assert.False(t, f.approved("v9.9.9", "linux", "amd64", hexSHA256([]byte("nothing"))))

	// A blob published for another platform is not the blob named.
	f.publish("v1.0.0", "linux", "amd64", []byte("linux"), false)
	rec = f.approveHash(approverPrincipal("alice"), "v1.0.0", "windows", "amd64", hexSHA256([]byte("linux")))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestApproveIdempotentKeepsFirstApprover(t *testing.T) {
	f := newApproveFixture(t)
	sha := f.publish("v1.0.0", "linux", "amd64", []byte("twice"), false)

	first := f.approveHash(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", sha)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	var a approveResponse
	require.NoError(t, json.Unmarshal(first.Body.Bytes(), &a))
	assert.True(t, a.Data.Created)

	second := f.approveHash(approverPrincipal("bob"), "v1.0.0", "linux", "amd64", sha)
	require.Equal(t, http.StatusOK, second.Code, second.Body.String())
	var b approveResponse
	require.NoError(t, json.Unmarshal(second.Body.Bytes(), &b))
	assert.False(t, b.Data.Created)
	assert.Equal(t, "alice", b.Data.ApprovedBy, "the first approver is kept")
	assert.True(t, a.Data.ApprovedAt.Equal(b.Data.ApprovedAt), "the first approval time is kept")

	rec, err := f.srv.stewardBinaryApproval(context.Background(), approveTestTenant, "v1.0.0", "linux", "amd64", sha)
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, "alice", rec.ApprovedBy)
}

func TestApproveHashMismatchRefused(t *testing.T) {
	f := newApproveFixture(t)
	f.publish("v1.0.0", "linux", "amd64", []byte("reviewed bytes"), false)
	other := hexSHA256([]byte("different bytes"))

	rec := f.approveHash(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", other)
	assert.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "HASH_MISMATCH")
	assert.False(t, f.approved("v1.0.0", "linux", "amd64", other), "no record for the hash named")
	assert.False(t, f.approved("v1.0.0", "linux", "amd64", hexSHA256([]byte("reviewed bytes"))), "nor for the stored bytes")
	assert.Empty(t, auditEntriesByAction(t, f.srv, auditActionStewardBinaryApprove), "a refused approval is not audited as made")

	for name, body := range map[string]string{
		"missing":        `{}`,
		"not hex":        `{"sha256":"zz"}`,
		"short":          `{"sha256":"abcd"}`,
		"unknown field":  `{"sha256":"` + other + `","tenant":"x"}`,
		"trailing value": `{"sha256":"` + other + `"}{}`,
		"not json":       `sha256=abc`,
	} {
		rec := f.approve(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", body, true)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "%s: %s", name, rec.Body.String())
	}
	rec = f.approve(approverPrincipal("alice"), "bad", "linux", "amd64", `{"sha256":"`+other+`"}`, true)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "coordinates are validated as on publish")
}

func TestApproveUppercaseHashAccepted(t *testing.T) {
	f := newApproveFixture(t)
	sha := f.publish("v1.0.0", "linux", "amd64", []byte("case"), false)
	rec := f.approveHash(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", strings.ToUpper(sha))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, f.approved("v1.0.0", "linux", "amd64", sha))
}

func TestApproveFailsClosedWithoutStores(t *testing.T) {
	f := newApproveFixture(t)
	sha := f.publish("v1.0.0", "linux", "amd64", []byte("no store"), false)

	f.srv.SetStewardBinaryApprovalStore(nil)
	rec := f.approveHash(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", sha)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "APPROVAL_UNAVAILABLE")

	wireTestStewardBinaryApprovalStore(t, f.srv)
	f.srv.auditManager = nil
	rec = f.approveHash(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", sha)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "no audit trail, no approval")
	assert.Contains(t, rec.Body.String(), "AUDIT_UNAVAILABLE")
	assert.False(t, f.approved("v1.0.0", "linux", "amd64", sha))
}

func TestApprovalAudited(t *testing.T) {
	f := newApproveFixture(t)
	sha := f.publish("v1.2.3", "darwin", "arm64", []byte("audited"), false)
	rec := f.approveHash(approverPrincipal("alice"), "v1.2.3", "darwin", "arm64", sha)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	entries := auditEntriesByAction(t, f.srv, auditActionStewardBinaryApprove)
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, "alice", e.UserID)
	assert.Equal(t, business.AuditResultSuccess, e.Result)
	assert.Equal(t, "alice", e.Details["principal"])
	assert.Equal(t, "v1.2.3", e.Details["version"])
	assert.Equal(t, "darwin", e.Details["platform"])
	assert.Equal(t, "arm64", e.Details["arch"])
	assert.Equal(t, sha, e.Details["sha256"])
}

// TestForceRepublishWithDifferentBytesUnapproves: an approval is bound to the bytes
// approved. After a force re-publish with different bytes no path hands the binary
// out, while the old record still exists but no longer matches.
func TestForceRepublishWithDifferentBytesUnapproves(t *testing.T) {
	stewards := []fleet.StewardData{{
		ID: "steward-1", TenantID: approveTestTenant, Status: "online",
		DNAAttributes: map[string]string{"runtime_os": "linux", "runtime_arch": "amd64", "deployment_ring": "pre-release"},
	}}
	server, _ := setupUpgradeServer(t, approveTestTenant, stewards)
	server.rolloutStore = newTestRolloutStore()
	f := newApproveFixtureOn(t, server, newStewardBinaryFixture(t))

	oldSHA := f.publish("v1.0.0", "linux", "amd64", []byte("original bytes"), false)
	require.Equal(t, http.StatusOK, f.approveHash(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", oldSHA).Code)
	require.Equal(t, http.StatusOK, doGetStewardBinaryPublic(server, "v1.0.0", "linux", "amd64", approveTestTenant).Code)

	newSHA := f.publish("v1.0.0", "linux", "amd64", []byte("replacement bytes"), true)
	require.NotEqual(t, oldSHA, newSHA)

	rec := doDispatchUpgrade(server, approveTestTenant, "id:steward-1", "v1.0.0", "linux", "amd64")
	assert.Equal(t, http.StatusForbidden, rec.Code, "dispatch is refused: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "NOT_APPROVED")

	assert.Equal(t, http.StatusNotFound, doGetStewardBinaryPublic(server, "v1.0.0", "linux", "amd64", approveTestTenant).Code,
		"self-fetch no longer serves the replaced bytes")

	rec = doStartRollout(server, approveTestTenant, "v1.0.0")
	assert.Equal(t, http.StatusForbidden, rec.Code, "rollout start is refused: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "NOT_APPROVED")

	old, err := server.stewardBinaryApproval(context.Background(), approveTestTenant, "v1.0.0", "linux", "amd64", oldSHA)
	require.NoError(t, err)
	require.NotNil(t, old, "the old record still exists")
	assert.Equal(t, "alice", old.ApprovedBy)
	approved, err := server.stewardBinaryApproved(context.Background(), approveTestTenant, "v1.0.0", "linux", "amd64", newSHA)
	require.NoError(t, err)
	assert.False(t, approved, "but it no longer matches the stored bytes")

	// Approving the replacement bytes restores every path.
	require.Equal(t, http.StatusOK, f.approveHash(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", newSHA).Code)
	assert.Equal(t, http.StatusAccepted, doDispatchUpgrade(server, approveTestTenant, "id:steward-1", "v1.0.0", "linux", "amd64").Code)
	assert.Equal(t, http.StatusOK, doGetStewardBinaryPublic(server, "v1.0.0", "linux", "amd64", approveTestTenant).Code)
}

func TestSelfFetchUnapprovedNotFoundThenServedAfterApproval(t *testing.T) {
	f := newApproveFixture(t)
	content := []byte("self-fetch me")
	sha := f.publish("v1.0.0", "linux", "amd64", content, false)

	rec := doGetStewardBinaryPublic(f.srv, "v1.0.0", "linux", "amd64", approveTestTenant)
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "BINARY_NOT_FOUND")
	assert.Empty(t, rec.Header().Get("X-CFGMS-Signature"), "an unapproved binary's metadata is not served")

	cacheKey := stewardBinaryDownloadCacheKey(approveTestTenant, "v1.0.0", "linux", "amd64")
	f.srv.publicDownloadCache.mu.Lock()
	_, cached := f.srv.publicDownloadCache.entries[cacheKey]
	f.srv.publicDownloadCache.mu.Unlock()
	assert.False(t, cached, "the 404 is not cached")

	require.Equal(t, http.StatusOK, f.approveHash(approverPrincipal("alice"), "v1.0.0", "linux", "amd64", sha).Code)
	rec = doGetStewardBinaryPublic(f.srv, "v1.0.0", "linux", "amd64", approveTestTenant)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, content, rec.Body.Bytes())
}

func TestSelfFetchFailsClosedWithoutApprovalStore(t *testing.T) {
	f := newApproveFixture(t)
	f.publish("v1.0.0", "linux", "amd64", []byte("no store"), false)
	f.srv.SetStewardBinaryApprovalStore(nil)

	rec := doGetStewardBinaryPublic(f.srv, "v1.0.0", "linux", "amd64", approveTestTenant)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "APPROVAL_UNAVAILABLE")
	f.srv.publicDownloadCache.mu.Lock()
	assert.Empty(t, f.srv.publicDownloadCache.entries, "nothing is cached for a failed check")
	f.srv.publicDownloadCache.mu.Unlock()
}

// TestTestAutoApproveRecordsApproval: the CFGMS_SEED_TEST_API_KEYS publish path
// approves through the same helper, as "auto-approved-test", with no blob label.
func TestTestAutoApproveRecordsApproval(t *testing.T) {
	f := newApproveFixture(t)
	f.srv.testAutoApproveStewardBinaries = true
	content := []byte("auto approved")
	sha := f.publish("v1.0.0", "linux", "amd64", content, false)

	rec, err := f.srv.stewardBinaryApproval(context.Background(), approveTestTenant, "v1.0.0", "linux", "amd64", sha)
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, "auto-approved-test", rec.ApprovedBy)
	assert.Equal(t, http.StatusOK, doGetStewardBinaryPublic(f.srv, "v1.0.0", "linux", "amd64", approveTestTenant).Code)

	rc, meta, err := f.srv.blobStore.GetBlob(context.Background(), stewardBinaryBlobKey(approveTestTenant, "v1.0.0", "linux", "amd64"))
	require.NoError(t, err)
	_ = rc.Close()
	assert.NotContains(t, meta.Labels, "approved_by", "the approval is a record, not a blob label")

	// Without an approval store the test mode cannot approve and publish reports it.
	f.srv.SetStewardBinaryApprovalStore(nil)
	req := httptest.NewRequest(http.MethodPost, "/x?signature="+f.fix.signContent([]byte("two"), "v1.0.1", "linux", "amd64"), bytes.NewReader([]byte("two")))
	req = withScopedPrincipal(req, approveTestTenant)
	req = mux.SetURLVars(req, map[string]string{"version": "v1.0.1", "platform": "linux", "arch": "amd64"})
	w := httptest.NewRecorder()
	f.srv.handlePublishStewardBinary(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
