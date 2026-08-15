// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package api

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSPAFS returns a minimal in-memory FS that mimics a Vite dist/ output.
func testSPAFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html": &fstest.MapFile{
			Data: []byte("<!DOCTYPE html><html><body>SPA</body></html>"),
		},
		"assets/app-Dh9fZ4zy.js": &fstest.MapFile{
			Data: []byte("// hashed asset"),
		},
		"assets/style-abc123.css": &fstest.MapFile{
			Data: []byte("/* hashed css */"),
		},
	}
}

// testPlaceholderIndex mirrors the tracked web/dist/index.html: a static shell
// carrying the sentinel and no content-hashed asset references.
const testPlaceholderIndex = `<!doctype html>
<!-- ` + distPlaceholderSentinel + ` this is a tracked placeholder, not a build -->
<html lang="en"><head><title>CFGMS</title></head><body><div id="root"></div></body></html>`

// testEmbeddedAssetsPlaceholderOnly mimics a clean checkout with no frontend
// build: web/dist holds only the placeholder, and web/dist/app does not exist.
func testEmbeddedAssetsPlaceholderOnly() fstest.MapFS {
	return fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte(testPlaceholderIndex)},
	}
}

// testEmbeddedAssetsWithBuild mimics a checkout after npm run build: the
// placeholder is still tracked at dist/index.html and the real output sits
// under dist/app/.
func testEmbeddedAssetsWithBuild() fstest.MapFS {
	assets := testEmbeddedAssetsPlaceholderOnly()
	assets["dist/app/index.html"] = &fstest.MapFile{
		Data: []byte(`<!doctype html><html><head><script type="module" crossorigin src="/assets/app-Dh9fZ4zy.js"></script></head><body><div id="root"></div></body></html>`),
	}
	assets["dist/app/assets/app-Dh9fZ4zy.js"] = &fstest.MapFile{Data: []byte("// hashed asset")}
	return assets
}

// withEmbeddedSPA substitutes the embedded asset tree the router wires up. It
// must be called BEFORE the test server is constructed: setupRouter resolves
// spaAssets once, at construction time.
func withEmbeddedSPA(t *testing.T, assets fs.FS) {
	t.Helper()
	prev := spaAssets
	prevChosen := spaAssetsChosen
	spaAssets = assets
	spaAssetsChosen = true
	t.Cleanup(func() { spaAssets = prev; spaAssetsChosen = prevChosen })
}

// spaAssetsChosen records that a test has deliberately substituted the embedded
// asset tree, so withDefaultEmbeddedSPA knows to leave it alone.
var spaAssetsChosen bool

// withDefaultEmbeddedSPA gives a test server a synthetic frontend build unless
// the test already chose its own tree (Issue #3043).
//
// Go tests never run `npm run build`, so web/dist holds only the tracked
// placeholder and setupRouter refuses to route "/" and logs the refusal. Two
// things break as a result, and neither looks like an SPA problem:
//
//   - TestRouteTableParity is short by exactly "* /", reading as "routes added
//     or removed during refactor".
//   - Every test asserting on a logged "error" value reads the SPA refusal
//     rather than its own fault, because the refusal is logged at construction
//     and kvValue() returns the FIRST match for a key.
//
// The guard matters: tests that exercise the placeholder path call
// withEmbeddedSPA themselves before constructing a server, and a default that
// overwrote that choice would silently invert what they assert.
func withDefaultEmbeddedSPA(t *testing.T) {
	t.Helper()
	if spaAssetsChosen {
		return
	}
	withEmbeddedSPA(t, testEmbeddedAssetsWithBuild())
}

// Issue #3043 — a binary embedding only the tracked placeholder must fail loudly
// rather than serve a shell that never loads the application (stale-SPA =
// patch-lag bug).
func TestNewEmbeddedSPAHandlerRejectsPlaceholder(t *testing.T) {
	h, err := newEmbeddedSPAHandler(testEmbeddedAssetsPlaceholderOnly())

	require.Error(t, err, "placeholder-only assets must not produce a servable SPA handler")
	assert.Nil(t, h)
	assert.ErrorIs(t, err, errSPAPlaceholder)
	assert.Contains(t, err.Error(), "npm run build",
		"the error must tell the operator how to produce a real build")
}

func TestNewEmbeddedSPAHandlerRejectsMissingIndex(t *testing.T) {
	assets := fstest.MapFS{
		"dist/robots.txt": &fstest.MapFile{Data: []byte("User-agent: *\n")},
	}

	h, err := newEmbeddedSPAHandler(assets)

	require.Error(t, err)
	assert.Nil(t, h)
	assert.ErrorIs(t, err, errSPANoIndex)
}

// The real build lives at dist/app; the placeholder at dist/index.html must not
// shadow it.
func TestNewEmbeddedSPAHandlerPrefersBuildOutput(t *testing.T) {
	h, err := newEmbeddedSPAHandler(testEmbeddedAssetsWithBuild())
	require.NoError(t, err)
	require.NotNil(t, h)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.NotContains(t, rr.Body.String(), distPlaceholderSentinel,
		"the placeholder must never be served when a build is embedded")
	assert.Contains(t, rr.Body.String(), "/assets/app-Dh9fZ4zy.js")

	// Assets resolve relative to the same root.
	rrAsset := httptest.NewRecorder()
	h.ServeHTTP(rrAsset, httptest.NewRequest(http.MethodGet, "/assets/app-Dh9fZ4zy.js", nil))
	assert.Equal(t, http.StatusOK, rrAsset.Code)
}

// A real build written directly to dist/ (rather than dist/app/) is still
// servable — the placeholder sentinel, not the path, is what marks "no build".
func TestNewEmbeddedSPAHandlerAcceptsBuildAtDistRoot(t *testing.T) {
	assets := fstest.MapFS{
		"dist/index.html": &fstest.MapFile{Data: []byte("<!doctype html><html><body>SPA</body></html>")},
	}

	h, err := newEmbeddedSPAHandler(assets)

	require.NoError(t, err)
	require.NotNil(t, h)
}

// Issue #3043 AC5 — end to end through the real router: a controller whose
// binary embeds only the placeholder must refuse to route "/" rather than serve
// the placeholder shell as if it were the application.
func TestSetupRouterRefusesRootWhenOnlyPlaceholderEmbedded(t *testing.T) {
	withEmbeddedSPA(t, testEmbeddedAssetsPlaceholderOnly())
	server := setupRouteTestServer(t)

	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusNotFound, rr.Code,
		"\"/\" must not be routed when only the dist placeholder is embedded")
	assert.NotContains(t, rr.Body.String(), distPlaceholderSentinel,
		"the placeholder must never reach a client")
	assert.NotContains(t, rr.Body.String(), "<div id=\"root\">",
		"the placeholder shell must never be served as the SPA")
}

// The counterpart: with a real build embedded, "/" is routed normally — proving
// the refusal above is specific to the placeholder, not a broken catch-all.
func TestSetupRouterServesRootWhenBuildEmbedded(t *testing.T) {
	withEmbeddedSPA(t, testEmbeddedAssetsWithBuild())
	server := setupRouteTestServer(t)

	rr := httptest.NewRecorder()
	server.router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "/assets/app-Dh9fZ4zy.js")
}

func TestSPAHandlerAssetLongCache(t *testing.T) {
	h := newSPAHandler(testSPAFS())

	req := httptest.NewRequest(http.MethodGet, "/assets/app-Dh9fZ4zy.js", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	cc := rr.Header().Get("Cache-Control")
	assert.Contains(t, cc, "max-age=31536000", "hashed assets must get long immutable cache")
	assert.Contains(t, cc, "immutable")
}

func TestSPAHandlerIndexNoStore(t *testing.T) {
	h := newSPAHandler(testSPAFS())

	for _, urlPath := range []string{"/", "/index.html"} {
		t.Run(urlPath, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, urlPath, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		})
	}
}

func TestSPAHandlerFallbackNoStore(t *testing.T) {
	h := newSPAHandler(testSPAFS())

	req := httptest.NewRequest(http.MethodGet, "/unknown/deep/link", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Contains(t, rr.Body.String(), "SPA", "fallback must serve index.html")
}

func TestSPAHandlerSecurityHeadersOnAsset(t *testing.T) {
	h := newSPAHandler(testSPAFS())

	req := httptest.NewRequest(http.MethodGet, "/assets/app-Dh9fZ4zy.js", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	csp := rr.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'self'")
	assert.Contains(t, csp, "frame-ancestors 'none'")
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.NotEmpty(t, rr.Header().Get("Referrer-Policy"))
}

func TestSPAHandlerAPIPathGuard(t *testing.T) {
	h := newSPAHandler(testSPAFS())

	for _, urlPath := range []string{"/api/v1/foo", "/api", "/raft/message", "/raft"} {
		t.Run(urlPath, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, urlPath, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusNotFound, rr.Code,
				"spaHandler must return 404 for %s, not serve SPA", urlPath)
			assert.NotContains(t, rr.Body.String(), "SPA")
		})
	}
}

func TestSPAHandlerMethodNotAllowed(t *testing.T) {
	h := newSPAHandler(testSPAFS())

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
		})
	}
}

func TestSPAHandlerPathTraversalUnit(t *testing.T) {
	h := newSPAHandler(testSPAFS())

	// All traversal paths clean to paths that don't exist in the test FS,
	// so the handler falls back to index.html (200 + SPA body). The key
	// security property is that no content from outside the embedded FS is
	// served — the assert.NotContains below is the authoritative guard.
	for _, urlPath := range []string{"/../secret", "/..%2fsecret", "/%2e%2e/secret"} {
		t.Run(urlPath, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, urlPath, nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			// Must be 200 (SPA fallback to index.html). 4xx and 5xx responses
			// do not indicate traversal, but a 200 with the correct SPA body
			// confirms the FS boundary was respected.
			assert.Equal(t, http.StatusOK, rr.Code,
				"traversal path %s must fall back to index.html (200)", urlPath)
			body := rr.Body.String()
			assert.Contains(t, body, "SPA",
				"traversal path %s must serve index.html content, got: %s", urlPath, body)
			assert.NotContains(t, body, "module github.com/cfgis/cfgms",
				"traversal path %s must not leak go.mod content", urlPath)
		})
	}
}
