// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package api

import (
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
