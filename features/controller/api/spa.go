// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package api

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/cfgis/cfgms/web"
)

// Embedded SPA roots, in preference order.
//
// The frontend build writes to web/dist/app/ (vite.config.ts build.outDir), which
// web/.gitignore excludes wholesale. web/dist/index.html is a tracked placeholder
// that no build ever rewrites — it exists only so //go:embed all:dist has a file
// to match, keeping `go build` self-contained with no Node toolchain (Issue #3043).
const (
	spaBuildRoot = "dist/app" // real Vite output, present only after npm run build
	spaEmbedRoot = "dist"     // embed anchor; holds the placeholder on a clean checkout
)

// distPlaceholderSentinel marks the tracked web/dist/index.html placeholder.
// Real Vite output never contains it, because the build never writes to that
// path. Its presence in the embedded index.html therefore means "no frontend
// build was embedded in this binary".
const distPlaceholderSentinel = "CFGMS_DIST_PLACEHOLDER"

var (
	// errSPAPlaceholder reports that the embedded index.html is the tracked
	// placeholder rather than a frontend build. Serving it would present an
	// empty shell that looks like a working — but permanently stale — SPA, so
	// the caller refuses to route "/" instead (Issue #3043, AC5).
	errSPAPlaceholder = errors.New("embedded SPA is the tracked web/dist placeholder, not a frontend build: run \"npm run build\" in web/ before building the controller binary")

	// errSPANoIndex reports that no index.html exists in the embedded tree.
	errSPANoIndex = errors.New("embedded SPA has no index.html")
)

// spaAssets is the embedded asset tree the SPA is served from. It is a variable
// rather than a direct web.Assets reference so tests can substitute a synthetic
// tree; production always uses the embedded assets.
var spaAssets fs.FS = web.Assets

// newEmbeddedSPAHandler resolves the SPA root inside assets and returns a handler
// for it. It prefers the frontend build at dist/app and falls back to dist, which
// on a checkout with no build carries only the placeholder.
//
// It returns an error — rather than a handler over the placeholder — whenever no
// real build is embedded, so the caller can refuse to route "/" loudly instead of
// silently serving a shell that never loads the application.
func newEmbeddedSPAHandler(assets fs.FS) (*spaHandler, error) {
	var lastErr error
	for _, root := range []string{spaBuildRoot, spaEmbedRoot} {
		sub, err := fs.Sub(assets, root)
		if err != nil {
			lastErr = fmt.Errorf("resolve %s: %w", root, err)
			continue
		}
		if err := validateSPARoot(sub); err != nil {
			lastErr = err
			continue
		}
		return newSPAHandler(sub), nil
	}
	return nil, lastErr
}

// validateSPARoot reports whether root holds a servable frontend build.
func validateSPARoot(root fs.FS) error {
	content, err := fs.ReadFile(root, "index.html")
	if err != nil {
		return errors.Join(errSPANoIndex, err)
	}
	if bytes.Contains(content, []byte(distPlaceholderSentinel)) {
		return errSPAPlaceholder
	}
	return nil
}

// spaCSP is the Content-Security-Policy applied to all SPA responses.
// 'self' only — no external origins. Vite emits hashed filenames so no inline
// scripts/styles are generated; no nonce machinery is needed. frame-ancestors,
// base-uri, and object-src close the clickjacking/injection surface (ADR-018,
// Issue #2494).
const spaCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"

// spaHandler serves the embedded web UI with SPA fallback routing.
//
// Route precedence: all /api/* and /raft/* routes are registered before the
// PathPrefix("/") catch-all in setupRouter, so those routes always take
// precedence. This handler is the lowest-priority catch-all; it additionally
// checks the path prefix to ensure unmatched /api/* and /raft/* requests
// receive a 404 instead of the SPA index.
type spaHandler struct {
	fileServer http.Handler
	distFS     fs.FS
}

// newSPAHandler returns a spaHandler that serves from distFS (already the dist
// root, not a parent containing dist/).
func newSPAHandler(distFS fs.FS) *spaHandler {
	return &spaHandler{
		fileServer: http.FileServer(http.FS(distFS)),
		distFS:     distFS,
	}
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path

	// API and raft paths are never handled by the SPA. Return 404 for all
	// methods so that unregistered API routes produce 404 (not 405), preserving
	// the behaviour that existed before the SPA catch-all was added.
	if strings.HasPrefix(urlPath, "/api/") || urlPath == "/api" ||
		strings.HasPrefix(urlPath, "/raft/") || urlPath == "/raft" {
		http.NotFound(w, r)
		return
	}

	// SPA paths are served only for GET and HEAD.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Resolve the path to a file in the embedded FS.
	// path.Clean normalises ".." and double-slash sequences in URL paths.
	fsPath := path.Clean(urlPath)
	switch fsPath {
	case "/", ".":
		fsPath = "index.html"
	default:
		fsPath = strings.TrimPrefix(fsPath, "/")
	}

	// Determine whether to serve the requested file or fall back to index.html.
	//
	// index.html is always served directly (not via http.FileServer) because
	// Go's http.FileServer redirects explicit /index.html requests to /, which
	// would produce a 301 instead of the 200 expected for SPA deep-link fallback.
	serveIndex := fsPath == "index.html"
	if !serveIndex {
		if _, err := h.distFS.Open(fsPath); err != nil {
			serveIndex = true
		}
	}

	// Cache policy:
	//   index.html (and SPA fallback) — no-store so browsers always fetch the
	//     latest shell and pick up new hashed asset references.
	//   assets/* — long immutable cache because Vite embeds a content hash in
	//     every filename, making stale-serving impossible.
	cacheControl := "no-store"
	if !serveIndex && strings.HasPrefix(fsPath, "assets/") {
		cacheControl = "public, max-age=31536000, immutable"
	}

	sw := &spaResponseWriter{ResponseWriter: w, cacheControl: cacheControl}

	if serveIndex {
		// Read and serve index.html directly so that:
		//   - deep-link fallback returns 200 (not a 301 redirect)
		//   - explicit /index.html requests are served without the FileServer
		//     redirect to /
		content, err := fs.ReadFile(h.distFS, "index.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		sw.Header().Set("Content-Type", "text/html; charset=utf-8")
		sw.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = sw.Write(content)
		}
		return
	}

	h.fileServer.ServeHTTP(sw, r)
}

// spaResponseWriter wraps http.ResponseWriter to inject security and cache
// headers before the first byte is written, regardless of what http.FileServer
// sets for Content-Type, ETag, or Last-Modified.
type spaResponseWriter struct {
	http.ResponseWriter
	cacheControl   string
	headersWritten bool
}

func (w *spaResponseWriter) WriteHeader(code int) {
	if !w.headersWritten {
		w.headersWritten = true
		h := w.Header()
		h.Set("Content-Security-Policy", spaCSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cache-Control", w.cacheControl)
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *spaResponseWriter) Write(b []byte) (int, error) {
	if !w.headersWritten {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *spaResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
