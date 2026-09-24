// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgcontroller "github.com/cfgis/cfgms/features/controller"
	controllerConfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// repoRoot resolves the repository root from this test's own package directory
// (test/integration/controller), matching docker_helper.go's "../../../" convention.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := filepath.Abs(filepath.Join(wd, "..", "..", ".."))
	require.NoError(t, err)
	return root
}

// freePort returns an available TCP port on localhost.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// newHealthTestControllerConfig builds a minimal real controller config (flatfile
// storage, auto-generated certs) under t.TempDir(), mirroring
// test/integration/session_store_test.go's newTestControllerConfig.
func newHealthTestControllerConfig(t *testing.T, httpPort int) *controllerConfig.Config {
	t.Helper()
	root := t.TempDir()
	certPath := filepath.Join(root, "certs")
	require.NoError(t, os.MkdirAll(certPath, 0755))
	return &controllerConfig.Config{
		ListenAddr:        fmt.Sprintf("127.0.0.1:%d", httpPort),
		ExternalURL:       fmt.Sprintf("https://127.0.0.1:%d", httpPort),
		MetricsListenAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		CertPath:          certPath,
		DataDir:           filepath.Join(root, "data"),
		AdminBundlePath:   filepath.Join(root, "admin.bundle.yaml"),
		Storage: &controllerConfig.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: filepath.Join(root, "storage"),
			SQLitePath:   filepath.Join(root, "storage", "entity-graph.db"),
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

// waitForHealthControllerReadyOrErr polls GET /api/v1/health until the controller
// answers, or fails fast if ctrl.Start returns a non-nil error early. ctrl.Start
// itself returns nil once startup completes (the HTTP server keeps serving on its
// own goroutine), so a nil read from errCh just means "startup finished" — not a
// failure — and errCh must not be selected on again afterwards.
func waitForHealthControllerReadyOrErr(t *testing.T, client *http.Client, base string, timeout time.Duration, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if errCh != nil {
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("controller Start returned early: %v", err)
				}
				errCh = nil // already consumed the single buffered value
			default:
			}
		}
		resp, err := client.Get(base + "/api/v1/health")
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

// startHealthTestController boots a real controller (real storage, real certs, real
// HTTP server) and returns it, its base URL, and an admin-mTLS *http.Client
// (ImplicitAdmin, per features/controller/api/middleware.go) authorized for every
// permission — including the monitoring:read-* gates the new health-detail routes
// carry (Issue #4208, AC1).
func startHealthTestController(t *testing.T) (*cfgcontroller.Controller, string, string, *http.Client) {
	t.Helper()
	ctrl, _, base, metricsBase, client := startHealthTestControllerWithConfig(t, nil)
	return ctrl, base, metricsBase, client
}

// startHealthTestControllerWithConfig is startHealthTestController's full form: it also
// returns the resolved *controllerConfig.Config, and — when beforeStart is non-nil —
// invokes it after initialization.Run but before ctrl.Start. That gap is the only window
// in which on-disk state can be seeded ahead of the real controller reading it at startup
// (e.g. pre-populating the module cache directory the way a real deployment's disk would
// already contain bundles — Issue #4270, AC4).
func startHealthTestControllerWithConfig(t *testing.T, beforeStart func(cfg *controllerConfig.Config)) (*cfgcontroller.Controller, *controllerConfig.Config, string, string, *http.Client) {
	t.Helper()
	testutil.SetupSecretsEnvForTest(t)
	cfg := newHealthTestControllerConfig(t, freePort(t))

	// First-run initialization (`controller --init`, features/controller/initialization.Run)
	// creates the CA and writes the init marker server.New's guard requires — real
	// controllers refuse to start without it (Issue #4208's test must go through the
	// same bootstrap a production controller does, not bypass it).
	_, err := initialization.Run(cfg, logging.NewNoopLogger())
	require.NoError(t, err, "initialization.Run")

	if beforeStart != nil {
		beforeStart(cfg)
	}

	ctrl, err := cfgcontroller.New(cfg, logging.NewNoopLogger())
	require.NoError(t, err, "controller.New")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() { errCh <- ctrl.Start(ctx) }()

	certMgr := ctrl.GetCertificateManager()
	require.NotNil(t, certMgr, "controller certificate manager")

	adminBundle, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "integ-health-admin",
		Organization:     "CFGMS",
		ValidityDays:     1,
		KeySize:          2048,
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err, "GenerateClientCertificate")
	adminTLSCert, err := tls.X509KeyPair(adminBundle.CertificatePEM, adminBundle.PrivateKeyPEM)
	require.NoError(t, err, "X509KeyPair")

	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)
	caPool := x509.NewCertPool()
	require.True(t, caPool.AppendCertsFromPEM(caPEM), "CA pool append")

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{adminTLSCert},
				RootCAs:      caPool,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}

	base := fmt.Sprintf("https://%s", cfg.ListenAddr)
	metricsBase := fmt.Sprintf("https://%s", cfg.MetricsListenAddr)
	waitForHealthControllerReadyOrErr(t, client, base, 30*time.Second, errCh)

	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		if err := ctrl.Stop(stopCtx); err != nil && !strings.Contains(err.Error(), "not running") {
			t.Logf("controller Stop: %v", err)
		}
	})

	return ctrl, cfg, base, metricsBase, client
}

// TestHealthDetailRoutes_EndToEnd is the AC2 [REQUIRED TEST]: cfg controller status,
// cfg controller metrics and cfg trace <id> succeed end-to-end against a real
// controller (real storage, real certs, real HTTP), asserting the response body
// shape the CLI decodes (cmd/cfg/cmd/controller.go's runControllerStatus /
// runControllerMetrics, cmd/cfg/cmd/trace.go's runTrace). The CLI's own request
// construction (cmd/cfg/cmd/api_client.go) is unexported and lives in a separate
// module boundary from this integration package, so this test issues the identical
// GET requests those commands issue and decodes into the same field shape.
func TestHealthDetailRoutes_EndToEnd(t *testing.T) {
	ctrl, base, metricsBase, client := startHealthTestController(t)

	t.Run("controller status (GET /api/v1/health/detailed)", func(t *testing.T) {
		resp, err := client.Get(base + "/api/v1/health/detailed")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var status struct {
			Status        string    `json:"status"`
			Timestamp     time.Time `json:"timestamp"`
			UptimeSeconds int64     `json:"uptime_seconds"`
			Components    map[string]struct {
				Name      string                 `json:"name"`
				Status    string                 `json:"status"`
				Message   string                 `json:"message"`
				LastCheck time.Time              `json:"last_check"`
				Details   map[string]interface{} `json:"details"`
			} `json:"components"`
			Alerts []struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			} `json:"alerts"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&status))
		assert.NotEmpty(t, status.Status)
		assert.False(t, status.Timestamp.IsZero())
	})

	t.Run("controller metrics (GET /api/v1/health/metrics) on the private metrics listener", func(t *testing.T) {
		// health.Collector metrics stay off the public listener (#3156): the
		// route is served only on metrics_listen_addr, which is what
		// `cfg controller metrics --url` must point at.
		public, err := client.Get(base + "/api/v1/health/metrics")
		require.NoError(t, err)
		_ = public.Body.Close()
		require.Equal(t, http.StatusNotFound, public.StatusCode, "metrics must not be served on the public listener")

		resp, err := client.Get(metricsBase + "/api/v1/health/metrics")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var metrics struct {
			Timestamp time.Time `json:"timestamp"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&metrics))
		assert.False(t, metrics.Timestamp.IsZero())
	})

	t.Run("trace (GET /api/v1/health/trace/{request_id})", func(t *testing.T) {
		traceMgr := ctrl.GetHealthTraceManager()
		require.NotNil(t, traceMgr, "controller health trace manager")

		seeded, _ := traceMgr.StartTrace("integration-test-op", "integration-test-component")
		traceMgr.EndTrace(seeded, "completed", "")

		resp, err := client.Get(base + "/api/v1/health/trace/" + seeded.RequestID)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var trace struct {
			RequestID string `json:"request_id"`
			Operation string `json:"operation"`
			Component string `json:"component"`
			Status    string `json:"status"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&trace))
		assert.Equal(t, seeded.RequestID, trace.RequestID)
		assert.Equal(t, "integration-test-op", trace.Operation)
		assert.Equal(t, "integration-test-component", trace.Component)
		assert.Equal(t, "completed", trace.Status)

		t.Run("unknown request id returns 404, not the router's 404", func(t *testing.T) {
			resp, err := client.Get(base + "/api/v1/health/trace/does-not-exist")
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	})
}

// sprintfVerbRe matches fmt-style verbs (%s, %d, %v, %q, ...) inside a path literal.
var sprintfVerbRe = regexp.MustCompile(`%[a-zA-Z]`)

// flattenPathConcat statically flattens a string-concatenation expression
// ("/api/v1/foo/" + url.PathEscape(id) + "/bar") into a path template, substituting
// "test-placeholder" for any operand that isn't itself a string literal or a nested
// "+" concatenation (e.g. a function call or identifier standing in for a path
// segment value).
func flattenPathConcat(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		left, leftOK := flattenPathConcat(v.X)
		if !leftOK {
			left = "test-placeholder"
		}
		right, rightOK := flattenPathConcat(v.Y)
		if !rightOK {
			// An unresolved operand (function call, identifier) only stands in for a
			// path segment when it's positioned like one (immediately after a "/",
			// e.g. "/api/v1/accounts/" + username). Otherwise — e.g. "/api/v1/roles" +
			// roleTenantQuery(), which returns "" or "?tenant=..." — it's a suffix, not
			// a segment, and forcing a placeholder there would fabricate a path
			// ("/api/v1/rolestest-placeholder") that was never a real route.
			if strings.HasSuffix(left, "/") {
				right = "test-placeholder"
			} else {
				right = ""
			}
		}
		return left + right, true
	default:
		return "", false
	}
}

// normalizeAPIPath strips any baked-in query string, replaces fmt.Sprintf verbs and
// unresolved concatenation operands with a single placeholder path segment, and pads
// a literal that ends mid-path (e.g. "/api/v1/accounts/" awaiting a concatenated
// username) with a trailing placeholder segment so the result is always a concrete,
// requestable path.
func normalizeAPIPath(raw string) string {
	if idx := strings.Index(raw, "?"); idx >= 0 {
		raw = raw[:idx]
	}
	raw = sprintfVerbRe.ReplaceAllString(raw, "test-placeholder")
	if strings.HasSuffix(raw, "/") {
		raw += "test-placeholder"
	}
	return raw
}

// cliAPIV1Paths statically scans every non-test .go file in cmd/cfg/cmd for
// "/api/v1/..." string literals — plain literals, fmt.Sprintf format strings (whose
// format string is itself a plain literal), and "+"-concatenated path expressions —
// and returns the deduplicated, normalized set. This is AC3's enumeration: every
// controller REST path the CLI is known to call.
func cliAPIV1Paths(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "cmd", "cfg", "cmd")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	fset := token.NewFileSet()
	seen := make(map[string]bool)
	var paths []string
	add := func(raw string) {
		norm := normalizeAPIPath(raw)
		if norm == "" || seen[norm] {
			return
		}
		seen[norm] = true
		paths = append(paths, norm)
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		require.NoError(t, err, "parsing %s", name)

		ast.Inspect(file, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.BinaryExpr:
				if e.Op != token.ADD {
					return true
				}
				if s, ok := flattenPathConcat(e); ok {
					// A leading dynamic operand (e.g. a base-URL prefix) means the
					// literal path doesn't start the flattened string — find it
					// rather than requiring an exact prefix match.
					if idx := strings.Index(s, "/api/v1"); idx >= 0 {
						add(s[idx:])
					}
				}
				return false // already flattened; don't re-visit the sub-literals individually
			case *ast.BasicLit:
				if e.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(e.Value)
				if err == nil && strings.HasPrefix(s, "/api/v1") {
					add(s)
				}
			}
			return true
		})
	}

	sort.Strings(paths)
	require.NotEmpty(t, paths, "expected to find /api/v1/... literals in cmd/cfg/cmd")
	return paths
}

// routerCatchAll404 is the exact body http.NotFound (used by
// features/controller/api/middleware.go's notFoundHandler, the router's
// NotFoundHandler) writes — distinct from any handler's own JSON-shaped business
// 404 (e.g. "trace not found"), which proves the route WAS matched.
const routerCatchAll404 = "404 page not found"

// TestCLIAPIV1RoutesAreRegistered is the AC3 [REQUIRED TEST]: every /api/v1/...
// path string referenced by the cfg CLI must resolve to a registered route on the
// controller router, so a handler that exists but was never wired (exactly this
// issue's bug) is caught automatically instead of silently shipping.
//
// A registered route can still answer 401/403 (auth/permission denied for this
// specific request shape) or a handler's own business 4xx/5xx (e.g. "trace not
// found") — those all prove the router matched a route. Only the router's own
// catch-all 404 (http.NotFound, plain-text "404 page not found") proves the
// opposite, so that exact body is what this test treats as a failure.
//
// The CLI call site (not scanned here — see cliAPIV1Paths) picks one specific
// HTTP method per path, but gorilla/mux's subrouters answer a method mismatch
// on an otherwise-real route with the very same catch-all 404 body a genuinely
// unregistered path gets (verified empirically: GET against the POST-only
// /api/v1/certificates/signing/rotate 404s exactly like an unknown path, while
// POST against it reaches the handler). So a path is only reported unregistered
// here if every common REST verb 404s the same way — one real match under any
// verb proves the router has a route for this path template.
var candidateMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

// knownUnregisteredCLIPaths are enumeration findings outside Issue #4208's own
// scope (its "Out of Scope" section covers only the three health/metrics/trace
// routes named in the story). Per AC3, any other unregistered path this
// enumeration finds is fixed here or filed as a separate fix issue and noted
// in the PR body. Issue #4270 closed the two gaps this enumeration originally
// found here: GET /api/v1/modules is now registered
// (features/controller/api/routes_modules.go), and cmd/cfg/cmd/module.go no
// longer builds ".../modules/{publisher}/{name}/{version}/approve" at all —
// runModuleApprove now resolves an address via GET /api/v1/modules/approvals
// and POSTs to the pre-existing .../modules/approvals/{address}/approve route,
// which this same enumeration also now finds and confirms registered.
var knownUnregisteredCLIPaths = map[string]string{}

// privateListenerCLIPaths are CLI-called routes served only on the private
// metrics listener (#3156); the scan checks them there, not on the public one.
var privateListenerCLIPaths = map[string]string{
	"/api/v1/health/metrics": "health.Collector metrics (Issue #4208)",
}

func TestCLIAPIV1RoutesAreRegistered(t *testing.T) {
	paths := cliAPIV1Paths(t)
	_, base, metricsBase, client := startHealthTestController(t)

	for _, p := range paths {
		p := p
		t.Run(p, func(t *testing.T) {
			if issue, known := knownUnregisteredCLIPaths[p]; known {
				t.Skipf("known gap, tracked separately (%s)", issue)
			}
			target := base
			if _, private := privateListenerCLIPaths[p]; private {
				target = metricsBase
			}
			matched := false
			for _, method := range candidateMethods {
				req, err := http.NewRequest(method, target+p, nil)
				require.NoError(t, err)
				resp, err := client.Do(req)
				require.NoError(t, err)
				body := make([]byte, 512)
				n, _ := resp.Body.Read(body)
				_ = resp.Body.Close()

				if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(body[:n]), routerCatchAll404) {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("route %s resolved to the router's catch-all 404 under every REST verb (handler exists but was never registered?)", p)
			}
		})
	}
}
