// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package testutil

import (
	"encoding/pem"
	"net/http"
	"net/http/cgi" // #nosec G504 -- test-only git smart-HTTP server for git http-backend; Httpoxy (CVE-2016-5386) fixed in Go >= 1.6.3
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// NewGitServer serves the git repositories found directly under reposRoot over
// TLS with git's own smart-HTTP CGI (git http-backend) and returns the base URL
// (a repository "mod" is cloned from "<base>/mod") and the path of a PEM file
// holding the server's certificate, which the caller trusts by pointing
// GIT_SSL_CAINFO at it with t.Setenv — and therefore must not call t.Parallel().
//
// It fails the test, never skips, if git or its http-backend is unavailable.
func NewGitServer(t testing.TB, reposRoot string) (baseURL, caFile string) {
	t.Helper()

	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Fatalf("git binary not found in PATH; the git test server requires git and git http-backend: %v", err)
	}
	// #nosec G204 -- fixed binary and fixed argument.
	out, err := exec.Command(gitBin, "--exec-path").Output()
	if err != nil {
		t.Fatalf("git --exec-path failed: %v", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if runtime.GOOS == "windows" {
		backend += ".exe"
	}
	if _, err := os.Stat(backend); err != nil {
		t.Fatalf("git http-backend not found at %s; install a git build that ships it: %v", backend, err)
	}

	root, err := filepath.Abs(reposRoot)
	if err != nil {
		t.Fatalf("resolve repositories root: %v", err)
	}
	handler := &cgi.Handler{
		Path: backend,
		Env: []string{
			"GIT_PROJECT_ROOT=" + root,
			"GIT_HTTP_EXPORT_ALL=1",
			"GIT_CONFIG_NOSYSTEM=1",
		},
		InheritEnv: []string{"PATH", "SYSTEMROOT", "HOME", "USERPROFILE", "TMP", "TEMP", "TMPDIR"},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(handler.ServeHTTP))
	t.Cleanup(srv.Close)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	caFile = filepath.Join(t.TempDir(), "git-server-ca.pem")
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatalf("write git server CA file: %v", err)
	}
	return srv.URL, caFile
}
