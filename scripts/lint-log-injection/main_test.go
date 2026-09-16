// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAnalyzeFile_FlagsStringFromDecodedBody is the canonical positive case:
// a string field on a json-Decoded request body, logged without a sanitizer,
// must be reported. This is the CodeQL "Log entries created from user input"
// pattern the linter exists to catch.
func TestAnalyzeFile_FlagsStringFromDecodedBody(t *testing.T) {
	src := `package api
import "encoding/json"
import "net/http"
type req struct { Name string }
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	var rq req
	json.NewDecoder(r.Body).Decode(&rq)
	s.logger.Info("got", "name", rq.Name)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, "rq.Name") {
		t.Errorf("expected finding to name rq.Name, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_SkipsScalarFromDecodedBody covers the false-positive that
// broke PR #1772 in CI: a `bool` (or any non-string scalar) field on a tainted
// struct cannot carry an injection payload. CodeQL doesn't flag these, neither
// should this linter — flagging them blocks legitimate merges and trains
// developers to ignore the lint.
func TestAnalyzeFile_SkipsScalarFromDecodedBody(t *testing.T) {
	cases := []struct {
		name      string
		fieldType string
	}{
		{"bool", "bool"},
		{"int", "int"},
		{"int64", "int64"},
		{"uint32", "uint32"},
		{"float64", "float64"},
		{"time.Time", "time.Time"},
		{"time.Duration", "time.Duration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := `package api
import "encoding/json"
import "net/http"
import "time"
var _ = time.Now
type req struct { Flag ` + tc.fieldType + ` }
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	var rq req
	json.NewDecoder(r.Body).Decode(&rq)
	s.logger.Info("got", "flag", rq.Flag)
}
`
			findings := analyzeSnippet(t, src)
			if len(findings) != 0 {
				t.Errorf("expected 0 findings for scalar field %s, got: %v", tc.fieldType, findings)
			}
		})
	}
}

// TestAnalyzeFile_FlagsStringSiblingOfScalar ensures the scalar suppression is
// per-field, not per-struct: a struct with one bool and one string still flags
// the string. Catches a regression where an overzealous fix might skip the
// whole tainted-struct branch the moment any scalar field is seen.
func TestAnalyzeFile_FlagsStringSiblingOfScalar(t *testing.T) {
	src := `package api
import "encoding/json"
import "net/http"
type req struct {
	Name string
	Verified bool
}
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	var rq req
	json.NewDecoder(r.Body).Decode(&rq)
	s.logger.Info("got",
		"name", rq.Name,
		"verified", rq.Verified,
	)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (rq.Name only), got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, "rq.Name") {
		t.Errorf("expected rq.Name flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_AcceptsSanitizedString is the negative case the linter must
// not regress: wrapping a tainted string in logging.SanitizeLogValue should
// eliminate the finding. Without this test, a broken sanitizer-detection path
// would silently make the linter report every wrapped call.
func TestAnalyzeFile_AcceptsSanitizedString(t *testing.T) {
	src := `package api
import "encoding/json"
import "net/http"
import "github.com/cfgis/cfgms/pkg/logging"
type req struct { Name string }
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	var rq req
	json.NewDecoder(r.Body).Decode(&rq)
	s.logger.Info("got", "name", logging.SanitizeLogValue(rq.Name))
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for sanitized string, got: %v", findings)
	}
}

// TestAnalyzeFile_UnknownStructTypeStillFlags asserts the conservative-on-
// uncertainty behavior: when the struct type is defined in another package
// (not in the file under analysis), the linter cannot prove the field type
// is scalar, so it must keep flagging. Silently dropping cross-package cases
// would let real findings slip past.
func TestAnalyzeFile_UnknownStructTypeStillFlags(t *testing.T) {
	src := `package api
import "encoding/json"
import "net/http"
import other "example.com/other"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	var rq other.Req
	json.NewDecoder(r.Body).Decode(&rq)
	s.logger.Info("got", "name", rq.Name)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (unknown type → conservative flag), got %d: %v", len(findings), findings)
	}
}

// TestIsScalarType pins the scalar set explicitly so any future widening (e.g.
// adding "string" by mistake — the very thing the linter is built to flag)
// breaks the test loudly instead of silently disabling the entire lint.
func TestIsScalarType(t *testing.T) {
	wantScalar := []string{
		"bool", "int", "int8", "int16", "int32", "int64",
		"uint", "uint8", "uint16", "uint32", "uint64", "uintptr",
		"float32", "float64", "complex64", "complex128", "rune",
		"time.Time", "time.Duration",
	}
	for _, typ := range wantScalar {
		if !isScalarType(typ) {
			t.Errorf("isScalarType(%q) = false, want true", typ)
		}
	}
	wantNotScalar := []string{
		"string", "[]byte", "[]string", "interface{}", "any",
		"map[string]string", "json.RawMessage", "",
	}
	for _, typ := range wantNotScalar {
		if isScalarType(typ) {
			t.Errorf("isScalarType(%q) = true, want false (would silently disable the lint)", typ)
		}
	}
}

// analyzeSnippet writes src to a temp file and runs the linter against it,
// returning the findings. This avoids exporting analyzeFile's internals while
// letting each table-test case use a focused, readable fixture inline.
// TestAnalyzeFile_FlagsBareErrorFromTaintedCall covers the defect class that kept
// reaching acceptance review: the obvious taint gets sanitized and the error
// returned by the same call does not. An error from a decode, lookup, or gRPC
// call quotes the offending value in its message, so logging it bare is the same
// injection as logging the value.
func TestAnalyzeFile_FlagsBareErrorFromTaintedCall(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger; client client }
type client interface{ GetRole(string) (string, error) }
type logger interface{ Error(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	roleID := mux.Vars(r)["id"]
	_, err := s.client.GetRole(roleID)
	s.logger.Error("Failed to get role", "role_id", logging.SanitizeLogValue(roleID), "error", err)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for the bare err, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, `"err"`) {
		t.Errorf("expected the finding to name err, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_AcceptsSanitizedError is the negative half: the documented
// remedy must actually clear the finding, or the rule is unsatisfiable.
func TestAnalyzeFile_AcceptsSanitizedError(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger; client client }
type client interface{ GetRole(string) (string, error) }
type logger interface{ Error(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	roleID := mux.Vars(r)["id"]
	_, err := s.client.GetRole(roleID)
	s.logger.Error("Failed to get role", "error", logging.SanitizeLogValue(err.Error()))
}
`
	if findings := analyzeSnippet(t, src); len(findings) != 0 {
		t.Fatalf("expected no findings for a sanitized error, got %v", findings)
	}
}

// TestAnalyzeFile_SkipsErrorFromTransmitOnlyCall guards the false positive found
// while building this rule: `w.Write(taintedBytes)` fails because the socket
// closed, not because of the payload, so its error cannot carry the payload back.
// Flagging every response-write error would put the lint back in the category
// developers learn to bypass.
func TestAnalyzeFile_SkipsErrorFromTransmitOnlyCall(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Error(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	body := []byte(mux.Vars(r)["id"])
	if _, err := w.Write(body); err != nil {
		s.logger.Error("failed to write response", "error", err)
	}
}
`
	if findings := analyzeSnippet(t, src); len(findings) != 0 {
		t.Fatalf("expected no findings for a transmit-only error, got %v", findings)
	}
}

// TestAnalyzeFile_SkipsErrorFromUntaintedCall keeps the rule from degenerating
// into "sanitize every error everywhere": a call that never saw user input
// produces an error that cannot carry it.
func TestAnalyzeFile_SkipsErrorFromUntaintedCall(t *testing.T) {
	src := `package api
import "net/http"
type S struct{ logger logger; store store }
type store interface{ Ping() error }
type logger interface{ Error(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(); err != nil {
		s.logger.Error("store unreachable", "error", err)
	}
}
`
	if findings := analyzeSnippet(t, src); len(findings) != 0 {
		t.Fatalf("expected no findings for an untainted error, got %v", findings)
	}
}

// TestAnalyzeFile_KnownSitesReportNothing records what this linter currently
// sees at the four Issue #4073 sites: nothing.
//
// NOT a regression pin, despite what it looks like. These files report zero
// findings whether or not they are sanitized — verified by running the linter
// against the unsanitized copies, which also exits 0 with no output. Reverting
// any of the four to a bare `err` leaves this test passing. The revert-proof
// guarantee for those sites lives in their own package tests, which inject a
// control-character payload and assert the sanitized form reaches the logger:
//
//	features/controller/api/handlers_audit_test.go
//	features/controller/api/handlers_fleet_test.go
//	features/controller/server/heartbeat_staleness_test.go
//	pkg/audit/manager_test.go
//
// Two gaps in the taint model put these sites out of reach. Sources are matched
// by exact selector string, so a chained r.URL.Query().Get(...) never taints its
// result — only the unchained q := r.URL.Query(); q.Get(...) form does. And
// there is no interprocedural taint, so sid and tenantID, which arrive as
// function parameters, are never tainted regardless of what the HTTP layer
// passed in.
//
// What this test is good for: it fails if the linter ever starts reporting on
// these files, which would mean either the taint model grew to reach them (make
// it a real pin then) or it began false-positiving on already-sanitized code.
func TestAnalyzeFile_KnownSitesReportNothing(t *testing.T) {
	files := []string{
		"../../features/controller/api/handlers_audit.go",
		"../../features/controller/api/handlers_fleet.go",
		"../../features/controller/server/server.go",
		"../../features/tenant/manager.go",
	}
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			findings, err := analyzeFile(f)
			if err != nil {
				t.Fatalf("analyzeFile(%s): %v", f, err)
			}
			if len(findings) != 0 {
				t.Errorf("expected 0 findings in %s, got %d: %v", f, len(findings), findings)
			}
		})
	}
}

// TestDiscoverScope_WidensAcrossRepoLayout fails on revert: reintroducing the
// `/api/` filter drops the non-`api` paths from the result, leaving only the
// nested api file.
func TestDiscoverScope_WidensAcrossRepoLayout(t *testing.T) {
	root := t.TempDir()
	want := []string{
		filepath.Join(root, "features", "foo", "handler.go"),
		filepath.Join(root, "pkg", "bar", "thing.go"),
		filepath.Join(root, "cmd", "baz", "main.go"),
		filepath.Join(root, "features", "foo", "api", "endpoint.go"),
	}
	for _, f := range want {
		mustWriteGoFile(t, f)
	}
	// A test file must never appear in scope regardless of location.
	mustWriteGoFile(t, filepath.Join(root, "features", "foo", "handler_test.go"))

	got, err := discoverScope(root)
	if err != nil {
		t.Fatalf("discoverScope: %v", err)
	}
	assertContainsAll(t, got, want)
	for _, f := range got {
		if strings.HasSuffix(f, "_test.go") {
			t.Errorf("discoverScope returned a test file: %s", f)
		}
	}
}

// TestDiscoverScope_SkipsNoiseDirectories fails on revert: a bare
// filepath.WalkDir(root, ...) with the skip-list removed would include all
// four noise-directory files below alongside the sibling normal-directory file.
func TestDiscoverScope_SkipsNoiseDirectories(t *testing.T) {
	root := t.TempDir()
	noise := []string{
		filepath.Join(root, ".cache", "go-mod", "vendored.go"),
		filepath.Join(root, "web", "node_modules", "somepkg", "index.go"),
		filepath.Join(root, "build", "artifact.go"),
		filepath.Join(root, ".git", "hooks", "dummy.go"),
	}
	for _, f := range noise {
		mustWriteGoFile(t, f)
	}
	wanted := filepath.Join(root, "features", "foo", "handler.go")
	mustWriteGoFile(t, wanted)

	got, err := discoverScope(root)
	if err != nil {
		t.Fatalf("discoverScope: %v", err)
	}
	for _, f := range noise {
		for _, g := range got {
			if g == f {
				t.Errorf("discoverScope included noise-directory file: %s", f)
			}
		}
	}
	found := false
	for _, g := range got {
		if g == wanted {
			found = true
		}
	}
	if !found {
		t.Errorf("discoverScope dropped sibling file in a normal directory: %s (got %v)", wanted, got)
	}
}

func mustWriteGoFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("package p\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func assertContainsAll(t *testing.T, got, want []string) {
	t.Helper()
	set := map[string]struct{}{}
	for _, g := range got {
		set[g] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			t.Errorf("discoverScope result missing %s; got %v", w, got)
		}
	}
}

func analyzeSnippet(t *testing.T, src string) []finding {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "snippet.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write snippet: %v", err)
	}
	findings, err := analyzeFile(path)
	if err != nil {
		t.Fatalf("analyzeFile: %v", err)
	}
	return findings
}
