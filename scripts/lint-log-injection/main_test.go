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

// TestAnalyzeFile_FlagsTaintedValueViaCtxSuffix covers CFGMS's own
// context-aware logging convention (InfoCtx/WarnCtx/ErrorCtx/DebugCtx/FatalCtx
// on logging.Logger and *logging.ModuleLogger), invisible to loggerMethods
// before this change. Fails on revert: removing "ErrorCtx" from loggerMethods
// makes analyzeFunc skip the call entirely (the loggerMethods lookup happens
// before any taint check), so this snippet would drop to 0 findings.
func TestAnalyzeFile_FlagsTaintedValueViaCtxSuffix(t *testing.T) {
	src := `package api
import "context"
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ ErrorCtx(context.Context, string, ...any) }
func (s *S) handle(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	s.logger.ErrorCtx(ctx, "msg", "id", mux.Vars(r)["id"])
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, "mux.Vars") {
		t.Errorf("expected finding to name the mux.Vars value, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_AcceptsSanitizedCtxSuffix is the negative half of the
// ErrorCtx case: the documented remedy (logging.SanitizeLogValue) must still
// clear the finding on a *Ctx-suffixed sink, or the rule is unsatisfiable for
// half of CFGMS's own logging convention.
func TestAnalyzeFile_AcceptsSanitizedCtxSuffix(t *testing.T) {
	src := `package api
import "context"
import "net/http"
import "github.com/gorilla/mux"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ ErrorCtx(context.Context, string, ...any) }
func (s *S) handle(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.logger.ErrorCtx(ctx, "msg", "id", logging.SanitizeLogValue(id))
}
`
	if findings := analyzeSnippet(t, src); len(findings) != 0 {
		t.Fatalf("expected 0 findings for a sanitized *Ctx sink, got %v", findings)
	}
}

// TestAnalyzeFile_FlagsTaintedValueViaShortLoggerName covers the widened
// looksLikeLogger tail match. Fails on revert: reverting the widening drops
// the receiver tail "l" from the accepted set (only "logger"-suffix, "log",
// and "slog" would remain), so looksLikeLogger(s.l) returns false and this
// snippet drops to 0 findings.
func TestAnalyzeFile_FlagsTaintedValueViaShortLoggerName(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ l logger }
type logger interface{ Error(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.l.Error("msg", "id", id)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, `"id"`) {
		t.Errorf("expected the id to be the one flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_AcceptsSanitizedViaFieldsRecursive covers the second real
// sanitizer wrapper, logging.SanitizeFieldsRecursive (pkg/logging/sanitize.go),
// already in production use (features/controller/api/middleware.go:1636) but
// unrecognized by sanitizerCalls before this change.
//
// Pairing note, documented rather than silently assumed: the obvious guard
// against a vacuous test -- "wrap the same value in an unregistered function
// name instead and confirm it flags" -- does not hold for this linter as
// written. isTaintedExpr's *ast.CallExpr case only asks whether the call
// EXPRESSION ITSELF is a known taint source; it never inspects the call's own
// arguments. So wrapping a tainted value in any function call -- a registered
// sanitizer, an unregistered one, or a typo -- already produces 0 findings,
// and adding an entry to sanitizerCalls does not change that outcome for a
// wrapped argument. Verified directly: emptying sanitizerCalls to `{}`
// entirely produces zero regressions across this file's whole existing test
// suite, before this story's changes. That gap in the taint model (a wrap in
// any function silences detection, sanitizer or not) is real, predates this
// story, is not something "sink/sanitizer registry" scope authorizes fixing
// here, and is filed as follow-up work rather than patched inline.
//
// What this test asserts instead, which is genuinely revert-provable and does
// guard against vacuousness: the same tainted value, logged bare in a sibling
// field on the very next line, still flags -- proving the value is live and
// reachable at this sink, not a position that could never have produced a
// finding regardless of the fix -- while the SanitizeFieldsRecursive-wrapped
// copy produces none. Fails on revert of the registry entry only in the sense
// that removing "logging.SanitizeFieldsRecursive" from sanitizerCalls while
// this exact snippet is otherwise unchanged does NOT reproduce a finding for
// the wrapped line (see gap above); the test instead pins the currently-true,
// checkable behavior of both lines together.
func TestAnalyzeFile_AcceptsSanitizedViaFieldsRecursive(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.logger.Info("sanitized", "fields", logging.SanitizeFieldsRecursive(map[string]interface{}{"id": id}))
	s.logger.Info("bare", "id", id)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (the bare id on the second call), got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, `"id"`) {
		t.Errorf("expected the bare id to be the one flagged, got %q", findings[0].msg)
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

// TestAnalyzeFile_FlagsChainedMethodCallOnTaintSource covers taint gap C: a
// method call chained directly off a taint-source call is invisible to
// selectorString, which only collapses a chain of Ident/SelectorExpr nodes.
// Fails on revert: without isMethodCallOnTaintedReceiver, isTaintSourceExpr
// never matches r.URL.Query().Get("id") because its receiver is itself a
// CallExpr, and this snippet drops to 0 findings.
func TestAnalyzeFile_FlagsChainedMethodCallOnTaintSource(t *testing.T) {
	src := `package api
import "net/http"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.logger.Info("got", "id", id)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, `"id"`) {
		t.Errorf("expected the id to be the one flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_FlagsUnchainedMethodCallOnTaintedVar covers the other half
// of gap C: q := r.URL.Query() taints q today, but q.Get("id") collapses to
// the selector string "q.Get", which is not and can never be a registered
// taint source key (q is a local variable name, not a package/type). Fails
// on revert: without the "receiver already tainted" check, this drops to 0
// findings.
func TestAnalyzeFile_FlagsUnchainedMethodCallOnTaintedVar(t *testing.T) {
	src := `package api
import "net/http"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := q.Get("id")
	s.logger.Info("got", "id", id)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzeFile_FlagsPlainAlias covers gap D's first shape: a plain
// re-assignment of a tainted identifier to a new name. Fails on revert:
// without the Ident-to-Ident propagation rule, alias never enters the
// tainted set and this drops to 0 findings.
func TestAnalyzeFile_FlagsPlainAlias(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	alias := id
	s.logger.Info("got", "id", alias)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzeFile_FlagsSprintfDerivedValue covers gap D's Sprintf shape: a
// value built via fmt.Sprintf over a tainted argument. Fails on revert:
// without the call-with-tainted-argument propagation rule, msg never enters
// the tainted set and this drops to 0 findings.
func TestAnalyzeFile_FlagsSprintfDerivedValue(t *testing.T) {
	src := `package api
import "fmt"
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	msg := fmt.Sprintf("lookup %s", id)
	s.logger.Info("got", "msg", msg)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzeFile_FlagsErrorWrapBoundToNonErrorName covers gap D's
// error-wrap shape reached through a rename: today's looksLikeErrorVar gate
// only taints error-*named* bindings, so binding an error-wrapping call to a
// non-error name defeats it. Fails on revert: reintroducing the name gate
// makes fmt.Errorf's result bind to "wrapped", which the gate rejects, and
// this drops to 0 findings.
func TestAnalyzeFile_FlagsErrorWrapBoundToNonErrorName(t *testing.T) {
	src := `package api
import "errors"
import "fmt"
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Error(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	err := errors.New("lookup failed")
	wrapped := fmt.Errorf("lookup %s failed: %w", id, err)
	s.logger.Error("failed", "error", wrapped)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, "wrapped") {
		t.Errorf("expected wrapped to be the one flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_FlagsTaintedStructFieldWrite covers gap D's struct-field
// shape: collectTaintedVars only ever taints *ast.Ident LHS targets, so a
// field write has no propagation path today. Fails on revert: without the
// SelectorExpr-LHS rule tainting the root identifier, s never enters the
// tainted set and this drops to 0 findings.
func TestAnalyzeFile_FlagsTaintedStructFieldWrite(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct {
	logger logger
	Field  string
}
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.Field = id
	s.logger.Info("got", "field", s.Field)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, "s.Field") {
		t.Errorf("expected s.Field to be the one flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_FlagsErrorFromCallArgWithTaintedField is the real-world
// shape found by Tech Lead review of the pre-fix diffs behind issue #4073's
// motivating sites (mirrors features/controller/api/handlers_audit.go): a
// struct field is written with tainted data, then the whole struct variable
// (not a field selector) is passed as a call argument whose returned error
// is logged bare. Fails on revert: without struct-field-write tainting the
// containing variable as a whole, `filter` never enters the tainted set, so
// anyArgTainted never sees it as an argument to QueryEntries, and this drops
// to 0 findings.
func TestAnalyzeFile_FlagsErrorFromCallArgWithTaintedField(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type Filter struct{ EventTypes []string }
type store interface{ QueryEntries(*Filter) ([]string, error) }
type S struct {
	logger logger
	q      store
}
type logger interface{ Error(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	filter := &Filter{}
	filter.EventTypes = []string{id}
	_, err := s.q.QueryEntries(filter)
	s.logger.Error("failed", "error", err)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, "err") {
		t.Errorf("expected err to be the one flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_FlagsErrorFromCallArgWithTaintedCompositeLiteralField is the
// declaration-form sibling of the above: the tainted field is set inside a
// composite literal at declaration rather than a later field write. Guards
// against a fix that only handles the x.Field = ... reassignment shape.
// Fails on revert: without composite-literal taint detection tainting
// `filter` as a whole, this drops to 0 findings the same way.
func TestAnalyzeFile_FlagsErrorFromCallArgWithTaintedCompositeLiteralField(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type Filter struct{ EventTypes []string }
type store interface{ QueryEntries(*Filter) ([]string, error) }
type S struct {
	logger logger
	q      store
}
type logger interface{ Error(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	filter := &Filter{EventTypes: []string{id}}
	_, err := s.q.QueryEntries(filter)
	s.logger.Error("failed", "error", err)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, "err") {
		t.Errorf("expected err to be the one flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_AcceptsSanitizedDerivedValues is the negative counterpart of
// the five widened-taint-model positive cases above: each one still produces
// 0 findings once the value is wrapped in logging.SanitizeLogValue at the
// point it's logged. Without this table, a broken sanitizer-detection path
// for any of these newly-tainted shapes would silently make the linter
// unsatisfiable for that shape.
func TestAnalyzeFile_AcceptsSanitizedDerivedValues(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			name: "alias",
			src: `package api
import "net/http"
import "github.com/gorilla/mux"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	alias := id
	s.logger.Info("got", "id", logging.SanitizeLogValue(alias))
}
`,
		},
		{
			name: "sprintf",
			src: `package api
import "fmt"
import "net/http"
import "github.com/gorilla/mux"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	msg := fmt.Sprintf("lookup %s", id)
	s.logger.Info("got", "msg", logging.SanitizeLogValue(msg))
}
`,
		},
		{
			name: "error-wrap-renamed",
			src: `package api
import "errors"
import "fmt"
import "net/http"
import "github.com/gorilla/mux"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ Error(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	err := errors.New("lookup failed")
	wrapped := fmt.Errorf("lookup %s failed: %w", id, err)
	s.logger.Error("failed", "error", logging.SanitizeLogValue(wrapped.Error()))
}
`,
		},
		{
			name: "struct-field",
			src: `package api
import "net/http"
import "github.com/gorilla/mux"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct {
	logger logger
	Field  string
}
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.Field = id
	s.logger.Info("got", "field", logging.SanitizeLogValue(s.Field))
}
`,
		},
		{
			name: "chained-method-call",
			src: `package api
import "net/http"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.logger.Info("got", "id", logging.SanitizeLogValue(id))
}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if findings := analyzeSnippet(t, tc.src); len(findings) != 0 {
				t.Errorf("expected 0 findings, got: %v", findings)
			}
		})
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
