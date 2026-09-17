// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestAnalyzeFile_FlagsTaintedValueViaUnrecognizedWrapper is the story #4097
// regression guard: the gap TestAnalyzeFile_AcceptsSanitizedViaFieldsRecursive
// documents above (isTaintedExpr's *ast.CallExpr case never looks at a call's
// own arguments, so wrapping a tainted value in ANY function -- sanitizer or
// not -- silenced the finding) is exactly what this fix closes. Wrapping id in
// an unregistered function name must still be flagged. Fails on revert:
// reverting the sink-check fix (back to isTaintedExpr) drops this to 0
// findings, identical to the pre-fix behavior documented above.
func TestAnalyzeFile_FlagsTaintedValueViaUnrecognizedWrapper(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func someUnrecognizedWrapper(s string) string { return s }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.logger.Info("got", "id", someUnrecognizedWrapper(id))
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, "someUnrecognizedWrapper") {
		t.Errorf("expected the wrapped call to be the one flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_StillAcceptsRecognizedWrapperAfterFix is the regression
// guard paired with the test above: the same snippet, with the unrecognized
// wrapper replaced by the real sanitizer, must still clear. Without this test,
// a fix that makes any call-wrapped argument tainted (dropping the sanitizer
// short-circuit) would flag every legitimate logging.SanitizeLogValue call in
// the repository.
func TestAnalyzeFile_StillAcceptsRecognizedWrapperAfterFix(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.logger.Info("got", "id", logging.SanitizeLogValue(id))
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for sanitized wrapper, got: %v", findings)
	}
}

// TestAnalyzeFile_AcceptsComparisonOfTaintedValue guards a false positive the
// #4097 sink-check fix surfaced repo-wide (features/controller/api/handlers_
// accounts.go, handlers_credential_requests.go): wiring the sink check to
// exprCarriesTaint exposed that its *ast.BinaryExpr case, unlike
// taintPropagatesFrom's identical case, did not restrict itself to token.ADD
// (string concatenation) — so a boolean comparison of a tainted operand
// (`tenantID == ""`) was treated as carrying taint even though `==` always
// produces a bool. Fails on revert of that ADD-only guard.
func TestAnalyzeFile_AcceptsComparisonOfTaintedValue(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.logger.Info("got", "is_empty", id == "")
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for a boolean comparison of a tainted value, got: %v", findings)
	}
}

// TestAnalyzeFile_AcceptsLenOfTaintedValue guards a false positive the #4097
// sink-check fix surfaced repo-wide (features/controller/api/handlers_push.go,
// handlers_tags.go): len(...) always returns an int, which cannot carry a
// log-injection payload no matter what it counted, but exprCarriesTaint's
// generic call-argument recursion would otherwise treat len(taintedSlice) as
// tainted purely because one of its arguments is. Fails on revert of the
// len(...) special case.
func TestAnalyzeFile_AcceptsLenOfTaintedValue(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	ids := []string{mux.Vars(r)["id"]}
	s.logger.Info("got", "count", len(ids))
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for len() of a tainted slice, got: %v", findings)
	}
}

// TestAnalyzeFile_AcceptsSanitizedViaRedactedID guards a false positive the
// #4097 sink-check fix surfaced repo-wide (features/controller/api/handlers_
// registration.go, four call sites): logging.RedactedID (pkg/logging/
// sanitize.go) is a genuine, CodeQL-recognized sanitizer that truncates and
// runs its result through SanitizeLogValue internally, but was missing from
// sanitizerCalls — its production call sites were previously masked by the
// same bug this story fixes (any unregistered wrapper silenced detection
// identically to a real sanitizer), not actually covered by a registry entry.
// Fails on revert of the registry addition.
func TestAnalyzeFile_AcceptsSanitizedViaRedactedID(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.logger.Info("got", "id_prefix", logging.RedactedID(id))
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for logging.RedactedID-wrapped value, got: %v", findings)
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

// TestAnalyzeFile_FlagsTwoStepMuxVarsIdiom covers issue #4109 AC1: the
// two-step idiom (`vars := mux.Vars(r); id := vars["id"]`) is the majority
// form in this repo (91 occurrences under features/ vs. 65 for the inline
// `mux.Vars(r)["id"]` form), but isTaintSourceExpr's *ast.IndexExpr case only
// ever matched the inline form (X being the mux.Vars(r) call itself), not an
// IndexExpr on an already-tainted identifier. Fails on revert: without the
// tainted-identifier check on IndexExpr.X, `vars` is tainted (mux.Vars(r)
// itself is a recognized source) but `vars["id"]` is not, and id never enters
// the tainted set — this drops to 0 findings.
func TestAnalyzeFile_FlagsTwoStepMuxVarsIdiom(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	s.logger.Info("got", "id", id)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, `"id"`) {
		t.Errorf("expected id to be the one flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzeFile_AcceptsSanitizedTwoStepMuxVarsIdiom is the negative half of
// AC1: the documented remedy must still clear the finding once the source
// model recognizes the two-step idiom, or the rule becomes unsatisfiable for
// the majority form in this repo.
func TestAnalyzeFile_AcceptsSanitizedTwoStepMuxVarsIdiom(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	s.logger.Info("got", "id", logging.SanitizeLogValue(id))
}
`
	if findings := analyzeSnippet(t, src); len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %v", findings)
	}
}

// TestAnalyzeFile_FlagsTriggerAPITwoStepShape is the AC3 revert-proof anchor.
// It mirrors the exact shape that lived at
// features/workflow/trigger/api.go:319 at the time this issue was filed
// (`vars := mux.Vars(r); triggerID := vars["id"]`, logged bare). That specific
// call site was independently sanitized by issue #4089 (merged the same day,
// commit ad4f1ad8) before this story landed, so a live repo-wide run no
// longer reports it — the vulnerability there is already fixed. This fixture
// keeps the AC's guarantee checkable anyway: if AC1's two-step recognition is
// ever reverted, this drops to 0 findings.
func TestAnalyzeFile_FlagsTriggerAPITwoStepShape(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ InfoCtx(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	triggerID := vars["id"]
	s.logger.InfoCtx("Trigger executed successfully via API", "trigger_id", triggerID)
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, `"triggerID"`) {
		t.Errorf("expected triggerID to be the one flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzePackage_FlagsValueFromHelperReadingTaintSource covers issue
// #4109 AC2: extractSessionID in features/workflow/debug_api.go reads
// r.URL.Path (already a recognized taint source) and returns a path segment,
// with no tainted parameter of its own — the caller's variable must still be
// seeded as tainted. Fails on revert of funcReturnsTaint: analyzeFunc has no
// way to know a same-package call's result is intrinsically tainted, and
// sessionID never enters the tainted set, dropping this to 0 findings.
func TestAnalyzePackage_FlagsValueFromHelperReadingTaintSource(t *testing.T) {
	a := `package api
import "net/http"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	s.logger.Info("got", "session_id", sessionID)
}
`
	b := `package api
import "net/http"
import "strings"
func extractSessionID(r *http.Request) string {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	for i, p := range parts {
		if p == "sessions" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": a, "b.go": b})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, "sessionID") {
		t.Errorf("expected sessionID to be the one flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzePackage_AcceptsSanitizedValueFromHelper is the negative half of
// AC2: sanitizing the helper's result at the log call site must still clear
// the finding.
func TestAnalyzePackage_AcceptsSanitizedValueFromHelper(t *testing.T) {
	a := `package api
import "net/http"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	sessionID := extractSessionID(r)
	s.logger.Info("got", "session_id", logging.SanitizeLogValue(sessionID))
}
`
	b := `package api
import "net/http"
import "strings"
func extractSessionID(r *http.Request) string {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	for i, p := range parts {
		if p == "sessions" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": a, "b.go": b})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzePackage_HelperNotCallingTaintSourceNotFlagged guards against an
// over-broad funcReturnsTaint implementation ("any same-package function
// return is tainted"): a helper that returns a plain static computation must
// not taint its callers.
func TestAnalyzePackage_HelperNotCallingTaintSourceNotFlagged(t *testing.T) {
	a := `package api
import "net/http"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	label := describeStatus()
	s.logger.Info("got", "label", label)
}
`
	b := `package api
func describeStatus() string {
	return "static-label"
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": a, "b.go": b})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %v", len(findings), findings)
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

// analyzeSnippets writes each named source to the same t.TempDir() directory
// — one resolution unit, the same way main() groups same-directory files —
// and runs analyzePackage over all of them together.
func analyzeSnippets(t *testing.T, srcs map[string]string) []finding {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for name, src := range srcs {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		paths = append(paths, path)
	}
	findings, err := analyzePackage(paths)
	if err != nil {
		t.Fatalf("analyzePackage: %v", err)
	}
	return findings
}

// TestAnalyzePackage_PropagatesTaintThroughParameter is the story's worked
// example (issue #4089): handle taints id from mux.Vars and passes it,
// unsanitized, to logIt in a sibling file of the same package. logIt logs its
// bare parameter. Fails on revert: analyzeFile's per-function analysis never
// sees the caller's argument, so the callee's parameter is never tainted and
// this drops to 0 findings (verified directly against origin/develop tip
// 7150e04d before this story).
func TestAnalyzePackage_PropagatesTaintThroughParameter(t *testing.T) {
	a := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.logIt(id)
}
`
	b := `package api
func (s *S) logIt(id string) {
	s.logger.Info("got", "id", id)
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": a, "b.go": b})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].file, "b.go") {
		t.Errorf("expected the finding inside logIt (b.go), got %s", findings[0].file)
	}
}

// TestAnalyzePackage_AcceptsSanitizedParameter covers the call-site
// sanitizing shape named explicitly by the story: the caller wraps the
// argument in logging.SanitizeLogValue before passing it, so the callee's
// parameter is never tainted even though it still logs it bare.
func TestAnalyzePackage_AcceptsSanitizedParameter(t *testing.T) {
	a := `package api
import "net/http"
import "github.com/gorilla/mux"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.logIt(logging.SanitizeLogValue(id))
}
`
	b := `package api
func (s *S) logIt(id string) {
	s.logger.Info("got", "id", id)
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": a, "b.go": b})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzePackage_UntaintedParameterNotFlagged guards against an
// over-broad "any parameter is tainted" regression: logIt's parameter is
// never passed a tainted argument by any caller in the resolution unit, so
// logging it bare must not be flagged.
func TestAnalyzePackage_UntaintedParameterNotFlagged(t *testing.T) {
	a := `package api
import "net/http"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	s.logIt("static-label")
}
`
	b := `package api
func (s *S) logIt(id string) {
	s.logger.Info("got", "id", id)
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": a, "b.go": b})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzePackage_BoundsMutualRecursion covers mutual recursion (a calls
// b, b calls a back) seeded with tainted data at the top of the chain,
// through the call-graph fixed point in resolveParameterTaint. The test
// itself fails via timeout if the analysis does not terminate — guarding
// funcParamTaintRounds' bound against an unbounded fixed point on a
// mutually-recursive same-package call graph.
func TestAnalyzePackage_BoundsMutualRecursion(t *testing.T) {
	done := make(chan []finding, 1)
	go func() {
		src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.a(id, 3)
}
func (s *S) a(id string, n int) {
	if n <= 0 {
		return
	}
	s.logger.Info("got", "id", id)
	s.b(id, n-1)
}
func (s *S) b(id string, n int) {
	if n <= 0 {
		return
	}
	s.a(id, n-1)
}
`
		done <- analyzeSnippets(t, map[string]string{"snippet.go": src})
	}()

	select {
	case findings := <-done:
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("analysis did not terminate on a mutually recursive call graph")
	}
}

// TestAnalyzePackage_SuppressesScalarFromSamePackageCall covers the
// type-resolution half of the same-package boundary: revokeSessions returns
// (int, error), so the `revoked` count logged beside it cannot carry an
// injection payload even though a tainted argument influenced its value.
// Fails on revert to per-file analysis, which cannot see the callee's result
// types and so flags the int.
func TestAnalyzePackage_SuppressesScalarFromSamePackageCall(t *testing.T) {
	a := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	revoked, _ := s.revokeSessions(id)
	s.logger.Info("revoked", "count", revoked)
}
`
	b := `package api
func (s *S) revokeSessions(id string) (int, error) {
	return 0, nil
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": a, "b.go": b})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzePackage_StillFlagsStringFromSamePackageCall is the guard on the
// test above: a resolved string result must stay flagged. Result types are
// used to suppress findings, so a bug that treated every resolved type as
// scalar would silently hide real ones. Single-return, unlike the sibling
// tests below: this call has no multi-value LHS to isolate, so root cause
// A's broadcast fix (see TestAnalyzePackage_MultiReturnDoesNotTaintUnrelatedSibling)
// does not change its outcome.
func TestAnalyzePackage_StillFlagsStringFromSamePackageCall(t *testing.T) {
	a := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	label := s.describe(id)
	s.logger.Info("described", "label", label)
}
`
	b := `package api
func (s *S) describe(id string) string {
	return id
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": a, "b.go": b})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzePackage_MultiReturnDoesNotTaintUnrelatedSibling is root cause
// A's core regression test (issue #4103): a multi-return call broadcasting
// taint from a tainted argument to EVERY result, not just the plausible
// error-carrying one, was the bug behind the majority of the 40 residual
// findings traced during #4088 — a crypto-random ID or a fixed-vocabulary
// label returned alongside a legitimately tainted-derived error. issueCert
// returns (string, error); only "err" (the last, error-named position)
// should inherit taint from the tainted id argument. "serial" is a sibling
// result structurally unrelated to that argument and must not be swept in.
// Fails on revert: without plausibleErrorReturnIndices restricting the
// broadcast, "serial" enters the tainted set too and this drops to 2
// findings (serial AND err) instead of 1.
func TestAnalyzePackage_MultiReturnDoesNotTaintUnrelatedSibling(t *testing.T) {
	a := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	serial, err := s.issueCert(id)
	s.logger.Info("issued", "serial", serial, "error", err)
}
`
	b := `package api
func (s *S) issueCert(id string) (string, error) {
	return "crypto-random-serial", nil
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": a, "b.go": b})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (err only), got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, `"err"`) {
		t.Errorf("expected the finding to name err, not the unrelated serial sibling, got %q", findings[0].msg)
	}
}

// TestAnalyzePackage_DoesNotBorrowResultTypesAcrossPackages guards
// samePackageResultTypes' receiver restriction: `client.Fetch(...)` calls an
// imported type's method that happens to share a name with a local
// int-returning function. Borrowing the local function's result type would
// suppress a real finding on a value of unknown type.
func TestAnalyzePackage_DoesNotBorrowResultTypesAcrossPackages(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger; client remote }
type logger interface{ Info(string, ...any) }
type remote interface{ Fetch(string) string }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	v := s.client.Fetch(id)
	s.logger.Info("fetched", "value", v)
}
func Fetch(id string) int {
	return len(id)
}
`
	findings := analyzeSnippets(t, map[string]string{"snippet.go": src})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzePackage_SuppressesScalarLocalFromLiteral covers the literal half
// of local type inference: `tail := 100` pins tail as an int for the whole
// function, so a later reassignment from a parsed query parameter cannot make
// it loggable-unsafe. This is the shape at handlers_stewards.go's log-pull
// handler.
func TestAnalyzePackage_SuppressesScalarLocalFromLiteral(t *testing.T) {
	src := `package api
import "net/http"
import "strconv"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	tail := 100
	if raw := r.URL.Query().Get("tail"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err == nil {
			tail = v
		}
	}
	s.logger.Info("pull", "tail", tail)
}
`
	findings := analyzeSnippets(t, map[string]string{"snippet.go": src})
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzePackage_AmbiguousLocalTypeStaysFlagged covers collectVarTypes'
// conflict demotion: a name bound to two different types within one function
// (a nested-scope re-declaration this flat walk cannot separate) resolves to
// unknown, not to whichever binding was seen last. Resolving it to the int
// binding would suppress the finding on the string one.
func TestAnalyzePackage_AmbiguousLocalTypeStaysFlagged(t *testing.T) {
	src := `package api
import "net/http"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	if true {
		v := 1
		_ = v
	}
	v := r.URL.Query().Get("v")
	s.logger.Info("got", "v", v)
}
`
	findings := analyzeSnippets(t, map[string]string{"snippet.go": src})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzeFile_LaterBlockRedeclarationClearsStaleTaint is root cause B's
// core regression test (issue #4103): two structurally unrelated variables
// sharing the name "err" — one genuinely tainted inside the if-block, a
// different one freshly declared via `:=` in the mutually-exclusive
// else-block — must not be conflated by collectTaintedVars' flat,
// name-keyed map. The real-world shape is handlers_certificates.go's
// handleListCertificates before this story: a tainted-argument call in one
// branch and a zero-argument call in the sibling branch, both binding "err".
// Fails on revert: without the reassignment-clears-taint rule, the if-block's
// tainted "err" leaks into the else-block's unrelated "err" and this reports
// a finding instead of 0.
func TestAnalyzeFile_LaterBlockRedeclarationClearsStaleTaint(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Error(string, ...any) }
func lookup(id string) (int, error) { return 0, nil }
func ping() (int, error) { return 0, nil }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id != "" {
		_, err := lookup(id)
		if err != nil {
			return
		}
	} else {
		_, err := ping()
		if err != nil {
			s.logger.Error("ping failed", "error", err)
		}
	}
}
`
	if findings := analyzeSnippet(t, src); len(findings) != 0 {
		t.Fatalf("expected 0 findings: the else-block's err is a different, untainted variable, got %v", findings)
	}
}

// TestAnalyzeFile_ReassignmentClearsStaleTaint covers the AC's literal
// minimum for root cause B: a plain `=` reassignment of an established name
// from a demonstrably-untainted source clears its prior taint, not just the
// `:=`-redeclaration shape above. Fails on revert: without the clearing
// rule, "err" stays in the tainted set after the reassignment and this
// reports a finding instead of 0.
func TestAnalyzeFile_ReassignmentClearsStaleTaint(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Error(string, ...any) }
func lookup(id string) error { return nil }
func ping() error { return nil }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	err := lookup(id)
	_ = err
	err = ping()
	s.logger.Error("done", "error", err)
}
`
	if findings := analyzeSnippet(t, src); len(findings) != 0 {
		t.Fatalf("expected 0 findings after the untainted reassignment clears err, got %v", findings)
	}
}

// TestAnalyzeFile_SuppressesBareIdentifierScalarArgument covers root cause
// C's first gap: a bare identifier argument was never checked against its
// own resolved type at all — analyzeFunc's finding loop only ever called
// isProvablyScalar on a *ast.SelectorExpr field access. An int or time.Time
// local cannot carry a log-injection payload regardless of what tainted the
// variable name. Fails on revert of the bare-Ident branch in analyzeFunc:
// both cases would report a finding instead of 0.
func TestAnalyzeFile_SuppressesBareIdentifierScalarArgument(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			name: "int",
			src: `package api
import "net/http"
import "strconv"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	tail := 100
	if raw := r.URL.Query().Get("tail"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			tail = v
		}
	}
	s.logger.Info("pull", "tail", tail)
}
`,
		},
		{
			name: "time.Time",
			src: `package api
import "net/http"
import "time"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour)
	if raw := r.URL.Query().Get("since"); raw != "" {
		if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
			since = parsed
		}
	}
	s.logger.Info("pull", "since", since)
}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if findings := analyzeSnippet(t, tc.src); len(findings) != 0 {
				t.Errorf("expected 0 findings for bare-identifier scalar %s, got: %v", tc.name, findings)
			}
		})
	}
}

// TestAnalyzePackage_ResolvesFieldTypeOnFunctionReturnAssignedStruct covers
// root cause C's second gap: a variable assigned from a same-package
// function-call return (not a `var x T` declaration or a `x := T{...}`
// composite literal) was invisible to collectVarTypes, so a field access on
// it could never resolve to its real, locally-defined field type. Total is
// an int field on Page, defined in the same file as buildPage; page.Total
// must be suppressed while q, the genuinely tainted argument, still flags.
// Fails on revert: without collectVarTypes recording page's return-derived
// type, isProvablyScalar can't resolve Page.Total and this reports 2
// findings instead of 1.
func TestAnalyzePackage_ResolvesFieldTypeOnFunctionReturnAssignedStruct(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type Page struct{ Total int }
func buildPage(n int) Page { return Page{Total: n} }
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	q := mux.Vars(r)["q"]
	page := buildPage(len(q))
	s.logger.Info("listed", "q", q, "total", page.Total)
}
`
	findings := analyzeSnippets(t, map[string]string{"snippet.go": src})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (q only; page.Total resolves to int and is suppressed), got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, `"q"`) {
		t.Errorf("expected q to be the one flagged, not page.Total, got %q", findings[0].msg)
	}
}

// TestAnalyzePackage_SuppressesScalarFieldOfTaintedParameter covers the
// parameter half of collectVarTypes' type resolution. A parameter's type is
// written out in the signature, but collectVarTypes only walked the body, so
// `param.Field` could never resolve and analyzeFunc's non-string scalar
// suppression never applied to it. features/terminal's newSession is the
// motivating shape: a caller builds a *SessionRequest carrying a tainted
// string, which taints the whole parameter, and the handler then logs the
// request's Cols/Rows — both `int`, neither able to carry a forged log
// record, and neither sanitizable (SanitizeLogValue takes a string). Shell,
// the string field on the same tainted parameter, must still flag.
// Fails on revert: without parameter types recorded, this reports 3 findings
// instead of 1.
func TestAnalyzePackage_SuppressesScalarFieldOfTaintedParameter(t *testing.T) {
	a := `package api
import "net/http"
import "github.com/gorilla/mux"
type SessionRequest struct {
	Shell string
	Cols  int
	Rows  int
}
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	req := &SessionRequest{Shell: mux.Vars(r)["shell"]}
	s.newSession(req)
}
`
	b := `package api
func (s *S) newSession(req *SessionRequest) {
	s.logger.Info("created", "shell", req.Shell, "cols", req.Cols, "rows", req.Rows)
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": a, "b.go": b})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (req.Shell only; Cols/Rows are ints), got %d: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].msg, `"req.Shell"`) {
		t.Errorf("expected req.Shell to be the one flagged, got %q", findings[0].msg)
	}
}

// TestAnalyzePackage_ScalarFieldSuppressionSkipsShadowedParameter guards the
// parameter-type recording against the shadowing case collectVarTypes'
// flat walk cannot distinguish. `req` names the pointer parameter in the
// signature and a different, locally-built struct inside the if block, so its
// type is ambiguous within the function — record demotes it to unknown and
// both selectors stay flagged rather than silently inheriting the signature's
// type and being suppressed.
func TestAnalyzePackage_ScalarFieldSuppressionSkipsShadowedParameter(t *testing.T) {
	a := `package api
import "net/http"
import "github.com/gorilla/mux"
type SessionRequest struct {
	Cols int
}
type Other struct {
	Cols string
}
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	req := &SessionRequest{Cols: len(mux.Vars(r)["cols"])}
	s.newSession(req, mux.Vars(r)["raw"])
}
`
	b := `package api
func (s *S) newSession(req *SessionRequest, raw string) {
	s.logger.Info("first", "cols", req.Cols)
	if raw != "" {
		req := Other{Cols: raw}
		s.logger.Info("second", "cols", req.Cols)
	}
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": a, "b.go": b})
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (ambiguous req type suppresses nothing), got %d: %v", len(findings), findings)
	}
}

// ── Issue #4126: a provably-clean contributor must not taint its container ──
//
// All five fixtures below reproduce one symptom seen on PR #4125:
// flattenFieldsToKV(auditFields) at features/controller/api/middleware.go:1640
// and :1642 reported a finding although every value in that map was sanitized,
// a number, a formatted timestamp or a fixed literal. Neither #4123 nor #4109
// produces it alone -- it needs #4123's exprCarriesTaint recursion and #4109's
// helper-derived source model to meet.

// TestAnalyzePackage_ScalarFieldDoesNotTaintContainer covers AC1. The scalar
// rule already refused to flag a tainted struct's bool field AT THE SINK, but
// was never applied when the value was STORED, so the bool tainted the map on
// the way in and its scalar origin was gone by the time the map reached a log
// call. Fails on revert of the store-time suppression.
func TestAnalyzePackage_ScalarFieldDoesNotTaintContainer(t *testing.T) {
	src := `package api
import "encoding/json"
import "net/http"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
type decision struct {
	Reason  string
	Granted bool
}
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	var d decision
	_ = json.NewDecoder(r.Body).Decode(&d)
	fields := map[string]interface{}{
		"reason":  logging.SanitizeLogValue(d.Reason),
		"granted": d.Granted,
	}
	s.logger.Info("audit", flattenFieldsToKV(fields)...)
}
func flattenFieldsToKV(fields map[string]interface{}) []interface{} {
	out := make([]interface{}, 0, len(fields)*2)
	for k, v := range fields {
		out = append(out, k, v)
	}
	return out
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": src})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings: a bool field cannot encode a forged log record, got: %v", findings)
	}
}

// TestAnalyzePackage_PassthroughHelperStillFlagged is the load-bearing half of
// AC2 and the specific hazard the joint fixed point introduces. Making a
// funcReturnsTaint "no" trustworthy is only safe if the "no" is computed with a
// parameter seed; without one, collectFuncReturnsTaint cannot see that echo
// returns its caller's taint and records "no" for a function that plainly
// carries it. This fixture fails if that seed is dropped.
func TestAnalyzePackage_PassthroughHelperStillFlagged(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.logger.Info("got", "id", echo(id))
}
func echo(s string) string { return s }
`
	findings := analyzeSnippets(t, map[string]string{"a.go": src})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding: echo returns its caller's taint, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzePackage_FixedVocabularyHelperNotFlagged is the other half of AC2.
// getAuditSeverity returns only CRITICAL/HIGH-class literals, never caller
// input, but exprCarriesTaint's CallExpr case used to fall straight through to
// anyArgTainted -- so passing the tainted struct tainted the result. The
// linter already computed funcReturnsTaint and then only ever used it to say
// yes. Fails on revert of the definitive-no path.
func TestAnalyzePackage_FixedVocabularyHelperNotFlagged(t *testing.T) {
	src := `package api
import "encoding/json"
import "net/http"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
type decision struct {
	Reason  string
	Granted bool
}
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	var d decision
	_ = json.NewDecoder(r.Body).Decode(&d)
	s.logger.Info("audit", "severity", s.getAuditSeverity(d))
}
func (s *S) getAuditSeverity(d decision) string {
	if d.Granted {
		return "LOW"
	}
	return "CRITICAL"
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": src})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings: the helper returns a fixed vocabulary, got: %v", findings)
	}
}

// TestAnalyzeFile_AcceptsTimeSinceOfTaintedValue covers AC3, the real call site
// being features/terminal/websocket.go:167. A bare tainted time.Time field was
// already suppressed as scalar, but wrapping it in time.Since made it a
// CallExpr, which fell through to anyArgTainted. time.Since returns a
// time.Duration whatever its argument was, for the same reason len(...) always
// returns an int. Fails on revert of the scalar-returning-call suppression.
func TestAnalyzeFile_AcceptsTimeSinceOfTaintedValue(t *testing.T) {
	src := `package api
import "encoding/json"
import "net/http"
import "time"
type S struct{ logger logger }
type logger interface{ Info(string, ...any) }
type session struct {
	ID        string
	CreatedAt time.Time
}
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	var sess session
	_ = json.NewDecoder(r.Body).Decode(&sess)
	s.logger.Info("ended", "duration", time.Since(sess.CreatedAt))
}
`
	findings := analyzeSnippet(t, src)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings: time.Since returns a time.Duration, got: %v", findings)
	}
}

// TestAnalyzePackage_AuditFieldsFlattenIsClean covers AC5 -- the original
// symptom, with both bugs present in one shape: the map carries a sanitized
// string, a provably-scalar bool field (bug 1) and a fixed-vocabulary helper
// call (bug 2), and is logged through a variadic flatten. Fails if EITHER fix
// is reverted, which is why the two are asserted together here as well as
// separately above.
func TestAnalyzePackage_AuditFieldsFlattenIsClean(t *testing.T) {
	src := `package api
import "encoding/json"
import "net/http"
import "github.com/cfgis/cfgms/pkg/logging"
type S struct{ logger logger }
type logger interface {
	Info(string, ...any)
	Warn(string, ...any)
}
type decision struct {
	Reason  string
	Granted bool
}
func (s *S) audit(w http.ResponseWriter, r *http.Request) {
	var d decision
	_ = json.NewDecoder(r.Body).Decode(&d)
	auditFields := map[string]interface{}{
		"reason":   logging.SanitizeLogValue(d.Reason),
		"granted":  d.Granted,
		"severity": s.getAuditSeverity(d),
	}
	if d.Granted {
		s.logger.Info("Authorization audit", flattenFieldsToKV(auditFields)...)
	} else {
		s.logger.Warn("Authorization audit - access denied", flattenFieldsToKV(auditFields)...)
	}
}
func (s *S) getAuditSeverity(d decision) string {
	if d.Granted {
		return "LOW"
	}
	return "CRITICAL"
}
func flattenFieldsToKV(fields map[string]interface{}) []interface{} {
	out := make([]interface{}, 0, len(fields)*2)
	for k, v := range fields {
		out = append(out, k, v)
	}
	return out
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": src})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for the middleware.go:1640/:1642 shape, got: %v", findings)
	}
}

// TestAnalyzePackage_SameNamedMethodOnOtherTypeStillFlagged is the negative
// half AC2 was missing, and the review of PR #4125 caught its absence by
// finding the defect it would have prevented.
//
// callCannotReturnTaint feeds finding SUPPRESSION, so resolving a callee by
// selector tail alone is unsafe: a package that declares ANY `Error() string`
// method would silence `logger.Error("x", "error", err.Error())` on a tainted
// err -- the exact shape CLAUDE.md names as a finding, in most of features/.
// samePackageResultTypes already refuses selector calls on anything but the
// enclosing receiver, for this stated reason; callCannotReturnTaint now
// matches it.
func TestAnalyzePackage_SameNamedMethodOnOtherTypeStillFlagged(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
type S struct{ logger logger }
type logger interface{ Error(string, ...any) }
type validationError struct{ msg string }
func (e *validationError) Error() string { return "invalid request" }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	err := s.validate(mux.Vars(r)["id"])
	if err != nil {
		s.logger.Error("bad", "error", err.Error())
	}
}
func (s *S) validate(id string) error { return &validationError{msg: id} }
`
	findings := analyzeSnippets(t, map[string]string{"a.go": src})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding: err.Error() must not borrow the verdict of an unrelated same-named method, got %d: %v", len(findings), findings)
	}
}

// TestAnalyzePackage_SameNamedCrossPackageCallStillFlagged is the other shape
// of the same defect: a call on an IMPORTED type's value must not borrow a
// local function's verdict just because the method name matches. Mirrors
// samePackageResultTypes' own documented `client.Get(...)` example.
func TestAnalyzePackage_SameNamedCrossPackageCallStillFlagged(t *testing.T) {
	src := `package api
import "net/http"
import "github.com/gorilla/mux"
import "github.com/cfgis/cfgms/pkg/cache"
type S struct {
	logger logger
	client *cache.Cache
}
type logger interface{ Info(string, ...any) }
type catalog struct{}
func (c *catalog) Get(k string) string { return "fixed" }
func (s *S) handle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s.logger.Info("got", "value", s.client.Get(id))
}
`
	findings := analyzeSnippets(t, map[string]string{"a.go": src})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding: an imported type's Get must not borrow the local catalog.Get verdict, got %d: %v", len(findings), findings)
	}
}
