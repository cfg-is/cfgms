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
