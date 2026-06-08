// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, content, 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write: %v", err)
	}
}

func TestStageBinary_CopiesAndMarksCurrent(t *testing.T) {
	l := newLayout(t)

	src := filepath.Join(t.TempDir(), "cfgms-steward-fresh")
	payload := []byte("fresh-binary-bytes")
	writeFile(t, src, payload)

	dst, err := l.StageBinary("v1", src)
	if err != nil {
		t.Fatalf("StageBinary: %v", err)
	}

	got, err := os.ReadFile(dst) //nolint:gosec // test
	if err != nil {
		t.Fatalf("read staged file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("staged content = %q, want %q", got, payload)
	}

	cur, _ := l.ReadCurrent()
	if cur != "v1" {
		t.Errorf("current after stage = %q, want v1", cur)
	}
}

func TestStageBinary_SecondStageRecordsPrevious(t *testing.T) {
	l := newLayout(t)
	src1 := filepath.Join(t.TempDir(), "v1")
	src2 := filepath.Join(t.TempDir(), "v2")
	writeFile(t, src1, []byte("first"))
	writeFile(t, src2, []byte("second"))

	if _, err := l.StageBinary("v1", src1); err != nil {
		t.Fatalf("StageBinary v1: %v", err)
	}
	if _, err := l.StageBinary("v2", src2); err != nil {
		t.Fatalf("StageBinary v2: %v", err)
	}

	cur, _ := l.ReadCurrent()
	prev, _ := l.ReadPrevious()
	if cur != "v2" || prev != "v1" {
		t.Errorf("after two stages: current=%q previous=%q, want v2/v1", cur, prev)
	}
}

func TestStageBinary_RejectsBadVersion(t *testing.T) {
	l := newLayout(t)
	src := filepath.Join(t.TempDir(), "x")
	writeFile(t, src, []byte("bytes"))

	if _, err := l.StageBinary("../escape", src); err == nil {
		t.Fatal("StageBinary with traversal version returned nil error")
	}
	if _, err := l.StageBinary("", src); err == nil {
		t.Fatal("StageBinary with empty version returned nil error")
	}
}

func TestStageBinary_MissingSourceReturnsError(t *testing.T) {
	l := newLayout(t)
	if _, err := l.StageBinary("v1", filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("StageBinary with missing source returned nil error")
	}
	// And current.txt must NOT have been written to half-committed state.
	cur, _ := l.ReadCurrent()
	if cur != "" {
		t.Errorf("current.txt = %q after failed stage, want empty (no half-commit)", cur)
	}
}
