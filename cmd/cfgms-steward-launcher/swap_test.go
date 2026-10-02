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

	if _, err := l.StageBinary("v1.0.0", src1); err != nil {
		t.Fatalf("StageBinary v1.0.0: %v", err)
	}
	if _, err := l.StageBinary("v2.0.0", src2); err != nil {
		t.Fatalf("StageBinary v2.0.0: %v", err)
	}

	cur, _ := l.ReadCurrent()
	prev, _ := l.ReadPrevious()
	if cur != "v2.0.0" || prev != "v1.0.0" {
		t.Errorf("after two stages: current=%q previous=%q, want v2.0.0/v1.0.0", cur, prev)
	}
}

func TestStageBinary_RejectsDowngradeByDefault(t *testing.T) {
	l := newLayout(t)
	newer := filepath.Join(t.TempDir(), "newer")
	older := filepath.Join(t.TempDir(), "older")
	writeFile(t, newer, []byte("newer"))
	writeFile(t, older, []byte("older"))

	if _, err := l.StageBinary("v2.0.0", newer); err != nil {
		t.Fatalf("StageBinary newer: %v", err)
	}
	if _, err := l.StageBinary("v1.9.9", older); err == nil {
		t.Fatal("StageBinary downgrade returned nil error")
	}
	cur, _ := l.ReadCurrent()
	if cur != "v2.0.0" {
		t.Fatalf("current after rejected downgrade = %q, want v2.0.0", cur)
	}
}

func TestStageBinary_RejectsPrereleaseDowngrade(t *testing.T) {
	l := newLayout(t)
	release := filepath.Join(t.TempDir(), "release")
	prerelease := filepath.Join(t.TempDir(), "prerelease")
	writeFile(t, release, []byte("release"))
	writeFile(t, prerelease, []byte("prerelease"))

	if _, err := l.StageBinary("v2.0.0", release); err != nil {
		t.Fatalf("StageBinary release: %v", err)
	}
	if _, err := l.StageBinary("v2.0.0-rc.1", prerelease); err == nil {
		t.Fatal("StageBinary prerelease downgrade returned nil error")
	}
}

func TestStageBinary_RejectsOpaqueCandidateAfterSemanticInstall(t *testing.T) {
	l := newLayout(t)
	semantic := filepath.Join(t.TempDir(), "semantic")
	opaque := filepath.Join(t.TempDir(), "opaque")
	writeFile(t, semantic, []byte("semantic"))
	writeFile(t, opaque, []byte("opaque"))

	if _, err := l.StageBinary("v2.0.0", semantic); err != nil {
		t.Fatalf("StageBinary semantic: %v", err)
	}
	if _, err := l.StageBinary("release-old", opaque); err == nil {
		t.Fatal("StageBinary opaque candidate returned nil error")
	}
}

func TestStageBinary_ExplicitDowngradeOverride(t *testing.T) {
	l := newLayout(t)
	newer := filepath.Join(t.TempDir(), "newer")
	older := filepath.Join(t.TempDir(), "older")
	writeFile(t, newer, []byte("newer"))
	writeFile(t, older, []byte("older"))

	if _, err := l.StageBinary("v2.0.0", newer); err != nil {
		t.Fatalf("StageBinary newer: %v", err)
	}
	if _, err := l.StageBinaryWithOptions("v1.9.9", older, StageOptions{AllowDowngrade: true}); err != nil {
		t.Fatalf("StageBinaryWithOptions explicit downgrade: %v", err)
	}
	cur, _ := l.ReadCurrent()
	if cur != "v1.9.9" {
		t.Fatalf("current after explicit downgrade = %q, want v1.9.9", cur)
	}
}

func TestStageBinary_AllowsLegacyOpaqueToSemanticMigration(t *testing.T) {
	l := newLayout(t)
	legacy := filepath.Join(t.TempDir(), "legacy")
	semantic := filepath.Join(t.TempDir(), "semantic")
	writeFile(t, legacy, []byte("legacy"))
	writeFile(t, semantic, []byte("semantic"))

	if _, err := l.StageBinary("legacy-build", legacy); err != nil {
		t.Fatalf("StageBinary legacy: %v", err)
	}
	if _, err := l.StageBinary("v1.0.0", semantic); err != nil {
		t.Fatalf("StageBinary semantic migration: %v", err)
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
