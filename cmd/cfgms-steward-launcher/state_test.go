// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newLayout(t *testing.T) Layout {
	t.Helper()
	return Layout{
		Root:              t.TempDir(),
		StewardBinaryName: defaultStewardBinaryName(),
	}
}

func TestLayout_PathsRoutedThroughRoot(t *testing.T) {
	// Use a literal binary name so the path assertions below stay
	// platform-independent; the launcher itself is OS-agnostic.
	l := Layout{Root: "/opt/cfgms", StewardBinaryName: "cfgms-steward"}

	if got, want := l.CurrentPath(), filepath.Join("/opt/cfgms", "current.txt"); got != want {
		t.Errorf("CurrentPath = %q, want %q", got, want)
	}
	if got, want := l.PreviousPath(), filepath.Join("/opt/cfgms", "previous.txt"); got != want {
		t.Errorf("PreviousPath = %q, want %q", got, want)
	}
	if got, want := l.VersionsDir(), filepath.Join("/opt/cfgms", "versions"); got != want {
		t.Errorf("VersionsDir = %q, want %q", got, want)
	}

	exe, err := l.StewardExeFor("v1")
	if err != nil {
		t.Fatalf("StewardExeFor: %v", err)
	}
	if want := filepath.Join("/opt/cfgms", "versions", "v1", "cfgms-steward"); exe != want {
		t.Errorf("StewardExeFor = %q, want %q", exe, want)
	}
}

func TestValidateVersion_RejectsBadInput(t *testing.T) {
	bad := []string{"", "..", "../escape", "a/b", `a\b`, "..\\evil", "v/1"}
	for _, v := range bad {
		if err := validateVersion(v); err == nil {
			t.Errorf("validateVersion(%q) = nil, want error", v)
		}
	}
	good := []string{"v1", "v1.2.3", "abc123", "release-2026.06", "sha256-deadbeef"}
	for _, v := range good {
		if err := validateVersion(v); err != nil {
			t.Errorf("validateVersion(%q) = %v, want nil", v, err)
		}
	}
}

func TestReadCurrent_MissingFileReturnsEmpty(t *testing.T) {
	l := newLayout(t)
	got, err := l.ReadCurrent()
	if err != nil {
		t.Fatalf("ReadCurrent on fresh layout: %v", err)
	}
	if got != "" {
		t.Errorf("ReadCurrent = %q, want empty string for missing current.txt", got)
	}
}

func TestWriteCurrent_StagesPreviousOnReplace(t *testing.T) {
	l := newLayout(t)

	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}
	if prev, _ := l.ReadPrevious(); prev != "" {
		t.Errorf("after first WriteCurrent previous = %q, want empty", prev)
	}

	if err := l.WriteCurrent("v2"); err != nil {
		t.Fatalf("WriteCurrent v2: %v", err)
	}
	cur, _ := l.ReadCurrent()
	prev, _ := l.ReadPrevious()
	if cur != "v2" || prev != "v1" {
		t.Errorf("after WriteCurrent v2: current=%q previous=%q, want current=v2 previous=v1", cur, prev)
	}
}

func TestWriteCurrent_SameVersionDoesNotShufflePrevious(t *testing.T) {
	l := newLayout(t)
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}
	if err := l.WriteCurrent("v2"); err != nil {
		t.Fatalf("WriteCurrent v2: %v", err)
	}
	// Re-writing the same current value must not blow away the rollback target.
	if err := l.WriteCurrent("v2"); err != nil {
		t.Fatalf("WriteCurrent v2 again: %v", err)
	}
	prev, _ := l.ReadPrevious()
	if prev != "v1" {
		t.Errorf("previous = %q, want v1 (not shuffled away by no-op WriteCurrent)", prev)
	}
}

func TestRollback_SwapsCurrentAndPrevious(t *testing.T) {
	l := newLayout(t)
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}
	if err := l.WriteCurrent("v2"); err != nil {
		t.Fatalf("WriteCurrent v2: %v", err)
	}

	newCur, err := l.Rollback()
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if newCur != "v1" {
		t.Errorf("Rollback returned %q, want v1", newCur)
	}
	cur, _ := l.ReadCurrent()
	prev, _ := l.ReadPrevious()
	if cur != "v1" || prev != "v2" {
		t.Errorf("after rollback: current=%q previous=%q, want current=v1 previous=v2", cur, prev)
	}
}

func TestRollback_NoPreviousReturnsError(t *testing.T) {
	l := newLayout(t)
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent v1: %v", err)
	}
	if _, err := l.Rollback(); err == nil {
		t.Fatal("Rollback with no previous returned nil error, want error")
	}
}

func TestReadLegacyPointer_TrimsTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "current.txt")
	if err := os.WriteFile(p, []byte("v1\n\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readLegacyPointer(p)
	if err != nil {
		t.Fatalf("readLegacyPointer: %v", err)
	}
	if got != "v1" {
		t.Errorf("readLegacyPointer = %q, want %q", got, "v1")
	}
	if strings.ContainsAny(got, " \t\r\n") {
		t.Errorf("readLegacyPointer returned whitespace: %q", got)
	}
}

// TestLayout_LegacyPointerMigration verifies installations that booted
// before state.json existed (with current.txt + previous.txt as the
// pointer files) are correctly read on first load. After a WriteCurrent
// call all subsequent reads come from state.json.
func TestLayout_LegacyPointerMigration(t *testing.T) {
	l := newLayout(t)
	require := func(cond bool, msg string) {
		t.Helper()
		if !cond {
			t.Fatal(msg)
		}
	}

	// Pre-seed legacy single-line pointer files like an older installation.
	require(os.WriteFile(l.CurrentPath(), []byte("v-legacy-current\n"), 0o600) == nil, "write legacy current.txt")
	require(os.WriteFile(l.PreviousPath(), []byte("v-legacy-previous\n"), 0o600) == nil, "write legacy previous.txt")

	cur, err := l.ReadCurrent()
	if err != nil {
		t.Fatalf("ReadCurrent: %v", err)
	}
	if cur != "v-legacy-current" {
		t.Errorf("ReadCurrent = %q, want v-legacy-current", cur)
	}
	prev, err := l.ReadPrevious()
	if err != nil {
		t.Fatalf("ReadPrevious: %v", err)
	}
	if prev != "v-legacy-previous" {
		t.Errorf("ReadPrevious = %q, want v-legacy-previous", prev)
	}

	// After WriteCurrent, the canonical source is state.json. The
	// previous slot must still hold v-legacy-current (the value
	// previously in current.txt) so a Rollback would still work.
	if err := l.WriteCurrent("v-new"); err != nil {
		t.Fatalf("WriteCurrent: %v", err)
	}
	if _, err := os.Stat(l.StatePath()); err != nil {
		t.Errorf("state.json must exist after WriteCurrent: %v", err)
	}
	cur, _ = l.ReadCurrent()
	prev, _ = l.ReadPrevious()
	if cur != "v-new" || prev != "v-legacy-current" {
		t.Errorf("post-migration state: current=%q previous=%q, want v-new / v-legacy-current", cur, prev)
	}
}

// TestLayout_StateJSONAtomicity verifies the single-file pointer state
// is the only on-disk source after migration: a manually corrupted
// state.json results in a parse error, NOT a fallback to the legacy
// files (because state.json existing is the signal that migration has
// happened — silently re-reading the stale legacy files would mask
// data loss).
func TestLayout_StateJSONCorruption_DoesNotFallBack(t *testing.T) {
	l := newLayout(t)
	if err := l.WriteCurrent("v1"); err != nil {
		t.Fatalf("WriteCurrent: %v", err)
	}
	// Corrupt state.json — write garbage that's not valid JSON.
	if err := os.WriteFile(l.StatePath(), []byte("garbage{"), 0o600); err != nil {
		t.Fatalf("corrupt write: %v", err)
	}
	// Pre-seed legacy files as a tempting-but-wrong fallback target.
	if err := os.WriteFile(l.CurrentPath(), []byte("v-old-legacy\n"), 0o600); err != nil {
		t.Fatalf("legacy write: %v", err)
	}

	_, err := l.ReadCurrent()
	if err == nil {
		t.Fatal("ReadCurrent must surface the state.json parse error, not silently fall back to current.txt")
	}
}
