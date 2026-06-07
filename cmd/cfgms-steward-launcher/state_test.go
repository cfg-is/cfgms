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

func TestReadVersionFile_TrimsTrailingNewline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "current.txt")
	if err := os.WriteFile(p, []byte("v1\n\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readVersionFile(p)
	if err != nil {
		t.Fatalf("readVersionFile: %v", err)
	}
	if got != "v1" {
		t.Errorf("readVersionFile = %q, want %q", got, "v1")
	}
	if strings.ContainsAny(got, " \t\r\n") {
		t.Errorf("readVersionFile returned whitespace: %q", got)
	}
}
