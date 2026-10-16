//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDanglingJunctionIntermediateRejected(t *testing.T) {
	base := t.TempDir()
	missing := filepath.Join(t.TempDir(), "gone")
	if err := os.Mkdir(missing, 0700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "junc")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, missing).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J failed: %v: %s", err, out)
	}
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}

	if _, err := ValidateAndCleanPath(base, `junc\new.txt`); err == nil {
		t.Fatal("ValidateAndCleanPath must reject a dangling junction")
	}
}

func TestOpenNoFollowRejectsSymlinkLeaf(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(target, []byte("orig"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("creating a symlink needs SeCreateSymbolicLinkPrivilege: %v", err)
	}
	if f, err := openNoFollow(link, os.O_WRONLY, 0600); err == nil {
		_ = f.Close()
		t.Fatal("openNoFollow must reject a symlink leaf")
	}
}

// A component holding ":" (for example a repo ID like "github:owner/repo") is not a
// valid Windows file name, so Lstat cannot find it: it is a not-yet-existing tail
// component inside the base, not a traversal.
func TestColonComponentIsMissingTail(t *testing.T) {
	base := t.TempDir()
	got, err := ValidateAndCleanPath(base, `github:test-owner\test-repo`)
	if err != nil {
		t.Fatalf("ValidateAndCleanPath must accept a colon component as a new tail: %v", err)
	}
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(resolvedBase, `github:test-owner\test-repo`); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func mklinkJunction(t *testing.T, junction, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J failed: %v: %s", err, out)
	}
}

func TestLiveJunctionEscapingBaseRejected(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "exists.txt"), []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	mklinkJunction(t, filepath.Join(base, "sub"), outside)

	for _, userPath := range []string{`sub`, `sub\x`, `sub\newdir\x`, `sub\exists.txt`} {
		if got, err := ValidateAndCleanPath(base, userPath); err == nil {
			t.Errorf("ValidateAndCleanPath(%q) = %q, want rejection of a junction pointing outside the base", userPath, got)
		}
	}

	if err := SecureWriteFile(base, `sub\newdir\x`, []byte("escaped")); err == nil {
		t.Error("SecureWriteFile must refuse to write through a junction pointing outside the base")
	}
	if err := SecureWriteFileWithPerms(base, `sub\x`, []byte("escaped"), 0600); err == nil {
		t.Error("SecureWriteFileWithPerms must refuse to write through a junction pointing outside the base")
	}
	for _, name := range []string{"x", "newdir"} {
		if _, err := os.Lstat(filepath.Join(outside, name)); !os.IsNotExist(err) {
			t.Errorf("%s was created outside the base (Lstat err = %v)", name, err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(outside, "exists.txt")); err != nil || string(data) != "outside" {
		t.Errorf("outside file changed: %q, %v", data, err)
	}
}

func TestChainedJunctionEscapingBaseRejected(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	mklinkJunction(t, filepath.Join(base, "far"), outside)
	mklinkJunction(t, filepath.Join(base, "near"), filepath.Join(base, "far"))

	if got, err := ValidateAndCleanPath(base, `near\x`); err == nil {
		t.Fatalf("ValidateAndCleanPath = %q, want rejection of a junction chain leaving the base", got)
	}
}

func TestLiveJunctionInsideBaseAllowed(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "real"), 0700); err != nil {
		t.Fatal(err)
	}
	mklinkJunction(t, filepath.Join(base, "in"), filepath.Join(base, "real"))
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ValidateAndCleanPath(base, `in\new\x`)
	if err != nil {
		t.Fatalf("ValidateAndCleanPath must accept a junction pointing inside the base: %v", err)
	}
	if want := filepath.Join(resolvedBase, `real\new\x`); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if err := SecureWriteFile(base, `in\new\x`, []byte("inside")); err != nil {
		t.Fatalf("SecureWriteFile through an in-base junction: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(base, `real\new\x`)); err != nil || string(data) != "inside" {
		t.Fatalf("in-base write not at the junction target: %q, %v", data, err)
	}
}
