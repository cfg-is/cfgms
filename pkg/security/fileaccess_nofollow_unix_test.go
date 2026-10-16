//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDanglingSymlinkLeafRejected(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.txt")
	if err := os.Symlink(target, filepath.Join(base, "link.txt")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if _, err := ValidateAndCleanPath(base, "link.txt"); err == nil {
		t.Fatal("ValidateAndCleanPath must reject a dangling symlink")
	}
	if err := SecureWriteFileWithPerms(base, "link.txt", []byte("x"), 0600); err == nil {
		t.Fatal("SecureWriteFileWithPerms must reject a dangling symlink")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("outside target must not be created, stat err = %v", err)
	}
}

func TestDanglingSymlinkIntermediateDirRejected(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(t.TempDir(), "newdir")
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	if _, err := ValidateAndCleanPath(base, "link/new.txt"); err == nil {
		t.Fatal("ValidateAndCleanPath must reject a dangling intermediate symlink")
	}
	if err := SecureWriteFile(base, "link/new.txt", []byte("x")); err == nil {
		t.Fatal("SecureWriteFile must reject a dangling intermediate symlink")
	}
	if _, err := os.Lstat(outside); !os.IsNotExist(err) {
		t.Fatalf("outside directory must not be created, stat err = %v", err)
	}
}

// A dangling link beneath an ancestor that is an absolute in-base symlink must still be
// rejected: the walk resolves the ancestor before probing the next component.
func TestDanglingSymlinkBehindAbsoluteInBaseLinkRejected(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(base, "abs")); err != nil {
		t.Fatalf("create absolute symlink: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "newdir")
	if err := os.Symlink(outside, filepath.Join(realDir, "dangling")); err != nil {
		t.Fatalf("create dangling symlink: %v", err)
	}

	if _, err := ValidateAndCleanPath(base, "abs/dangling/new.txt"); err == nil {
		t.Fatal("ValidateAndCleanPath must reject a dangling link behind an absolute in-base link")
	}
}

// An absolute symlink that points inside the base is legitimate; a non-existent tail beneath
// it resolves to the link's target directory.
func TestAbsoluteInBaseLinkWithMissingTailAccepted(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDir, filepath.Join(base, "abs")); err != nil {
		t.Fatalf("create absolute symlink: %v", err)
	}

	got, err := ValidateAndCleanPath(base, "abs/newdir/new.txt")
	if err != nil {
		t.Fatalf("ValidateAndCleanPath rejected an in-base absolute link: %v", err)
	}
	resolvedReal, err := filepath.EvalSymlinks(realDir)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(resolvedReal, "newdir", "new.txt"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestOpenNoFollowRejectsSwappedLeaf(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(target, []byte("orig"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "swapped")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	f, err := openNoFollow(link, os.O_WRONLY|os.O_TRUNC, 0600)
	if err == nil {
		_ = f.Close()
		t.Fatal("openNoFollow must fail on a symlink leaf")
	}
	if b, _ := os.ReadFile(target); string(b) != "orig" {
		t.Fatalf("target was modified: %q", b)
	}
}
