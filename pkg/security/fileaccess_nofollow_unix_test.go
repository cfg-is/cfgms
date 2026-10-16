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
