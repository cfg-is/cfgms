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
