// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package cert_trust

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStageForTrustCommand_SymlinkAtOldNameNotFollowed(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(target, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, der := generateTestCAPEM(t)
	link := filepath.Join(base, legacyStagedName(certFingerprint(der)))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	want := []byte("the real pem")

	path, cleanup, err := stageForTrustCommand(base, want)
	if err != nil {
		t.Fatalf("stageForTrustCommand: %v", err)
	}
	defer cleanup()

	if path == link {
		t.Fatalf("helper returned the predictable path %q", link)
	}
	if got, _ := os.ReadFile(target); string(got) != "victim" {
		t.Errorf("symlink target modified: %q", got)
	}
	if got, _ := os.ReadFile(path); string(got) != string(want) {
		t.Errorf("staged content = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("staged file mode = %o, want 600", info.Mode().Perm())
	}
	dinfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if dinfo.Mode().Perm() != 0o700 {
		t.Errorf("staging dir mode = %o, want 700", dinfo.Mode().Perm())
	}
}

func TestStageForTrustCommand_SymlinkBaseRefused(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "base")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stageForTrustCommand(link, []byte("x")); err == nil {
		t.Fatal("expected symlink base to be refused")
	}
	entries, _ := os.ReadDir(real)
	if len(entries) != 0 {
		t.Errorf("symlink target polluted: %d entries", len(entries))
	}
}

func TestStageForTrustCommand_WritableBaseRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777, 0o720} {
		base := filepath.Join(t.TempDir(), "base")
		if err := os.Mkdir(base, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(base, mode); err != nil {
			t.Fatal(err)
		}
		if _, _, err := stageForTrustCommand(base, []byte("x")); err == nil {
			t.Errorf("mode %o: expected base to be refused", mode)
		}
	}
}

func TestStageForTrustCommand_WrongOwnerRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing directory ownership requires root")
	}
	base := filepath.Join(t.TempDir(), "base")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(base, 12345, 12345); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stageForTrustCommand(base, []byte("x")); err == nil {
		t.Fatal("expected base owned by another user to be refused")
	}
}

func TestStageForTrustCommand_FileBaseRefused(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stageForTrustCommand(f, []byte("x")); err == nil {
		t.Fatal("expected non-directory base to be refused")
	}
}
