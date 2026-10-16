// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package cert_trust

import (
	"os"
	"path/filepath"
	"testing"
)

// legacyStagedName is the predictable name the old darwin executor used.
func legacyStagedName(fp string) string { return "cfgms-cert-install-" + fp + ".pem" }

func TestStageForTrustCommand_WritesExactPEM(t *testing.T) {
	base := filepath.Join(t.TempDir(), "staging")
	want := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")

	path, cleanup, err := stageForTrustCommand(base, want)
	if err != nil {
		t.Fatalf("stageForTrustCommand: %v", err)
	}
	defer cleanup()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged file: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("staged content = %q, want %q", got, want)
	}
}

func TestStageForTrustCommand_PreexistingFileAtOldNameUntouched(t *testing.T) {
	base := t.TempDir()
	_, der := generateTestCAPEM(t)
	old := filepath.Join(base, legacyStagedName(certFingerprint(der)))
	if err := os.WriteFile(old, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := []byte("the real pem")

	path, cleanup, err := stageForTrustCommand(base, want)
	if err != nil {
		t.Fatalf("stageForTrustCommand: %v", err)
	}
	defer cleanup()

	if path == old {
		t.Fatalf("helper returned the predictable path %q", old)
	}
	if got, _ := os.ReadFile(old); string(got) != "planted" {
		t.Errorf("pre-created file modified: %q", got)
	}
	if got, _ := os.ReadFile(path); string(got) != string(want) {
		t.Errorf("staged content = %q, want %q", got, want)
	}
}

func TestStageForTrustCommand_UniquePathsAndCleanup(t *testing.T) {
	base := t.TempDir()
	p1, c1, err := stageForTrustCommand(base, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	p2, c2, err := stageForTrustCommand(base, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	defer c2()
	if p1 == p2 {
		t.Fatalf("two calls returned the same path %q", p1)
	}

	c1()
	if _, err := os.Stat(p1); !os.IsNotExist(err) {
		t.Errorf("staged file still present after cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(p1)); !os.IsNotExist(err) {
		t.Errorf("staging subdirectory still present after cleanup: %v", err)
	}
	c1() // idempotent
}

func TestStageForTrustCommand_CreatesMissingBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "a", "b")
	_, cleanup, err := stageForTrustCommand(base, []byte("x"))
	if err != nil {
		t.Fatalf("stageForTrustCommand: %v", err)
	}
	defer cleanup()
	if _, err := os.Stat(base); err != nil {
		t.Errorf("base not created: %v", err)
	}
}

func TestStageForTrustCommand_EmptyBaseRefused(t *testing.T) {
	if _, _, err := stageForTrustCommand("", []byte("x")); err == nil {
		t.Fatal("expected error for empty base")
	}
}
