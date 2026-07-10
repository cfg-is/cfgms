// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package conformance_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/conformance"
	filemod "github.com/cfgis/cfgms/features/modules/stdlib/file"
)

// configuredFileModule creates a file module with AllowedBasePath set to basePath,
// ready for Get calls without needing a prior Set.
func configuredFileModule(t *testing.T, basePath string) modules.Module {
	t.Helper()
	m := filemod.New()
	cfg, ok := m.(modules.Configurable)
	if !ok {
		t.Fatal("file module does not implement modules.Configurable")
	}
	// FileConfig with only AllowedBasePath is sufficient for Configure —
	// it only reads the allowed_base_path key from AsMap().
	baseCfg := &filemod.FileConfig{AllowedBasePath: basePath}
	if err := cfg.Configure(baseCfg); err != nil {
		t.Fatalf("Configure(basePath=%q): %v", basePath, err)
	}
	return m
}

// TestAssertDeterministicGet_FileModule verifies that AssertDeterministicGet
// passes against the stdlib/file module, which is the canonical worked example
// for ADR-016 clause 4 compliance.
func TestAssertDeterministicGet_FileModule(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "hello.txt")
	if err := os.WriteFile(testFile, []byte("hello conformance"), 0644); err != nil {
		t.Fatalf("setup: write test file: %v", err)
	}

	m := configuredFileModule(t, tmpDir)
	conformance.AssertDeterministicGet(t, m, testFile)
}

// TestAssertDeterministicGet_AbsentResource verifies determinism when Get
// returns an "absent" state (resource does not exist on disk).
func TestAssertDeterministicGet_AbsentResource(t *testing.T) {
	tmpDir := t.TempDir()
	m := configuredFileModule(t, tmpDir)
	absent := filepath.Join(tmpDir, "does-not-exist.txt")
	conformance.AssertDeterministicGet(t, m, absent)
}

// TestAssertNoEphemeralFields_FileModule verifies that AssertNoEphemeralFields
// passes against the state returned by the stdlib/file module Get.
func TestAssertNoEphemeralFields_FileModule(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "hello.txt")
	if err := os.WriteFile(testFile, []byte("hello conformance"), 0644); err != nil {
		t.Fatalf("setup: write test file: %v", err)
	}

	m := configuredFileModule(t, tmpDir)
	state, err := m.Get(context.Background(), testFile)
	if err != nil {
		t.Fatalf("Get(%q): %v", testFile, err)
	}
	conformance.AssertNoEphemeralFields(t, state, conformance.DefaultBannedEphemeralFields)
}
