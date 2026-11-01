// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/features/controller/config"
)

// Tests use t.TempDir()-derived paths (absolute and OS-appropriate on both the
// Linux CI runners and a Windows dev box) rather than hard-coded "/var/..."
// literals, which are not absolute under Windows filepath semantics.

// TestResolveDNADataRoot_RelativeDataDirDerivesAbsoluteFromStorage is the
// regression guard for Issue #2010: a relative (non-empty) DataDir — the
// shipped default is "data/" — must NOT yield a CWD-relative DNA store path.
// Before the fix the relative DataDir was used verbatim, so a blue/green
// candidate launched from a different working directory opened a different,
// empty dna.db and warm-loaded zero stewards.
func TestResolveDNADataRoot_RelativeDataDirDerivesAbsoluteFromStorage(t *testing.T) {
	storageRoot := filepath.Join(t.TempDir(), "storage")
	cfg := &config.Config{
		DataDir: "data/", // the shipped relative default
		Storage: &config.StorageConfig{
			SQLitePath:   filepath.Join(storageRoot, "cfgms.db"),
			FlatfileRoot: filepath.Join(storageRoot, "flatfile"),
		},
	}

	got := resolveDNADataRoot(cfg)

	if !filepath.IsAbs(got) {
		t.Fatalf("resolveDNADataRoot returned a non-absolute path %q; a CWD-relative DNA store breaks blue/green warm-load (Issue #2010)", got)
	}
	if got != storageRoot {
		t.Fatalf("resolveDNADataRoot = %q, want %q (derived from SQLitePath dir)", got, storageRoot)
	}
}

// TestResolveDNADataRoot_EmptyDataDirDerivesFromStorage covers the original
// guarded case (empty DataDir) which must keep working.
func TestResolveDNADataRoot_EmptyDataDirDerivesFromStorage(t *testing.T) {
	dbDir := filepath.Join(t.TempDir(), "db")
	cfg := &config.Config{
		DataDir: "",
		Storage: &config.StorageConfig{SQLitePath: filepath.Join(dbDir, "cfgms.db")},
	}
	got := resolveDNADataRoot(cfg)
	if got != dbDir {
		t.Fatalf("resolveDNADataRoot = %q, want %q", got, dbDir)
	}
}

// TestResolveDNADataRoot_FlatfileFallback exercises the FlatfileRoot branch
// when no SQLitePath is configured.
func TestResolveDNADataRoot_FlatfileFallback(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Config{
		DataDir: "data/",
		Storage: &config.StorageConfig{FlatfileRoot: filepath.Join(root, "flat")},
	}
	got := resolveDNADataRoot(cfg)
	if got != root {
		t.Fatalf("resolveDNADataRoot = %q, want %q", got, root)
	}
}

// TestResolveDNADataRoot_AbsoluteDataDirHonored asserts an explicitly-set
// absolute DataDir is returned unchanged (storage derivation must not override
// an operator's deliberate choice).
func TestResolveDNADataRoot_AbsoluteDataDirHonored(t *testing.T) {
	abs := t.TempDir() // absolute, OS-appropriate
	cfg := &config.Config{
		DataDir: abs,
		Storage: &config.StorageConfig{SQLitePath: filepath.Join(t.TempDir(), "cfgms.db")},
	}
	got := resolveDNADataRoot(cfg)
	if got != abs {
		t.Fatalf("resolveDNADataRoot = %q, want %q (absolute DataDir must be honored)", got, abs)
	}
}

// TestResolveDNADataRoot_POSIXAbsoluteDataDirHonoredOnEveryPlatform is the Issue #3460
// regression: a controller.cfg is a reviewed, hand-authored artefact using POSIX paths
// (the canonical example ships `data_dir: "/var/lib/cfgms"` right next to `cert_path`)
// and is parsed on every platform the controller builds for. filepath.IsAbs answers for
// the running platform only — on Windows a path needs a volume name, so
// filepath.IsAbs("/var/lib/cfgms") is false — which silently discarded the operator's
// declared absolute DataDir and re-derived it from Storage instead. A leading slash must
// be honored as rooted regardless of GOOS, exactly as config.IsRootedPath already
// guarantees for cert_path.
func TestResolveDNADataRoot_POSIXAbsoluteDataDirHonoredOnEveryPlatform(t *testing.T) {
	cfg := &config.Config{
		DataDir: "/var/lib/cfgms",
		Storage: &config.StorageConfig{SQLitePath: filepath.Join(t.TempDir(), "cfgms.db")},
	}

	got := resolveDNADataRoot(cfg)

	if got != "/var/lib/cfgms" {
		t.Fatalf("resolveDNADataRoot = %q, want %q (a POSIX-rooted DataDir must be honored on every platform, not re-derived from Storage)", got, "/var/lib/cfgms")
	}
}

// TestResolveDNADataRoot_NoStorageStillAbsolute is the degenerate last-resort:
// no storage configured and a relative/empty DataDir must still yield an
// absolute path rather than silently landing in an arbitrary CWD. The exact
// resolved path is deliberately NOT asserted — the last-resort branch anchors
// to the process CWD at test time, which is not a valid configuration for a
// real deployment; only the absoluteness invariant is meaningful here.
func TestResolveDNADataRoot_NoStorageStillAbsolute(t *testing.T) {
	cfg := &config.Config{DataDir: "data/", Storage: nil}
	got := resolveDNADataRoot(cfg)
	if !filepath.IsAbs(got) {
		t.Fatalf("resolveDNADataRoot = %q, want an absolute path even with no storage configured", got)
	}
}
