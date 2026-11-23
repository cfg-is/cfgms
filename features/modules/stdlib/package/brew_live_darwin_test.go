// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build darwin && brewlive

package package_module

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// liveFormula is a small formula with no dependencies, so the live run stays
// short.
const liveFormula = "hello"

// TestBrewLiveRunsAsPrefixOwner starts the real Homebrew provider as root and
// proves brew ran as the Homebrew prefix owner, never as root. It is built with
// the brewlive tag and run only by the macos-brew-live job of
// cross-platform-build-pr.yml on a hosted macOS runner (passwordless sudo,
// Homebrew installed at its fixed path and owned by the runner user). It
// installs and removes real software, so it never runs under the ordinary
// test targets.
//
// Prerequisites are failures, not skips: a skipped run would let the gate pass
// without the root-to-owner switch having run.
func TestBrewLiveRunsAsPrefixOwner(t *testing.T) {
	if euid := os.Geteuid(); euid != 0 {
		t.Fatalf("this test must run as root (euid 0), got euid %d: run the test binary under sudo", euid)
	}

	loc, err := brewLocationFor(runtime.GOARCH)
	if err != nil {
		t.Fatalf("brewLocationFor(%q): %v", runtime.GOARCH, err)
	}
	if _, err := os.Stat(loc.BinPath); err != nil {
		t.Fatalf("brew is missing at its fixed path %s for %s: %v", loc.BinPath, runtime.GOARCH, err)
	}

	// The prefix owner as the module's own lookup determines it.
	target, err := resolveBrew(runtime.GOARCH)
	if err != nil {
		t.Fatalf("resolveBrew(%q): %v", runtime.GOARCH, err)
	}
	if target.UID == 0 {
		t.Fatalf("prefix owner resolved to root (uid 0); expected the Homebrew repository owner")
	}
	repoUID := fileUID(t, loc.RepoDir)
	if target.UID != repoUID {
		t.Fatalf("resolveBrew owner uid %d differs from repository directory %s owner uid %d", target.UID, loc.RepoDir, repoUID)
	}

	mgr := newHomebrewManager()
	checker, ok := mgr.(interface {
		IsInstalled(ctx context.Context, name string) (bool, error)
	})
	if !ok {
		t.Fatalf("%T does not provide IsInstalled", mgr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// The keg lives under the prefix: /opt/homebrew on arm64, /usr/local on
	// amd64 (whose repository directory is /usr/local/Homebrew).
	prefix := filepath.Dir(target.BinDir)
	kegDir := filepath.Join(prefix, "Cellar", liveFormula)

	installed, err := checker.IsInstalled(ctx, liveFormula)
	if err != nil {
		t.Fatalf("IsInstalled(%q) before install: %v", liveFormula, err)
	}
	if installed {
		t.Fatalf("%q is already installed before the test started; the runner image must not carry it", liveFormula)
	}
	if _, err := os.Lstat(kegDir); err == nil {
		t.Fatalf("keg directory %s already exists before the test started", kegDir)
	}

	// Remove is deferred so a failure after install does not leave the formula
	// on the runner; the explicit Remove below is the asserted one.
	removed := false
	defer func() {
		if !removed {
			if err := mgr.Remove(context.Background(), liveFormula); err != nil {
				t.Logf("cleanup Remove(%q): %v", liveFormula, err)
			}
		}
	}()

	// The provider's Install requires version "latest" (Homebrew has no
	// generic version pin) and rejects an empty version.
	if err := mgr.Install(ctx, liveFormula, "latest"); err != nil {
		t.Fatalf("Install(%q) as root: %v", liveFormula, err)
	}

	installed, err = checker.IsInstalled(ctx, liveFormula)
	if err != nil {
		t.Fatalf("IsInstalled(%q) after install: %v", liveFormula, err)
	}
	if !installed {
		t.Fatalf("IsInstalled(%q) = false after a successful Install", liveFormula)
	}
	list, err := mgr.ListInstalled(ctx)
	if err != nil {
		t.Fatalf("ListInstalled after install: %v", err)
	}
	if _, found := list[liveFormula]; !found {
		t.Fatalf("ListInstalled does not report %q after install: %v", liveFormula, list)
	}

	// brew ran as the prefix owner: everything it wrote belongs to that uid,
	// and none of it to root.
	entries := 0
	walkErr := filepath.Walk(kegDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		entries++
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Errorf("%s: no ownership information", path)
			return nil
		}
		if st.Uid == 0 {
			t.Errorf("%s is owned by root (uid 0); brew must run as the prefix owner (uid %d)", path, repoUID)
		} else if st.Uid != repoUID {
			t.Errorf("%s is owned by uid %d, want the Homebrew repository owner uid %d", path, st.Uid, repoUID)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking keg directory %s: %v", kegDir, walkErr)
	}
	if entries < 2 {
		t.Fatalf("keg directory %s holds %d entries; expected the keg directory and its contents", kegDir, entries)
	}

	if err := mgr.Remove(ctx, liveFormula); err != nil {
		t.Fatalf("Remove(%q) as root: %v", liveFormula, err)
	}
	removed = true

	installed, err = checker.IsInstalled(ctx, liveFormula)
	if err != nil {
		t.Fatalf("IsInstalled(%q) after remove: %v", liveFormula, err)
	}
	if installed {
		t.Fatalf("IsInstalled(%q) = true after Remove", liveFormula)
	}
	list, err = mgr.ListInstalled(ctx)
	if err != nil {
		t.Fatalf("ListInstalled after remove: %v", err)
	}
	if _, found := list[liveFormula]; found {
		t.Fatalf("ListInstalled still reports %q after Remove: %v", liveFormula, list)
	}
	if _, err := os.Lstat(kegDir); !os.IsNotExist(err) {
		t.Fatalf("keg directory %s still exists after Remove (stat error: %v)", kegDir, err)
	}
}

// fileUID returns the owning uid of path.
func fileUID(t *testing.T, path string) uint32 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no ownership information for %s", path)
	}
	return st.Uid
}
