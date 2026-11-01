//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package file

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cfgis/cfgms/pkg/logging"
)

func TestFileModule_Set_DanglingSymlinkRejected(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "created.txt")
	link := filepath.Join(base, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	err := New().Set(context.Background(), link, createConfigFromYAML(testFileConfigYAML("x", "", "", base)))
	if err == nil {
		t.Fatal("Set() through a dangling symlink must fail")
	}
	if _, statErr := os.Lstat(target); !os.IsNotExist(statErr) {
		t.Fatalf("link target must not be created, stat err = %v", statErr)
	}
}

func TestNoFollowMetadataHelpers_RejectSymlinkLeaf(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	outFile := filepath.Join(outside, "f.txt")
	if err := os.WriteFile(outFile, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(outside, "d")
	if err := os.Mkdir(outDir, 0700); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		target string
		isDir  bool
	}{"file": {outFile, false}, "dir": {outDir, true}} {
		t.Run(name, func(t *testing.T) {
			link := filepath.Join(base, name+"-link")
			if err := os.Symlink(tc.target, link); err != nil {
				t.Skipf("cannot create symlink: %v", err)
			}
			before, _ := os.Stat(tc.target)

			if err := chmodNoFollow(link, 0777, tc.isDir); err == nil {
				t.Error("chmodNoFollow must fail on a symlink leaf")
			}
			if err := chownNoFollow(link, os.Getuid(), os.Getgid(), tc.isDir); err == nil {
				t.Error("chownNoFollow must fail on a symlink leaf")
			}
			if err := setOwnership(context.Background(), link, "root", "", logging.NewNoopLogger(), "r"); err == nil {
				t.Error("setOwnership must fail on a symlink leaf")
			}
			after, _ := os.Stat(tc.target)
			if before.Mode() != after.Mode() {
				t.Errorf("target mode changed: %v -> %v", before.Mode(), after.Mode())
			}
		})
	}
}

func TestFileModule_Set_SwappedIntermediateDirRejected(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(base, "sub")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	path := filepath.Join(base, "sub", "deep", "f.txt")

	err := New().Set(context.Background(), path, createConfigFromYAML(testFileConfigYAML("x", "", "", base)))
	if err == nil {
		t.Fatal("Set() through a swapped intermediate directory must fail")
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("nothing may be written outside AllowedBasePath, found %d entries", len(entries))
	}
}

// A racing goroutine flips the intermediate directory between a real directory and
// a link to an outside directory while Set runs, so some writes are validated
// against the real directory and then hit the link.
func TestFileModule_Set_RacingIntermediateSwapStaysInBase(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	sub := filepath.Join(base, "sub")
	if err := os.Symlink(outside, filepath.Join(base, "probe")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.RemoveAll(sub)
			_ = os.Mkdir(sub, 0750)
			_ = os.Remove(sub)
			_ = os.Symlink(outside, sub)
		}
	}()

	mod := New()
	cfg := createConfigFromYAML(testFileConfigYAML("x", "", "", base))
	for i := 0; i < 300; i++ {
		_ = mod.Set(context.Background(), filepath.Join(sub, "deep", "f.txt"), cfg)
	}
	close(stop)
	wg.Wait()

	entries, _ := os.ReadDir(outside)
	if len(entries) != 0 {
		t.Fatalf("nothing may be written outside AllowedBasePath, found %d entries", len(entries))
	}
}
