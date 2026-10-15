// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build !windows

package install

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// protectedDirMode is the mode of every directory the installer creates.
const protectedDirMode os.FileMode = 0o755

// writableByOthers reports whether mode carries a group or other write bit.
func writableByOthers(mode fs.FileMode) bool {
	return mode.Perm()&0o022 != 0
}

func ensureProtectedDir(path string) error {
	// #nosec G301 -- module trees are world-readable, administrator-writable.
	if err := os.MkdirAll(path, protectedDirMode); err != nil {
		return fmt.Errorf("create protected directory: %w", os.ErrPermission)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return ErrTreeNotProtected
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !ownerAcceptable(st.Uid, uint32(os.Geteuid())) { // #nosec G115 -- uid fits uint32
		return ErrTreeNotProtected
	}
	// #nosec G302 -- module directories are world-readable, administrator-writable.
	if err := os.Chmod(path, protectedDirMode); err != nil {
		return ErrTreeNotProtected
	}
	return nil
}

func checkProtectedDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return ErrTreeNotProtected
	}
	return checkEntry(info)
}

func checkEntry(info fs.FileInfo) error {
	if !info.IsDir() && !info.Mode().IsRegular() {
		return ErrTreeNotProtected
	}
	if writableByOthers(info.Mode()) {
		return ErrTreeNotProtected
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !ownerAcceptable(st.Uid, uint32(os.Geteuid())) { // #nosec G115 -- uid fits uint32
		return ErrTreeNotProtected
	}
	return nil
}

func checkProtectedTree(root string) error {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() {
		return ErrTreeNotProtected
	}
	walkErr := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return ErrTreeNotProtected
		}
		info, err := d.Info()
		if err != nil {
			return ErrTreeNotProtected
		}
		return checkEntry(info)
	})
	if walkErr != nil {
		return ErrTreeNotProtected
	}
	return nil
}
