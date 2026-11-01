// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package cert_trust

import (
	"fmt"
	"os"
	"syscall"
)

// checkStagingBase refuses a staging base directory that another local user
// could have prepared or could modify: a symlink, a non-directory, a directory
// owned by someone other than the effective user, or one that is group- or
// other-writable. It uses Lstat so a symlink is never followed.
func checkStagingBase(baseDir string) error {
	info, err := os.Lstat(baseDir)
	if err != nil {
		return fmt.Errorf("stat staging base directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("staging base directory %q is a symlink", baseDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("staging base directory %q is not a directory", baseDir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("staging base directory %q: ownership unavailable", baseDir)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("staging base directory %q is not owned by the current user", baseDir)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("staging base directory %q is group- or other-writable (mode %o)", baseDir, info.Mode().Perm())
	}
	return nil
}
