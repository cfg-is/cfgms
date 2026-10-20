// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// secureCredentialsDir creates the credentials directory at mode 0700 if it does
// not exist. An existing directory must not be a symlink and must be owned by the
// current user; any group or other access is removed with chmod 0700.
func secureCredentialsDir(dir string) error {
	dir = filepath.Clean(dir)
	// #nosec G301 G703 - 0700: traversable but private to the user; dir is
	// derived only from the user's own config directory (os.UserConfigDir),
	// never from request or remote input.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// #nosec G703 - dir comes only from the user's own config directory and is checked below.
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("credentials directory %s is a symlink; remove it and run again", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("credentials path %s is not a directory", dir)
	}
	if err := requireOwnedByCurrentUser(dir, fi); err != nil {
		return err
	}
	if fi.Mode().Perm()&0077 != 0 {
		// #nosec G302 G703 - restricting an owned directory to the user only.
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("cannot restrict credentials directory %s to 0700: %w", dir, err)
		}
	}
	return nil
}

// secureCredentialFile enforces mode 0600 on a credential or salt file and
// refuses a symlink or a file owned by another user.
func secureCredentialFile(path string) error {
	path = filepath.Clean(path)
	// #nosec G703 - path is the fixed credentials dir joined with a validated name or "salt".
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("credential file %s is a symlink", path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("credential file %s is not a regular file", path)
	}
	if err := requireOwnedByCurrentUser(path, fi); err != nil {
		return err
	}
	if fi.Mode().Perm() != 0600 {
		// #nosec G302 G703 - restricting an owned file to the user only.
		if err := os.Chmod(path, 0600); err != nil {
			return fmt.Errorf("cannot restrict %s to 0600: %w", path, err)
		}
	}
	return nil
}

func requireOwnedByCurrentUser(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner of %s", path)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is not owned by the current user", path)
	}
	return nil
}
