//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package file

import (
	"errors"
	"os"
	"syscall"
)

// openNoFollowMeta opens path for a metadata change without following a link at the
// final component. Opening a symlink leaf fails (ELOOP), so there is no check-then-act.
func openNoFollowMeta(path string, isDir bool) (*os.File, error) {
	flags := syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if isDir {
		flags |= syscall.O_DIRECTORY
	}
	// #nosec G304 -- path validated by security.ValidateAndCleanPath before this call
	f, err := os.OpenFile(path, os.O_RDONLY|flags, 0)
	if err != nil && errors.Is(err, os.ErrPermission) && !isDir {
		// Write-only files cannot be opened for reading by a non-root caller.
		// #nosec G304 -- path validated by security.ValidateAndCleanPath before this call
		f, err = os.OpenFile(path, os.O_WRONLY|flags, 0)
	}
	return f, err
}

// chownNoFollow changes ownership through a descriptor opened without following the leaf.
func chownNoFollow(path string, uid, gid int, isDir bool) error {
	f, err := openNoFollowMeta(path, isDir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Chown(uid, gid)
}

// chmodNoFollow changes the mode through a descriptor opened without following the leaf.
func chmodNoFollow(path string, mode os.FileMode, isDir bool) error {
	f, err := openNoFollowMeta(path, isDir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Chmod(mode)
}
