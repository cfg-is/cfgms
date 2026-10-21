// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package security

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// openLeafForWrite opens rel for writing inside root without following a link at
// the leaf and without truncating. The parent directory is opened through root, so
// no component can leave the base, and the leaf is opened relative to that
// directory with O_NOFOLLOW, so the link check and the open are one step.
// O_NONBLOCK keeps a FIFO swapped in at the leaf from blocking the open.
func openLeafForWrite(root *os.Root, rel string, perm os.FileMode) (*os.File, error) {
	dir, err := root.Open(filepath.Dir(rel))
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()

	leaf := filepath.Base(rel)
	flags := unix.O_WRONLY | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	var fd int
	for {
		fd, err = unix.Openat(int(dir.Fd()), leaf, flags, uint32(perm.Perm()))
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EMLINK) {
			return nil, ErrSymlinkInPath
		}
		return nil, &os.PathError{Op: "openat", Path: rel, Err: err}
	}
	return os.NewFile(uintptr(fd), rel), nil
}
