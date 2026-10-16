//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package file

import (
	"fmt"
	"os"
)

// rejectLinkLeaf returns an error when path's final component is a symlink or
// reparse point.
func rejectLinkLeaf(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("refusing to modify %s: final component is a symlink or reparse point", path)
	}
	return nil
}

// chownNoFollow refuses link leaves, then changes ownership.
func chownNoFollow(path string, uid, gid int, _ bool) error {
	if err := rejectLinkLeaf(path); err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}

// chmodNoFollow refuses link leaves, then changes the mode.
func chmodNoFollow(path string, mode os.FileMode, _ bool) error {
	if err := rejectLinkLeaf(path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
