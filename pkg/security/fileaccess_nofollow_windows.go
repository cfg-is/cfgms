// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package security

import (
	"fmt"
	"os"
)

// openNoFollow rejects a symlink or reparse point at the final component, then opens it.
func openNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return nil, fmt.Errorf("refusing to open %s: final component is a symlink or reparse point", path)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// #nosec G304 - callers pass a path already validated by ValidateAndCleanPath
	return os.OpenFile(path, flag, perm)
}
