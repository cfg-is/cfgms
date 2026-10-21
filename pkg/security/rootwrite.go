// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// afterValidateHook, when set by a test, runs between path validation and the
// write so a test can swap a path component at the moment an attack would.
var afterValidateHook func()

// beforeLeafOpenHook, when set by a test, runs between the leaf pre-check and the
// leaf open so a test can swap the leaf itself at the moment an attack would.
var beforeLeafOpenHook func()

// writeFileInRoot writes data to validatedPath, creating missing parent
// directories, with every path component resolved relative to an os.Root opened
// on basePath. A directory swapped for a link after validation cannot redirect
// the write outside the base, and a leaf that is a link is refused.
func writeFileInRoot(basePath, userPath, validatedPath string, data []byte, perm os.FileMode) error {
	if afterValidateHook != nil {
		afterValidateHook()
	}
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return fmt.Errorf("failed to resolve base path: %w", err)
	}
	rootBase, err := filepath.EvalSymlinks(absBase)
	if err != nil {
		return fmt.Errorf("failed to resolve base path: %w", err)
	}
	rel, err := filepath.Rel(rootBase, validatedPath)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path %q escapes the base directory", filepath.Base(validatedPath))
	}

	root, err := os.OpenRoot(rootBase)
	if err != nil {
		return fmt.Errorf("failed to open base directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	if dir := filepath.Dir(rel); dir != "." {
		if err := root.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// ValidateAndCleanPath resolves an in-base leaf link to its target, so the link
	// itself is checked as the caller named it.
	rawAbs := userPath
	if !filepath.IsAbs(rawAbs) {
		rawAbs = filepath.Join(absBase, rawAbs)
	}
	if rawRel, rerr := filepath.Rel(absBase, rawAbs); rerr == nil && filepath.IsLocal(rawRel) {
		if info, lerr := root.Lstat(rawRel); lerr == nil && info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return ErrSymlinkInPath
		}
	}

	// Root.OpenFile follows leaf links that stay inside the root, so refuse them here.
	before, err := root.Lstat(rel)
	switch {
	case err == nil:
		if before.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return ErrSymlinkInPath
		}
	case errors.Is(err, os.ErrNotExist):
		before = nil
	default:
		return err
	}

	// The leaf is opened without O_TRUNC. Before anything is truncated or written,
	// the handle must be a regular file that is the same file as the leaf named rel
	// right now (and as before the open, if it existed), so a leaf swapped for a
	// link during the open is refused with the link target left untouched.
	if beforeLeafOpenHook != nil {
		beforeLeafOpenHook()
	}
	f, err := openLeafForWrite(root, rel, perm)
	if err != nil {
		return err
	}
	if err := verifyOpenedLeaf(root, rel, f, before); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

// verifyOpenedLeaf checks that f, opened at rel inside root, is a regular file and
// is the file currently linked at rel and, when before is non-nil, the file that
// was there before the open.
func verifyOpenedLeaf(root *os.Root, rel string, f *os.File, before os.FileInfo) error {
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() {
		return ErrSymlinkInPath
	}
	if before != nil && !os.SameFile(before, opened) {
		return ErrSymlinkInPath
	}
	now, err := root.Lstat(rel)
	if err != nil {
		return err
	}
	if now.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !os.SameFile(now, opened) {
		return ErrSymlinkInPath
	}
	return nil
}
