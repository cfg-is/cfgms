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

// writeFileInRoot writes data to validatedPath, creating missing parent
// directories, with every path component resolved relative to an os.Root opened
// on basePath. A directory swapped for a link after validation cannot redirect
// the write outside the base, and a leaf that is a link is refused.
func writeFileInRoot(basePath, userPath, validatedPath string, data []byte, perm os.FileMode) error {
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

	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	after, err := f.Stat()
	if err == nil && (!after.Mode().IsRegular() || (before != nil && !os.SameFile(before, after))) {
		err = ErrSymlinkInPath
	}
	if err != nil {
		_ = f.Close()
		return err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}
