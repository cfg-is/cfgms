// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package security

import (
	"path/filepath"
	"runtime"
	"strings"
)

func isProtectedBootConfigPath(path string) bool {
	target := resolveForCompare(path)
	for _, dir := range BootConfigDirs() {
		d := resolveForCompare(dir)
		if samePath(target, d) {
			return true
		}
	}
	for _, c := range protectedCandidates() {
		if samePath(target, resolveForCompare(c)) {
			return true
		}
	}
	return false
}

// resolveForCompare cleans path and resolves symlinks in its parent
// directory (the leaf may not exist yet or may itself be the link target).
func resolveForCompare(path string) string {
	clean := filepath.Clean(path)
	if abs, err := filepath.Abs(clean); err == nil {
		clean = abs
	}
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		return resolved
	}
	parent, leaf := filepath.Split(clean)
	if resolvedParent, err := filepath.EvalSymlinks(filepath.Clean(parent)); err == nil {
		return filepath.Join(resolvedParent, leaf)
	}
	return clean
}

func samePath(a, b string) bool {
	if runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
