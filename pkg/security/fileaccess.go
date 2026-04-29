// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package security provides secure file access utilities for CFGMS.
//
// This package implements centralized security controls for file operations,
// including path validation, directory traversal prevention, and secure
// permission defaults.
//
// Basic usage:
//
//	// Secure file reading with path validation
//	data, err := security.SecureReadFile("/safe/base/path", userProvidedPath)
//
//	// Secure file writing with proper permissions
//	err := security.SecureWriteFile("/safe/base/path", userProvidedPath, data)
package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SecureReadFile safely reads a file with path validation and directory traversal prevention.
//
// basePath is the allowed base directory - all file access must be within this directory.
// userPath is the user-provided path that will be cleaned and validated.
//
// Returns an error if:
// - The resolved path is outside the base directory (directory traversal attempt)
// - The file cannot be read
// - Path validation fails
func SecureReadFile(basePath, userPath string) ([]byte, error) {
	validatedPath, err := ValidateAndCleanPath(basePath, userPath)
	if err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	// #nosec G304 - Secure file access wrapper with comprehensive path validation
	// This function specifically prevents directory traversal attacks
	return os.ReadFile(validatedPath)
}

// SecureWriteFile safely writes a file with path validation and secure permissions.
//
// Files are written with 0600 permissions (owner read/write only) by default.
// Directories are created with 0750 permissions if they don't exist.
func SecureWriteFile(basePath, userPath string, data []byte) error {
	validatedPath, err := ValidateAndCleanPath(basePath, userPath)
	if err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	// Ensure parent directory exists with secure permissions
	dir := filepath.Dir(validatedPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	return os.WriteFile(validatedPath, data, 0600)
}

// SecureWriteFileWithPerms writes a file with custom permissions after path validation.
//
// Use this when you need specific permissions (e.g., 0700 for executable files).
func SecureWriteFileWithPerms(basePath, userPath string, data []byte, perm os.FileMode) error {
	validatedPath, err := ValidateAndCleanPath(basePath, userPath)
	if err != nil {
		return fmt.Errorf("path validation failed: %w", err)
	}

	// Ensure parent directory exists with secure permissions
	dir := filepath.Dir(validatedPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	return os.WriteFile(validatedPath, data, perm)
}

// SecureOpenFile safely opens a file with path validation.
//
// Returns an *os.File that must be closed by the caller.
func SecureOpenFile(basePath, userPath string, flag int, perm os.FileMode) (*os.File, error) {
	validatedPath, err := ValidateAndCleanPath(basePath, userPath)
	if err != nil {
		return nil, fmt.Errorf("path validation failed: %w", err)
	}

	// #nosec G304 - Secure file access wrapper with comprehensive path validation
	// This function specifically prevents directory traversal attacks
	return os.OpenFile(validatedPath, flag, perm)
}

// ValidateAndCleanPath validates a user-provided path against a base directory.
//
// This function:
//  1. Cleans the user path using filepath.Clean()
//  2. Resolves both paths to absolute paths
//  3. Eval-symlinks the base path so all containment comparisons use canonical paths
//  4. Resolves symlinks in the user path; for non-existent targets, walks up to the
//     deepest existing ancestor, eval-symlinks it, and re-joins the non-existing remainder
//  5. Validates containment after symlink resolution using filepath.Rel (not strings.HasPrefix)
//     to prevent sibling-prefix attacks (e.g. /base_extra/secret incorrectly matching /base)
//     and symlink-escape attacks
//
// Symlink resolution of the user path happens before containment checks so that both
// the base and user path use canonical filesystem paths. On macOS /tmp is a symlink to
// /private/tmp; on Windows short path forms (RUNNER~1) differ from long forms. Without
// resolving the user path first, comparing against an already-resolved base would produce
// false "path traversal" errors for valid paths.
//
// Returns the validated, canonicalized absolute path.
func ValidateAndCleanPath(basePath, userPath string) (string, error) {
	if basePath == "" {
		return "", fmt.Errorf("base path cannot be empty")
	}
	if userPath == "" {
		return "", fmt.Errorf("user path cannot be empty")
	}

	cleanUserPath := filepath.Clean(userPath)

	absBasePath, err := filepath.Abs(basePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base path: %w", err)
	}
	// Eval-symlink base so comparisons are against canonical paths.
	// Without this, a symlinked base would make the containment check unreliable.
	absBasePath, err = filepath.EvalSymlinks(absBasePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base path symlinks: %w", err)
	}

	var absUserPath string
	if filepath.IsAbs(cleanUserPath) {
		absUserPath = cleanUserPath
	} else {
		absUserPath = filepath.Join(absBasePath, cleanUserPath)
	}

	// Resolve symlinks in the user path, with fallback for non-existent targets.
	// This must happen before the containment check so both paths are in canonical form.
	resolved, resolveErr := filepath.EvalSymlinks(absUserPath)
	if resolveErr == nil {
		absUserPath = resolved
	} else if errors.Is(resolveErr, os.ErrNotExist) {
		// Non-existent target: walk up to the deepest existing ancestor,
		// eval-symlink it, then re-join the non-existing tail components.
		// This handles paths like "newdir/newfile.txt" where the parent dirs
		// don't yet exist, and also catches ancestors that are malicious symlinks.
		parent := absUserPath
		var tail []string
		for {
			if _, statErr := os.Stat(parent); statErr == nil {
				break
			}
			tail = append([]string{filepath.Base(parent)}, tail...)
			next := filepath.Dir(parent)
			if next == parent {
				return "", fmt.Errorf("failed to resolve any ancestor of %s", userPath)
			}
			parent = next
		}
		resolvedParent, resolveParentErr := filepath.EvalSymlinks(parent)
		if resolveParentErr != nil {
			return "", fmt.Errorf("failed to resolve parent: %w", resolveParentErr)
		}
		absUserPath = filepath.Join(append([]string{resolvedParent}, tail...)...)
	} else {
		return "", fmt.Errorf("failed to evaluate symlinks: %w", resolveErr)
	}

	// Containment check after full symlink resolution prevents both sibling-prefix
	// and symlink-escape attacks using canonical paths for both sides.
	if err := containmentCheck(absBasePath, absUserPath, userPath); err != nil {
		return "", err
	}

	return absUserPath, nil
}

// containmentCheck verifies that absUserPath is within absBasePath using filepath.Rel.
// filepath.Rel (not strings.HasPrefix) correctly rejects sibling-prefix attacks where a
// path like /base_extra/secret would falsely pass a HasPrefix("/base") check.
func containmentCheck(absBasePath, absUserPath, userPath string) error {
	rel, err := filepath.Rel(absBasePath, absUserPath)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return fmt.Errorf("path traversal attempt detected: %s is outside %s", userPath, absBasePath)
	}
	return nil
}
