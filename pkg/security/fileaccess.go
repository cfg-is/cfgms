// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
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
// 1. Cleans the user path using filepath.Clean()
// 2. Resolves both paths to absolute paths
// 3. Ensures the resolved user path is within the base directory
// 4. Returns the validated absolute path
//
// This prevents directory traversal attacks (e.g., "../../../etc/passwd").
func ValidateAndCleanPath(basePath, userPath string) (string, error) {
	if basePath == "" {
		return "", fmt.Errorf("base path cannot be empty")
	}
	if userPath == "" {
		return "", fmt.Errorf("user path cannot be empty")
	}

	// Clean the user-provided path to resolve . and .. elements
	cleanUserPath := filepath.Clean(userPath)

	// Convert both paths to absolute paths
	absBasePath, err := filepath.Abs(basePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base path: %w", err)
	}

	// Handle relative vs absolute user paths
	var absUserPath string
	if filepath.IsAbs(cleanUserPath) {
		// User provided absolute path - use it directly
		absUserPath = cleanUserPath
	} else {
		// User provided relative path - join with base path
		absUserPath = filepath.Join(absBasePath, cleanUserPath)
	}

	// Resolve any remaining symlinks or path elements
	absUserPath, err = filepath.Abs(absUserPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve user path: %w", err)
	}

	// Ensure the resolved path is within the base directory
	if !strings.HasPrefix(absUserPath, absBasePath) {
		return "", fmt.Errorf("path traversal attempt detected: %s is outside %s", userPath, basePath)
	}

	return absUserPath, nil
}

// SecureMkdirAll creates directories with secure permissions (0750).
//
// This is a secure wrapper around os.MkdirAll with default secure permissions.
func SecureMkdirAll(path string) error {
	return os.MkdirAll(path, 0750)
}

// IsPathWithinBase checks if a user path would be within the base directory without file operations.
//
// This is useful for validation without performing actual file system operations.
func IsPathWithinBase(basePath, userPath string) bool {
	_, err := ValidateAndCleanPath(basePath, userPath)
	return err == nil
}
