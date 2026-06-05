// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package file

import "errors"

var (
	// ErrAllowedBasePathRequired is returned when AllowedBasePath is missing or non-absolute.
	// See docs/modules/file.md for configuration guidance.
	ErrAllowedBasePathRequired = errors.New("AllowedBasePath is required and must be an absolute path; see docs/modules/file.md")

	// ErrNotADirectory is returned when the path exists but is not a directory (type: directory).
	ErrNotADirectory = errors.New("path exists but is not a directory")

	// ErrRecursiveRequired is returned when parent directories don't exist and recursive is false.
	ErrRecursiveRequired = errors.New("parent directories don't exist and recursive is false")

	// ErrInvalidPath is returned when the path is invalid (empty or relative).
	ErrInvalidPath = errors.New("invalid path")

	// ErrInvalidOwner is returned when the specified owner does not exist.
	ErrInvalidOwner = errors.New("invalid owner")

	// ErrInvalidGroup is returned when the specified group does not exist.
	ErrInvalidGroup = errors.New("invalid group")

	// ErrInvalidPermissions is returned when the specified permissions are out of range.
	ErrInvalidPermissions = errors.New("invalid permissions")
)
