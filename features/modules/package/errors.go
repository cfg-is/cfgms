// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package package_module

import "errors"

var (
	// ErrInvalidPackageName is returned when the package name is invalid
	ErrInvalidPackageName = errors.New("invalid package name")

	// ErrInvalidState is returned when the state is not 'present' or 'absent'
	ErrInvalidState = errors.New("invalid state (must be 'present' or 'absent')")

	// ErrInvalidVersion is returned when the version format is invalid
	ErrInvalidVersion = errors.New("invalid version format")

	// ErrPackageNotFound is returned when a package cannot be found
	ErrPackageNotFound = errors.New("package not found")

	// ErrInvalidResourceID is returned when the resource ID is empty
	ErrInvalidResourceID = errors.New("invalid resource ID")

	// ErrInvalidConfig is returned when the configuration is invalid
	ErrInvalidConfig = errors.New("invalid configuration")

	// ErrResourceIDMismatch is returned when the resource ID doesn't match the package name
	ErrResourceIDMismatch = errors.New("resource ID must match package name")

	// ErrDependencyFailed is returned when a dependency installation fails
	ErrDependencyFailed = errors.New("failed to install dependencies")

	// ErrUpdateFailed is returned when a package update fails
	ErrUpdateFailed = errors.New("failed to update package")

	// ErrPermissionDenied is returned when the operation requires elevated privileges
	ErrPermissionDenied = errors.New("permission denied (requires root/administrator)")

	// ErrCircularDependency is returned when a circular dependency is detected
	ErrCircularDependency = errors.New("circular dependency detected")

	// ErrVersionConflict is returned when there's a version conflict in dependencies
	ErrVersionConflict = errors.New("version conflict in dependencies")

	// ErrInvalidPackageManager is returned when an invalid package manager is specified
	ErrInvalidPackageManager = errors.New("invalid package manager")
)
