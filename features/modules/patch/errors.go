// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package patch

import "errors"

var (
	// ErrInvalidPatchType is returned when the patch type is not valid
	ErrInvalidPatchType = errors.New("invalid patch type (must be 'security', 'all', 'kernel', or 'critical')")

	// ErrInvalidMaxDowntime is returned when the max downtime format is invalid
	ErrInvalidMaxDowntime = errors.New("invalid max downtime format (must be a valid duration like '30m', '1h')")

	// ErrInvalidMaintenanceWindow is returned when the maintenance window format is invalid
	ErrInvalidMaintenanceWindow = errors.New("invalid maintenance window format")

	// ErrInvalidPatchID is returned when a patch ID is invalid
	ErrInvalidPatchID = errors.New("invalid patch ID format")

	// ErrConflictingPatchLists is returned when a patch appears in both include and exclude lists
	ErrConflictingPatchLists = errors.New("patch appears in both include and exclude lists")

	// ErrConflictingPlatformOptions is returned when conflicting platform options are specified
	ErrConflictingPlatformOptions = errors.New("conflicting platform options specified")

	// ErrPatchingInProgress is returned when a patch operation is already in progress
	ErrPatchingInProgress = errors.New("patch operation already in progress")

	// ErrRebootRequired is returned when a reboot is required before continuing
	ErrRebootRequired = errors.New("system reboot required before proceeding")

	// ErrMaintenanceWindowNotActive is returned when trying to patch outside maintenance window
	ErrMaintenanceWindowNotActive = errors.New("patching not allowed outside maintenance window")

	// ErrInsufficientDiskSpace is returned when there's not enough disk space for patches
	ErrInsufficientDiskSpace = errors.New("insufficient disk space for patch installation")

	// ErrPatchNotFound is returned when a specific patch cannot be found
	ErrPatchNotFound = errors.New("specified patch not found")

	// ErrPatchAlreadyInstalled is returned when trying to install an already installed patch
	ErrPatchAlreadyInstalled = errors.New("patch already installed")

	// ErrPatchInstallationFailed is returned when patch installation fails
	ErrPatchInstallationFailed = errors.New("patch installation failed")

	// ErrUnsupportedPlatform is returned when the current platform is not supported
	ErrUnsupportedPlatform = errors.New("patch management not supported on this platform")

	// ErrPermissionDenied is returned when the operation requires elevated privileges
	ErrPermissionDenied = errors.New("permission denied (requires root/administrator privileges)")

	// ErrNetworkError is returned when network connectivity issues prevent patching
	ErrNetworkError = errors.New("network error during patch operation")

	// ErrInvalidResourceID is returned when the resource ID is invalid
	ErrInvalidResourceID = errors.New("invalid resource ID")

	// ErrInvalidConfig is returned when the configuration is invalid
	ErrInvalidConfig = errors.New("invalid configuration")
)
