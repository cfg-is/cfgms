// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package patch

import (
	"context"
	"time"
)

// unsupportedPlatformPatchManager is the documented platform-fallback for non-Windows
// systems where no real patch manager is implemented. All operations return
// errPatchNotAvailable, ensuring the steward never silently provides fake patch data.
//
// This is not an unresolved-work stub: Linux and macOS patch management (apt/yum/softwareupdate)
// is explicitly out of scope per the story's PM Notes. Windows is the only platform with a
// real backend today (WindowsUpdateManager via the Windows Update COM API).
type unsupportedPlatformPatchManager struct{}

func newUnsupportedPlatformPatchManager() PatchManager {
	return &unsupportedPlatformPatchManager{}
}

// newPlatformPatchManager returns the platform-appropriate PatchManager. On non-Windows
// systems, no real implementation exists and the unsupported-platform fallback is used.
func newPlatformPatchManager() PatchManager {
	return newUnsupportedPlatformPatchManager()
}

func (s *unsupportedPlatformPatchManager) ListAvailablePatches(_ context.Context, _ string) ([]PatchInfo, error) {
	return nil, errPatchNotAvailable
}

func (s *unsupportedPlatformPatchManager) ListInstalledPatches(_ context.Context) ([]PatchInfo, error) {
	return nil, errPatchNotAvailable
}

func (s *unsupportedPlatformPatchManager) InstallPatches(_ context.Context, _ *Config) error {
	return errPatchNotAvailable
}

func (s *unsupportedPlatformPatchManager) CheckRebootRequired(_ context.Context) (bool, error) {
	return false, errPatchNotAvailable
}

func (s *unsupportedPlatformPatchManager) GetLastPatchDate(_ context.Context) (time.Time, error) {
	return time.Time{}, errPatchNotAvailable
}

// Name returns "stub" to preserve the observable name behaviour of the original
// stubPatchManager — external callers that inspect the manager name via Name()
// continue to receive the same value after this rename.
func (s *unsupportedPlatformPatchManager) Name() string {
	return "stub"
}

func (s *unsupportedPlatformPatchManager) IsValidPatchType(patchType string) bool {
	return validPatchTypes[patchType]
}
