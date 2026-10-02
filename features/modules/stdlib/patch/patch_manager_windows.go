// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package patch

import (
	"context"
	"time"
)

// newPlatformPatchManager returns the Windows Update COM-backed PatchManager. On a
// healthy Windows system COM initialisation always succeeds; if it fails (broken WMI
// subsystem, unusual container sandbox), the module degrades gracefully to a
// windowsManagerInitFailure that propagates the init error from every operation rather
// than panicking or returning a nil pointer.
func newPlatformPatchManager() PatchManager {
	mgr, err := NewWindowsUpdateManager()
	if err != nil {
		return &windowsManagerInitFailure{err: err}
	}
	return mgr
}

// windowsManagerInitFailure is returned when Windows Update COM initialization fails.
// All PatchManager operations return the captured init error so callers receive a
// meaningful failure instead of a nil-pointer panic.
type windowsManagerInitFailure struct {
	err error
}

func (f *windowsManagerInitFailure) ListAvailablePatches(_ context.Context, _ string) ([]PatchInfo, error) {
	return nil, f.err
}

func (f *windowsManagerInitFailure) ListInstalledPatches(_ context.Context) ([]PatchInfo, error) {
	return nil, f.err
}

func (f *windowsManagerInitFailure) InstallPatches(_ context.Context, _ *Config) error {
	return f.err
}

func (f *windowsManagerInitFailure) CheckRebootRequired(_ context.Context) (bool, error) {
	return false, f.err
}

func (f *windowsManagerInitFailure) GetLastPatchDate(_ context.Context) (time.Time, error) {
	return time.Time{}, f.err
}

func (f *windowsManagerInitFailure) Name() string {
	return "windows-init-failure"
}

func (f *windowsManagerInitFailure) IsValidPatchType(_ string) bool {
	return false
}
