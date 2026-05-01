// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package patch

import (
	"context"
	"errors"
	"time"
)

var errPatchNotAvailable = errors.New("patch management not available on this platform")

// stubPatchManager is a no-op PatchManager used on platforms without a real
// patch implementation. All operations return errPatchNotAvailable so the
// steward never silently provides fake patch data.
type stubPatchManager struct{}

func newStubPatchManager() PatchManager {
	return &stubPatchManager{}
}

func (s *stubPatchManager) ListAvailablePatches(_ context.Context, _ string) ([]PatchInfo, error) {
	return nil, errPatchNotAvailable
}

func (s *stubPatchManager) ListInstalledPatches(_ context.Context) ([]PatchInfo, error) {
	return nil, errPatchNotAvailable
}

func (s *stubPatchManager) InstallPatches(_ context.Context, _ *Config) error {
	return errPatchNotAvailable
}

func (s *stubPatchManager) CheckRebootRequired(_ context.Context) (bool, error) {
	return false, errPatchNotAvailable
}

func (s *stubPatchManager) GetLastPatchDate(_ context.Context) (time.Time, error) {
	return time.Time{}, errPatchNotAvailable
}

func (s *stubPatchManager) Name() string {
	return "stub"
}

func (s *stubPatchManager) IsValidPatchType(patchType string) bool {
	return validPatchTypes[patchType]
}
