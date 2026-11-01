// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package cert

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// lockRevocationFile takes an exclusive cross-process lock on lockPath
// (created if missing) and returns a function that releases it.
func lockRevocationFile(lockPath string) (func(), error) {
	// #nosec G304 -- path is controlled: constructed from the cert manager's storage path
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open revocation lock: %w", err)
	}
	h := windows.Handle(f.Fd())
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to lock revocation list: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(h, 0, 1, 0, ol)
		_ = f.Close()
	}, nil
}
