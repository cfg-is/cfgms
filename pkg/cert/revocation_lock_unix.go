// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package cert

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockRevocationFile takes an exclusive cross-process lock on lockPath
// (created if missing) and returns a function that releases it.
func lockRevocationFile(lockPath string) (func(), error) {
	// #nosec G304 -- path is controlled: constructed from the cert manager's storage path
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open revocation lock: %w", err)
	}
	for {
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX) // #nosec G115 -- fd fits in int
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to lock revocation list: %w", err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN) // #nosec G115 -- fd fits in int
		_ = f.Close()
	}, nil
}
