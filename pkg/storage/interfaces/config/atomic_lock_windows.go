// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package config

import (
	"errors"
	"os"
	"syscall"
)

// isRetryableLockError also treats ERROR_ACCESS_DENIED as retryable: an O_EXCL
// create racing a lock file that is mid-delete fails that way on Windows.
func isRetryableLockError(err error) bool {
	return os.IsExist(err) || errors.Is(err, syscall.ERROR_ACCESS_DENIED)
}
