// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package sops

import (
	"errors"
	"syscall"
)

// isWindowsPendingDeleteAccessDenied reports whether err is the
// ERROR_ACCESS_DENIED a Windows O_CREATE|O_EXCL open returns when it races a
// lock file that is mid-delete: the file stays visible under its
// pending-delete flag for a short window, and a create attempt that overlaps
// that window fails with ACCESS_DENIED rather than the FILE_EXISTS os.IsExist
// already handles. Treating it as retryable keeps acquireCASLock in its poll
// loop instead of returning a hard error (Issue #3817).
func isWindowsPendingDeleteAccessDenied(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED)
}
