// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package sops

import (
	"io/fs"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsWindowsPendingDeleteAccessDenied_AlwaysFalseOffWindows proves the
// non-Windows stub is genuinely unconditional, not an accident of the errors
// it happens to be handed. Errno 5 is ERROR_ACCESS_DENIED on Windows and EIO
// on Unix; the same numeric errno that is retryable on Windows must remain a
// hard failure here, because Linux and macOS return EEXIST — already covered
// by os.IsExist — for the lock-file-mid-delete overlap and never ACCESS_DENIED
// (Issue #3817).
//
// This is the guard against the fix widening into "retry every permission
// error on every platform", which would make acquireCASLock spin-poll until
// its deadline on a genuinely unwritable lock directory.
func TestIsWindowsPendingDeleteAccessDenied_AlwaysFalseOffWindows(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"errno 5 (ACCESS_DENIED on Windows, EIO here)", syscall.Errno(5)},
		{"wrapped errno 5", &fs.PathError{Op: "open", Path: "x.lock", Err: syscall.Errno(5)}},
		{"permission denied", &fs.PathError{Op: "open", Path: "x.lock", Err: syscall.EACCES}},
		{"exists", &fs.PathError{Op: "open", Path: "x.lock", Err: syscall.EEXIST}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, isWindowsPendingDeleteAccessDenied(tc.err))
		})
	}
}

// TestIsRetryableCASLockError_OffWindowsEEXISTDrivesTheRetry confirms the
// classification off Windows rests entirely on os.IsExist: the EEXIST the
// platform really returns is retryable, and EACCES — which the Windows helper
// would match numerically — is not.
func TestIsRetryableCASLockError_OffWindowsEEXISTDrivesTheRetry(t *testing.T) {
	assert.True(t, isRetryableCASLockError(
		&fs.PathError{Op: "open", Path: "x.lock", Err: syscall.EEXIST}))

	assert.False(t, isRetryableCASLockError(
		&fs.PathError{Op: "open", Path: "x.lock", Err: syscall.EACCES}))
}
