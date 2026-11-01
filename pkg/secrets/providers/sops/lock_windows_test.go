// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package sops

import (
	"io/fs"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsWindowsPendingDeleteAccessDenied_AccessDeniedIsDetected is the
// true-positive proof for the whole reason lock_windows.go exists: the
// ERROR_ACCESS_DENIED a Windows O_CREATE|O_EXCL open returns when it races a
// lock file that is mid-delete must be detected (Issue #3817).
//
// The error is asserted in the shape the acquire loop actually sees it —
// os.OpenFile wraps the raw syscall.Errno in an *fs.PathError — as well as
// bare, so the errors.Is unwrapping is covered rather than assumed.
func TestIsWindowsPendingDeleteAccessDenied_AccessDeniedIsDetected(t *testing.T) {
	pathErr := &fs.PathError{Op: "open", Path: "x.lock", Err: syscall.ERROR_ACCESS_DENIED}
	assert.True(t, isWindowsPendingDeleteAccessDenied(pathErr),
		"the *fs.PathError shape os.OpenFile returns must be detected")

	assert.True(t, isWindowsPendingDeleteAccessDenied(syscall.ERROR_ACCESS_DENIED),
		"a bare syscall.Errno must be detected")
}

// TestIsWindowsPendingDeleteAccessDenied_OtherWindowsErrorsAreNotDetected is
// the false-negative half: the check must be narrow. Only ERROR_ACCESS_DENIED
// is the pending-delete overlap. Other Windows error codes — including the
// FILE_EXISTS case os.IsExist already handles, and a vanished parent directory
// — must not be absorbed by this helper, or acquireCASLock would spin-poll on
// genuine hard failures until its deadline.
func TestIsWindowsPendingDeleteAccessDenied_OtherWindowsErrorsAreNotDetected(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"file not found", &fs.PathError{Op: "open", Path: "x.lock", Err: syscall.ERROR_FILE_NOT_FOUND}},
		{"path not found", &fs.PathError{Op: "open", Path: "x.lock", Err: syscall.ERROR_PATH_NOT_FOUND}},
		{"file exists", &fs.PathError{Op: "open", Path: "x.lock", Err: syscall.ERROR_FILE_EXISTS}},
		{"already exists", &fs.PathError{Op: "open", Path: "x.lock", Err: syscall.ERROR_ALREADY_EXISTS}},
		{"privilege not held", &fs.PathError{Op: "open", Path: "x.lock", Err: syscall.ERROR_PRIVILEGE_NOT_HELD}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, isWindowsPendingDeleteAccessDenied(tc.err))
		})
	}
}

// TestIsRetryableCASLockError_WindowsAccessDeniedIsRetryable is the AC1
// regression proof at the classification boundary acquireCASLock actually
// calls: the pending-delete ERROR_ACCESS_DENIED keeps the acquire loop
// polling. It also pins down why the helper is needed at all — os.IsExist
// does not match ERROR_ACCESS_DENIED, so before Issue #3817 this error was
// returned as a hard failure and evicted PRs from the merge queue.
func TestIsRetryableCASLockError_WindowsAccessDeniedIsRetryable(t *testing.T) {
	err := &fs.PathError{Op: "open", Path: "x.lock", Err: syscall.ERROR_ACCESS_DENIED}

	assert.False(t, os.IsExist(err),
		"os.IsExist must not match ERROR_ACCESS_DENIED — that gap is why the helper exists")
	assert.True(t, isRetryableCASLockError(err))
}
