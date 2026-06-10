// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package flatfile

import (
	"errors"
	"math/rand/v2"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// atomicRename renames src → dst on Windows with semantics that match POSIX
// rename(2): the rename is atomic with respect to concurrent readers, who
// keep reading their handle's view of the pre-rename file until they close
// it.
//
// We use ReplaceFileW for the existing-dst path. The Win32 API guarantees:
//   - atomic from observer perspective (no torn read between unlink + rename)
//   - succeeds with REPLACEFILE_WRITE_THROUGH while readers have dst open;
//     they keep their pre-rename view, same as POSIX
//   - the implementation does the directory-entry swap in a single critical
//     section inside the filesystem driver
//
// For the first-write case (dst does not yet exist), ReplaceFileW returns
// ERROR_FILE_NOT_FOUND and we fall back to MoveFileEx via os.Rename. That
// path has no contention risk because there's no destination handle to clash
// with.
//
// This replaces the earlier retry-loop strategy (30 × 100ms backoff). Under
// the cross-process stress test (#1919) on slow CI runners — 3 readers + 1
// writer for 5s — every retry attempt could coincide with at least one open
// reader, and the writer occasionally exhausted the 3.6s budget. The retry
// path was a workaround for not using ReplaceFileW; this commit switches to
// the API that was always the correct choice (the previous comment block
// already acknowledged ReplaceFileW would be "a more elegant solution" but
// rejected it because of the first-write split — which we handle cleanly via
// the ERROR_FILE_NOT_FOUND fallback below).
func atomicRename(src, dst string) error {
	// Fast path: try POSIX-style atomic replace.
	if err := replaceFileW(dst, src); err == nil {
		return nil
	} else if !errors.Is(err, syscall.Errno(2 /* ERROR_FILE_NOT_FOUND */)) {
		return err
	}
	// dst does not exist — first write. Plain rename is safe here because
	// there's no destination handle to contend with.
	return os.Rename(src, dst)
}

// replaceFileW calls the Win32 ReplaceFileW API. dst must exist; src must
// exist; dst is replaced by src atomically. Returns the syscall errno on
// failure so the caller can switch on ERROR_FILE_NOT_FOUND for the
// first-write fallback.
func replaceFileW(dst, src string) error {
	const replaceFlagWriteThrough = 0x00000001
	dstW, err := syscall.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	srcW, err := syscall.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	r1, _, e1 := procReplaceFileW.Call(
		uintptr(unsafe.Pointer(dstW)),
		uintptr(unsafe.Pointer(srcW)),
		0, // no backup
		uintptr(replaceFlagWriteThrough),
		0, 0,
	)
	if r1 == 0 {
		return e1
	}
	return nil
}

var (
	kernel32         = syscall.MustLoadDLL("kernel32.dll")
	procReplaceFileW = kernel32.MustFindProc("ReplaceFileW")
)

// jitter returns d randomised by ±50% so concurrent readers/writers retrying
// against the same target don't fire on aligned millisecond boundaries.
// Used by readFile's retry on ERROR_SHARING_VIOLATION. The writer side no
// longer needs retries (ReplaceFileW handles open readers natively) but the
// reader-side retry is kept as defense-in-depth against transient FS-driver
// hiccups during the rename window.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	factor := 0.5 + rand.Float64() //nolint:gosec // jitter, not crypto
	return time.Duration(float64(d) * factor)
}

// isRetryableRenameError reports whether err is the Windows transient
// failure mode that occurs when a concurrent operation has the file open.
// Used by readFile (rename_windows is no longer the only caller after the
// ReplaceFileW switch — the name is kept for continuity with read_windows.go).
func isRetryableRenameError(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// ERROR_ACCESS_DENIED = 5, ERROR_SHARING_VIOLATION = 32
		return errno == syscall.Errno(5) || errno == syscall.Errno(32)
	}
	return false
}
