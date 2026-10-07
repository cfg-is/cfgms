// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package config

import (
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// renameFenceRatchetFile replaces dst with src using Windows semantics that
// match POSIX rename(2): the replace is atomic with respect to a concurrent
// reader, who keeps observing its handle's pre-replace view until it closes.
//
// Plain os.Rename (MoveFileEx under the hood) fails with ERROR_ACCESS_DENIED
// when a concurrent Load has dst open — Go's stock os.Open on Windows does
// not set FILE_SHARE_DELETE, so MoveFileEx cannot get the delete access it
// needs to swap the directory entry. This is the exact failure the Windows
// merge-queue leg hit under TestFenceRatchet_ConcurrentLoadAndSave: 32
// goroutines each doing NewFenceRatchet(dir).Load() alongside 32 concurrent
// Saves.
//
// ReplaceFileW does not have that requirement — it succeeds while a reader
// holds dst open (WRITE_THROUGH commits the swap; the reader keeps reading
// the pre-replace bytes). This mirrors
// pkg/storage/providers/flatfile/rename_windows.go's atomicRename, which
// solved the identical reader/writer contention shape for #1919.
//
// For the first-write case (dst does not exist yet), ReplaceFileW returns
// ERROR_FILE_NOT_FOUND; fall back to a plain os.Rename, which has no
// contention risk because there is no destination handle to clash with.
func renameFenceRatchetFile(src, dst string) error {
	if err := replaceFileW(dst, src); err == nil {
		return nil
	} else if !errors.Is(err, syscall.Errno(2 /* ERROR_FILE_NOT_FOUND */)) {
		return err
	}
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

// readFenceRatchetFile reads path with Windows share semantics that let a
// concurrent renameFenceRatchetFile succeed underneath us, plus a short
// retry on the rare transient sharing violation during the replace window —
// defense-in-depth mirroring pkg/storage/providers/flatfile/read_windows.go.
func readFenceRatchetFile(path string) ([]byte, error) {
	const (
		maxAttempts = 12
		baseDelay   = 1 * time.Millisecond
		maxDelay    = 50 * time.Millisecond
	)
	var lastErr error
	delay := baseDelay
	for attempt := 0; attempt < maxAttempts; attempt++ {
		data, err := readWithShareFlags(path)
		if err == nil {
			return data, nil
		}
		if !isRetryableRenameError(err) {
			return nil, err
		}
		lastErr = err
		time.Sleep(jitter(delay))
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
	return nil, lastErr
}

// readWithShareFlags opens path with FILE_SHARE_READ | FILE_SHARE_WRITE |
// FILE_SHARE_DELETE, reads the whole file, and closes. Equivalent to
// os.ReadFile except for the share-mode override that lets a concurrent
// writer's ReplaceFileW succeed while this read is in flight.
func readWithShareFlags(path string) ([]byte, error) {
	pathW, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(
		pathW,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		// Surface the underlying errno (syscall.Errno) so os.IsNotExist and
		// isRetryableRenameError both work uniformly on the returned error.
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(handle), path)
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// jitter returns d randomised by +/-50% so concurrent readers/writers
// retrying against the same target don't fire on aligned millisecond
// boundaries.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	factor := 0.5 + rand.Float64() //nolint:gosec // jitter, not crypto
	return time.Duration(float64(d) * factor)
}

// isRetryableRenameError reports whether err is the Windows transient
// failure mode that occurs when a concurrent operation has the file open.
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
