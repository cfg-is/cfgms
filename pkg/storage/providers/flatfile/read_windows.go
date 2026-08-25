// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package flatfile

import (
	"io"
	"os"
	"syscall"
	"time"
)

// readFile reads path with Windows share semantics that let concurrent
// writers replace the file underneath us. Without these flags, Go's stock
// os.ReadFile opens with dwShareMode = FILE_SHARE_READ, which blocks any
// concurrent ReplaceFileW / MoveFileEx for the entire open window. Under
// the blue/green substrate (#1919), where readers cycle continuously, that
// blockage is exactly what trips the writer's atomic-replace path on
// Windows CI runners.
//
// FILE_SHARE_DELETE: lets the writer rename the file (the reader keeps its
// own handle to the original directory entry).
// FILE_SHARE_WRITE: lets the writer open the file for write during replace.
//
// The reader keeps reading from the pre-rename inode-equivalent until it
// closes its handle, matching POSIX rename(2) semantics. A subsequent
// reader sees the post-rename file.
//
// We keep a short retry on ERROR_SHARING_VIOLATION (errno 32) as
// defense-in-depth for transient FS-driver glitches during the rename
// window. With the share flags above, retries should be rare.
func readFile(path string) ([]byte, error) {
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
// writer's ReplaceFileW succeed.
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
		// Surface the underlying errno (syscall.Errno) so caller's
		// isRetryableRenameError / os.IsNotExist work uniformly.
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(handle), path)
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}
