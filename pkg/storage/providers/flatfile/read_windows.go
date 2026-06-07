// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package flatfile

import (
	"os"
	"time"
)

// readFile reads path with a short retry loop on the Windows-specific
// "process cannot access the file because it is being used by another
// process" failure mode that occurs when a concurrent writer is in the
// middle of replacing the file.
//
// Windows opens a regular os.ReadFile with dwShareMode = FILE_SHARE_READ.
// If another process has the file open (which a writer briefly does
// during its MoveFileEx replace operation), the open fails with
// ERROR_SHARING_VIOLATION (errno 32) until the writer's handle closes.
// The blue/green substrate (#1919) needs concurrent reader + writer
// processes to coexist without spurious read failures, so this helper
// retries with a short backoff that outlasts a single writer's
// in-flight replace.
//
// Symmetric with atomicRename's writer-side retry: same error codes,
// same bounded budget.
func readFile(path string) ([]byte, error) {
	const (
		maxAttempts = 12
		baseDelay   = 1 * time.Millisecond
		maxDelay    = 50 * time.Millisecond
	)
	var lastErr error
	delay := baseDelay
	for attempt := 0; attempt < maxAttempts; attempt++ {
		data, err := os.ReadFile(path) //#nosec G304 -- caller validates path
		if err == nil {
			return data, nil
		}
		if !isRetryableRenameError(err) {
			return nil, err
		}
		lastErr = err
		time.Sleep(delay)
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
	return nil, lastErr
}
