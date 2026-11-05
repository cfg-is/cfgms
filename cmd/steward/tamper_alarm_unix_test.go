// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package main

import (
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// plantUnreadable returns a path holding a named pipe. Opening it for reading
// blocks until a writer appears, so any code that opens the planted file stalls
// and a test waiting on a controller heartbeat fails.
func plantUnreadable(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "planted")
	plantUnreadableAt(t, p)
	return p
}

func plantUnreadableAt(t *testing.T, p string) {
	t.Helper()
	require.NoError(t, syscall.Mkfifo(p, 0o600))
}
