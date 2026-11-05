// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// plantUnreadable returns a path holding a file the tamper path must not open.
// Windows has no named-pipe equivalent a plain open would block on, so the
// Windows leg asserts the order through the real data-directory refusal.
func plantUnreadable(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "planted")
	plantUnreadableAt(t, p)
	return p
}

func plantUnreadableAt(t *testing.T, p string) {
	t.Helper()
	require.NoError(t, os.WriteFile(p, []byte("planted"), 0o600))
}
