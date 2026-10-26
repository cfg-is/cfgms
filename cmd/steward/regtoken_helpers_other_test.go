// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// makeReadableByOthers makes path group- and other-readable.
func makeReadableByOthers(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.Chmod(path, 0o644))
}
