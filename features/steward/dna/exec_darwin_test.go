//go:build darwin

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dna

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDarwinRunCmd_StuckChildDoesNotHang is the regression guard for the macOS CI
// hang that ejected PRs from the merge queue (Issue #2361). It reproduces the
// failure mode directly: a shell that backgrounds a long-lived grandchild which
// inherits the stdout pipe, then exits. The grandchild keeps the write end open,
// so Output()'s stdout copy cannot see EOF. Without cmd.WaitDelay this blocks for
// the full grandchild lifetime (here 120s); with WaitDelay it must return within
// roughly darwinCmdWaitDelay.
func TestDarwinRunCmd_StuckChildDoesNotHang(t *testing.T) {
	// A long grandchild lifetime makes a regression unmistakable: a hang would run
	// ~120s (until the go test alarm), a healthy path returns in ~darwinCmdWaitDelay.
	start := time.Now()
	_, _ = darwinRunCmd(context.Background(), 2*time.Second, "sh", "-c", "sleep 120 &")
	elapsed := time.Since(start)

	require.Less(t, elapsed, 30*time.Second,
		"darwinRunCmd must return within WaitDelay when a grandchild holds the stdout pipe open, not block on it")
}

// TestDarwinRunCmd_NormalCommandSucceeds confirms the WaitDelay wrapper does not
// disturb ordinary fast commands: output is returned intact with no error.
func TestDarwinRunCmd_NormalCommandSucceeds(t *testing.T) {
	out, err := darwinRunCmd(context.Background(), darwinCmdWaitDelay, "echo", "cfgms")
	require.NoError(t, err)
	require.Equal(t, "cfgms", string(out[:len(out)-1])) // strip trailing newline
}
