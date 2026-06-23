// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package hyperv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// On non-Windows builds the Hyper-V VM-state Monitor is unavailable: Monitor
// reports ErrNotSupported, Changes returns nil, and Close is a no-op. The
// steward's scheduled poll is the cross-platform backstop.
func TestHypervMonitorNotSupportedOnNonWindows(t *testing.T) {
	m, ok := New(nil).(*hypervModule)
	require.True(t, ok, "New must return *hypervModule")

	err := m.Monitor(context.Background(), "vm:x", nil)
	require.ErrorIs(t, err, ErrNotSupported)

	require.Nil(t, m.Changes(), "Changes() is nil when monitoring is unsupported")
	require.NoError(t, m.Close(), "Close is a no-op on non-Windows")
}
