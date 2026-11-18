// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleetkit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLastLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"fewer lines than n returns input unchanged", "a\nb\n", 5, "a\nb\n"},
		{"exactly n lines returns input unchanged", "a\nb", 2, "a\nb"},
		{"keeps the last n lines", "a\nb\nc\nd", 2, "c\nd"},
		{"trailing newline is not a line", "a\nb\nc\n", 2, "b\nc"},
		{"empty input", "", 3, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, LastLines(tt.in, tt.n))
		})
	}
}

func TestStewardSessionMarkersNameBothSessionKinds(t *testing.T) {
	require.Len(t, StewardSessionMarkers, 2)
	for _, m := range StewardSessionMarkers {
		require.NotEmpty(t, m)
	}
}

// TestStewardLogCountUnreachableContainer covers the error path: when the log
// copy fails (no such container, or no Docker), the count is 0 rather than a test
// failure, and a wait for a new entry reports false once its window has passed.
func TestStewardLogCountUnreachableContainer(t *testing.T) {
	s := &FleetTestSuite{}
	const missing = "fleetkit-no-such-container"

	require.Equal(t, 0, s.StewardLogCount(t, missing, StewardSessionMarkers...))
	require.False(t, s.WaitForNewStewardLogEntry(t, missing, 0, time.Millisecond, StewardSessionMarkers...))
}
