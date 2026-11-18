// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleetkit

import (
	"strings"
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

// Log lines in the shapes the steward writes (job logs of the 2026-11-16 and
// 2026-11-18 fleet-e2e failures, Issue #6346). The client transport logs its
// steward_id through logging.RedactedID, which keeps 8 characters and appends
// U+2026; the connect sequence logs the full ID.
const (
	fullIDA   = "steward-1795021278065063387-ca4fc9cef72f8308"
	fullIDB   = "steward-1795021278065063999-0123456789abcdef"
	redactedL = `{"level":"info","msg":"Subscribing to commands","steward_id":"steward-\u2026"}`
	redactedR = `{"level":"info","msg":"Configuration executor initialized with event emitter","steward_id":"steward-…"}`
)

func fullIDLine(id string) string {
	return `{"level":"info","msg":"Reconnected to controller via stored identity","steward_id":"` + id + `"}`
}

// TestStewardIDFromLogTextIgnoresRedactedIDs proves steward-ID discovery returns a
// complete steward ID or reports not-found — never a redacted one — whatever line
// happens to come last in the log. The old `grep | tail -1` returned "steward-…"
// when a redacted line was the last steward_id field, which the rotation test then
// reported as a re-registration.
func TestStewardIDFromLogTextIgnoresRedactedIDs(t *testing.T) {
	tests := []struct {
		name   string
		log    []string
		want   string
		wantOK bool
	}{
		{"full ID followed by a redacted one returns the full ID",
			[]string{fullIDLine(fullIDA), redactedR}, fullIDA, true},
		{"full ID followed by a JSON-escaped redacted one returns the full ID",
			[]string{fullIDLine(fullIDA), redactedL}, fullIDA, true},
		{"only redacted values is not-found",
			[]string{redactedL, redactedR}, "", false},
		{"several full IDs returns the last full one",
			[]string{fullIDLine(fullIDA), redactedR, fullIDLine(fullIDB), redactedL}, fullIDB, true},
		{"no steward_id field at all is not-found",
			[]string{`{"level":"info","msg":"Connected to controller via gRPC transport"}`}, "", false},
		{"empty log is not-found", nil, "", false},
		{"empty steward_id value is not-found",
			[]string{`{"msg":"x","steward_id":""}`}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseStewardIDFromLogText(strings.Join(tt.log, "\n"))
			require.Equal(t, tt.wantOK, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsCompleteStewardID(t *testing.T) {
	require.True(t, isCompleteStewardID(fullIDA))
	for _, bad := range []string{"", "steward-…", `steward-\u2026`, "abc…", "steward-12…"} {
		require.False(t, isCompleteStewardID(bad), bad)
	}
}
