// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/version"
)

func scrapeSignals(t *testing.T, s *Server) string {
	t.Helper()
	var sb strings.Builder
	require.NoError(t, s.healthCollector.Signals().WriteText(&sb))
	return sb.String()
}

// TestBuildInfoAndStartTimeScrape registers the identity source on a real
// collector and checks the exposition carries both series.
func TestBuildInfoAndStartTimeScrape(t *testing.T) {
	origCommit, origVersion := version.GitCommit, version.Version
	t.Cleanup(func() { version.GitCommit, version.Version = origCommit, origVersion })
	version.GitCommit = "a1b2c3d4e5f6"
	version.Version = "v1.2.3"

	srv := newSignalSourceTestServer(t)
	require.NoError(t, registerIdentitySignals(srv))
	out := scrapeSignals(t, srv)

	assert.Contains(t, out, "# TYPE cfgms_build_info gauge")
	assert.Contains(t, out, `cfgms_build_info{revision="a1b2c3d4e5f6",version="1.2.3"} 1`)
	assert.Contains(t, out, "# TYPE cfgms_process_start_time_seconds gauge")

	var start float64
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "cfgms_process_start_time_seconds "); ok {
			var err error
			start, err = strconv.ParseFloat(v, 64)
			require.NoError(t, err)
		}
	}
	require.NotZero(t, start, "start time series missing from %q", out)
	assert.InDelta(t, float64(time.Now().Unix()), start, 24*3600, "start time must be a recent Unix timestamp")
	assert.LessOrEqual(t, start, float64(time.Now().UnixNano())/1e9)
}

// TestIdentitySourceIsRegistered proves the init()-time registration puts the
// source on the list startHealthServices runs.
func TestIdentitySourceIsRegistered(t *testing.T) {
	srv := newSignalSourceTestServer(t)

	assert.Equal(t, 0, srv.runSignalSources())
	out := scrapeSignals(t, srv)
	assert.Contains(t, out, "cfgms_build_info{")
	assert.Contains(t, out, "cfgms_process_start_time_seconds ")
}

func TestBuildInfoRevisionLabelValidated(t *testing.T) {
	origCommit := version.GitCommit
	t.Cleanup(func() { version.GitCommit = origCommit })

	tests := []struct {
		name, commit, want string
	}{
		{"hex", "0123456789abcdef0123456789abcdef01234567", "0123456789abcdef0123456789abcdef01234567"},
		{"dirty hex", "0123456789abcdef-dirty", "0123456789abcdef-dirty"},
		{"unknown", "unknown", "unknown"},
		{"free text", `v1.0 "quoted"` + "\nnewline", "unknown"},
		{"too short", "abc", "unknown"},
		{"non hex", "ghijklmnop", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version.GitCommit = tt.commit
			srv := newSignalSourceTestServer(t)
			require.NoError(t, registerIdentitySignals(srv))
			assert.Contains(t, scrapeSignals(t, srv), `revision="`+tt.want+`"`)
		})
	}
}

// TestIdentitySignalsRejectDuplicateRegistration covers the error path: a name
// already taken makes the source fail instead of silently double-registering.
func TestIdentitySignalsRejectDuplicateRegistration(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	require.NoError(t, registerIdentitySignals(srv))

	err := registerIdentitySignals(srv)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cfgms_build_info")
}
