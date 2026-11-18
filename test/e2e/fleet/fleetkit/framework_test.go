// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleetkit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestGatherDiagnosticsReportsEverySection proves the stalled-state capture
// returns the evidence it can get and names what it cannot: a failing collector
// and a collector that never returns each appear in the output, and neither stops
// the sections after it. It needs no Docker or controller.
func TestGatherDiagnosticsReportsEverySection(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	sections := []diagnosticsSection{
		{"first", func(context.Context) (string, error) { return "evidence-one\n", nil }},
		{"failing", func(context.Context) (string, error) { return "", fmt.Errorf("docker: no such container") }},
		{"stalled", func(context.Context) (string, error) { <-release; return "never", nil }},
		{"last", func(context.Context) (string, error) { return "evidence-two", nil }},
	}

	start := time.Now()
	out := gatherDiagnostics(100*time.Millisecond, sections)
	require.Less(t, time.Since(start), 5*time.Second, "a hung collector must be abandoned at its timeout")

	require.Contains(t, out, "── first ──\nevidence-one\n")
	require.Contains(t, out, "── failing ──\n(unavailable: docker: no such container)")
	require.Contains(t, out, "── stalled ──\n(timed out after 100ms)")
	require.NotContains(t, out, "never")
	require.Contains(t, out, "── last ──\nevidence-two", "a section after a stalled one must still be captured")
}

// TestFetchDiagnosticsBodyKeepsRefusalBody proves an error response is returned as
// evidence rather than dropped, and that a server that never answers is bounded by
// the caller's context.
func TestFetchDiagnosticsBodyKeepsRefusalBody(t *testing.T) {
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/refused", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "steward not found", http.StatusNotFound)
	})
	mux.HandleFunc("/hang", func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(func() { close(release); srv.Close() })

	out, err := fetchDiagnosticsBody(context.Background(), srv.Client(), srv.URL+"/refused")
	require.NoError(t, err)
	require.Equal(t, "HTTP 404\nsteward not found", out)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = fetchDiagnosticsBody(ctx, srv.Client(), srv.URL+"/hang")
	require.ErrorIs(t, err, context.DeadlineExceeded)

	_, err = fetchDiagnosticsBody(context.Background(), srv.Client(), "://bad url")
	require.Error(t, err)
}

// TestFilterLogLinesKeepsRelevantTail proves the controller-log filter keeps lines
// naming the steward or a stall keyword and bounds the result to the newest lines.
func TestFilterLogLinesKeepsRelevantTail(t *testing.T) {
	log := strings.Join([]string{
		`{"msg":"heartbeat ok"}`,
		`{"msg":"steward connected to ControlChannel","steward_id":"abc"}`,
		`{"msg":"unrelated"}`,
		`{"msg":"command push_signing_cert timed out"}`,
		`{"msg":"sync_dna failed","error":"DeadlineExceeded"}`,
	}, "\n")

	got := filterLogLines(log, 10, append([]string{"abc"}, diagnosticsLogKeywords...)...)
	require.Equal(t, strings.Join([]string{
		`{"msg":"steward connected to ControlChannel","steward_id":"abc"}`,
		`{"msg":"command push_signing_cert timed out"}`,
		`{"msg":"sync_dna failed","error":"DeadlineExceeded"}`,
	}, "\n"), got)

	got = filterLogLines(log, 1, "ControlChannel", "timed out", "DeadlineExceeded")
	require.Equal(t, `{"msg":"sync_dna failed","error":"DeadlineExceeded"}`, got)

	require.Empty(t, filterLogLines(log, 10, ""), "an empty needle (no steward ID) must not match every line")
}
