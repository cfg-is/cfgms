// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package dex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// TestParseGUID verifies that parseGUID correctly parses the canonical GUID
// format used by the ETW provider registry.
func TestParseGUID(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
	}{
		{"{8c416c79-d49b-4f01-a467-e56d3aa8234c}", false},
		{"{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}", false},
		{"{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}", false},
		{"{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}", false},
		{"not-a-guid", true},
		{"{8c416c79-d49b-4f01-a467}", true},                // too short
		{"{8c416c79-d49b-4f01-a467-e56d3aa8234cXX}", true}, // data4 too long
	}
	for _, tc := range cases {
		_, err := parseGUID(tc.input)
		if tc.wantErr {
			assert.Error(t, err, "expected error for %q", tc.input)
		} else {
			assert.NoError(t, err, "expected success for %q", tc.input)
		}
	}
}

// TestParseGUIDRoundtrip verifies that parseGUID → guidString is idempotent.
func TestParseGUIDRoundtrip(t *testing.T) {
	inputs := []string{
		"{8c416c79-d49b-4f01-a467-e56d3aa8234c}",
		"{3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c}",
		"{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}",
		"{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}",
	}
	for _, in := range inputs {
		guid, err := parseGUID(in)
		require.NoError(t, err, "parseGUID(%q)", in)
		out := guidString(guid)
		assert.Equal(t, strings.ToLower(in), strings.ToLower(out),
			"round-trip mismatch for %q", in)
	}
}

// TestETWProviderRegistryComplete verifies that every etwProvider entry has a
// non-empty name, a parseable GUID, and a non-empty SignalClass.
func TestETWProviderRegistryComplete(t *testing.T) {
	assert.NotEmpty(t, etwProviders, "etwProviders must not be empty")
	for _, p := range etwProviders {
		assert.NotEmpty(t, string(p.class), "provider missing class")
		assert.NotEmpty(t, p.name, "provider missing name")
		_, err := parseGUID(p.guidStr)
		assert.NoError(t, err, "unparseable GUID for provider %q: %q", p.name, p.guidStr)
	}
}

// TestWMIProviderRegistryComplete verifies that every wmiProvider entry has a
// non-empty namespace, wmiClass, and query.
func TestWMIProviderRegistryComplete(t *testing.T) {
	assert.NotEmpty(t, wmiProviders, "wmiProviders must not be empty")
	for _, p := range wmiProviders {
		assert.NotEmpty(t, string(p.class), "wmi provider missing class")
		assert.NotEmpty(t, p.namespace, "wmi provider missing namespace")
		assert.NotEmpty(t, p.wmiClass, "wmi provider missing wmiClass")
		assert.NotEmpty(t, p.query, "wmi provider missing query")
	}
}

// TestClassForGUIDKnownProviders verifies that classForGUID returns the right
// SignalClass for every registered ETW provider GUID.
func TestClassForGUIDKnownProviders(t *testing.T) {
	for _, p := range etwProviders {
		guid, err := parseGUID(p.guidStr)
		require.NoError(t, err, "parseGUID(%q)", p.guidStr)
		got := classForGUID(guid)
		assert.Equal(t, p.class, got, "classForGUID mismatch for provider %q", p.name)
	}
}

// TestClassForGUIDUnknown verifies that an arbitrary GUID returns the empty
// string (not a panic).
func TestClassForGUIDUnknown(t *testing.T) {
	// An all-zeros GUID is not in the registry.
	guid, err := parseGUID("{00000000-0000-0000-0000-000000000000}")
	require.NoError(t, err)
	assert.Empty(t, string(classForGUID(guid)))
}

// TestProcessTimesNs verifies that processTimesNs returns a positive value and
// that two calls taken close together return a non-decreasing value.
func TestProcessTimesNs(t *testing.T) {
	t1, err := processTimesNs()
	require.NoError(t, err)
	assert.Greater(t, t1, uint64(0), "processTimesNs must return a positive value")

	// Do some work to consume measurable CPU.
	sum := 0
	for i := 0; i < 1_000_000; i++ {
		sum += i
	}
	_ = sum

	t2, err := processTimesNs()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, t2, t1, "processTimesNs must be non-decreasing")
}

// TestCollectorRunShort exercises the full Run() path with a 2-second overhead
// window so the spike completes in CI without spinning for 30 s. It verifies
// that reachability records are emitted for all expected signal classes and
// that overhead is recorded with the correct budget ceiling.
//
// This test requires the ETW session privilege (local administrator or SYSTEM).
// It auto-detects whether the privilege is present by attempting a transient
// StartTrace; if that fails with ERROR_ACCESS_DENIED it skips rather than
// failing with a confusing syscall error.
func TestCollectorRunShort(t *testing.T) {
	// Probe ETW privilege by attempting a transient trace session.
	// Only skip on privilege-related errors; other errors indicate a bug in
	// startNamedTrace itself and must fail rather than silently skip.
	probeHandle, probeErr := startNamedTrace("cfgms-dex-priv-probe", eventTraceRealTimeMode)
	if probeErr != nil {
		var errno windows.Errno
		if errors.As(probeErr, &errno) &&
			(errno == windows.ERROR_ACCESS_DENIED || errno == 1314 /* ERROR_PRIVILEGE_NOT_HELD */) {
			t.Skipf("ETW session requires admin privilege (StartTrace: %v) — skipping", probeErr)
		}
		t.Fatalf("startNamedTrace probe failed with unexpected error (not a privilege issue): %v", probeErr)
	}
	// Clean up probe session before proceeding.
	require.NoError(t, stopNamedTrace(probeHandle, "cfgms-dex-priv-probe"), "cleanup probe ETW session")

	cfg := DefaultConfig()
	cfg.OverheadWindowSec = 2
	cfg.MaxEventsPerClass = 3

	var buf bytes.Buffer
	sink := NewSink(&buf)
	col := NewCollector(cfg, sink)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	report, err := col.Run(ctx)
	require.NoError(t, err)

	// Every registered signal class must appear in the reachability results.
	expectedClasses := make(map[SignalClass]bool)
	for _, p := range etwProviders {
		expectedClasses[p.class] = false
	}
	for _, p := range wmiProviders {
		expectedClasses[p.class] = false
	}
	for _, r := range report.Reachability {
		expectedClasses[r.Class] = true
	}
	for class, seen := range expectedClasses {
		assert.True(t, seen, "signal class %q missing from reachability report", class)
	}

	// Overhead must have the correct budget ceiling.
	assert.Equal(t, 1.0, report.Overhead.BudgetPercent)
	assert.Greater(t, report.Overhead.DurationSec, 0.0)

	// Verify all records are valid JSON lines.
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		var rec SpikeRecord
		assert.NoError(t, json.Unmarshal([]byte(line), &rec),
			"line %d is not valid JSON: %s", i, line)
	}
}

// TestMergeClassDoesNotMutate verifies (Windows side, in case build tags differ)
// that mergeClass does not mutate the caller's map.
func TestMergeClassDoesNotMutate(t *testing.T) {
	in := map[string]any{"key": "value"}
	out := mergeClass(SignalDiskIO, in)
	assert.Equal(t, "disk_io", out["class"])
	_, hasClass := in["class"]
	assert.False(t, hasClass, "mergeClass must not mutate the input map")
}
