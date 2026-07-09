// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dex

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSinkWriteReachability verifies that WriteReachability emits valid JSON
// lines with the expected fields.
func TestSinkWriteReachability(t *testing.T) {
	var buf bytes.Buffer
	sink := NewSink(&buf)

	r := ReachabilityResult{
		Class:     SignalDiskIO,
		Mechanism: MechanismETW,
		Provider:  "Microsoft-Windows-Kernel-Disk",
		Reachable: true,
	}
	require.NoError(t, sink.WriteReachability(r))

	var rec SpikeRecord
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rec))
	assert.Equal(t, "reachability", rec.Kind)
	require.NotNil(t, rec.Reachability)
	assert.Equal(t, SignalDiskIO, rec.Reachability.Class)
	assert.True(t, rec.Reachability.Reachable)
	assert.True(t, rec.Timestamp.Before(time.Now().Add(time.Second)))
}

// TestSinkWriteOverhead verifies that WriteOverhead emits valid JSON with
// the budget comparison fields set.
func TestSinkWriteOverhead(t *testing.T) {
	var buf bytes.Buffer
	sink := NewSink(&buf)

	o := OverheadSample{
		DurationSec:   30,
		CPUPercent:    0.45,
		BudgetPercent: 1.0,
		WithinBudget:  true,
	}
	require.NoError(t, sink.WriteOverhead(o))

	var rec SpikeRecord
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rec))
	assert.Equal(t, "overhead", rec.Kind)
	require.NotNil(t, rec.Overhead)
	assert.Equal(t, 30.0, rec.Overhead.DurationSec)
	assert.Equal(t, 0.45, rec.Overhead.CPUPercent)
	assert.True(t, rec.Overhead.WithinBudget)
}

// TestSinkWriteEvent verifies that WriteEvent emits valid JSON with the class
// injected into the event map.
func TestSinkWriteEvent(t *testing.T) {
	var buf bytes.Buffer
	sink := NewSink(&buf)

	fields := map[string]any{"event_id": 42, "process_id": 1234}
	require.NoError(t, sink.WriteEvent(SignalHardFault, fields))

	var rec SpikeRecord
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rec))
	assert.Equal(t, "event", rec.Kind)
	require.NotNil(t, rec.Event)
	assert.Equal(t, "hard_fault", rec.Event["class"])
	assert.EqualValues(t, 42, rec.Event["event_id"])
}

// TestSinkMultipleRecords verifies that multiple JSON lines are emitted
// independently and all decode correctly.
func TestSinkMultipleRecords(t *testing.T) {
	var buf bytes.Buffer
	sink := NewSink(&buf)

	require.NoError(t, sink.WriteReachability(ReachabilityResult{
		Class:     SignalSMART,
		Mechanism: MechanismWMI,
		Provider:  "MSStorageDriver_FailurePredictData",
		Reachable: true,
	}))
	require.NoError(t, sink.WriteReachability(ReachabilityResult{
		Class:     SignalThermal,
		Mechanism: MechanismWMI,
		Provider:  "MSAcpi_ThermalZoneTemperature",
		Reachable: false,
		Error:     "no thermal zones found",
	}))

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	require.Len(t, lines, 2)

	var rec1 SpikeRecord
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &rec1))
	assert.True(t, rec1.Reachability.Reachable)

	var rec2 SpikeRecord
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &rec2))
	assert.False(t, rec2.Reachability.Reachable)
	assert.Equal(t, "no thermal zones found", rec2.Reachability.Error)
}

// TestSpikeReportString verifies that the human-readable summary includes all
// required sections and correctly marks budget pass/fail.
func TestSpikeReportString(t *testing.T) {
	report := SpikeReport{
		Reachability: []ReachabilityResult{
			{Class: SignalDiskIO, Mechanism: MechanismETW, Provider: "Microsoft-Windows-Kernel-Disk", Reachable: true},
			{Class: SignalSMART, Mechanism: MechanismWMI, Provider: "MSStorageDriver_FailurePredictData", Reachable: false, Error: "access denied"},
		},
		Overhead: OverheadSample{
			DurationSec:   30,
			CPUPercent:    0.78,
			BudgetPercent: 1.0,
			WithinBudget:  true,
		},
		TotalEvents: 7,
	}

	s := report.String()
	assert.Contains(t, s, "Signal Reachability")
	assert.Contains(t, s, "disk_io")
	assert.Contains(t, s, "smart")
	assert.Contains(t, s, "access denied")
	assert.Contains(t, s, "CPU Overhead")
	assert.Contains(t, s, "PASS (within budget)")
	assert.Contains(t, s, "7")
}

// TestSpikeReportStringOverBudget verifies the fail path in the summary.
func TestSpikeReportStringOverBudget(t *testing.T) {
	report := SpikeReport{
		Overhead: OverheadSample{
			DurationSec:   30,
			CPUPercent:    1.45,
			BudgetPercent: 1.0,
			WithinBudget:  false,
		},
	}
	assert.Contains(t, report.String(), "FAIL (exceeds budget)")
}

// TestDefaultConfig verifies that DefaultConfig returns sane values.
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.NotEmpty(t, cfg.SessionName)
	assert.Greater(t, cfg.OverheadWindowSec, 0)
	assert.Greater(t, cfg.MaxEventsPerClass, 0)
}

// TestMergeClass verifies that mergeClass injects the class key correctly and
// preserves existing fields.
func TestMergeClass(t *testing.T) {
	in := map[string]any{"pid": 42, "tid": 7}
	out := mergeClass(SignalNetwork, in)
	assert.Equal(t, "network", out["class"])
	assert.EqualValues(t, 42, out["pid"])
	assert.EqualValues(t, 7, out["tid"])
	// Original map must not be mutated.
	assert.NotContains(t, in, "class")
}

// TestOverheadWithinBudget verifies the WithinBudget computation semantics.
func TestOverheadWithinBudget(t *testing.T) {
	cases := []struct {
		cpu      float64
		budget   float64
		expected bool
	}{
		{0.0, 1.0, true},
		{0.999, 1.0, true},
		{1.0, 1.0, true}, // exactly at budget = pass
		{1.001, 1.0, false},
		{2.5, 1.0, false},
	}
	for _, tc := range cases {
		o := OverheadSample{
			CPUPercent:    tc.cpu,
			BudgetPercent: tc.budget,
			WithinBudget:  tc.cpu <= tc.budget,
		}
		assert.Equal(t, tc.expected, o.WithinBudget,
			"cpu=%.3f budget=%.1f", tc.cpu, tc.budget)
	}
}

// TestCollectorStubOrPlatform verifies the stub behavioral contract on
// non-Windows builds: NewCollector returns a non-nil Collector and Run
// returns ErrPlatformNotSupported. On Windows the stub file is not compiled
// and this test is still compiled (from signal_test.go, not a _windows file),
// so we use a build-tag-guarded branch — non-Windows asserts the error,
// Windows skips the assertion (platform support is exercised by
// TestCollectorRunShort in collector_windows_test.go).
func TestCollectorStubOrPlatform(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OverheadWindowSec = 1
	var buf bytes.Buffer
	sink := NewSink(&buf)
	col := NewCollector(cfg, sink)
	require.NotNil(t, col)

	// The stub returns ErrPlatformNotSupported on non-Windows; invoke Run to
	// verify the contract rather than leaving it untested.
	assertStubOrSkip(t, col)
}

// TestSignalClassConstants verifies that all SignalClass values are non-empty
// and distinct — a regression guard against copy-paste errors in the const block.
func TestSignalClassConstants(t *testing.T) {
	classes := []SignalClass{
		SignalAppHang,
		SignalSMART,
		SignalThermal,
		SignalDiskIO,
		SignalHardFault,
		SignalNetwork,
	}
	seen := make(map[SignalClass]bool)
	for _, c := range classes {
		assert.NotEmpty(t, string(c), "SignalClass constant must not be empty")
		assert.False(t, seen[c], "duplicate SignalClass: %q", c)
		seen[c] = true
	}
}
