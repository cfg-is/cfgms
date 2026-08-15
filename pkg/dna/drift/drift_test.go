// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package drift_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/dna/drift"
)

// makeFragment builds a minimal Fragment for test fixtures.
func makeFragment(id, hash string) *commonpb.Fragment {
	return &commonpb.Fragment{
		FragmentId:   id,
		Authority:    "test",
		FragmentHash: hash,
	}
}

// makeDNA builds a DNA with the given fragments, sharing the same ID.
func makeDNA(id string, frags ...*commonpb.Fragment) *commonpb.DNA {
	return &commonpb.DNA{
		Id:        id,
		Fragments: frags,
	}
}

func TestDefaultDetectorConfig_ReturnsNonNil(t *testing.T) {
	config := drift.DefaultDetectorConfig()
	require.NotNil(t, config)
}

func TestNewDetector_NilConfigAndLogger(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, d)
}

// TestDetectDrift_NoChanges verifies that identical fragment sets produce no events.
func TestDetectDrift_NoChanges(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v1"),
		makeFragment("service:sshd", "hash-sshd-v1"),
	)
	curr := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v1"),
		makeFragment("service:sshd", "hash-sshd-v1"),
	)

	events, err := d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)
	assert.Empty(t, events, "identical fragment sets must produce no drift events")
}

// TestDetectDrift_FragmentAdded verifies that a new fragment produces an added change.
func TestDetectDrift_FragmentAdded(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v1"),
	)
	curr := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v1"),
		makeFragment("service:sshd", "hash-sshd-v1"),
	)

	events, err := d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)
	require.NotEmpty(t, events, "added fragment must produce a drift event")

	found := false
	for _, ev := range events {
		for _, ch := range ev.Changes {
			if ch.Attribute == "service:sshd" && ch.ChangeType == drift.ChangeTypeAdded {
				found = true
				assert.Equal(t, "", ch.PreviousValue)
				assert.Equal(t, "hash-sshd-v1", ch.CurrentValue)
			}
		}
	}
	assert.True(t, found, "expected an added change for service:sshd")
}

// TestDetectDrift_FragmentRemoved verifies that a missing fragment produces a removed change.
func TestDetectDrift_FragmentRemoved(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v1"),
		makeFragment("service:sshd", "hash-sshd-v1"),
	)
	curr := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v1"),
	)

	events, err := d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)
	require.NotEmpty(t, events, "removed fragment must produce a drift event")

	found := false
	for _, ev := range events {
		for _, ch := range ev.Changes {
			if ch.Attribute == "service:sshd" && ch.ChangeType == drift.ChangeTypeRemoved {
				found = true
				assert.Equal(t, "hash-sshd-v1", ch.PreviousValue)
				assert.Equal(t, "", ch.CurrentValue)
			}
		}
	}
	assert.True(t, found, "expected a removed change for service:sshd")
}

// TestDetectDrift_FragmentModified verifies that a hash change produces a modified change.
func TestDetectDrift_FragmentModified(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v1"),
	)
	curr := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v2"),
	)

	events, err := d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)
	require.NotEmpty(t, events, "modified fragment must produce a drift event")

	found := false
	for _, ev := range events {
		for _, ch := range ev.Changes {
			if ch.Attribute == "host:cpu" && ch.ChangeType == drift.ChangeTypeModified {
				found = true
				assert.Equal(t, "hash-cpu-v1", ch.PreviousValue)
				assert.Equal(t, "hash-cpu-v2", ch.CurrentValue)
			}
		}
	}
	assert.True(t, found, "expected a modified change for host:cpu")
}

// TestDetectDrift_SeverityClassification_CriticalFragment verifies that fragments
// whose IDs match critical patterns receive SeverityCritical.
func TestDetectDrift_SeverityClassification_CriticalFragment(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	// "cert_trust:foo" matches the ".*cert.*" critical pattern.
	prev := makeDNA("device-1",
		makeFragment("cert_trust:my-ca", "hash-cert-v1"),
	)
	curr := makeDNA("device-1",
		makeFragment("cert_trust:my-ca", "hash-cert-v2"),
	)

	events, err := d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)
	require.NotEmpty(t, events, "modified cert fragment must produce a drift event")

	found := false
	for _, ev := range events {
		for _, ch := range ev.Changes {
			if ch.Attribute == "cert_trust:my-ca" {
				found = true
				assert.Equal(t, drift.SeverityCritical, ch.Severity,
					"cert_trust fragment must be classified as critical")
			}
		}
	}
	assert.True(t, found, "expected change for cert_trust:my-ca")
}

// TestDetectDrift_SeverityClassification_SecurityFragment verifies that fragments
// whose IDs match security patterns receive SeverityCritical.
func TestDetectDrift_SeverityClassification_SecurityFragment(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1")
	curr := makeDNA("device-1",
		makeFragment("firewall:iptables", "hash-fw-v1"),
	)

	events, err := d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)
	require.NotEmpty(t, events, "added firewall fragment must produce a drift event")

	found := false
	for _, ev := range events {
		for _, ch := range ev.Changes {
			if ch.Attribute == "firewall:iptables" {
				found = true
				assert.Equal(t, drift.SeverityCritical, ch.Severity,
					"firewall fragment must be classified as critical")
			}
		}
	}
	assert.True(t, found, "expected change for firewall:iptables")
}

// TestDetectDrift_SeverityClassification_HardwareFragment verifies that hardware
// fragments receive SeverityWarning.
func TestDetectDrift_SeverityClassification_HardwareFragment(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v1"),
	)
	curr := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v2"),
	)

	events, err := d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)
	require.NotEmpty(t, events)

	found := false
	for _, ev := range events {
		for _, ch := range ev.Changes {
			if ch.Attribute == "host:cpu" {
				found = true
				assert.Equal(t, drift.SeverityWarning, ch.Severity,
					"host:cpu fragment must be classified as warning (hardware)")
			}
		}
	}
	assert.True(t, found, "expected change for host:cpu")
}

// TestDetectDrift_IgnoredFragment verifies that fragments matching an ignored
// pattern produce no drift events.
func TestDetectDrift_IgnoredFragment(t *testing.T) {
	config := drift.DefaultDetectorConfig()
	config.IgnoredAttributes = []string{".*_metrics$"}
	d, err := drift.NewDetector(config, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v1"),
	)
	curr := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v1"),
		makeFragment("perf_metrics", "hash-metrics-v1"),
	)

	events, err := d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)

	for _, ev := range events {
		for _, ch := range ev.Changes {
			assert.NotEqual(t, "perf_metrics", ch.Attribute,
				"ignored fragment must not appear in drift events")
		}
	}
}

// TestDetectDrift_EmptyFragments verifies that two DNAs with no fragments produce
// no drift events.
func TestDetectDrift_EmptyFragments(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1")
	curr := makeDNA("device-1")

	events, err := d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)
	assert.Empty(t, events, "empty fragment sets must produce no drift events")
}

// TestDetectDrift_MixedChanges verifies that added, removed, and modified fragments
// are all reported correctly in a single comparison.
func TestDetectDrift_MixedChanges(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v1"),      // will be modified
		makeFragment("service:sshd", "hash-sshd-v1"), // will be removed
	)
	curr := makeDNA("device-1",
		makeFragment("host:cpu", "hash-cpu-v2"),    // modified
		makeFragment("host:memory", "hash-mem-v1"), // added
	)

	events, err := d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)
	require.NotEmpty(t, events)

	changeTypes := make(map[string]drift.ChangeType)
	for _, ev := range events {
		for _, ch := range ev.Changes {
			changeTypes[ch.Attribute] = ch.ChangeType
		}
	}

	assert.Equal(t, drift.ChangeTypeModified, changeTypes["host:cpu"], "host:cpu must be modified")
	assert.Equal(t, drift.ChangeTypeRemoved, changeTypes["service:sshd"], "service:sshd must be removed")
	assert.Equal(t, drift.ChangeTypeAdded, changeTypes["host:memory"], "host:memory must be added")
}

// TestDetectDrift_SignatureUnchanged verifies that DetectDrift's signature accepts
// *commonpb.DNA parameters and returns ([]*DriftEvent, error) — callers in
// steward.go, reports/provider, and controller/server must not need changes.
func TestDetectDrift_SignatureUnchanged(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1", makeFragment("host:cpu", "hash-a"))
	curr := makeDNA("device-1", makeFragment("host:cpu", "hash-b"))

	var events []*drift.DriftEvent
	events, err = d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)
	require.NotEmpty(t, events, "a changed fragment hash must produce at least one event")

	var found bool
	for _, ev := range events {
		for _, ch := range ev.Changes {
			if ch.Attribute == "host:cpu" {
				found = true
				assert.Equal(t, drift.ChangeTypeModified, ch.ChangeType, "host:cpu must be reported as modified")
				assert.Equal(t, "hash-a", ch.PreviousValue)
				assert.Equal(t, "hash-b", ch.CurrentValue)
			}
		}
	}
	assert.True(t, found, "events must carry a change entry for host:cpu")
}

// TestDetectDrift_NilInputError verifies that nil DNA inputs return an error.
func TestDetectDrift_NilInputError(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1")
	_, err = d.DetectDrift(context.Background(), nil, prev)
	assert.Error(t, err)

	_, err = d.DetectDrift(context.Background(), prev, nil)
	assert.Error(t, err)
}

// TestDetectDrift_IDMismatchError verifies that mismatched DNA IDs return an error.
func TestDetectDrift_IDMismatchError(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1")
	curr := makeDNA("device-2")

	_, err = d.DetectDrift(context.Background(), prev, curr)
	assert.Error(t, err)
}

// TestDetectDrift_DriftEventCarriesFullDNA verifies that DriftEvent.PreviousDNA
// and DriftEvent.CurrentDNA are populated with the original DNA values (unchanged
// public field shape — callers may inspect these).
func TestDetectDrift_DriftEventCarriesFullDNA(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1", makeFragment("host:cpu", "hash-v1"))
	curr := makeDNA("device-1", makeFragment("host:cpu", "hash-v2"))

	events, err := d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)
	require.NotEmpty(t, events)

	for _, ev := range events {
		assert.Equal(t, prev, ev.PreviousDNA, "PreviousDNA must be the original prev DNA")
		assert.Equal(t, curr, ev.CurrentDNA, "CurrentDNA must be the original curr DNA")
	}
}

// ─── DetectDriftBatch ─────────────────────────────────────────────────────────

// TestDetectDriftBatch_BatchModeDisabled verifies that with EnableBatchMode=false
// the detector processes each comparison sequentially and returns all events.
func TestDetectDriftBatch_BatchModeDisabled(t *testing.T) {
	config := drift.DefaultDetectorConfig()
	config.EnableBatchMode = false
	d, err := drift.NewDetector(config, nil)
	require.NoError(t, err)

	comparisons := []*drift.DNAComparison{
		{
			DeviceID: "device-1",
			Previous: makeDNA("device-1", makeFragment("host:cpu", "hash-cpu-v1")),
			Current:  makeDNA("device-1", makeFragment("host:cpu", "hash-cpu-v2")),
		},
		{
			DeviceID: "device-2",
			Previous: makeDNA("device-2", makeFragment("service:sshd", "hash-ssh-v1")),
			Current:  makeDNA("device-2", makeFragment("service:sshd", "hash-ssh-v2")),
		},
	}

	events, err := d.DetectDriftBatch(context.Background(), comparisons)
	require.NoError(t, err)
	assert.Len(t, events, 2, "one drift event group per changed device")
}

// TestDetectDriftBatch_BatchModeEnabled verifies that with EnableBatchMode=true
// the detector processes comparisons in batches and returns all events.
func TestDetectDriftBatch_BatchModeEnabled(t *testing.T) {
	config := drift.DefaultDetectorConfig()
	config.EnableBatchMode = true
	config.BatchSize = 1 // force single-item batches to exercise the loop boundary
	d, err := drift.NewDetector(config, nil)
	require.NoError(t, err)

	comparisons := []*drift.DNAComparison{
		{
			DeviceID: "device-1",
			Previous: makeDNA("device-1", makeFragment("host:cpu", "hash-v1")),
			Current:  makeDNA("device-1", makeFragment("host:cpu", "hash-v2")),
		},
		{
			DeviceID: "device-2",
			Previous: makeDNA("device-2", makeFragment("host:memory", "hash-mem-v1")),
			Current:  makeDNA("device-2", makeFragment("host:memory", "hash-mem-v2")),
		},
		{
			DeviceID: "device-3",
			Previous: makeDNA("device-3", makeFragment("service:nginx", "hash-ng-v1")),
			Current:  makeDNA("device-3", makeFragment("service:nginx", "hash-ng-v2")),
		},
	}

	events, err := d.DetectDriftBatch(context.Background(), comparisons)
	require.NoError(t, err)
	assert.Len(t, events, 3, "all three modified-fragment comparisons must produce events")
}

// TestDetectDriftBatch_ErrorContinuation verifies that a failing comparison does
// not abort the batch — the detector logs and continues, returning events from the
// remaining valid comparisons.
func TestDetectDriftBatch_ErrorContinuation(t *testing.T) {
	config := drift.DefaultDetectorConfig()
	config.EnableBatchMode = false
	d, err := drift.NewDetector(config, nil)
	require.NoError(t, err)

	// The middle comparison has mismatched IDs, which DetectDrift rejects with an
	// error. The detector must skip it and still return events from the other two.
	comparisons := []*drift.DNAComparison{
		{
			DeviceID: "device-1",
			Previous: makeDNA("device-1", makeFragment("host:cpu", "hash-v1")),
			Current:  makeDNA("device-1", makeFragment("host:cpu", "hash-v2")),
		},
		{
			DeviceID: "bad",
			Previous: makeDNA("device-bad-a"),
			Current:  makeDNA("device-bad-b"), // ID mismatch → DetectDrift errors
		},
		{
			DeviceID: "device-3",
			Previous: makeDNA("device-3", makeFragment("service:sshd", "hash-v1")),
			Current:  makeDNA("device-3", makeFragment("service:sshd", "hash-v2")),
		},
	}

	events, err := d.DetectDriftBatch(context.Background(), comparisons)
	require.NoError(t, err, "batch must not propagate individual comparison errors")
	assert.Len(t, events, 2, "events from valid comparisons must still be returned")
}

// TestDetectDriftBatch_ContextCancellation verifies that a cancelled context causes
// DetectDriftBatch to stop processing and return the context error.
func TestDetectDriftBatch_ContextCancellation(t *testing.T) {
	config := drift.DefaultDetectorConfig()
	config.EnableBatchMode = true
	config.BatchSize = 1
	d, err := drift.NewDetector(config, nil)
	require.NoError(t, err)

	// Build enough comparisons that context cancellation can interrupt between batches.
	var comparisons []*drift.DNAComparison
	for i := range 10 {
		deviceID := "device-" + string(rune('0'+i))
		comparisons = append(comparisons, &drift.DNAComparison{
			DeviceID: deviceID,
			Previous: makeDNA(deviceID, makeFragment("host:cpu", "hash-v1")),
			Current:  makeDNA(deviceID, makeFragment("host:cpu", "hash-v2")),
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err = d.DetectDriftBatch(ctx, comparisons)
	assert.ErrorIs(t, err, context.Canceled, "cancelled context must propagate as context.Canceled")
}

// TestDetectDriftBatch_EmptyComparisons verifies that an empty slice produces no
// events and no error in either batch mode.
func TestDetectDriftBatch_EmptyComparisons(t *testing.T) {
	for _, batchMode := range []bool{false, true} {
		config := drift.DefaultDetectorConfig()
		config.EnableBatchMode = batchMode
		d, err := drift.NewDetector(config, nil)
		require.NoError(t, err)

		events, err := d.DetectDriftBatch(context.Background(), nil)
		require.NoError(t, err)
		assert.Empty(t, events, "empty comparisons must produce no events")
	}
}

// ─── GetStats ─────────────────────────────────────────────────────────────────

// TestGetStats_InitialState verifies that a freshly created detector has zero
// counters and no LastDetection timestamp.
func TestGetStats_InitialState(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	stats := d.GetStats()
	require.NotNil(t, stats)
	assert.Equal(t, int64(0), stats.TotalComparisons)
	assert.Equal(t, int64(0), stats.DriftEventsDetected)
	assert.Equal(t, int64(0), stats.CriticalEvents)
	assert.Equal(t, int64(0), stats.WarningEvents)
	assert.Equal(t, int64(0), stats.InfoEvents)
	assert.Nil(t, stats.LastDetection, "LastDetection must be nil before any drift is detected")
}

// TestGetStats_TotalComparisons verifies that TotalComparisons increments for
// every DetectDrift call, regardless of whether drift was found.
func TestGetStats_TotalComparisons(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	same := makeDNA("device-1", makeFragment("host:cpu", "hash-v1"))

	// Three identical comparisons → three total, no events.
	for range 3 {
		_, err = d.DetectDrift(context.Background(), same, same)
		require.NoError(t, err)
	}

	stats := d.GetStats()
	assert.Equal(t, int64(3), stats.TotalComparisons)
	assert.Equal(t, int64(0), stats.DriftEventsDetected, "no drift → no events counted")
	assert.Nil(t, stats.LastDetection, "no drift → LastDetection remains nil")
}

// TestGetStats_CriticalEventsAccumulate verifies that CriticalEvents increments
// when a critical-severity drift event is produced (e.g. a cert_trust fragment change).
func TestGetStats_CriticalEventsAccumulate(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1", makeFragment("cert_trust:my-ca", "hash-cert-v1"))
	curr := makeDNA("device-1", makeFragment("cert_trust:my-ca", "hash-cert-v2"))

	_, err = d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)

	stats := d.GetStats()
	assert.Equal(t, int64(1), stats.TotalComparisons)
	assert.Positive(t, stats.CriticalEvents, "cert_trust fragment change must increment CriticalEvents")
	assert.NotNil(t, stats.LastDetection, "drift detected → LastDetection must be set")
}

// TestGetStats_WarningEventsAccumulate verifies that WarningEvents increments when
// a warning-severity drift event is produced (e.g. a host:cpu fragment change).
func TestGetStats_WarningEventsAccumulate(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	prev := makeDNA("device-1", makeFragment("host:cpu", "hash-v1"))
	curr := makeDNA("device-1", makeFragment("host:cpu", "hash-v2"))

	_, err = d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)

	stats := d.GetStats()
	assert.Equal(t, int64(1), stats.TotalComparisons)
	assert.Positive(t, stats.WarningEvents, "host:cpu fragment change must increment WarningEvents")
	assert.NotNil(t, stats.LastDetection)
}

// TestGetStats_InfoEventsAccumulate verifies that InfoEvents increments when an
// info-severity drift event is produced (e.g. a plain service fragment change that
// doesn't match any critical/warning pattern).
func TestGetStats_InfoEventsAccumulate(t *testing.T) {
	// Use a config with no critical/security/hardware patterns so the change lands
	// as info-severity.
	config := drift.DefaultDetectorConfig()
	config.CriticalAttributes = nil
	config.SecurityAttributes = nil
	d, err := drift.NewDetector(config, nil)
	require.NoError(t, err)

	// "app:myapp" has no hardware/network/security keywords → categorized as
	// "configuration" → info severity.
	prev := makeDNA("device-1", makeFragment("app:myapp", "hash-v1"))
	curr := makeDNA("device-1", makeFragment("app:myapp", "hash-v2"))

	_, err = d.DetectDrift(context.Background(), prev, curr)
	require.NoError(t, err)

	stats := d.GetStats()
	assert.Equal(t, int64(1), stats.TotalComparisons)
	assert.Positive(t, stats.InfoEvents, "app:myapp fragment change must increment InfoEvents")
}

// TestGetStats_RulesTriggeredDeepCopy verifies that the returned DetectorStats is
// an independent copy — mutating its RulesTriggered map must not affect the
// internal stats.
func TestGetStats_RulesTriggeredDeepCopy(t *testing.T) {
	d, err := drift.NewDetector(nil, nil)
	require.NoError(t, err)

	stats := d.GetStats()
	// Mutate the returned copy.
	stats.RulesTriggered["injected"] = 99

	// The internal state must be unaffected.
	stats2 := d.GetStats()
	_, exists := stats2.RulesTriggered["injected"]
	assert.False(t, exists, "mutating the returned stats must not affect internal state")
}
