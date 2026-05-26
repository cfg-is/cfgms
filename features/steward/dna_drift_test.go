// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package steward_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	steward "github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/pkg/logging"
)

// writeMinimalCfgForDNA writes a minimal valid cfg file for DNA drift tests.
func writeMinimalCfgForDNA(t *testing.T, dir, id string) string {
	t.Helper()
	cfgData := `steward:
  id: ` + id + `

resources: []
`
	path := filepath.Join(dir, "dna-test.cfg")
	require.NoError(t, os.WriteFile(path, []byte(cfgData), 0644))
	return path
}

func TestDNACollectorInitializedInStandaloneMode(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-init-steward")

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	ctx := context.Background()

	// Run a convergence — detectUnmanagedDNADrift returns early (no previousDNA stored)
	// when dnaCollector is nil. A non-nil snapshot proves the collector was initialized.
	steward.RunConvergence(s, ctx)
	prevDNA := steward.GetPreviousDNA(s)
	assert.NotNil(t, prevDNA, "DNA collector should be initialized in standalone mode — convergence captured a DNA snapshot")

	require.NoError(t, s.Stop(context.Background()))
}

func TestDriftDetectorInitializedInStandaloneMode(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "drift-detector-steward")

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	ctx := context.Background()

	// Seed the current real DNA to learn the system's stable ID.
	steward.RunConvergence(s, ctx)
	realDNA := steward.GetPreviousDNA(s)
	require.NotNil(t, realDNA, "first convergence must capture DNA")

	// Inject a previousDNA with the same stable ID but an extra sentinel attribute.
	// The drift detector compares prev vs current; the sentinel attribute is present
	// in prev but absent in current → generates a ChangeTypeRemoved drift event.
	// If driftDetector is nil, detectUnmanagedDNADrift returns (nil, nil) immediately
	// after the ID comparison, so events would be empty.
	sentinelDNA := &commonpb.DNA{
		Id: realDNA.Id, // same ID — avoids the ID-mismatch early-return path
		Attributes: map[string]string{
			"__drift_detector_init_sentinel__": "present_in_prev_only",
		},
	}
	steward.SetPreviousDNA(s, sentinelDNA)

	events, err := steward.DetectUnmanagedDNADrift(s, ctx)
	assert.NoError(t, err, "drift detector must not error on attribute removal")
	assert.NotEmpty(t, events, "drift detector must be initialized — sentinel attribute removal must generate events")

	require.NoError(t, s.Stop(context.Background()))
}

func TestDNASnapshotCapturedAfterConvergence(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-snapshot-steward")

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Before Start, no DNA snapshot exists.
	prevDNA := steward.GetPreviousDNA(s)
	assert.Nil(t, prevDNA, "no DNA snapshot before convergence")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start runs an initial convergence synchronously, so when Start returns the
	// DNA snapshot is already captured.
	require.NoError(t, s.Start(ctx))

	prevDNA = steward.GetPreviousDNA(s)

	assert.NotNil(t, prevDNA, "DNA snapshot should be captured after initial convergence")
	assert.NotEmpty(t, prevDNA.Id, "DNA snapshot should have a non-empty ID")
	assert.NotEmpty(t, prevDNA.Attributes, "DNA snapshot should have attributes")

	require.NoError(t, s.Stop(context.Background()))
}

func TestRunConvergenceCapturesDNASnapshot(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-run-steward")

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	ctx := context.Background()

	// Run convergence directly — no Start needed for this unit test.
	steward.RunConvergence(s, ctx)

	// DNA snapshot should be set.
	prevDNA := steward.GetPreviousDNA(s)
	assert.NotNil(t, prevDNA, "runConvergence should capture a DNA snapshot")

	require.NoError(t, s.Stop(context.Background()))
}

func TestRunConvergenceDetectsDNADriftOnSecondRun(t *testing.T) {
	// Verify that runConvergence can detect DNA changes between runs.
	// On the same machine, IDs should be stable so comparison runs correctly.
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-drift-steward")

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	ctx := context.Background()

	// First convergence captures initial snapshot.
	steward.RunConvergence(s, ctx)

	firstDNA := steward.GetPreviousDNA(s)
	require.NotNil(t, firstDNA, "first convergence should capture DNA")

	// Second convergence compares against first snapshot.
	// System DNA should be stable on the same machine, so no drift events expected,
	// but the snapshot should be refreshed.
	steward.RunConvergence(s, ctx)

	secondDNA := steward.GetPreviousDNA(s)

	assert.NotNil(t, secondDNA, "second convergence should update DNA snapshot")
	// System IDs must match on the same machine — they are derived from stable hardware.
	assert.Equal(t, firstDNA.Id, secondDNA.Id, "DNA IDs should be stable across runs on same machine")

	require.NoError(t, s.Stop(context.Background()))
}

func TestDetectUnmanagedDNADrift_NilDNACollector(t *testing.T) {
	// When dnaCollector is nil, detectUnmanagedDNADrift should return early without panic.
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-nil-collector-steward")

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)

	// Override with nil collector to test the nil guard.
	steward.SetDNACollector(s, nil)

	ctx := context.Background()
	// Should not panic — nil collector is handled gracefully.
	assert.NotPanics(t, func() {
		_, _ = steward.DetectUnmanagedDNADrift(s, ctx)
	})

	require.NoError(t, s.Stop(context.Background()))
}

func TestDetectUnmanagedDNADrift_NilDriftDetector(t *testing.T) {
	// When driftDetector is nil, detectUnmanagedDNADrift should skip drift detection
	// but still update the DNA snapshot.
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-nil-detector-steward")

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Set a previous snapshot so we reach the driftDetector nil check.
	steward.SetPreviousDNA(s, &commonpb.DNA{
		Id:         "same-id",
		Attributes: map[string]string{"test": "value"},
	})

	// Override drift detector with nil — DNA collector still runs but detection is skipped.
	steward.SetDriftDetector(s, nil)

	ctx := context.Background()
	// Should not panic — nil drift detector is handled gracefully.
	assert.NotPanics(t, func() {
		_, _ = steward.DetectUnmanagedDNADrift(s, ctx)
	})

	require.NoError(t, s.Stop(context.Background()))
}

func TestDetectUnmanagedDNADrift_IDMismatchSkipsComparison(t *testing.T) {
	// When DNA IDs differ between snapshots, drift detection is skipped
	// (e.g., VM migration or container restarts where hardware identity changes).
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-id-mismatch-steward")

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Inject a previous DNA with a different ID than the real system DNA will produce.
	steward.SetPreviousDNA(s, &commonpb.DNA{
		Id:         "different-id-that-will-not-match-real-system",
		Attributes: map[string]string{"fake": "previous"},
	})

	ctx := context.Background()
	// Should not panic — ID mismatch returns ErrDNAIDMismatch rather than panicking.
	assert.NotPanics(t, func() {
		_, _ = steward.DetectUnmanagedDNADrift(s, ctx)
	})

	// Snapshot should be updated to the current (real) DNA despite the mismatch.
	updatedDNA := steward.GetPreviousDNA(s)

	assert.NotNil(t, updatedDNA)
	assert.NotEqual(t, "different-id-that-will-not-match-real-system", updatedDNA.Id,
		"snapshot should be updated to the real system DNA after ID mismatch")

	require.NoError(t, s.Stop(context.Background()))
}
