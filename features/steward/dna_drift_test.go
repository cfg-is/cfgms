// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package steward

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
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

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	// DNA collector should be initialized for standalone mode
	assert.NotNil(t, s.dnaCollector, "DNA collector should be initialized in standalone mode")

	require.NoError(t, s.Stop(context.Background()))
}

func TestDriftDetectorInitializedInStandaloneMode(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "drift-detector-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Drift detector should be initialized for standalone mode
	assert.NotNil(t, s.driftDetector, "drift detector should be initialized in standalone mode")

	require.NoError(t, s.Stop(context.Background()))
}

func TestDNASnapshotCapturedAfterConvergence(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-snapshot-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Before Start, no DNA snapshot exists
	s.previousDNAMu.Lock()
	prevDNA := s.previousDNA
	s.previousDNAMu.Unlock()
	assert.Nil(t, prevDNA, "no DNA snapshot before convergence")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start runs an initial convergence synchronously, so when Start returns the
	// DNA snapshot is already captured.
	require.NoError(t, s.Start(ctx))

	s.previousDNAMu.Lock()
	prevDNA = s.previousDNA
	s.previousDNAMu.Unlock()

	assert.NotNil(t, prevDNA, "DNA snapshot should be captured after initial convergence")
	assert.NotEmpty(t, prevDNA.Id, "DNA snapshot should have a non-empty ID")
	assert.NotEmpty(t, prevDNA.Attributes, "DNA snapshot should have attributes")

	require.NoError(t, s.Stop(context.Background()))
}

func TestRunConvergenceCapturesDNASnapshot(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-run-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	ctx := context.Background()

	// Run convergence directly — no Start needed for this unit test
	s.runConvergence(ctx)

	// DNA snapshot should be set
	s.previousDNAMu.Lock()
	prevDNA := s.previousDNA
	s.previousDNAMu.Unlock()

	assert.NotNil(t, prevDNA, "runConvergence should capture a DNA snapshot")

	require.NoError(t, s.Stop(context.Background()))
}

func TestRunConvergenceDetectsDNADriftOnSecondRun(t *testing.T) {
	// Verify that runConvergence can detect DNA changes between runs.
	// On the same machine, IDs should be stable so comparison runs correctly.
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-drift-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	ctx := context.Background()

	// First convergence captures initial snapshot
	s.runConvergence(ctx)

	s.previousDNAMu.Lock()
	firstDNA := s.previousDNA
	s.previousDNAMu.Unlock()

	require.NotNil(t, firstDNA, "first convergence should capture DNA")

	// Second convergence compares against first snapshot.
	// System DNA should be stable on the same machine, so no drift events expected,
	// but the snapshot should be refreshed.
	s.runConvergence(ctx)

	s.previousDNAMu.Lock()
	secondDNA := s.previousDNA
	s.previousDNAMu.Unlock()

	assert.NotNil(t, secondDNA, "second convergence should update DNA snapshot")
	// System IDs must match on the same machine — they are derived from stable hardware
	assert.Equal(t, firstDNA.Id, secondDNA.Id, "DNA IDs should be stable across runs on same machine")

	require.NoError(t, s.Stop(context.Background()))
}

func TestDetectUnmanagedDNADrift_NilDNACollector(t *testing.T) {
	// When dnaCollector is nil, detectUnmanagedDNADrift should return early without panic.
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-nil-collector-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)

	// Override with nil collector to test the nil guard
	s.dnaCollector = nil

	ctx := context.Background()
	// Should not panic — nil collector is handled gracefully
	assert.NotPanics(t, func() {
		s.detectUnmanagedDNADrift(ctx)
	})

	require.NoError(t, s.Stop(context.Background()))
}

func TestDetectUnmanagedDNADrift_NilDriftDetector(t *testing.T) {
	// When driftDetector is nil, detectUnmanagedDNADrift should skip drift detection
	// but still update the DNA snapshot.
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-nil-detector-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Set a previous snapshot so we reach the driftDetector nil check
	s.previousDNAMu.Lock()
	s.previousDNA = &commonpb.DNA{
		Id:         "same-id",
		Attributes: map[string]string{"test": "value"},
	}
	s.previousDNAMu.Unlock()

	// Override drift detector with nil — DNA collector still runs but detection is skipped
	s.driftDetector = nil

	ctx := context.Background()
	// Should not panic — nil drift detector is handled gracefully
	assert.NotPanics(t, func() {
		s.detectUnmanagedDNADrift(ctx)
	})

	require.NoError(t, s.Stop(context.Background()))
}

func TestDetectUnmanagedDNADrift_IDMismatchSkipsComparison(t *testing.T) {
	// When DNA IDs differ between snapshots, drift detection is skipped
	// (e.g., VM migration or container restarts where hardware identity changes).
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForDNA(t, dir, "dna-id-mismatch-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Inject a previous DNA with a different ID than the real system DNA will produce
	s.previousDNAMu.Lock()
	s.previousDNA = &commonpb.DNA{
		Id:         "different-id-that-will-not-match-real-system",
		Attributes: map[string]string{"fake": "previous"},
	}
	s.previousDNAMu.Unlock()

	ctx := context.Background()
	// Should not panic — ID mismatch is handled gracefully, snapshot is updated
	assert.NotPanics(t, func() {
		s.detectUnmanagedDNADrift(ctx)
	})

	// Snapshot should be updated to the current (real) DNA despite the mismatch
	s.previousDNAMu.Lock()
	updatedDNA := s.previousDNA
	s.previousDNAMu.Unlock()

	assert.NotNil(t, updatedDNA)
	assert.NotEqual(t, "different-id-that-will-not-match-real-system", updatedDNA.Id,
		"snapshot should be updated to the real system DNA after ID mismatch")

	require.NoError(t, s.Stop(context.Background()))
}
