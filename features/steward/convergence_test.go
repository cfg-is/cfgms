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
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
)

// writeMinimalCfg writes a minimal valid cfg file into dir and returns its path.
func writeMinimalCfg(t *testing.T, dir, id string) string {
	t.Helper()
	cfgData := `steward:
  id: ` + id + `

resources: []
`
	path := filepath.Join(dir, "test.cfg")
	require.NoError(t, os.WriteFile(path, []byte(cfgData), 0644))
	return path
}

// writeMinimalCfgWithInterval writes a cfg with a custom converge_interval.
func writeMinimalCfgWithInterval(t *testing.T, dir, id, interval string) string {
	t.Helper()
	cfgData := `steward:
  id: ` + id + `
  converge_interval: ` + interval + `

resources: []
`
	path := filepath.Join(dir, "test.cfg")
	require.NoError(t, os.WriteFile(path, []byte(cfgData), 0644))
	return path
}

func TestConvergenceLoopStopsOnContextCancel(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeMinimalCfg(t, dir, "loop-test-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	ctx, cancel := context.WithCancel(context.Background())

	// Start is synchronous: it runs initial convergence then launches the loop goroutine.
	require.NoError(t, s.Start(ctx))

	// Cancel context — the convergence loop goroutine checks ctx.Done() and exits.
	cancel()

	// Stop blocks until all goroutines have been signalled; returns immediately here
	// because Stop closes the shutdown channel and the health monitor is already stopping.
	require.NoError(t, s.Stop(context.Background()))
}

func TestConvergenceLoopStopsOnShutdown(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeMinimalCfg(t, dir, "shutdown-test-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	ctx := context.Background()

	// Start is synchronous: runs initial convergence then launches the loop goroutine.
	require.NoError(t, s.Start(ctx))

	// Stop signals the shutdown channel — convergence loop must exit.
	require.NoError(t, s.Stop(context.Background()))
}

func TestConvergeIntervalReadFromCfg(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgWithInterval(t, dir, "interval-test-steward", "5m")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Verify the config was loaded with the correct interval
	assert.Equal(t, "5m", s.standaloneConfig.Steward.ConvergeInterval)

	require.NoError(t, s.Stop(context.Background()))
}

func TestStandaloneRunsInitialConvergenceOnStart(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeMinimalCfg(t, dir, "initial-convergence-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start should complete without error (initial convergence runs synchronously)
	err = s.Start(ctx)
	assert.NoError(t, err)

	cancel()
	require.NoError(t, s.Stop(context.Background()))
}

// TestDetectUnmanagedDNADrift_IDMismatch verifies that detectUnmanagedDNADrift
// returns ErrDNAIDMismatch and a SeverityCritical drift event when the DNA identity
// changes between convergence cycles.
func TestDetectUnmanagedDNADrift_IDMismatch(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeMinimalCfg(t, dir, "dna-mismatch-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)

	// Inject a previousDNA with a sentinel ID that the real DNA collector will not produce.
	// The collector derives IDs from stable hardware identifiers (MAC + hostname), so the
	// real ID will always differ from the sentinel "guaranteed-mismatch-id-xyz".
	s.previousDNAMu.Lock()
	s.previousDNA = &commonpb.DNA{Id: "guaranteed-mismatch-id-xyz"}
	s.previousDNAMu.Unlock()

	ctx := context.Background()
	events, driftErr := s.detectUnmanagedDNADrift(ctx)

	assert.ErrorIs(t, driftErr, ErrDNAIDMismatch)
	require.Len(t, events, 1, "expected exactly one critical drift event on ID mismatch")
	assert.Equal(t, drift.SeverityCritical, events[0].Severity)
	assert.Equal(t, drift.CategoryConfiguration, events[0].Category)
	assert.Contains(t, events[0].Description, "manual reconciliation required")
	require.NoError(t, s.Stop(ctx))
}

// TestDetectUnmanagedDNADrift_SameID verifies that no error is returned when
// DNA IDs match (normal convergence cycle).
func TestDetectUnmanagedDNADrift_SameID(t *testing.T) {
	logger := logging.NewLogger("debug")
	dir := t.TempDir()
	cfgPath := writeMinimalCfg(t, dir, "dna-same-id-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// First call seeds previousDNA — no comparison possible yet.
	events, driftErr := s.detectUnmanagedDNADrift(ctx)
	assert.NoError(t, driftErr)
	assert.Empty(t, events)

	// Second call — same DNA ID, should produce no error.
	events2, driftErr2 := s.detectUnmanagedDNADrift(ctx)
	assert.NoError(t, driftErr2, "same-ID path must not return ErrDNAIDMismatch")
	// events2 may be non-empty if real DNA attributes changed between calls, but
	// none should carry SeverityCritical (that severity is reserved for ID mismatches).
	for _, evt := range events2 {
		assert.NotEqual(t, drift.SeverityCritical, evt.Severity,
			"same-ID path must not emit SeverityCritical events")
	}

	require.NoError(t, s.Stop(ctx))
}
