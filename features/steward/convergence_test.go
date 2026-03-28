// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package steward

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	// Start the steward (launches the convergence loop internally)
	startErr := make(chan error, 1)
	go func() {
		startErr <- s.Start(ctx)
	}()

	// Allow the loop to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context — convergence loop must stop
	cancel()

	// Give the loop goroutine time to exit
	time.Sleep(100 * time.Millisecond)

	// Stop the steward
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

	go func() {
		_ = s.Start(ctx)
	}()

	time.Sleep(100 * time.Millisecond)

	// Stop signals shutdown channel — convergence loop must exit
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

	_ = s.Stop(context.Background())
}

func TestStandaloneRunsInitialConvergenceOnStart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode — Start() invokes DNA collection which takes 6+ minutes on Windows via WMI")
	}
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
	_ = s.Stop(context.Background())
}
