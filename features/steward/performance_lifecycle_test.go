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

	"github.com/cfgis/cfgms/pkg/logging"
)

// writeMinimalCfgForPerf writes a minimal valid cfg file for performance tests.
func writeMinimalCfgForPerf(t *testing.T, dir, id string) string {
	t.Helper()
	cfgData := `steward:
  id: ` + id + `

resources: []
`
	path := filepath.Join(dir, "perf-test.cfg")
	require.NoError(t, os.WriteFile(path, []byte(cfgData), 0644))
	return path
}

func TestPerformanceCollectorStartsWithStandalone(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForPerf(t, dir, "perf-standalone-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Performance collector should be initialized at construction time
	assert.NotNil(t, s.performanceCollector, "performance collector should be initialized")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = s.Start(ctx)
	require.NoError(t, err)

	// performanceCollector.Start() collects initial metrics synchronously before
	// returning, so metrics are available immediately after s.Start() returns.
	metrics, err := s.GetPerformanceMetrics()
	assert.NoError(t, err)
	assert.NotNil(t, metrics, "performance metrics should be available after start")

	require.NoError(t, s.Stop(context.Background()))
}

func TestPerformanceCollectorStopsWithSteward(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForPerf(t, dir, "perf-stop-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, s.Start(ctx))

	// Stop should not return an error even with collector running
	err = s.Stop(context.Background())
	assert.NoError(t, err, "stopping steward with performance collector should succeed")
}

func TestPerformanceCollectorInitializedBeforeStart(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForPerf(t, dir, "perf-init-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	// Collector is initialized at construction time, not Start time
	assert.NotNil(t, s.performanceCollector)

	// Before start, metrics are not yet available — Start() has not been called
	// so the collector's background goroutine and initial sync collection have
	// not run yet.
	metrics, err := s.GetPerformanceMetrics()
	assert.Error(t, err, "metrics should not be available before Start")
	assert.Nil(t, metrics)

	require.NoError(t, s.Stop(context.Background()))
}

func TestGetPerformanceMetricsReturnsErrorBeforeStart(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfgForPerf(t, dir, "perf-before-start-steward")

	s, err := NewStandalone(cfgPath, logger)
	require.NoError(t, err)

	// GetPerformanceMetrics before Start should return an error because
	// the collector has not run its initial synchronous collection yet.
	metrics, err := s.GetPerformanceMetrics()
	assert.Error(t, err)
	assert.Nil(t, metrics)

	require.NoError(t, s.Stop(context.Background()))
}
