// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package performance_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/performance"
)

func TestProcessCollector_GetTopProcesses(t *testing.T) {
	collector := performance.NewProcessCollector()

	ctx := context.Background()
	processes, err := collector.GetTopProcesses(ctx, 10)
	require.NoError(t, err)

	// Should have at least some processes
	assert.NotEmpty(t, processes)
	assert.LessOrEqual(t, len(processes), 10)

	// Verify each process has valid data
	for _, proc := range processes {
		assert.Greater(t, proc.PID, int32(0))
		assert.NotEmpty(t, proc.Name)
		assert.GreaterOrEqual(t, proc.CPUPercent, 0.0)
		assert.GreaterOrEqual(t, proc.MemoryBytes, int64(0))
	}
}

func TestProcessCollector_GetProcessByPID(t *testing.T) {
	collector := performance.NewProcessCollector()

	ctx := context.Background()
	// Use current process PID
	pid := int32(os.Getpid())

	proc, err := collector.GetProcessByPID(ctx, pid)
	require.NoError(t, err)
	require.NotNil(t, proc)

	assert.Equal(t, pid, proc.PID)
	assert.NotEmpty(t, proc.Name)
	assert.GreaterOrEqual(t, proc.MemoryBytes, int64(0))
}

func TestProcessCollector_GetWatchlistProcesses(t *testing.T) {
	collector := performance.NewProcessCollector()

	ctx := context.Background()
	// Use common process names that likely exist
	watchlist := []string{"systemd", "init", "launchd", "sshd", "dockerd"}

	processes, err := collector.GetWatchlistProcesses(ctx, watchlist)
	require.NoError(t, err)

	// May be empty if no watchlist processes are running
	for _, proc := range processes {
		assert.True(t, proc.IsWatchlisted)
		assert.NotEmpty(t, proc.Name)
	}
}
