// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noopListener satisfies ExecutionListener for tests that need a listener registered
// but don't assert on specific callback invocations.
type noopListener struct{}

func (noopListener) OnExecutionStart(*MonitoredExecution)          {}
func (noopListener) OnExecutionComplete(*MonitoredExecution)       {}
func (noopListener) OnDeviceStart(string, *DeviceExecution)        {}
func (noopListener) OnDeviceComplete(string, *DeviceExecution)     {}
func (noopListener) OnDeviceError(string, *DeviceExecution, error) {}

// TestUpdateDeviceStatus_NoDeadlockWithListener is a regression test for the deadlock
// that occurred when UpdateDeviceStatus called notify* helpers while holding the write
// lock. The notify* helpers acquire m.mu.RLock() internally; calling them under the
// write lock caused a deadlock in Go's sync.RWMutex.
//
// With a listener registered, UpdateDeviceStatus must complete without hanging.
func TestUpdateDeviceStatus_NoDeadlockWithListener(t *testing.T) {
	monitor := NewExecutionMonitor()
	monitor.AddListener("noop", noopListener{})

	ctx := context.Background()
	execution, err := monitor.StartExecution(ctx, "script-1", "Test Script", "", []string{"device-1"})
	require.NoError(t, err)

	// UpdateDeviceStatus with a terminal status triggers notifyExecutionComplete.
	// If the deadlock is present this call will hang; the test timeout catches it.
	err = monitor.UpdateDeviceStatus(execution.ID, "device-1", StatusCompleted, nil, nil)
	require.NoError(t, err)

	exec, err := monitor.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, exec.Status)
	assert.NotNil(t, exec.EndTime, "EndTime must be set when execution completes")
}

// TestUpdateDeviceStatus_CompletesExecution verifies that updating all devices to a
// terminal status marks the overall execution complete with the correct status.
func TestUpdateDeviceStatus_CompletesExecution(t *testing.T) {
	monitor := NewExecutionMonitor()

	ctx := context.Background()
	execution, err := monitor.StartExecution(ctx, "s1", "S", "", []string{"d1", "d2"})
	require.NoError(t, err)

	require.NoError(t, monitor.UpdateDeviceStatus(execution.ID, "d1", StatusCompleted, nil, nil))

	// Execution is not complete yet — one device still pending.
	exec, err := monitor.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusRunning, exec.Status)

	require.NoError(t, monitor.UpdateDeviceStatus(execution.ID, "d2", StatusCompleted, nil, nil))

	// Both devices done — execution must now be complete.
	exec, err = monitor.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, exec.Status)
	assert.NotNil(t, exec.EndTime)
}

// TestUpdateDeviceStatus_FailedDeviceMarksExecutionFailed verifies that a single failed
// device causes the overall execution to be marked as failed.
func TestUpdateDeviceStatus_FailedDeviceMarksExecutionFailed(t *testing.T) {
	monitor := NewExecutionMonitor()

	ctx := context.Background()
	execution, err := monitor.StartExecution(ctx, "s1", "S", "", []string{"d1"})
	require.NoError(t, err)

	require.NoError(t, monitor.UpdateDeviceStatus(execution.ID, "d1", StatusFailed, nil, nil))

	exec, err := monitor.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusFailed, exec.Status)
}

// TestUpdateDeviceStatus_ConcurrentUpdates verifies that concurrent status updates from
// multiple goroutines do not race or deadlock, and that the final execution state is
// correct after all updates complete.
func TestUpdateDeviceStatus_ConcurrentUpdates(t *testing.T) {
	const deviceCount = 10
	monitor := NewExecutionMonitor()
	monitor.AddListener("noop", noopListener{})

	deviceIDs := make([]string, deviceCount)
	for i := range deviceIDs {
		deviceIDs[i] = "device-" + string(rune('0'+i))
	}

	ctx := context.Background()
	execution, err := monitor.StartExecution(ctx, "s1", "S", "", deviceIDs)
	require.NoError(t, err)

	done := make(chan error, deviceCount)
	for _, id := range deviceIDs {
		id := id
		go func() {
			done <- monitor.UpdateDeviceStatus(execution.ID, id, StatusCompleted, nil, nil)
		}()
	}

	deadline := time.After(5 * time.Second)
	for range deviceIDs {
		select {
		case updateErr := <-done:
			require.NoError(t, updateErr, "concurrent UpdateDeviceStatus must not error")
		case <-deadline:
			t.Fatal("concurrent UpdateDeviceStatus deadlocked or timed out")
		}
	}

	// Verify the final execution state is correct after all concurrent updates.
	exec, err := monitor.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, exec.Status, "execution must be completed after all devices finish")
	require.NotNil(t, exec.Summary)
	assert.Equal(t, deviceCount, exec.Summary.Completed, "all devices must be counted as completed")
	assert.NotNil(t, exec.EndTime, "EndTime must be set when execution completes")
}

// TestUpdateDeviceStatus_UnknownExecutionID verifies that updating a non-existent
// execution returns an error.
func TestUpdateDeviceStatus_UnknownExecutionID(t *testing.T) {
	monitor := NewExecutionMonitor()
	err := monitor.UpdateDeviceStatus("does-not-exist", "device-1", StatusCompleted, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does-not-exist")
}

// TestUpdateDeviceStatus_UnknownDeviceID verifies that updating a device that does not
// belong to the execution returns an error.
func TestUpdateDeviceStatus_UnknownDeviceID(t *testing.T) {
	monitor := NewExecutionMonitor()

	ctx := context.Background()
	execution, err := monitor.StartExecution(ctx, "s1", "S", "", []string{"device-1"})
	require.NoError(t, err)

	err = monitor.UpdateDeviceStatus(execution.ID, "device-999", StatusCompleted, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "device-999")
}
