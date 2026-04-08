// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingListener captures execution events for test assertions.
type recordingListener struct {
	mu              sync.Mutex
	executionStarts []*MonitoredExecution
	execCompletes   []*MonitoredExecution
	deviceCompletes []string
	deviceErrors    []string
}

func (l *recordingListener) OnExecutionStart(e *MonitoredExecution) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.executionStarts = append(l.executionStarts, e)
}

func (l *recordingListener) OnExecutionComplete(e *MonitoredExecution) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.execCompletes = append(l.execCompletes, e)
}

func (l *recordingListener) OnDeviceStart(executionID string, d *DeviceExecution) {}

func (l *recordingListener) OnDeviceComplete(executionID string, d *DeviceExecution) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.deviceCompletes = append(l.deviceCompletes, d.DeviceID)
}

func (l *recordingListener) OnDeviceError(executionID string, d *DeviceExecution, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.deviceErrors = append(l.deviceErrors, d.DeviceID)
}

// TestExecutionMonitor_UpdateDeviceStatus_WithListener is a regression test for
// the deadlock that occurred when UpdateDeviceStatus (holding write lock) called
// notify methods that tried to acquire read lock on the same mutex.
// If the deadlock is reintroduced, this test will hang and timeout under -race.
func TestExecutionMonitor_UpdateDeviceStatus_WithListener(t *testing.T) {
	monitor := NewExecutionMonitor()
	listener := &recordingListener{}
	monitor.AddListener("test", listener)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	execution, err := monitor.StartExecution(ctx, "script-1", "test-script", "tenant-1", []string{"dev-1"})
	require.NoError(t, err)

	// This call previously deadlocked: UpdateDeviceStatus held the write lock
	// and called notifyDeviceComplete, which tried to acquire the read lock.
	err = monitor.UpdateDeviceStatus(execution.ID, "dev-1", StatusCompleted, &ExecutionResult{
		ExitCode: 0,
		Stdout:   "ok",
	}, nil)
	require.NoError(t, err, "UpdateDeviceStatus must not deadlock when listeners are registered")

	// Listener notifications are dispatched in goroutines — wait briefly
	require.Eventually(t, func() bool {
		listener.mu.Lock()
		defer listener.mu.Unlock()
		return len(listener.deviceCompletes) >= 1 && len(listener.execCompletes) >= 1
	}, 2*time.Second, 10*time.Millisecond, "listener must receive device-complete and execution-complete notifications")

	listener.mu.Lock()
	defer listener.mu.Unlock()
	assert.Contains(t, listener.deviceCompletes, "dev-1")
	assert.Equal(t, StatusCompleted, listener.execCompletes[0].Status)
}

// TestExecutionMonitor_UpdateDeviceStatus_ErrorDevice verifies that updating a
// device that was not registered in the execution returns an error.
func TestExecutionMonitor_UpdateDeviceStatus_ErrorDevice(t *testing.T) {
	monitor := NewExecutionMonitor()
	ctx := context.Background()

	execution, err := monitor.StartExecution(ctx, "script-1", "test", "t1", []string{"dev-1"})
	require.NoError(t, err)

	err = monitor.UpdateDeviceStatus(execution.ID, "unknown-dev", StatusCompleted, nil, nil)
	assert.Error(t, err, "updating an unknown device must return an error")
}

// TestExecutionMonitor_UpdateDeviceStatus_ErrorExecution verifies that updating
// a non-existent execution returns an error.
func TestExecutionMonitor_UpdateDeviceStatus_ErrorExecution(t *testing.T) {
	monitor := NewExecutionMonitor()

	err := monitor.UpdateDeviceStatus("no-such-execution", "dev-1", StatusCompleted, nil, nil)
	assert.Error(t, err, "updating a non-existent execution must return an error")
}
