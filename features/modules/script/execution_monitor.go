// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ExecutionMonitor tracks and monitors script executions across devices
type ExecutionMonitor struct {
	executions map[string]*MonitoredExecution
	mu         sync.RWMutex
	listeners  map[string][]ExecutionListener
}

// MonitoredExecution represents a tracked script execution
type MonitoredExecution struct {
	ID         string            `json:"id"`
	ScriptID   string            `json:"script_id"`
	ScriptName string            `json:"script_name"`
	TenantID   string            `json:"tenant_id"`
	Devices    []DeviceExecution `json:"devices"`
	Status     ExecutionStatus   `json:"status"`
	StartTime  time.Time         `json:"start_time"`
	EndTime    *time.Time        `json:"end_time,omitempty"`
	Summary    *ExecutionSummary `json:"summary"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// DeviceExecution represents execution on a single device
type DeviceExecution struct {
	DeviceID     string           `json:"device_id"`
	DeviceName   string           `json:"device_name"`
	Status       ExecutionStatus  `json:"status"`
	Result       *ExecutionResult `json:"result,omitempty"`
	Stdout       string           `json:"stdout,omitempty"`
	Stderr       string           `json:"stderr,omitempty"`
	StartTime    time.Time        `json:"start_time"`
	EndTime      *time.Time       `json:"end_time,omitempty"`
	EphemeralKey string           `json:"ephemeral_key,omitempty"`
	Error        string           `json:"error,omitempty"`
}

// ExecutionSummary provides aggregate statistics
type ExecutionSummary struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Running   int `json:"running"`
	Failed    int `json:"failed"`
	Timeout   int `json:"timeout"`
	Pending   int `json:"pending"`
	Cancelled int `json:"cancelled"`
}

// ExecutionListener receives execution events
type ExecutionListener interface {
	OnExecutionStart(execution *MonitoredExecution)
	OnExecutionComplete(execution *MonitoredExecution)
	OnDeviceStart(executionID string, device *DeviceExecution)
	OnDeviceComplete(executionID string, device *DeviceExecution)
	OnDeviceError(executionID string, device *DeviceExecution, err error)
}

// NewExecutionMonitor creates a new execution monitor
func NewExecutionMonitor() *ExecutionMonitor {
	return &ExecutionMonitor{
		executions: make(map[string]*MonitoredExecution),
		listeners:  make(map[string][]ExecutionListener),
	}
}

// StartExecution creates and tracks a new execution
func (m *ExecutionMonitor) StartExecution(ctx context.Context, scriptID, scriptName, tenantID string, deviceIDs []string) (*MonitoredExecution, error) {
	executionID := generateScriptExecutionID()

	devices := make([]DeviceExecution, len(deviceIDs))
	for i, deviceID := range deviceIDs {
		devices[i] = DeviceExecution{
			DeviceID:   deviceID,
			DeviceName: deviceID, // Use deviceID as name until directory service integration is available
			Status:     StatusPending,
			StartTime:  time.Now(),
		}
	}

	execution := &MonitoredExecution{
		ID:         executionID,
		ScriptID:   scriptID,
		ScriptName: scriptName,
		TenantID:   tenantID,
		Devices:    devices,
		Status:     StatusRunning,
		StartTime:  time.Now(),
		Summary: &ExecutionSummary{
			Total:   len(deviceIDs),
			Pending: len(deviceIDs),
		},
		Metadata: make(map[string]string),
	}

	m.mu.Lock()
	m.executions[executionID] = execution
	m.mu.Unlock()

	m.notifyExecutionStart(execution)

	return execution, nil
}

// UpdateDeviceStatus updates the status of a device execution
func (m *ExecutionMonitor) UpdateDeviceStatus(executionID, deviceID string, status ExecutionStatus, result *ExecutionResult, err error) error {
	m.mu.Lock()

	execution, exists := m.executions[executionID]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("execution %s not found", executionID)
	}

	// Find device
	deviceIndex := -1
	for i, device := range execution.Devices {
		if device.DeviceID == deviceID {
			deviceIndex = i
			break
		}
	}

	if deviceIndex == -1 {
		m.mu.Unlock()
		return fmt.Errorf("device %s not found in execution %s", deviceID, executionID)
	}

	device := &execution.Devices[deviceIndex]
	oldStatus := device.Status

	// Update device status
	device.Status = status
	if result != nil {
		device.Result = result
		device.Stdout = result.Stdout
		device.Stderr = result.Stderr
	}
	if err != nil {
		device.Error = err.Error()
	}

	// Set end time if completed
	if status == StatusCompleted || status == StatusFailed || status == StatusTimeout || status == StatusCancelled {
		now := time.Now()
		device.EndTime = &now
	}

	// Update summary
	m.updateSummary(execution, oldStatus, status)

	// Determine what notifications are needed while still holding the lock,
	// then release before calling notify methods. The notify methods acquire
	// RLock internally; calling them while holding the write lock would deadlock
	// since sync.RWMutex is not reentrant.
	var execToNotifyComplete *MonitoredExecution
	var deviceToNotifyStart, deviceToNotifyComplete, deviceToNotifyError *DeviceExecution

	if m.isExecutionComplete(execution) {
		now := time.Now()
		execution.EndTime = &now
		execution.Status = m.calculateExecutionStatus(execution)
		execToNotifyComplete = execution
	}
	if status == StatusRunning && oldStatus == StatusPending {
		deviceToNotifyStart = device
	} else if status == StatusCompleted || status == StatusFailed {
		deviceToNotifyComplete = device
	}
	if err != nil {
		deviceToNotifyError = device
	}

	m.mu.Unlock() // Release write lock before calling notify (which acquire RLock)

	if execToNotifyComplete != nil {
		m.notifyExecutionComplete(execToNotifyComplete)
	}
	if deviceToNotifyStart != nil {
		m.notifyDeviceStart(executionID, deviceToNotifyStart)
	}
	if deviceToNotifyComplete != nil {
		m.notifyDeviceComplete(executionID, deviceToNotifyComplete)
	}
	if deviceToNotifyError != nil {
		m.notifyDeviceError(executionID, deviceToNotifyError, err)
	}

	return nil
}

// GetExecution retrieves an execution by ID
func (m *ExecutionMonitor) GetExecution(executionID string) (*MonitoredExecution, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	execution, exists := m.executions[executionID]
	if !exists {
		return nil, fmt.Errorf("execution %s not found", executionID)
	}

	return execution, nil
}

// GetDeviceExecution retrieves a specific device execution
func (m *ExecutionMonitor) GetDeviceExecution(executionID, deviceID string) (*DeviceExecution, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	execution, exists := m.executions[executionID]
	if !exists {
		return nil, fmt.Errorf("execution %s not found", executionID)
	}

	for _, device := range execution.Devices {
		if device.DeviceID == deviceID {
			return &device, nil
		}
	}

	return nil, fmt.Errorf("device %s not found in execution %s", deviceID, executionID)
}

// ListExecutions lists all executions (optionally filtered by tenant)
func (m *ExecutionMonitor) ListExecutions(tenantID string) []*MonitoredExecution {
	m.mu.RLock()
	defer m.mu.RUnlock()

	executions := make([]*MonitoredExecution, 0)
	for _, execution := range m.executions {
		if tenantID == "" || execution.TenantID == tenantID {
			executions = append(executions, execution)
		}
	}

	return executions
}

// StreamDeviceOutput streams stdout/stderr for a specific device in real-time
func (m *ExecutionMonitor) StreamDeviceOutput(ctx context.Context, executionID, deviceID string, callback func(stdout, stderr string)) error {
	// This is a placeholder for real-time streaming
	// In practice, this would connect to a streaming endpoint on the device
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			device, err := m.GetDeviceExecution(executionID, deviceID)
			if err != nil {
				return err
			}

			// Call callback with current output
			callback(device.Stdout, device.Stderr)

			// Stop if device execution is complete
			if device.Status == StatusCompleted || device.Status == StatusFailed ||
				device.Status == StatusTimeout || device.Status == StatusCancelled {
				return nil
			}
		}
	}
}

// AddListener adds an execution listener
func (m *ExecutionMonitor) AddListener(id string, listener ExecutionListener) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[id]; !exists {
		m.listeners[id] = make([]ExecutionListener, 0)
	}
	m.listeners[id] = append(m.listeners[id], listener)
}

// RemoveListener removes an execution listener
func (m *ExecutionMonitor) RemoveListener(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.listeners, id)
}

// CancelExecution cancels an ongoing execution
func (m *ExecutionMonitor) CancelExecution(executionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	execution, exists := m.executions[executionID]
	if !exists {
		return fmt.Errorf("execution %s not found", executionID)
	}

	// Cancel all running/pending devices
	for i := range execution.Devices {
		device := &execution.Devices[i]
		if device.Status == StatusRunning || device.Status == StatusPending {
			device.Status = StatusCancelled
			now := time.Now()
			device.EndTime = &now
		}
	}

	execution.Status = StatusCancelled
	now := time.Now()
	execution.EndTime = &now

	return nil
}

// CleanupOldExecutions removes executions older than the specified duration
func (m *ExecutionMonitor) CleanupOldExecutions(maxAge time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	count := 0

	for id, execution := range m.executions {
		if execution.EndTime != nil && execution.EndTime.Before(cutoff) {
			delete(m.executions, id)
			count++
		}
	}

	return count
}

// Helper methods

func (m *ExecutionMonitor) updateSummary(execution *MonitoredExecution, oldStatus, newStatus ExecutionStatus) {
	summary := execution.Summary

	// Decrement old status count
	switch oldStatus {
	case StatusPending:
		summary.Pending--
	case StatusRunning:
		summary.Running--
	case StatusCompleted:
		summary.Completed--
	case StatusFailed:
		summary.Failed--
	case StatusTimeout:
		summary.Timeout--
	case StatusCancelled:
		summary.Cancelled--
	}

	// Increment new status count
	switch newStatus {
	case StatusPending:
		summary.Pending++
	case StatusRunning:
		summary.Running++
	case StatusCompleted:
		summary.Completed++
	case StatusFailed:
		summary.Failed++
	case StatusTimeout:
		summary.Timeout++
	case StatusCancelled:
		summary.Cancelled++
	}
}

func (m *ExecutionMonitor) isExecutionComplete(execution *MonitoredExecution) bool {
	for _, device := range execution.Devices {
		if device.Status == StatusPending || device.Status == StatusRunning {
			return false
		}
	}
	return true
}

func (m *ExecutionMonitor) calculateExecutionStatus(execution *MonitoredExecution) ExecutionStatus {
	if execution.Summary.Failed > 0 || execution.Summary.Timeout > 0 {
		return StatusFailed
	}
	if execution.Summary.Cancelled > 0 {
		return StatusCancelled
	}
	return StatusCompleted
}

func (m *ExecutionMonitor) notifyExecutionStart(execution *MonitoredExecution) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, listeners := range m.listeners {
		for _, listener := range listeners {
			go listener.OnExecutionStart(execution)
		}
	}
}

func (m *ExecutionMonitor) notifyExecutionComplete(execution *MonitoredExecution) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, listeners := range m.listeners {
		for _, listener := range listeners {
			go listener.OnExecutionComplete(execution)
		}
	}
}

func (m *ExecutionMonitor) notifyDeviceStart(executionID string, device *DeviceExecution) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, listeners := range m.listeners {
		for _, listener := range listeners {
			go listener.OnDeviceStart(executionID, device)
		}
	}
}

func (m *ExecutionMonitor) notifyDeviceComplete(executionID string, device *DeviceExecution) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, listeners := range m.listeners {
		for _, listener := range listeners {
			go listener.OnDeviceComplete(executionID, device)
		}
	}
}

func (m *ExecutionMonitor) notifyDeviceError(executionID string, device *DeviceExecution, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, listeners := range m.listeners {
		for _, listener := range listeners {
			go listener.OnDeviceError(executionID, device, err)
		}
	}
}

// generateScriptExecutionID generates a unique execution ID for script monitoring
func generateScriptExecutionID() string {
	return fmt.Sprintf("script-exec-%d", time.Now().UnixNano())
}
