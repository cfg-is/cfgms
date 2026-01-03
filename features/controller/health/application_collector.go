// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package health

import (
	"context"
	"sync"
	"time"
)

// ApplicationQueueStats defines the interface for accessing application queue statistics
// This interface allows the collector to gather metrics from workflow and script execution queues
type ApplicationQueueStats interface {
	// GetWorkflowStats returns workflow queue metrics
	GetWorkflowStats() (queueDepth int64, maxWaitTime float64, activeWorkflows int64)

	// GetScriptStats returns script execution queue metrics
	GetScriptStats() (queueDepth int64, maxWaitTime float64, activeScripts int64)

	// GetConfigQueueDepth returns the configuration push queue depth
	GetConfigQueueDepth() int64
}

// DefaultApplicationCollector implements ApplicationCollector
type DefaultApplicationCollector struct {
	mu         sync.RWMutex
	metrics    *ApplicationMetrics
	queueStats ApplicationQueueStats
}

// NewDefaultApplicationCollector creates a new application metrics collector
func NewDefaultApplicationCollector(queueStats ApplicationQueueStats) *DefaultApplicationCollector {
	return &DefaultApplicationCollector{
		metrics:    &ApplicationMetrics{},
		queueStats: queueStats,
	}
}

// CollectMetrics gathers application-level metrics
func (c *DefaultApplicationCollector) CollectMetrics(ctx context.Context) error {
	timestamp := time.Now()

	// Get workflow metrics
	workflowQueueDepth, workflowMaxWait, activeWorkflows := c.queueStats.GetWorkflowStats()

	// Get script metrics
	scriptQueueDepth, scriptMaxWait, activeScripts := c.queueStats.GetScriptStats()

	// Get config queue depth
	configQueueDepth := c.queueStats.GetConfigQueueDepth()

	// Build metrics
	metrics := &ApplicationMetrics{
		WorkflowQueueDepth:  workflowQueueDepth,
		WorkflowMaxWaitTime: workflowMaxWait,
		ActiveWorkflows:     activeWorkflows,
		ScriptQueueDepth:    scriptQueueDepth,
		ScriptMaxWaitTime:   scriptMaxWait,
		ActiveScripts:       activeScripts,
		ConfigQueueDepth:    configQueueDepth,
		CollectedAt:         timestamp,
	}

	c.mu.Lock()
	c.metrics = metrics
	c.mu.Unlock()

	return nil
}

// GetMetrics returns the current application metrics
func (c *DefaultApplicationCollector) GetMetrics() *ApplicationMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}

// MockApplicationQueueStats implements ApplicationQueueStats for testing
type MockApplicationQueueStats struct {
	WorkflowQueueDepth  int64
	WorkflowMaxWaitTime float64
	ActiveWorkflows     int64
	ScriptQueueDepth    int64
	ScriptMaxWaitTime   float64
	ActiveScripts       int64
	ConfigQueueDepth    int64
}

// GetWorkflowStats returns workflow queue metrics
func (m *MockApplicationQueueStats) GetWorkflowStats() (queueDepth int64, maxWaitTime float64, activeWorkflows int64) {
	return m.WorkflowQueueDepth, m.WorkflowMaxWaitTime, m.ActiveWorkflows
}

// GetScriptStats returns script execution queue metrics
func (m *MockApplicationQueueStats) GetScriptStats() (queueDepth int64, maxWaitTime float64, activeScripts int64) {
	return m.ScriptQueueDepth, m.ScriptMaxWaitTime, m.ActiveScripts
}

// GetConfigQueueDepth returns the configuration push queue depth
func (m *MockApplicationQueueStats) GetConfigQueueDepth() int64 {
	return m.ConfigQueueDepth
}
