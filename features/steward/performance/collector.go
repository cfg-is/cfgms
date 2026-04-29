// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package performance

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// DefaultCollector implements the Collector interface
type DefaultCollector struct {
	stewardID string
	hostname  string

	// Component collectors
	systemCollector  SystemCollector
	processCollector ProcessCollector

	// Configuration
	mu     sync.RWMutex
	config *CollectorConfig

	// Metrics storage
	metricsMu      sync.RWMutex
	currentMetrics *PerformanceMetrics
	metricsHistory []*PerformanceMetrics

	// Control
	ctx        context.Context
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup
	started    bool
}

// NewCollector creates a new performance metrics collector
func NewCollector(stewardID string, config *CollectorConfig) *DefaultCollector {
	if config == nil {
		config = DefaultConfig()
	}

	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create platform-specific system collector
	systemCollector := NewSystemCollector()

	// Create process collector
	processCollector := NewProcessCollector()

	return &DefaultCollector{
		stewardID:        stewardID,
		hostname:         hostname,
		systemCollector:  systemCollector,
		processCollector: processCollector,
		config:           config,
		metricsHistory:   make([]*PerformanceMetrics, 0),
	}
}

// Start begins metric collection with the configured interval
func (c *DefaultCollector) Start(ctx context.Context) error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return fmt.Errorf("collector already started")
	}

	c.ctx, c.cancelFunc = context.WithCancel(ctx)
	c.started = true
	c.wg.Add(1) // increment before unlock so Stop()'s wg.Wait() sees the goroutine
	c.mu.Unlock()

	// Collect initial metrics synchronously to ensure data is available immediately
	if err := c.collectMetrics(); err != nil {
		fmt.Printf("[PERF] Warning: initial metric collection failed: %v\n", err)
	}

	// Start collection goroutine for periodic updates (wg already incremented above)
	go c.collectionLoop()

	return nil
}

// Stop halts metric collection
func (c *DefaultCollector) Stop() error {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return fmt.Errorf("collector not started")
	}

	c.cancelFunc()
	c.started = false
	c.mu.Unlock()

	// Wait for collection goroutine to finish
	c.wg.Wait()

	return nil
}

// GetCurrentMetrics returns the most recent metrics snapshot
func (c *DefaultCollector) GetCurrentMetrics() (*PerformanceMetrics, error) {
	c.metricsMu.RLock()
	defer c.metricsMu.RUnlock()

	if c.currentMetrics == nil {
		return nil, fmt.Errorf("no metrics available")
	}

	return c.currentMetrics, nil
}

// GetMetricsHistory returns metrics within the specified time range
func (c *DefaultCollector) GetMetricsHistory(start, end time.Time) ([]*PerformanceMetrics, error) {
	c.metricsMu.RLock()
	defer c.metricsMu.RUnlock()

	result := make([]*PerformanceMetrics, 0)
	for _, m := range c.metricsHistory {
		if (m.Timestamp.After(start) || m.Timestamp.Equal(start)) &&
			(m.Timestamp.Before(end) || m.Timestamp.Equal(end)) {
			result = append(result, m)
		}
	}

	return result, nil
}

// GetConfig returns the current collector configuration
func (c *DefaultCollector) GetConfig() *CollectorConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy to prevent external modifications
	configCopy := *c.config
	return &configCopy
}

// UpdateConfig updates the collector configuration
func (c *DefaultCollector) UpdateConfig(config *CollectorConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	c.config = config
	return nil
}

// collectionLoop runs the periodic metric collection
func (c *DefaultCollector) collectionLoop() {
	defer c.wg.Done()

	// Get interval from config
	c.mu.RLock()
	interval := c.config.Interval
	c.mu.RUnlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Note: Initial collection is done synchronously in Start()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.collectMetrics(); err != nil {
				// Log error but continue collection
				fmt.Printf("[PERF] Error collecting metrics: %v\n", err)
			}
		}
	}
}

// collectMetrics gathers metrics from all collectors
func (c *DefaultCollector) collectMetrics() error {
	timestamp := time.Now()

	// Create collection context with timeout
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()

	// Collect system metrics
	systemMetrics, err := c.systemCollector.CollectMetrics(ctx)
	if err != nil {
		return fmt.Errorf("system metrics collection failed: %w", err)
	}

	// Get config for top process count and watchlist
	c.mu.RLock()
	topCount := c.config.TopProcessCount
	processWatchlist := c.config.ProcessWatchlist
	c.mu.RUnlock()

	// Collect top processes
	topProcesses, err := c.processCollector.GetTopProcesses(ctx, topCount)
	if err != nil {
		// Log but don't fail - top processes are optional
		fmt.Printf("Warning: failed to collect top processes: %v\n", err)
		topProcesses = []ProcessMetrics{}
	}

	// Collect watchlist processes if configured
	watchlistData := []ProcessMetrics{}
	if len(processWatchlist) > 0 {
		watchlistProcs, err := c.processCollector.GetWatchlistProcesses(ctx, processWatchlist)
		if err != nil {
			// Log but don't fail - watchlist is optional
			fmt.Printf("Warning: failed to collect watchlist processes: %v\n", err)
		} else {
			watchlistData = watchlistProcs
		}
	}

	// Build metrics
	metrics := &PerformanceMetrics{
		StewardID:     c.stewardID,
		Hostname:      c.hostname,
		Timestamp:     timestamp,
		CollectedAt:   timestamp,
		System:        systemMetrics,
		TopProcesses:  topProcesses,
		WatchlistData: watchlistData,
		Online:        true, // If we're collecting, we're online
	}

	// Store metrics
	c.metricsMu.Lock()
	c.currentMetrics = metrics
	c.metricsHistory = append(c.metricsHistory, metrics)

	// Cleanup old metrics
	c.cleanupOldMetrics()
	c.metricsMu.Unlock()

	return nil
}

// cleanupOldMetrics removes metrics older than the retention period
func (c *DefaultCollector) cleanupOldMetrics() {
	c.mu.RLock()
	retentionPeriod := c.config.RetentionPeriod
	c.mu.RUnlock()

	cutoff := time.Now().Add(-retentionPeriod)

	// Find first index to keep
	keepIndex := 0
	for i, m := range c.metricsHistory {
		if m.Timestamp.After(cutoff) {
			keepIndex = i
			break
		}
	}

	// Remove old metrics
	if keepIndex > 0 {
		c.metricsHistory = c.metricsHistory[keepIndex:]
	}
}
