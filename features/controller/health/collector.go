// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package health

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
)

// MetricsCollector defines the interface for collecting controller metrics
type MetricsCollector interface {
	// Start begins metric collection with the specified interval
	Start(ctx context.Context, interval time.Duration) error

	// Stop halts metric collection
	Stop() error

	// GetCurrentMetrics returns the most recent metrics snapshot
	GetCurrentMetrics() (*ControllerMetrics, error)

	// GetMetricsHistory returns metrics within the specified time range
	GetMetricsHistory(start, end time.Time) ([]*ControllerMetrics, error)
}

// ComponentCollector defines the interface for component-specific metric collectors
type ComponentCollector interface {
	// CollectMetrics gathers metrics for this component
	CollectMetrics(ctx context.Context) error
}

// MQTTCollector collects MQTT broker metrics
type MQTTCollector interface {
	ComponentCollector
	GetMetrics() *MQTTMetrics
}

// StorageCollector collects storage provider metrics
type StorageCollector interface {
	ComponentCollector
	GetMetrics() *StorageMetrics
}

// ApplicationCollector collects application-level metrics
type ApplicationCollector interface {
	ComponentCollector
	GetMetrics() *ApplicationMetrics
}

// SystemCollector collects system resource metrics
type SystemCollector interface {
	ComponentCollector
	GetMetrics() *SystemMetrics
}

// Collector implements MetricsCollector for comprehensive controller monitoring
type Collector struct {
	mqttCollector        MQTTCollector
	storageCollector     StorageCollector
	applicationCollector ApplicationCollector
	systemCollector      SystemCollector

	// Metrics storage with retention
	mu              sync.RWMutex
	currentMetrics  *ControllerMetrics
	metricsHistory  []*ControllerMetrics
	retentionPeriod time.Duration

	// Collection control
	ctx        context.Context
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup
	started    bool
	startTime  time.Time
}

// NewCollector creates a new metrics collector
func NewCollector(
	mqttCollector MQTTCollector,
	storageCollector StorageCollector,
	applicationCollector ApplicationCollector,
	systemCollector SystemCollector,
) *Collector {
	return &Collector{
		mqttCollector:        mqttCollector,
		storageCollector:     storageCollector,
		applicationCollector: applicationCollector,
		systemCollector:      systemCollector,
		retentionPeriod:      7 * 24 * time.Hour,                   // 7 days
		metricsHistory:       make([]*ControllerMetrics, 0, 20160), // 7 days * 24 hours * 60 minutes * 2 (30-second intervals)
		startTime:            time.Now(),
	}
}

// Start begins metric collection with the specified interval
func (c *Collector) Start(ctx context.Context, interval time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return fmt.Errorf("collector already started")
	}

	c.ctx, c.cancelFunc = context.WithCancel(ctx)
	c.started = true
	c.startTime = time.Now()

	// Start collection goroutine
	c.wg.Add(1)
	go c.collectionLoop(interval)

	return nil
}

// Stop halts metric collection
func (c *Collector) Stop() error {
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
func (c *Collector) GetCurrentMetrics() (*ControllerMetrics, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.currentMetrics == nil {
		return nil, fmt.Errorf("no metrics available")
	}

	return c.currentMetrics, nil
}

// GetMetricsHistory returns metrics within the specified time range
func (c *Collector) GetMetricsHistory(start, end time.Time) ([]*ControllerMetrics, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*ControllerMetrics, 0)
	for _, m := range c.metricsHistory {
		if m.Timestamp.After(start) && m.Timestamp.Before(end) {
			result = append(result, m)
		}
	}

	return result, nil
}

// collectionLoop runs the periodic metric collection
func (c *Collector) collectionLoop(interval time.Duration) {
	defer c.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Collect initial metrics immediately
	if err := c.collectMetrics(); err != nil {
		// Log error but continue
		fmt.Printf("Error collecting initial metrics: %v\n", err)
	}

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.collectMetrics(); err != nil {
				// Log error but continue collection
				fmt.Printf("Error collecting metrics: %v\n", err)
			}
		}
	}
}

// collectMetrics gathers metrics from all collectors
func (c *Collector) collectMetrics() error {
	timestamp := time.Now()

	// Collect from each component in parallel for efficiency
	var wg sync.WaitGroup
	errors := make([]error, 0)
	var errMu sync.Mutex

	collectWithTimeout := func(collector ComponentCollector, name string) {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
		defer cancel()

		if err := collector.CollectMetrics(ctx); err != nil {
			errMu.Lock()
			errors = append(errors, fmt.Errorf("%s collection failed: %w", name, err))
			errMu.Unlock()
		}
	}

	// Start all collections
	wg.Add(4)
	go collectWithTimeout(c.mqttCollector, "MQTT")
	go collectWithTimeout(c.storageCollector, "Storage")
	go collectWithTimeout(c.applicationCollector, "Application")
	go collectWithTimeout(c.systemCollector, "System")

	// Wait for all collections to complete
	wg.Wait()

	// Aggregate metrics
	metrics := &ControllerMetrics{
		Timestamp:   timestamp,
		MQTT:        c.mqttCollector.GetMetrics(),
		Storage:     c.storageCollector.GetMetrics(),
		Application: c.applicationCollector.GetMetrics(),
		System:      c.systemCollector.GetMetrics(),
	}

	// Store metrics
	c.mu.Lock()
	c.currentMetrics = metrics
	c.metricsHistory = append(c.metricsHistory, metrics)

	// Cleanup old metrics beyond retention period
	c.cleanupOldMetrics()
	c.mu.Unlock()

	// Return first error if any
	if len(errors) > 0 {
		return errors[0]
	}

	return nil
}

// cleanupOldMetrics removes metrics older than the retention period
func (c *Collector) cleanupOldMetrics() {
	cutoff := time.Now().Add(-c.retentionPeriod)

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

// DefaultSystemCollector implements SystemCollector using gopsutil
type DefaultSystemCollector struct {
	mu      sync.RWMutex
	metrics *SystemMetrics
	process *process.Process
}

// NewDefaultSystemCollector creates a new system metrics collector
func NewDefaultSystemCollector() (*DefaultSystemCollector, error) {
	proc, err := process.NewProcess(int32(runtime.GOMAXPROCS(0))) // #nosec G115 -- CPU count will never exceed int32 max (2 billion)
	if err != nil {
		// Fall back to self process
		proc = nil
	}

	return &DefaultSystemCollector{
		metrics: &SystemMetrics{},
		process: proc,
	}, nil
}

// CollectMetrics gathers system resource metrics
func (c *DefaultSystemCollector) CollectMetrics(ctx context.Context) error {
	timestamp := time.Now()

	// CPU metrics
	cpuPercent, err := cpu.PercentWithContext(ctx, 0, false)
	if err != nil {
		return fmt.Errorf("failed to get CPU metrics: %w", err)
	}

	// Memory metrics
	vmem, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to get memory metrics: %w", err)
	}

	// Go runtime metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// File descriptor count (Unix-like systems)
	var openFDs int64
	if c.process != nil {
		fds, err := c.process.NumFDs()
		if err == nil {
			openFDs = int64(fds)
		}
	}

	// Build metrics
	metrics := &SystemMetrics{
		CPUPercent:          cpuPercent[0],
		MemoryUsedBytes:     int64(vmem.Used), // #nosec G115 -- Memory size cannot exceed int64 max (8 exabytes)
		MemoryPercent:       vmem.UsedPercent,
		HeapBytes:           int64(memStats.HeapAlloc), // #nosec G115 -- Heap size cannot exceed int64 max (8 exabytes)
		RSSBytes:            int64(memStats.Sys),       // #nosec G115 -- RSS size cannot exceed int64 max (8 exabytes)
		GoroutineCount:      int64(runtime.NumGoroutine()),
		OpenFileDescriptors: openFDs,
		CollectedAt:         timestamp,
	}

	c.mu.Lock()
	c.metrics = metrics
	c.mu.Unlock()

	return nil
}

// GetMetrics returns the current system metrics
func (c *DefaultSystemCollector) GetMetrics() *SystemMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}
