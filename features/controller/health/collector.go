// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package health

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"

	"github.com/cfgis/cfgms/pkg/logging"
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
	transportCollector   TransportCollector
	storageCollector     StorageCollector
	applicationCollector ApplicationCollector
	systemCollector      SystemCollector

	// Metrics storage with retention
	mu              sync.RWMutex
	currentMetrics  *ControllerMetrics
	metricsHistory  []*ControllerMetrics
	retentionPeriod time.Duration

	// Service-level signals and the samplers that refresh them each tick.
	signals  *SignalRegistry
	samplers []func(ctx context.Context)

	// Collection control
	ctx        context.Context
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup
	started    bool
	startTime  time.Time
}

// NewCollector creates a new metrics collector.
// transportCollector may be nil when the transport has not yet started — the
// corresponding Transport section of ControllerMetrics will be nil in that case.
func NewCollector(
	transportCollector TransportCollector,
	storageCollector StorageCollector,
	applicationCollector ApplicationCollector,
	systemCollector SystemCollector,
) *Collector {
	return &Collector{
		transportCollector:   transportCollector,
		storageCollector:     storageCollector,
		applicationCollector: applicationCollector,
		systemCollector:      systemCollector,
		retentionPeriod:      7 * 24 * time.Hour,                   // 7 days
		metricsHistory:       make([]*ControllerMetrics, 0, 20160), // 7 days * 24 hours * 60 minutes * 2 (30-second intervals)
		startTime:            time.Now(),
		signals:              NewSignalRegistry(),
	}
}

// Signals returns the registry of service-level signals exposed alongside the
// collector's own metrics on the Prometheus endpoint.
func (c *Collector) Signals() *SignalRegistry {
	return c.signals
}

// RegisterSampler adds a function that runs on every collection tick, including
// the initial collection at Start, to refresh signals that are read rather than
// pushed (queue depths, pool sizes). The context is cancelled when the collector
// stops, and Stop waits for running samplers. A nil sampler is ignored and a
// panicking sampler is recovered so it cannot end collection.
func (c *Collector) RegisterSampler(sampler func(ctx context.Context)) {
	if sampler == nil {
		return
	}
	c.mu.Lock()
	c.samplers = append(c.samplers, sampler)
	c.mu.Unlock()
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

	// Start collections for non-nil collectors
	if c.transportCollector != nil {
		wg.Add(1)
		go collectWithTimeout(c.transportCollector, "Transport")
	}
	if c.storageCollector != nil {
		wg.Add(1)
		go collectWithTimeout(c.storageCollector, "Storage")
	}
	if c.applicationCollector != nil {
		wg.Add(1)
		go collectWithTimeout(c.applicationCollector, "Application")
	}
	if c.systemCollector != nil {
		wg.Add(1)
		go collectWithTimeout(c.systemCollector, "System")
	}

	// Samplers run beside the component collectors.
	c.startSamplers(&wg)

	// Wait for all collections to complete
	wg.Wait()

	metrics := c.snapshot(timestamp)

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

// snapshot aggregates the component collectors' latest values. A nil collector
// produces a nil metric section.
func (c *Collector) snapshot(timestamp time.Time) *ControllerMetrics {
	metrics := &ControllerMetrics{
		Timestamp: timestamp,
	}
	if c.transportCollector != nil {
		metrics.Transport = c.transportCollector.GetMetrics()
	}
	if c.storageCollector != nil {
		metrics.Storage = c.storageCollector.GetMetrics()
	}
	if c.applicationCollector != nil {
		metrics.Application = c.applicationCollector.GetMetrics()
	}
	if c.systemCollector != nil {
		metrics.System = c.systemCollector.GetMetrics()
	}
	return metrics
}

// startSamplers launches every registered sampler into wg, each under the same
// timeout as a component collector.
func (c *Collector) startSamplers(wg *sync.WaitGroup) {
	c.mu.RLock()
	samplers := slices.Clone(c.samplers)
	c.mu.RUnlock()
	for _, sampler := range samplers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runSampler(sampler)
		}()
	}
}

// runSampler runs one sampler, recovering a panic so it cannot end collection.
func (c *Collector) runSampler(sampler func(ctx context.Context)) {
	defer func() {
		if r := recover(); r != nil {
			logging.ForModule("controller.health").Error("Signal sampler panicked",
				"panic", logging.SanitizeLogValue(fmt.Sprint(r)))
		}
	}()
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	sampler(ctx)
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

	// readCPU is the CPU sample source; a seam so tests can return an empty sample.
	readCPU func(ctx context.Context) ([]float64, error)
	// logger reports the one-time CPU-unavailable warning.
	logger      logging.Logger
	cpuWarnOnce sync.Once
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
		readCPU: func(ctx context.Context) ([]float64, error) {
			return cpu.PercentWithContext(ctx, 0, false)
		},
		logger: logging.ForModule("controller.health"),
	}, nil
}

// CollectMetrics gathers system resource metrics
func (c *DefaultSystemCollector) CollectMetrics(ctx context.Context) error {
	timestamp := time.Now()

	// CPU metrics
	cpuPercent, err := c.readCPU(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CPU metrics: %w", err)
	}
	// A host whose /proc/stat yields no CPU line returns an empty sample with a
	// nil error. Report CPU as 0 and keep memory/runtime metrics instead of
	// failing the whole collection every tick.
	cpuPercentValue, err := firstCPUPercent(cpuPercent)
	if err != nil {
		cpuPercentValue = 0
		c.cpuWarnOnce.Do(func() {
			c.logger.Warn("CPU metric unavailable: host returned no CPU samples; reporting CPU percent as 0")
		})
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
		CPUPercent:          cpuPercentValue,
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

func firstCPUPercent(samples []float64) (float64, error) {
	if len(samples) == 0 {
		return 0, fmt.Errorf("failed to get CPU metrics: no CPU samples returned")
	}

	return samples[0], nil
}

// GetMetrics returns the current system metrics
func (c *DefaultSystemCollector) GetMetrics() *SystemMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}
