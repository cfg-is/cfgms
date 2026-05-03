// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package siem

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// SIEMEngine is the main orchestrator for the lightweight SIEM stream processing system.
// It coordinates all components to achieve 10,000+ log entries per second processing
// with <100ms latency for real-time security event detection and workflow automation.
type SIEMEngine struct {
	logger *logging.ModuleLogger

	// Core components
	streamProcessor     StreamProcessor
	patternMatcher      PatternMatcher
	eventCorrelator     EventCorrelator
	ruleManager         RuleManager
	workflowIntegration *WorkflowIntegration

	// Configuration
	config ProcessingConfig

	// State management
	running  int32 // atomic
	stopChan chan struct{}

	// Metrics and monitoring
	metrics     *SIEMMetrics
	metricsLock sync.RWMutex
	startTime   time.Time

	// Memory management
	memoryMonitor *MemoryMonitor
	gcController  *GCController
}

// SIEMMetrics aggregates all SIEM processing metrics
type SIEMMetrics struct {
	// Throughput metrics
	TotalEntriesProcessed    int64
	EntriesProcessedLastHour int64
	EntriesProcessedLastDay  int64
	CurrentThroughput        float64
	PeakThroughput           float64

	// Latency metrics
	AverageLatency float64
	P95Latency     float64
	P99Latency     float64
	MaxLatency     float64

	// Detection metrics
	SecurityEventsGenerated   int64
	CorrelatedEventsGenerated int64
	WorkflowsTriggered        int64
	PatternsMatched           int64

	// Performance metrics
	BufferUtilization float64
	MemoryUsage       int64
	CPUUsage          float64
	GoroutineCount    int
	GCPauseTime       time.Duration

	// Error metrics
	ProcessingErrors     int64
	DroppedEntries       int64
	WorkerTimeouts       int64
	MemoryPressureEvents int64

	// Time tracking
	StartTime      time.Time
	LastUpdateTime time.Time
	Uptime         time.Duration
}

// MemoryMonitor tracks memory usage and prevents OOM
type MemoryMonitor struct {
	maxMemoryBytes    int64
	warningThreshold  float64
	criticalThreshold float64
	lastGC            time.Time
}

// GCController manages garbage collection optimization
type GCController struct {
	targetGCPercent int
	lastAdjustment  time.Time
	adjustmentCount int64
}

// NewSIEMEngine creates a new SIEM processing engine with all components
func NewSIEMEngine(config ProcessingConfig, triggerManager trigger.TriggerManager,
	workflowTrigger trigger.WorkflowTrigger) (*SIEMEngine, error) {

	logger := logging.ForModule("siem.engine").WithField("component", "engine")

	// Set performance-optimized defaults
	if config.BufferSize == 0 {
		config.BufferSize = 100000 // Large buffer for high throughput
	}
	if config.BatchSize == 0 {
		config.BatchSize = 200 // Optimal batch size for processing
	}
	if config.WorkerCount == 0 {
		config.WorkerCount = runtime.NumCPU() * 4 // High parallelism
	}
	if config.MaxLatency == 0 {
		config.MaxLatency = 100 * time.Millisecond
	}
	if config.TargetThroughput == 0 {
		config.TargetThroughput = 12000 // Target above 10k for safety margin
	}

	// Validate configuration after defaults are applied
	if err := validateProcessingConfig(config); err != nil {
		return nil, fmt.Errorf("invalid processing configuration: %w", err)
	}

	// Create core components
	patternMatcher := NewPatternMatcher()
	eventCorrelator := NewEventCorrelator(config.CorrelationWindow)
	ruleManager := NewRuleManager(patternMatcher, eventCorrelator)
	streamProcessor := NewStreamProcessor(config, patternMatcher, eventCorrelator, ruleManager)

	// Create workflow integration
	workflowConfig := WorkflowIntegrationConfig{
		EnableWorkflowTriggers: true,
		DefaultTimeout:         5 * time.Minute,
		MaxConcurrentWorkflows: 50,
		RetryAttempts:          3,
		RetryDelay:             1 * time.Second,
		ThrottleLimit:          200,
		ThrottleWindow:         1 * time.Minute,
	}
	workflowIntegration := NewWorkflowIntegration(triggerManager, workflowTrigger, workflowConfig)

	// Create performance monitoring components
	memoryMonitor := &MemoryMonitor{
		maxMemoryBytes:    config.MaxMemoryUsage,
		warningThreshold:  0.8,
		criticalThreshold: 0.95,
	}

	gcController := &GCController{
		targetGCPercent: 100,
	}

	return &SIEMEngine{
		logger:              logger,
		streamProcessor:     streamProcessor,
		patternMatcher:      patternMatcher,
		eventCorrelator:     eventCorrelator,
		ruleManager:         ruleManager,
		workflowIntegration: workflowIntegration,
		config:              config,
		stopChan:            make(chan struct{}),
		metrics: &SIEMMetrics{
			StartTime: time.Now(),
		},
		memoryMonitor: memoryMonitor,
		gcController:  gcController,
	}, nil
}

// Start initializes and starts the SIEM processing engine
func (se *SIEMEngine) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&se.running, 0, 1) {
		return fmt.Errorf("SIEM engine already running")
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := se.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Starting SIEM processing engine",
		"buffer_size", se.config.BufferSize,
		"batch_size", se.config.BatchSize,
		"worker_count", se.config.WorkerCount,
		"target_throughput", se.config.TargetThroughput,
		"max_latency", se.config.MaxLatency.String())

	se.startTime = time.Now()

	// Start core components
	if err := se.streamProcessor.Start(ctx); err != nil {
		return fmt.Errorf("failed to start stream processor: %w", err)
	}

	if err := se.eventCorrelator.Start(ctx); err != nil {
		return fmt.Errorf("failed to start event correlator: %w", err)
	}

	// Start metrics collection
	if se.config.EnableMetrics {
		go se.metricsCollectionLoop(ctx)
	}

	// Start memory monitoring
	go se.memoryMonitoringLoop(ctx)

	logger.InfoCtx(ctx, "SIEM processing engine started successfully")
	return nil
}

// Stop gracefully stops the SIEM processing engine
func (se *SIEMEngine) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&se.running, 1, 0) {
		return fmt.Errorf("SIEM engine not running")
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := se.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Stopping SIEM processing engine")

	// Signal engine goroutines (metricsCollectionLoop, memoryMonitoringLoop) to exit
	close(se.stopChan)

	// Stop core components — each has its own internal shutdown and timeout
	if se.streamProcessor != nil {
		if err := se.streamProcessor.Stop(ctx); err != nil {
			logger.WarnCtx(ctx, "Failed to stop stream processor", "error", err)
		}
	}
	if se.eventCorrelator != nil {
		if err := se.eventCorrelator.Stop(ctx); err != nil {
			logger.WarnCtx(ctx, "Failed to stop event correlator", "error", err)
		}
	}

	logger.InfoCtx(ctx, "SIEM processing engine stopped gracefully")
	return nil
}

// ProcessLogEntry is the main entry point for log processing.
// It routes entries directly into StreamProcessor.ProcessEntry.
func (se *SIEMEngine) ProcessLogEntry(ctx context.Context, entry interfaces.LogEntry) error {
	if atomic.LoadInt32(&se.running) == 0 {
		return fmt.Errorf("SIEM engine not running")
	}

	atomic.AddInt64(&se.metrics.TotalEntriesProcessed, 1)

	if err := se.streamProcessor.ProcessEntry(ctx, entry); err != nil {
		atomic.AddInt64(&se.metrics.DroppedEntries, 1)
		return err
	}
	return nil
}

// ProcessLogStream processes a continuous stream of log entries
func (se *SIEMEngine) ProcessLogStream(ctx context.Context, entries <-chan interfaces.LogEntry) error {
	if atomic.LoadInt32(&se.running) == 0 {
		return fmt.Errorf("SIEM engine not running")
	}

	return se.streamProcessor.ProcessStream(ctx, entries)
}

// metricsCollectionLoop periodically collects and updates metrics
func (se *SIEMEngine) metricsCollectionLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-se.stopChan:
			return
		case <-ticker.C:
			se.updateMetrics()
		}
	}
}

// memoryMonitoringLoop monitors memory usage and triggers GC when needed
func (se *SIEMEngine) memoryMonitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-se.stopChan:
			return
		case <-ticker.C:
			se.monitorMemoryUsage()
		}
	}
}

// updateMetrics updates comprehensive SIEM metrics
func (se *SIEMEngine) updateMetrics() {
	se.metricsLock.Lock()
	defer se.metricsLock.Unlock()

	now := time.Now()
	se.metrics.LastUpdateTime = now
	se.metrics.Uptime = now.Sub(se.metrics.StartTime)

	// Update system metrics
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	// Safe conversion to prevent integer overflow
	if memStats.Alloc > math.MaxInt64 {
		se.metrics.MemoryUsage = math.MaxInt64
	} else {
		se.metrics.MemoryUsage = int64(memStats.Alloc)
	}
	se.metrics.GoroutineCount = runtime.NumGoroutine()

	// Safe GC pause time conversion
	pauseNs := memStats.PauseNs[(memStats.NumGC+255)%256]
	if pauseNs > math.MaxInt64 {
		se.metrics.GCPauseTime = time.Duration(math.MaxInt64)
	} else {
		se.metrics.GCPauseTime = time.Duration(pauseNs)
	}

	// Calculate throughput. TotalEntriesProcessed is written atomically without
	// the lock, so use atomic.Load to avoid a race with the write lock held here.
	if se.metrics.Uptime > 0 {
		total := atomic.LoadInt64(&se.metrics.TotalEntriesProcessed)
		se.metrics.CurrentThroughput = float64(total) / se.metrics.Uptime.Seconds()
		if se.metrics.CurrentThroughput > se.metrics.PeakThroughput {
			se.metrics.PeakThroughput = se.metrics.CurrentThroughput
		}
	}
}

// monitorMemoryUsage monitors memory usage and triggers optimization
func (se *SIEMEngine) monitorMemoryUsage() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	currentUsage := float64(memStats.Alloc) / float64(se.memoryMonitor.maxMemoryBytes)

	if currentUsage > se.memoryMonitor.criticalThreshold {
		// Critical memory pressure - force GC
		runtime.GC()
		atomic.AddInt64(&se.metrics.MemoryPressureEvents, 1)
		se.memoryMonitor.lastGC = time.Now()
	} else if currentUsage > se.memoryMonitor.warningThreshold {
		// Warning threshold - optimize GC settings
		se.gcController.optimizeGC()
	}
}

// optimizeGC optimizes garbage collection settings
func (gc *GCController) optimizeGC() {
	now := time.Now()
	if now.Sub(gc.lastAdjustment) < 30*time.Second {
		return // Don't adjust too frequently
	}

	// Adaptive GC tuning based on memory pressure
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	if memStats.HeapAlloc > memStats.HeapSys/2 {
		// High heap usage - reduce GC percent
		if gc.targetGCPercent > 50 {
			gc.targetGCPercent -= 10
			debug.SetGCPercent(gc.targetGCPercent)
		}
	} else {
		// Low heap usage - increase GC percent
		if gc.targetGCPercent < 200 {
			gc.targetGCPercent += 10
			debug.SetGCPercent(gc.targetGCPercent)
		}
	}

	gc.lastAdjustment = now
	gc.adjustmentCount++
}

// GetMetrics returns comprehensive SIEM engine metrics.
// Fields written atomically (without the lock) are read with atomic.Load* to
// avoid a data race between the struct-level copy and concurrent atomic writers.
func (se *SIEMEngine) GetMetrics(ctx context.Context) (*SIEMMetrics, error) {
	// Read lock-protected fields (written under metricsLock.Lock()).
	se.metricsLock.RLock()
	snap := SIEMMetrics{
		EntriesProcessedLastHour: se.metrics.EntriesProcessedLastHour,
		EntriesProcessedLastDay:  se.metrics.EntriesProcessedLastDay,
		CurrentThroughput:        se.metrics.CurrentThroughput,
		PeakThroughput:           se.metrics.PeakThroughput,
		AverageLatency:           se.metrics.AverageLatency,
		P95Latency:               se.metrics.P95Latency,
		P99Latency:               se.metrics.P99Latency,
		MaxLatency:               se.metrics.MaxLatency,
		WorkflowsTriggered:       se.metrics.WorkflowsTriggered,
		BufferUtilization:        se.metrics.BufferUtilization,
		MemoryUsage:              se.metrics.MemoryUsage,
		CPUUsage:                 se.metrics.CPUUsage,
		GoroutineCount:           se.metrics.GoroutineCount,
		GCPauseTime:              se.metrics.GCPauseTime,
		WorkerTimeouts:           se.metrics.WorkerTimeouts,
		StartTime:                se.metrics.StartTime,
		LastUpdateTime:           se.metrics.LastUpdateTime,
		Uptime:                   se.metrics.Uptime,
	}
	se.metricsLock.RUnlock()

	// Read atomically-updated fields outside the lock using atomic.Load*.
	snap.TotalEntriesProcessed = atomic.LoadInt64(&se.metrics.TotalEntriesProcessed)
	snap.DroppedEntries = atomic.LoadInt64(&se.metrics.DroppedEntries)
	snap.ProcessingErrors = atomic.LoadInt64(&se.metrics.ProcessingErrors)
	snap.PatternsMatched = atomic.LoadInt64(&se.metrics.PatternsMatched)
	snap.SecurityEventsGenerated = atomic.LoadInt64(&se.metrics.SecurityEventsGenerated)
	snap.CorrelatedEventsGenerated = atomic.LoadInt64(&se.metrics.CorrelatedEventsGenerated)
	snap.MemoryPressureEvents = atomic.LoadInt64(&se.metrics.MemoryPressureEvents)

	return &snap, nil
}

// GetRuleManager returns the rule manager for external configuration
func (se *SIEMEngine) GetRuleManager() RuleManager {
	return se.ruleManager
}

// GetPatternMatcher returns the pattern matcher for external configuration
func (se *SIEMEngine) GetPatternMatcher() PatternMatcher {
	return se.patternMatcher
}

// GetEventCorrelator returns the event correlator for external configuration
func (se *SIEMEngine) GetEventCorrelator() EventCorrelator {
	return se.eventCorrelator
}

// validateProcessingConfig validates the processing configuration
func validateProcessingConfig(config ProcessingConfig) error {
	if config.BufferSize < 1000 {
		return fmt.Errorf("buffer size must be at least 1000")
	}
	if config.BatchSize < 10 {
		return fmt.Errorf("batch size must be at least 10")
	}
	if config.WorkerCount < 1 {
		return fmt.Errorf("worker count must be at least 1")
	}
	if config.TargetThroughput < 1000 {
		return fmt.Errorf("target throughput must be at least 1000")
	}
	return nil
}
