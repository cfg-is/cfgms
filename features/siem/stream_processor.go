package siem

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// StreamProcessorImpl implements the StreamProcessor interface with high-performance
// buffered processing capabilities designed to handle 10,000+ log entries per second
// with <100ms processing latency.
type StreamProcessorImpl struct {
	logger *logging.ModuleLogger
	config ProcessingConfig

	// Processing components
	patternMatcher  PatternMatcher
	eventCorrelator EventCorrelator
	ruleManager     RuleManager

	// Processing pipeline
	inputBuffer      chan interfaces.LogEntry
	processingBuffer chan *ProcessingBatch
	workers          []*StreamWorker
	batchProcessor   *BatchProcessor

	// State management
	running     int32 // atomic
	stopChan    chan struct{}
	workerWg    sync.WaitGroup
	processorWg sync.WaitGroup

	// Metrics tracking
	metrics     *ProcessingMetrics
	metricsLock sync.RWMutex
	startTime   time.Time

	// Performance monitoring
	latencyTracker    *LatencyTracker
	throughputTracker *ThroughputTracker
}

// ProcessingBatch represents a batch of log entries for processing
type ProcessingBatch struct {
	ID        string
	Entries   []interfaces.LogEntry
	Timestamp time.Time
	TenantID  string
}

// StreamWorker handles parallel processing of log entry batches
type StreamWorker struct {
	id              int
	processor       *StreamProcessorImpl
	inputChan       chan *ProcessingBatch
	logger          *logging.ModuleLogger
	processingStats *WorkerStats
}

// WorkerStats tracks individual worker performance
type WorkerStats struct {
	BatchesProcessed int64
	EntriesProcessed int64
	ProcessingTime   time.Duration
	LastActivity     time.Time
	Errors           int64
}

// NewStreamProcessor creates a new high-performance stream processor
func NewStreamProcessor(config ProcessingConfig, patternMatcher PatternMatcher,
	eventCorrelator EventCorrelator, ruleManager RuleManager) *StreamProcessorImpl {

	logger := logging.ForModule("siem.stream_processor").WithField("component", "processor")

	// Set defaults if not configured
	if config.BufferSize == 0 {
		config.BufferSize = 50000 // Large buffer for high throughput
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100 // Optimize for batch processing
	}
	if config.BatchTimeout == 0 {
		config.BatchTimeout = 10 * time.Millisecond // Low latency batching
	}
	if config.WorkerCount == 0 {
		config.WorkerCount = runtime.NumCPU() * 2 // CPU-bound optimization
	}
	if config.WorkerQueueSize == 0 {
		config.WorkerQueueSize = 1000
	}
	if config.MaxLatency == 0 {
		config.MaxLatency = 100 * time.Millisecond // Target latency
	}
	if config.TargetThroughput == 0 {
		config.TargetThroughput = 10000 // 10k entries/second
	}

	return &StreamProcessorImpl{
		logger:          logger,
		config:          config,
		patternMatcher:  patternMatcher,
		eventCorrelator: eventCorrelator,
		ruleManager:     ruleManager,
		stopChan:        make(chan struct{}),
		metrics: &ProcessingMetrics{
			StartTime: time.Now(),
		},
		latencyTracker:    NewLatencyTracker(),
		throughputTracker: NewThroughputTracker(),
	}
}

// Start initializes and starts the stream processing engine
func (sp *StreamProcessorImpl) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&sp.running, 0, 1) {
		return fmt.Errorf("stream processor already running")
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := sp.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Starting SIEM stream processor",
		"buffer_size", sp.config.BufferSize,
		"batch_size", sp.config.BatchSize,
		"worker_count", sp.config.WorkerCount,
		"target_throughput", sp.config.TargetThroughput)

	sp.startTime = time.Now()

	// Initialize buffers
	sp.inputBuffer = make(chan interfaces.LogEntry, sp.config.BufferSize)
	sp.processingBuffer = make(chan *ProcessingBatch, sp.config.WorkerCount*2)

	// Initialize batch processor
	sp.batchProcessor = NewBatchProcessor(sp.config, sp.processingBuffer, sp.inputBuffer)

	// Initialize workers
	sp.workers = make([]*StreamWorker, sp.config.WorkerCount)
	for i := 0; i < sp.config.WorkerCount; i++ {
		sp.workers[i] = &StreamWorker{
			id:              i,
			processor:       sp,
			inputChan:       make(chan *ProcessingBatch, sp.config.WorkerQueueSize),
			logger:          logger.WithField("worker_id", i),
			processingStats: &WorkerStats{},
		}
	}

	// Start batch processor
	sp.processorWg.Add(1)
	go sp.batchProcessor.Run(ctx, &sp.processorWg)

	// Start workers
	for _, worker := range sp.workers {
		sp.workerWg.Add(1)
		go worker.Run(ctx, &sp.workerWg)
	}

	// Start batch distributor
	sp.processorWg.Add(1)
	go sp.distributeBatches(ctx, &sp.processorWg)

	// Start metrics collector if enabled
	if sp.config.EnableMetrics {
		sp.processorWg.Add(1)
		go sp.collectMetrics(ctx, &sp.processorWg)
	}

	logger.InfoCtx(ctx, "SIEM stream processor started successfully")
	return nil
}

// Stop gracefully stops the stream processing engine
func (sp *StreamProcessorImpl) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&sp.running, 1, 0) {
		return fmt.Errorf("stream processor not running")
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := sp.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Stopping SIEM stream processor")

	// Signal shutdown
	close(sp.stopChan)

	// Wait for components to shutdown with timeout
	shutdownComplete := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Handle WaitGroup reuse panics during shutdown
				logger.WarnCtx(ctx, "WaitGroup panic during shutdown", "error", r)
			}
			close(shutdownComplete)
		}()
		sp.processorWg.Wait()
		sp.workerWg.Wait()
	}()

	select {
	case <-shutdownComplete:
		logger.InfoCtx(ctx, "SIEM stream processor stopped gracefully")
	case <-time.After(5 * time.Second): // Reduce timeout for tests
		logger.WarnCtx(ctx, "SIEM stream processor shutdown timeout, forcing stop")
	}

	// Close channels
	if sp.inputBuffer != nil {
		close(sp.inputBuffer)
	}
	if sp.processingBuffer != nil {
		close(sp.processingBuffer)
	}

	return nil
}

// ProcessStream processes a continuous stream of log entries
func (sp *StreamProcessorImpl) ProcessStream(ctx context.Context, entries <-chan interfaces.LogEntry) error {
	if atomic.LoadInt32(&sp.running) == 0 {
		return fmt.Errorf("stream processor not running")
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := sp.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Starting stream processing")

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sp.stopChan:
				return
			case entry, ok := <-entries:
				if !ok {
					logger.InfoCtx(ctx, "Input stream closed")
					return
				}

				// Track input metrics
				atomic.AddInt64(&sp.metrics.EntriesProcessed, 1)

				// Send to input buffer (non-blocking to prevent backpressure)
				select {
				case sp.inputBuffer <- entry:
					// Successfully buffered
				default:
					// Buffer full, drop entry and track
					atomic.AddInt64(&sp.metrics.DroppedEntries, 1)
					logger.WarnCtx(ctx, "Input buffer full, dropping log entry",
						"service_name", entry.ServiceName,
						"level", entry.Level)
				}
			}
		}
	}()

	return nil
}

// distributeBatches distributes processing batches to workers using round-robin
func (sp *StreamProcessorImpl) distributeBatches(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := sp.logger.WithTenant(tenantID)

	workerIndex := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-sp.stopChan:
			return
		case batch, ok := <-sp.processingBuffer:
			if !ok {
				return
			}

			// Distribute to next worker (round-robin)
			worker := sp.workers[workerIndex]
			workerIndex = (workerIndex + 1) % len(sp.workers)

			select {
			case worker.inputChan <- batch:
				// Successfully queued
			default:
				// Worker queue full, track error
				atomic.AddInt64(&sp.metrics.ProcessingErrors, 1)
				logger.WarnCtx(ctx, "Worker queue full, dropping batch",
					"worker_id", worker.id,
					"batch_size", len(batch.Entries))
			}
		}
	}
}

// collectMetrics periodically collects and updates processing metrics
func (sp *StreamProcessorImpl) collectMetrics(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sp.stopChan:
			return
		case <-ticker.C:
			sp.updateMetrics()
		}
	}
}

// updateMetrics updates current processing metrics
func (sp *StreamProcessorImpl) updateMetrics() {
	sp.metricsLock.Lock()
	defer sp.metricsLock.Unlock()

	now := time.Now()

	// Update time metrics
	sp.metrics.Uptime = now.Sub(sp.startTime)
	sp.metrics.LastProcessedTime = now

	// Update throughput metrics
	if sp.throughputTracker != nil {
		sp.metrics.EntriesPerSecond = sp.throughputTracker.GetRate()
	}

	// Update latency metrics
	if sp.latencyTracker != nil {
		sp.metrics.AverageLatency = sp.latencyTracker.GetAverage()
		sp.metrics.P95Latency = sp.latencyTracker.GetPercentile(0.95)
		sp.metrics.P99Latency = sp.latencyTracker.GetPercentile(0.99)
	}

	// Update buffer utilization
	if sp.inputBuffer != nil {
		utilization := float64(len(sp.inputBuffer)) / float64(cap(sp.inputBuffer)) * 100
		sp.metrics.BufferUtilization = utilization
	}

	// Update memory usage with safe conversion
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	if memStats.Alloc > math.MaxInt64 {
		sp.metrics.MemoryUsage = math.MaxInt64
	} else {
		sp.metrics.MemoryUsage = int64(memStats.Alloc)
	}
	sp.metrics.GoroutineCount = runtime.NumGoroutine()
}

// GetMetrics returns current processing metrics
func (sp *StreamProcessorImpl) GetMetrics(ctx context.Context) (*ProcessingMetrics, error) {
	sp.metricsLock.RLock()
	defer sp.metricsLock.RUnlock()

	// Return a copy to prevent concurrent modification
	metricsCopy := *sp.metrics
	return &metricsCopy, nil
}

// Run executes the main worker processing loop
func (w *StreamWorker) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	w.logger.InfoCtx(ctx, "Starting stream worker")

	for {
		select {
		case <-ctx.Done():
			w.logger.InfoCtx(ctx, "Stream worker stopped due to context cancellation")
			return
		case <-w.processor.stopChan:
			w.logger.InfoCtx(ctx, "Stream worker stopped due to stop signal")
			return
		case batch, ok := <-w.inputChan:
			if !ok {
				w.logger.InfoCtx(ctx, "Stream worker input channel closed")
				return
			}

			w.processBatch(ctx, batch)
		}
	}
}

// processBatch processes a single batch of log entries
func (w *StreamWorker) processBatch(ctx context.Context, batch *ProcessingBatch) {
	startTime := time.Now()
	defer func() {
		processingTime := time.Since(startTime)
		w.processingStats.ProcessingTime += processingTime
		w.processingStats.LastActivity = time.Now()
		w.processingStats.BatchesProcessed++
		w.processingStats.EntriesProcessed += int64(len(batch.Entries))

		// Track latency
		if w.processor.latencyTracker != nil {
			w.processor.latencyTracker.Record(processingTime)
		}
	}()

	w.logger.DebugCtx(ctx, "Processing batch",
		"batch_id", batch.ID,
		"entry_count", len(batch.Entries),
		"tenant_id", batch.TenantID)

	// Pattern matching phase
	if w.processor.config.EnablePatternMatching && w.processor.patternMatcher != nil {
		matches, err := w.processor.patternMatcher.MatchBatch(batch.Entries)
		if err != nil {
			w.processingStats.Errors++
			atomic.AddInt64(&w.processor.metrics.ProcessingErrors, 1)
			w.logger.ErrorCtx(ctx, "Pattern matching failed",
				"batch_id", batch.ID,
				"error", err.Error())
			return
		}

		// Convert matches to security events
		securityEvents := w.convertMatchesToEvents(matches, batch.TenantID)
		atomic.AddInt64(&w.processor.metrics.PatternsMatched, int64(len(matches)))
		atomic.AddInt64(&w.processor.metrics.SecurityEventsGenerated, int64(len(securityEvents)))

		// Event correlation phase
		if w.processor.config.EnableEventCorrelation && w.processor.eventCorrelator != nil && len(securityEvents) > 0 {
			correlatedEvents, err := w.processor.eventCorrelator.CorrelateEvents(
				ctx, securityEvents, w.processor.config.CorrelationWindow)
			if err != nil {
				w.processingStats.Errors++
				atomic.AddInt64(&w.processor.metrics.ProcessingErrors, 1)
				w.logger.ErrorCtx(ctx, "Event correlation failed",
					"batch_id", batch.ID,
					"error", err.Error())
				return
			}

			atomic.AddInt64(&w.processor.metrics.EventsCorrelated, int64(len(correlatedEvents)))

			// TODO: Integrate with workflow trigger system for correlated events
			w.processCorrelatedEvents(ctx, correlatedEvents)
		}

		// TODO: Integrate with workflow trigger system for individual events
		w.processSecurityEvents(ctx, securityEvents)
	}
}

// convertMatchesToEvents converts pattern matches to security events
func (w *StreamWorker) convertMatchesToEvents(matches []*PatternMatch, tenantID string) []*SecurityEvent {
	events := make([]*SecurityEvent, 0, len(matches))

	for _, match := range matches {
		event := &SecurityEvent{
			ID:          generateEventID(),
			Timestamp:   match.Timestamp,
			EventType:   "pattern_match",
			Severity:    SeverityMedium, // Default severity, can be configured per pattern
			Source:      match.LogEntry.ServiceName,
			Description: fmt.Sprintf("Pattern '%s' matched in %s", match.PatternID, match.Field),
			RuleID:      match.PatternID,
			TenantID:    tenantID,
			Fields: map[string]interface{}{
				"matched_text": match.MatchedText,
				"field":        match.Field,
				"confidence":   match.Confidence,
			},
			RawLog: match.LogEntry,
		}
		events = append(events, event)
	}

	return events
}

// processSecurityEvents processes individual security events (stub for workflow integration)
func (w *StreamWorker) processSecurityEvents(ctx context.Context, events []*SecurityEvent) {
	// TODO: Implement workflow trigger integration
	for _, event := range events {
		w.logger.DebugCtx(ctx, "Processing security event",
			"event_id", event.ID,
			"event_type", event.EventType,
			"severity", event.Severity,
			"tenant_id", event.TenantID)
	}
}

// processCorrelatedEvents processes correlated events (stub for workflow integration)
func (w *StreamWorker) processCorrelatedEvents(ctx context.Context, events []*CorrelatedEvent) {
	// TODO: Implement workflow trigger integration for correlated events
	for _, event := range events {
		w.logger.InfoCtx(ctx, "Processing correlated event",
			"event_id", event.ID,
			"rule_id", event.RuleID,
			"event_count", len(event.Events),
			"severity", event.Severity,
			"tenant_id", event.TenantID)
	}
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("evt_%d_%d", time.Now().UnixNano(), runtime.NumGoroutine())
}
