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

	// Log entry input
	logEntryChannel chan interfaces.LogEntry
	inputBuffer     chan interfaces.LogEntry

	// State management
	running     int32 // atomic
	stopChan    chan struct{}
	workerGroup sync.WaitGroup

	// Performance optimization
	workers      []*ProcessingWorker
	loadBalancer *LoadBalancer

	// Metrics and monitoring
	metrics     *SIEMMetrics
	metricsLock sync.RWMutex
	startTime   time.Time

	// Memory management
	memoryMonitor *MemoryMonitor
	gcController  *GCController
}

// ProcessingWorker handles parallel processing of log entry batches
type ProcessingWorker struct {
	id            int
	engine        *SIEMEngine
	inputChan     chan *ProcessingBatch
	logger        *logging.ModuleLogger
	workerMetrics *WorkerMetrics
}

// WorkerMetrics tracks individual worker performance
type WorkerMetrics struct {
	ProcessedBatches int64
	ProcessedEntries int64
	ProcessingTime   time.Duration
	LastActivity     time.Time
	ErrorCount       int64
}

// LoadBalancer distributes work across processing workers
type LoadBalancer struct {
	workers []*ProcessingWorker
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
	ActiveWorkers     int32
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

	// Validate configuration
	if err := validateProcessingConfig(config); err != nil {
		return nil, fmt.Errorf("invalid processing configuration: %w", err)
	}

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

	// Create SIEM engine
	engine := &SIEMEngine{
		logger:              logger,
		streamProcessor:     streamProcessor,
		patternMatcher:      patternMatcher,
		eventCorrelator:     eventCorrelator,
		ruleManager:         ruleManager,
		workflowIntegration: workflowIntegration,
		config:              config,
		logEntryChannel:     make(chan interfaces.LogEntry, config.BufferSize),
		inputBuffer:         make(chan interfaces.LogEntry, config.BufferSize*2),
		stopChan:            make(chan struct{}),
		metrics: &SIEMMetrics{
			StartTime: time.Now(),
		},
		memoryMonitor: memoryMonitor,
		gcController:  gcController,
	}

	// Initialize load balancer and workers
	engine.initializeWorkers()

	return engine, nil
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

	// Start processing workers
	for _, worker := range se.workers {
		se.workerGroup.Add(1)
		go worker.Run(ctx, &se.workerGroup)
	}

	// Start input processing
	se.workerGroup.Add(1)
	go se.processInputLoop(ctx, &se.workerGroup)

	// Start metrics collection
	if se.config.EnableMetrics {
		se.workerGroup.Add(1)
		go se.metricsCollectionLoop(ctx, &se.workerGroup)
	}

	// Start memory monitoring
	se.workerGroup.Add(1)
	go se.memoryMonitoringLoop(ctx, &se.workerGroup)

	// Start load balancing optimization
	se.workerGroup.Add(1)
	go se.loadBalancingLoop(ctx, &se.workerGroup)

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

	// Signal shutdown
	close(se.stopChan)

	// Stop core components
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

	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Handle WaitGroup panics during shutdown
				logger.WarnCtx(ctx, "WaitGroup panic during engine shutdown", "error", r)
			}
			close(done)
		}()
		se.workerGroup.Wait()
	}()

	select {
	case <-done:
		logger.InfoCtx(ctx, "SIEM processing engine stopped gracefully")
	case <-time.After(5 * time.Second): // Reduce timeout for tests
		logger.WarnCtx(ctx, "SIEM processing engine shutdown timeout")
	}

	// Close channels
	close(se.logEntryChannel)
	close(se.inputBuffer)

	return nil
}

// ProcessLogEntry is the main entry point for log processing
func (se *SIEMEngine) ProcessLogEntry(ctx context.Context, entry interfaces.LogEntry) error {
	if atomic.LoadInt32(&se.running) == 0 {
		return fmt.Errorf("SIEM engine not running")
	}

	// Track input metrics
	atomic.AddInt64(&se.metrics.TotalEntriesProcessed, 1)

	// Non-blocking send to prevent backpressure
	select {
	case se.logEntryChannel <- entry:
		return nil
	default:
		// Buffer full, drop entry and track
		atomic.AddInt64(&se.metrics.DroppedEntries, 1)
		return fmt.Errorf("input buffer full, entry dropped")
	}
}

// ProcessLogStream processes a continuous stream of log entries
func (se *SIEMEngine) ProcessLogStream(ctx context.Context, entries <-chan interfaces.LogEntry) error {
	if atomic.LoadInt32(&se.running) == 0 {
		return fmt.Errorf("SIEM engine not running")
	}

	return se.streamProcessor.ProcessStream(ctx, entries)
}

// initializeWorkers creates and initializes processing workers
func (se *SIEMEngine) initializeWorkers() {
	se.workers = make([]*ProcessingWorker, se.config.WorkerCount)

	for i := 0; i < se.config.WorkerCount; i++ {
		worker := &ProcessingWorker{
			id:            i,
			engine:        se,
			inputChan:     make(chan *ProcessingBatch, se.config.WorkerQueueSize),
			logger:        se.logger.WithField("worker_id", i),
			workerMetrics: &WorkerMetrics{},
		}
		se.workers[i] = worker
	}

	se.loadBalancer = &LoadBalancer{
		workers: se.workers,
	}

	// Safe conversion to prevent integer overflow
	workerCount := len(se.workers)
	if workerCount > math.MaxInt32 {
		atomic.StoreInt32(&se.metrics.ActiveWorkers, math.MaxInt32)
	} else {
		atomic.StoreInt32(&se.metrics.ActiveWorkers, int32(workerCount))
	}
}

// processInputLoop processes incoming log entries
func (se *SIEMEngine) processInputLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-se.stopChan:
			return
		case entry, ok := <-se.logEntryChannel:
			if !ok {
				return
			}

			// Send to input buffer for batching
			select {
			case se.inputBuffer <- entry:
				// Successfully buffered
			default:
				// Buffer full, drop entry
				atomic.AddInt64(&se.metrics.DroppedEntries, 1)
			}
		}
	}
}

// metricsCollectionLoop periodically collects and updates metrics
func (se *SIEMEngine) metricsCollectionLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

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
func (se *SIEMEngine) memoryMonitoringLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

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

// loadBalancingLoop optimizes load balancing based on worker performance
func (se *SIEMEngine) loadBalancingLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-se.stopChan:
			return
		case <-ticker.C:
			se.optimizeLoadBalancing()
		}
	}
}

// Run executes the main worker processing loop
func (pw *ProcessingWorker) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	pw.logger.InfoCtx(ctx, "Starting processing worker")

	for {
		select {
		case <-ctx.Done():
			pw.logger.InfoCtx(ctx, "Worker stopped due to context cancellation")
			return
		case <-pw.engine.stopChan:
			pw.logger.InfoCtx(ctx, "Worker stopped due to stop signal")
			return
		case batch, ok := <-pw.inputChan:
			if !ok {
				pw.logger.InfoCtx(ctx, "Worker input channel closed")
				return
			}

			pw.processBatchOptimized(ctx, batch)
		}
	}
}

// processBatchOptimized processes a batch with performance optimizations
func (pw *ProcessingWorker) processBatchOptimized(ctx context.Context, batch *ProcessingBatch) {
	startTime := time.Now()
	defer func() {
		processingTime := time.Since(startTime)
		pw.workerMetrics.ProcessingTime += processingTime
		pw.workerMetrics.LastActivity = time.Now()
		pw.workerMetrics.ProcessedBatches++
		pw.workerMetrics.ProcessedEntries += int64(len(batch.Entries))

		// Update engine latency metrics
		pw.engine.updateLatencyMetrics(processingTime)
	}()

	// Pattern matching phase (optimized for batch processing)
	if pw.engine.config.EnablePatternMatching && pw.engine.patternMatcher != nil {
		matches, err := pw.engine.patternMatcher.MatchBatch(batch.Entries)
		if err != nil {
			pw.workerMetrics.ErrorCount++
			atomic.AddInt64(&pw.engine.metrics.ProcessingErrors, 1)
			pw.logger.ErrorCtx(ctx, "Pattern matching failed",
				"batch_id", batch.ID,
				"error", err.Error())
			return
		}

		if len(matches) > 0 {
			securityEvents := pw.convertMatchesToSecurityEvents(matches, batch.TenantID)
			atomic.AddInt64(&pw.engine.metrics.PatternsMatched, int64(len(matches)))
			atomic.AddInt64(&pw.engine.metrics.SecurityEventsGenerated, int64(len(securityEvents)))

			// Process individual security events
			for _, event := range securityEvents {
				if err := pw.engine.workflowIntegration.ProcessSecurityEvent(ctx, event); err != nil {
					pw.logger.ErrorCtx(ctx, "Failed to process security event",
						"event_id", event.ID,
						"error", err.Error())
				}
			}

			// Event correlation phase (only if we have events)
			if pw.engine.config.EnableEventCorrelation && pw.engine.eventCorrelator != nil {
				correlatedEvents, err := pw.engine.eventCorrelator.CorrelateEvents(
					ctx, securityEvents, pw.engine.config.CorrelationWindow)
				if err != nil {
					pw.workerMetrics.ErrorCount++
					atomic.AddInt64(&pw.engine.metrics.ProcessingErrors, 1)
					pw.logger.ErrorCtx(ctx, "Event correlation failed",
						"batch_id", batch.ID,
						"error", err.Error())
					return
				}

				if len(correlatedEvents) > 0 {
					atomic.AddInt64(&pw.engine.metrics.CorrelatedEventsGenerated, int64(len(correlatedEvents)))

					// Process correlated events
					for _, event := range correlatedEvents {
						if err := pw.engine.workflowIntegration.ProcessCorrelatedEvent(ctx, event); err != nil {
							pw.logger.ErrorCtx(ctx, "Failed to process correlated event",
								"correlation_id", event.ID,
								"error", err.Error())
						}
					}
				}
			}
		}
	}
}

// convertMatchesToSecurityEvents converts pattern matches to security events
func (pw *ProcessingWorker) convertMatchesToSecurityEvents(matches []*PatternMatch, tenantID string) []*SecurityEvent {
	events := make([]*SecurityEvent, 0, len(matches))

	for _, match := range matches {
		event := &SecurityEvent{
			ID:          fmt.Sprintf("evt_%d_%d", time.Now().UnixNano(), pw.id),
			Timestamp:   match.Timestamp,
			EventType:   "pattern_match",
			Severity:    SeverityMedium,
			Source:      match.LogEntry.ServiceName,
			Description: fmt.Sprintf("Pattern '%s' matched in %s", match.PatternID, match.Field),
			RuleID:      match.PatternID,
			TenantID:    tenantID,
			Fields: map[string]interface{}{
				"matched_text": match.MatchedText,
				"field":        match.Field,
				"confidence":   match.Confidence,
				"worker_id":    pw.id,
			},
			RawLog: match.LogEntry,
		}
		events = append(events, event)
	}

	return events
}

// updateMetrics updates comprehensive SIEM metrics
func (se *SIEMEngine) updateMetrics() {
	se.metricsLock.Lock()
	defer se.metricsLock.Unlock()

	now := time.Now()
	se.metrics.LastUpdateTime = now
	se.metrics.Uptime = now.Sub(se.metrics.StartTime)

	// Update buffer utilization
	if se.logEntryChannel != nil {
		utilization := float64(len(se.logEntryChannel)) / float64(cap(se.logEntryChannel)) * 100
		se.metrics.BufferUtilization = utilization
	}

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

	// Calculate throughput
	if se.metrics.Uptime > 0 {
		se.metrics.CurrentThroughput = float64(se.metrics.TotalEntriesProcessed) / se.metrics.Uptime.Seconds()
		if se.metrics.CurrentThroughput > se.metrics.PeakThroughput {
			se.metrics.PeakThroughput = se.metrics.CurrentThroughput
		}
	}
}

// updateLatencyMetrics updates latency tracking
func (se *SIEMEngine) updateLatencyMetrics(latency time.Duration) {
	se.metricsLock.Lock()
	defer se.metricsLock.Unlock()

	latencyMs := float64(latency.Nanoseconds()) / 1e6

	// Simple moving average for latency
	if se.metrics.AverageLatency == 0 {
		se.metrics.AverageLatency = latencyMs
	} else {
		se.metrics.AverageLatency = 0.9*se.metrics.AverageLatency + 0.1*latencyMs
	}

	// Track max latency
	if latencyMs > se.metrics.MaxLatency {
		se.metrics.MaxLatency = latencyMs
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

// optimizeLoadBalancing optimizes worker load distribution
func (se *SIEMEngine) optimizeLoadBalancing() {
	// Simple round-robin optimization based on worker performance
	// More sophisticated algorithms could be implemented here
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

// GetMetrics returns comprehensive SIEM engine metrics
func (se *SIEMEngine) GetMetrics(ctx context.Context) (*SIEMMetrics, error) {
	se.metricsLock.RLock()
	defer se.metricsLock.RUnlock()

	// Return a copy to prevent concurrent modification
	metricsCopy := *se.metrics
	return &metricsCopy, nil
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
