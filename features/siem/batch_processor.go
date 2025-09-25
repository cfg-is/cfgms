package siem

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// BatchProcessor handles batching of log entries for efficient processing.
// It aggregates individual log entries into batches based on size and timeout
// to optimize throughput while maintaining low latency.
type BatchProcessor struct {
	logger       *logging.ModuleLogger
	config       ProcessingConfig
	outputChan   chan<- *ProcessingBatch
	inputChan    <-chan interfaces.LogEntry

	// Batching state
	currentBatch *ProcessingBatch
	batchMutex   sync.Mutex
	batchTimer   *time.Timer
	batchCounter int64
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(config ProcessingConfig, outputChan chan<- *ProcessingBatch,
	inputChan <-chan interfaces.LogEntry) *BatchProcessor {

	logger := logging.ForModule("siem.batch_processor").WithField("component", "batcher")

	return &BatchProcessor{
		logger:     logger,
		config:     config,
		outputChan: outputChan,
		inputChan:  inputChan,
	}
}

// Run starts the batch processing loop
func (bp *BatchProcessor) Run(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := bp.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Starting batch processor",
		"batch_size", bp.config.BatchSize,
		"batch_timeout", bp.config.BatchTimeout.String())

	// Initialize first batch
	bp.currentBatch = bp.newBatch(tenantID)

	// Start batch timeout timer
	bp.batchTimer = time.NewTimer(bp.config.BatchTimeout)

	for {
		select {
		case <-ctx.Done():
			logger.InfoCtx(ctx, "Batch processor stopped due to context cancellation")
			bp.flushCurrentBatch(ctx)
			return

		case entry, ok := <-bp.inputChan:
			if !ok {
				logger.InfoCtx(ctx, "Input channel closed, flushing final batch")
				bp.flushCurrentBatch(ctx)
				return
			}

			bp.addEntryToBatch(ctx, entry)

		case <-bp.batchTimer.C:
			logger.DebugCtx(ctx, "Batch timeout reached, flushing batch")
			bp.flushCurrentBatch(ctx)
			bp.resetBatchTimer()
		}
	}
}

// addEntryToBatch adds a log entry to the current batch
func (bp *BatchProcessor) addEntryToBatch(ctx context.Context, entry interfaces.LogEntry) {
	bp.batchMutex.Lock()
	defer bp.batchMutex.Unlock()

	// Ensure tenant consistency within batch
	if bp.currentBatch.TenantID != "" && bp.currentBatch.TenantID != entry.TenantID {
		// Different tenant, flush current batch first
		bp.flushCurrentBatchLocked(ctx)
		bp.currentBatch = bp.newBatch(entry.TenantID)
	}

	// Set tenant ID if this is the first entry
	if bp.currentBatch.TenantID == "" {
		bp.currentBatch.TenantID = entry.TenantID
	}

	// Add entry to current batch
	bp.currentBatch.Entries = append(bp.currentBatch.Entries, entry)

	// Check if batch is full
	if len(bp.currentBatch.Entries) >= bp.config.BatchSize {
		bp.logger.DebugCtx(ctx, "Batch size limit reached, flushing batch",
			"batch_size", len(bp.currentBatch.Entries),
			"batch_id", bp.currentBatch.ID)

		bp.flushCurrentBatchLocked(ctx)
		bp.currentBatch = bp.newBatch(entry.TenantID)
		bp.resetBatchTimer()
	}
}

// flushCurrentBatch flushes the current batch (thread-safe)
func (bp *BatchProcessor) flushCurrentBatch(ctx context.Context) {
	bp.batchMutex.Lock()
	defer bp.batchMutex.Unlock()
	bp.flushCurrentBatchLocked(ctx)
}

// flushCurrentBatchLocked flushes the current batch (must hold batchMutex)
func (bp *BatchProcessor) flushCurrentBatchLocked(ctx context.Context) {
	if bp.currentBatch == nil || len(bp.currentBatch.Entries) == 0 {
		return
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := bp.logger.WithTenant(tenantID)

	logger.DebugCtx(ctx, "Flushing batch",
		"batch_id", bp.currentBatch.ID,
		"entry_count", len(bp.currentBatch.Entries),
		"tenant_id", bp.currentBatch.TenantID)

	// Send batch to output channel (non-blocking)
	select {
	case bp.outputChan <- bp.currentBatch:
		logger.DebugCtx(ctx, "Batch sent successfully", "batch_id", bp.currentBatch.ID)
	default:
		logger.WarnCtx(ctx, "Output channel full, dropping batch",
			"batch_id", bp.currentBatch.ID,
			"entry_count", len(bp.currentBatch.Entries))
	}

	// Clear current batch
	bp.currentBatch = nil
}

// newBatch creates a new processing batch
func (bp *BatchProcessor) newBatch(tenantID string) *ProcessingBatch {
	bp.batchCounter++

	return &ProcessingBatch{
		ID:        fmt.Sprintf("batch_%d_%d", time.Now().UnixNano(), bp.batchCounter),
		Entries:   make([]interfaces.LogEntry, 0, bp.config.BatchSize),
		Timestamp: time.Now(),
		TenantID:  tenantID,
	}
}

// resetBatchTimer resets the batch timeout timer
func (bp *BatchProcessor) resetBatchTimer() {
	if bp.batchTimer != nil {
		bp.batchTimer.Reset(bp.config.BatchTimeout)
	}
}