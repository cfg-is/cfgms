// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package interfaces - Bulk Operations with Batching and Rate Limiting
//
// This file implements bulk operations support with intelligent batching, rate limiting,
// and error handling for directory providers. It enables efficient processing of large
// datasets while respecting provider limits and maintaining reliability.

package interfaces

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// BulkOperationManager manages bulk operations with batching and rate limiting
type BulkOperationManager interface {
	// Bulk User Operations
	BulkCreateUsers(ctx context.Context, users []*DirectoryUser, options *BulkOptions) (*BulkResult, error)
	BulkUpdateUsers(ctx context.Context, updates []*UserUpdate, options *BulkOptions) (*BulkResult, error)
	BulkDeleteUsers(ctx context.Context, userIDs []string, options *BulkOptions) (*BulkResult, error)

	// Bulk Group Operations
	BulkCreateGroups(ctx context.Context, groups []*DirectoryGroup, options *BulkOptions) (*BulkResult, error)
	BulkUpdateGroups(ctx context.Context, updates []*GroupUpdate, options *BulkOptions) (*BulkResult, error)
	BulkDeleteGroups(ctx context.Context, groupIDs []string, options *BulkOptions) (*BulkResult, error)

	// Bulk Membership Operations
	BulkAddUsersToGroups(ctx context.Context, memberships []*GroupMembership, options *BulkOptions) (*BulkResult, error)
	BulkRemoveUsersFromGroups(ctx context.Context, memberships []*GroupMembership, options *BulkOptions) (*BulkResult, error)

	// Operation Management
	GetOperationStatus(operationID string) (*BulkOperationStatus, error)
	CancelOperation(operationID string) error

	// Configuration
	SetRateLimit(requests int, window time.Duration)
	SetBatchSize(batchSize int)
	GetCapabilities() *BulkCapabilities
}

// DefaultBulkOperationManager implements bulk operations with advanced features
type DefaultBulkOperationManager struct {
	provider         DirectoryProvider
	rateLimiter      *RateLimiter
	batchProcessor   *BatchProcessor
	operationTracker *OperationTracker
	config           BulkConfig
	mutex            sync.RWMutex
}

// BulkConfig contains configuration for bulk operations
type BulkConfig struct {
	// Batching
	DefaultBatchSize int `json:"default_batch_size"` // Default items per batch
	MaxBatchSize     int `json:"max_batch_size"`     // Maximum items per batch
	MinBatchSize     int `json:"min_batch_size"`     // Minimum items per batch

	// Concurrency
	MaxConcurrentBatches int `json:"max_concurrent_batches"` // Maximum concurrent batches
	WorkerPoolSize       int `json:"worker_pool_size"`       // Number of worker goroutines

	// Rate Limiting
	RequestsPerSecond int `json:"requests_per_second"` // Max requests per second
	RequestsPerMinute int `json:"requests_per_minute"` // Max requests per minute
	RequestsPerHour   int `json:"requests_per_hour"`   // Max requests per hour
	BurstSize         int `json:"burst_size"`          // Burst request allowance

	// Error Handling
	MaxRetries         int           `json:"max_retries"`          // Max retry attempts
	RetryDelay         time.Duration `json:"retry_delay"`          // Initial retry delay
	RetryBackoffFactor float64       `json:"retry_backoff_factor"` // Exponential backoff factor
	MaxRetryDelay      time.Duration `json:"max_retry_delay"`      // Maximum retry delay

	// Timeouts
	OperationTimeout time.Duration `json:"operation_timeout"` // Overall operation timeout
	BatchTimeout     time.Duration `json:"batch_timeout"`     // Individual batch timeout

	// Progress and Monitoring
	ProgressReporting bool          `json:"progress_reporting"` // Enable progress reporting
	ProgressInterval  time.Duration `json:"progress_interval"`  // Progress reporting interval
	DetailedLogging   bool          `json:"detailed_logging"`   // Enable detailed logging
}

// GroupUpdate represents an update to a group for bulk operations
type GroupUpdate struct {
	GroupID string          `json:"group_id"`
	Updates *DirectoryGroup `json:"updates"`
}

// GroupMembership represents a group membership operation
type GroupMembership struct {
	UserID  string `json:"user_id"`
	GroupID string `json:"group_id"`
}

// BulkOperationStatus represents the status of a bulk operation
type BulkOperationStatus struct {
	OperationID            string                 `json:"operation_id"`
	Status                 OperationStatus        `json:"status"`
	StartTime              time.Time              `json:"start_time"`
	EndTime                *time.Time             `json:"end_time,omitempty"`
	TotalItems             int                    `json:"total_items"`
	ProcessedItems         int                    `json:"processed_items"`
	SuccessCount           int                    `json:"success_count"`
	ErrorCount             int                    `json:"error_count"`
	Progress               float64                `json:"progress"` // 0-100
	EstimatedTimeRemaining *time.Duration         `json:"estimated_time_remaining,omitempty"`
	CurrentBatch           int                    `json:"current_batch"`
	TotalBatches           int                    `json:"total_batches"`
	Errors                 []BulkItemError        `json:"errors,omitempty"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
	Cancelable             bool                   `json:"cancelable"`
}

// OperationStatus represents the status of a bulk operation
type OperationStatus string

const (
	OperationStatusPending   OperationStatus = "pending"
	OperationStatusRunning   OperationStatus = "running"
	OperationStatusCompleted OperationStatus = "completed"
	OperationStatusFailed    OperationStatus = "failed"
	OperationStatusCancelled OperationStatus = "cancelled"
	OperationStatusPartial   OperationStatus = "partial" // Some items succeeded, some failed
)

// BulkCapabilities describes the bulk operation capabilities of a provider
type BulkCapabilities struct {
	MaxBatchSize         int                   `json:"max_batch_size"`
	MaxConcurrentBatches int                   `json:"max_concurrent_batches"`
	SupportedOperations  []string              `json:"supported_operations"`
	RateLimits           map[string]*RateLimit `json:"rate_limits"`
	RequiresOrdering     bool                  `json:"requires_ordering"`     // Operations must be processed in order
	SupportsTransactions bool                  `json:"supports_transactions"` // Provider supports transactional operations
	SupportsCancellation bool                  `json:"supports_cancellation"` // Operations can be cancelled
}

// RateLimit defines rate limiting parameters
type RateLimit struct {
	Requests int           `json:"requests"`
	Window   time.Duration `json:"window"`
	Burst    int           `json:"burst,omitempty"`
}

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	tokens    chan struct{}
	ticker    *time.Ticker
	rate      int
	window    time.Duration
	burstSize int
	mutex     sync.Mutex
	closed    bool
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requests int, window time.Duration, burstSize int) *RateLimiter {
	if burstSize <= 0 {
		burstSize = requests
	}

	limiter := &RateLimiter{
		tokens:    make(chan struct{}, burstSize),
		rate:      requests,
		window:    window,
		burstSize: burstSize,
	}

	// Fill initial tokens
tokenFill:
	for i := 0; i < burstSize; i++ {
		select {
		case limiter.tokens <- struct{}{}:
		default:
			break tokenFill
		}
	}

	// Start token replenishment
	limiter.ticker = time.NewTicker(window / time.Duration(requests))
	go limiter.replenishTokens()

	return limiter
}

// Wait waits for permission to make a request
func (r *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-r.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryAcquire tries to acquire a token without blocking
func (r *RateLimiter) TryAcquire() bool {
	select {
	case <-r.tokens:
		return true
	default:
		return false
	}
}

// replenishTokens replenishes tokens at the configured rate
func (r *RateLimiter) replenishTokens() {
	for range r.ticker.C {
		r.mutex.Lock()
		if r.closed {
			r.mutex.Unlock()
			return
		}
		r.mutex.Unlock()

		select {
		case r.tokens <- struct{}{}:
		default:
			// Token bucket is full
		}
	}
}

// Close stops the rate limiter
func (r *RateLimiter) Close() {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.closed {
		r.closed = true
		r.ticker.Stop()
		close(r.tokens)
	}
}

// BatchProcessor handles batch processing with concurrency control
type BatchProcessor struct {
	maxConcurrentBatches int
	workerPool           chan struct{}
	batchQueue           chan *BatchJob
	results              chan *BatchResult
	ctx                  context.Context
	cancel               context.CancelFunc
	wg                   sync.WaitGroup
}

// BatchJob represents a batch processing job
type BatchJob struct {
	ID        string
	Items     []interface{}
	Processor func(ctx context.Context, items []interface{}) (*BatchResult, error)
	Options   *BulkOptions
}

// BatchResult represents the result of processing a batch
type BatchResult struct {
	BatchID        string           `json:"batch_id"`
	Success        bool             `json:"success"`
	ProcessedCount int              `json:"processed_count"`
	SuccessCount   int              `json:"success_count"`
	ErrorCount     int              `json:"error_count"`
	Duration       time.Duration    `json:"duration"`
	Errors         []BulkItemError  `json:"errors,omitempty"`
	Results        []BulkItemResult `json:"results,omitempty"`
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(maxConcurrentBatches int, workerPoolSize int) *BatchProcessor {
	ctx, cancel := context.WithCancel(context.Background())

	processor := &BatchProcessor{
		maxConcurrentBatches: maxConcurrentBatches,
		workerPool:           make(chan struct{}, workerPoolSize),
		batchQueue:           make(chan *BatchJob, maxConcurrentBatches*2),
		results:              make(chan *BatchResult, maxConcurrentBatches*2),
		ctx:                  ctx,
		cancel:               cancel,
	}

	// Start workers
	for i := 0; i < workerPoolSize; i++ {
		go processor.worker()
	}

	return processor
}

// ProcessBatch submits a batch for processing
func (p *BatchProcessor) ProcessBatch(job *BatchJob) error {
	select {
	case p.batchQueue <- job:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

// GetResult retrieves a batch result
func (p *BatchProcessor) GetResult(ctx context.Context) (*BatchResult, error) {
	select {
	case result := <-p.results:
		return result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// worker processes batches from the queue
func (p *BatchProcessor) worker() {
	p.wg.Add(1)
	defer p.wg.Done()

	for {
		select {
		case job := <-p.batchQueue:
			p.processBatch(job)
		case <-p.ctx.Done():
			return
		}
	}
}

// processBatch processes a single batch
func (p *BatchProcessor) processBatch(job *BatchJob) {
	// Acquire worker slot
	select {
	case p.workerPool <- struct{}{}:
		defer func() { <-p.workerPool }()
	case <-p.ctx.Done():
		return
	}

	startTime := time.Now()

	// Create batch context with timeout
	batchCtx := p.ctx
	if job.Options != nil && job.Options.BatchTimeout > 0 {
		var cancel context.CancelFunc
		batchCtx, cancel = context.WithTimeout(p.ctx, job.Options.BatchTimeout)
		defer cancel()
	}

	// Process the batch
	result, err := job.Processor(batchCtx, job.Items)
	if err != nil {
		result = &BatchResult{
			BatchID:        job.ID,
			Success:        false,
			ProcessedCount: 0,
			SuccessCount:   0,
			ErrorCount:     len(job.Items),
			Duration:       time.Since(startTime),
			Errors: []BulkItemError{{
				ItemIndex: -1,
				Error:     err.Error(),
			}},
		}
	} else {
		result.BatchID = job.ID
		result.Duration = time.Since(startTime)
	}

	// Send result
	select {
	case p.results <- result:
	case <-p.ctx.Done():
		return
	}
}

// Close stops the batch processor
func (p *BatchProcessor) Close() {
	p.cancel()
	close(p.batchQueue)
	p.wg.Wait()
	close(p.results)
}

// OperationTracker tracks the status of bulk operations
type OperationTracker struct {
	operations map[string]*BulkOperationStatus
	mutex      sync.RWMutex
}

// NewOperationTracker creates a new operation tracker
func NewOperationTracker() *OperationTracker {
	return &OperationTracker{
		operations: make(map[string]*BulkOperationStatus),
	}
}

// StartOperation starts tracking a new operation
func (t *OperationTracker) StartOperation(operationID string, totalItems int) *BulkOperationStatus {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	status := &BulkOperationStatus{
		OperationID:    operationID,
		Status:         OperationStatusRunning,
		StartTime:      time.Now(),
		TotalItems:     totalItems,
		ProcessedItems: 0,
		SuccessCount:   0,
		ErrorCount:     0,
		Progress:       0.0,
		CurrentBatch:   0,
		Cancelable:     true,
		Metadata:       make(map[string]interface{}),
	}

	t.operations[operationID] = status
	return status
}

// UpdateOperation updates the status of an operation
func (t *OperationTracker) UpdateOperation(operationID string, updates func(*BulkOperationStatus)) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if status, exists := t.operations[operationID]; exists {
		updates(status)

		// Update progress
		if status.TotalItems > 0 {
			status.Progress = float64(status.ProcessedItems) / float64(status.TotalItems) * 100
		}

		// Estimate remaining time
		if status.ProcessedItems > 0 && status.Progress > 0 && status.Progress < 100 {
			elapsed := time.Since(status.StartTime)
			totalEstimated := time.Duration(float64(elapsed) / (status.Progress / 100))
			remaining := totalEstimated - elapsed
			status.EstimatedTimeRemaining = &remaining
		}
	}
}

// CompleteOperation marks an operation as completed
func (t *OperationTracker) CompleteOperation(operationID string, finalStatus OperationStatus) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if status, exists := t.operations[operationID]; exists {
		status.Status = finalStatus
		now := time.Now()
		status.EndTime = &now
		status.Progress = 100.0
		status.Cancelable = false
	}
}

// GetOperation retrieves operation status
func (t *OperationTracker) GetOperation(operationID string) (*BulkOperationStatus, error) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	if status, exists := t.operations[operationID]; exists {
		// Return a copy to prevent race conditions
		statusCopy := *status
		statusCopy.Errors = append([]BulkItemError(nil), status.Errors...)
		return &statusCopy, nil
	}

	return nil, fmt.Errorf("operation not found: %s", operationID)
}

// CancelOperation attempts to cancel an operation
func (t *OperationTracker) CancelOperation(operationID string) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	status, exists := t.operations[operationID]
	if !exists {
		return fmt.Errorf("operation not found: %s", operationID)
	}

	if !status.Cancelable {
		return fmt.Errorf("operation cannot be cancelled")
	}

	if status.Status == OperationStatusRunning {
		status.Status = OperationStatusCancelled
		now := time.Now()
		status.EndTime = &now
		status.Cancelable = false
		return nil
	}

	return fmt.Errorf("operation is not running")
}

// NewDefaultBulkOperationManager creates a new bulk operation manager
func NewDefaultBulkOperationManager(provider DirectoryProvider, config BulkConfig) *DefaultBulkOperationManager {
	// Set defaults
	if config.DefaultBatchSize <= 0 {
		config.DefaultBatchSize = 100
	}
	if config.MaxBatchSize <= 0 {
		config.MaxBatchSize = 1000
	}
	if config.MinBatchSize <= 0 {
		config.MinBatchSize = 1
	}
	if config.MaxConcurrentBatches <= 0 {
		config.MaxConcurrentBatches = 5
	}
	if config.WorkerPoolSize <= 0 {
		config.WorkerPoolSize = 10
	}
	if config.RequestsPerSecond <= 0 {
		config.RequestsPerSecond = 10
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = time.Second
	}
	if config.RetryBackoffFactor <= 0 {
		config.RetryBackoffFactor = 2.0
	}
	if config.MaxRetryDelay <= 0 {
		config.MaxRetryDelay = 60 * time.Second
	}
	if config.OperationTimeout <= 0 {
		config.OperationTimeout = 30 * time.Minute
	}
	if config.BatchTimeout <= 0 {
		config.BatchTimeout = 5 * time.Minute
	}
	if config.ProgressInterval <= 0 {
		config.ProgressInterval = 30 * time.Second
	}

	manager := &DefaultBulkOperationManager{
		provider:         provider,
		config:           config,
		operationTracker: NewOperationTracker(),
	}

	// Initialize rate limiter
	manager.rateLimiter = NewRateLimiter(
		config.RequestsPerSecond,
		time.Second,
		config.BurstSize,
	)

	// Initialize batch processor
	manager.batchProcessor = NewBatchProcessor(
		config.MaxConcurrentBatches,
		config.WorkerPoolSize,
	)

	return manager
}

// BulkCreateUsers creates multiple users in batches
func (m *DefaultBulkOperationManager) BulkCreateUsers(ctx context.Context, users []*DirectoryUser, options *BulkOptions) (*BulkResult, error) {
	return m.executeBulkOperation(ctx, "create_users", users, options, func(ctx context.Context, batch []interface{}) (*BatchResult, error) {
		userBatch := make([]*DirectoryUser, len(batch))
		for i, item := range batch {
			userBatch[i] = item.(*DirectoryUser)
		}

		return m.processBatchCreateUsers(ctx, userBatch, options)
	})
}

// BulkUpdateUsers updates multiple users in batches
func (m *DefaultBulkOperationManager) BulkUpdateUsers(ctx context.Context, updates []*UserUpdate, options *BulkOptions) (*BulkResult, error) {
	return m.executeBulkOperation(ctx, "update_users", updates, options, func(ctx context.Context, batch []interface{}) (*BatchResult, error) {
		updateBatch := make([]*UserUpdate, len(batch))
		for i, item := range batch {
			updateBatch[i] = item.(*UserUpdate)
		}

		return m.processBatchUpdateUsers(ctx, updateBatch, options)
	})
}

// BulkDeleteUsers deletes multiple users in batches
func (m *DefaultBulkOperationManager) BulkDeleteUsers(ctx context.Context, userIDs []string, options *BulkOptions) (*BulkResult, error) {
	return m.executeBulkOperation(ctx, "delete_users", userIDs, options, func(ctx context.Context, batch []interface{}) (*BatchResult, error) {
		idBatch := make([]string, len(batch))
		for i, item := range batch {
			idBatch[i] = item.(string)
		}

		return m.processBatchDeleteUsers(ctx, idBatch, options)
	})
}

// BulkCreateGroups creates multiple groups in batches
func (m *DefaultBulkOperationManager) BulkCreateGroups(ctx context.Context, groups []*DirectoryGroup, options *BulkOptions) (*BulkResult, error) {
	return m.executeBulkOperation(ctx, "create_groups", groups, options, func(ctx context.Context, batch []interface{}) (*BatchResult, error) {
		groupBatch := make([]*DirectoryGroup, len(batch))
		for i, item := range batch {
			groupBatch[i] = item.(*DirectoryGroup)
		}

		return m.processBatchCreateGroups(ctx, groupBatch, options)
	})
}

// BulkUpdateGroups updates multiple groups in batches
func (m *DefaultBulkOperationManager) BulkUpdateGroups(ctx context.Context, updates []*GroupUpdate, options *BulkOptions) (*BulkResult, error) {
	return m.executeBulkOperation(ctx, "update_groups", updates, options, func(ctx context.Context, batch []interface{}) (*BatchResult, error) {
		updateBatch := make([]*GroupUpdate, len(batch))
		for i, item := range batch {
			updateBatch[i] = item.(*GroupUpdate)
		}

		return m.processBatchUpdateGroups(ctx, updateBatch, options)
	})
}

// BulkDeleteGroups deletes multiple groups in batches
func (m *DefaultBulkOperationManager) BulkDeleteGroups(ctx context.Context, groupIDs []string, options *BulkOptions) (*BulkResult, error) {
	return m.executeBulkOperation(ctx, "delete_groups", groupIDs, options, func(ctx context.Context, batch []interface{}) (*BatchResult, error) {
		idBatch := make([]string, len(batch))
		for i, item := range batch {
			idBatch[i] = item.(string)
		}

		return m.processBatchDeleteGroups(ctx, idBatch, options)
	})
}

// BulkAddUsersToGroups adds users to groups in batches
func (m *DefaultBulkOperationManager) BulkAddUsersToGroups(ctx context.Context, memberships []*GroupMembership, options *BulkOptions) (*BulkResult, error) {
	return m.executeBulkOperation(ctx, "add_memberships", memberships, options, func(ctx context.Context, batch []interface{}) (*BatchResult, error) {
		membershipBatch := make([]*GroupMembership, len(batch))
		for i, item := range batch {
			membershipBatch[i] = item.(*GroupMembership)
		}

		return m.processBatchAddMemberships(ctx, membershipBatch, options)
	})
}

// BulkRemoveUsersFromGroups removes users from groups in batches
func (m *DefaultBulkOperationManager) BulkRemoveUsersFromGroups(ctx context.Context, memberships []*GroupMembership, options *BulkOptions) (*BulkResult, error) {
	return m.executeBulkOperation(ctx, "remove_memberships", memberships, options, func(ctx context.Context, batch []interface{}) (*BatchResult, error) {
		membershipBatch := make([]*GroupMembership, len(batch))
		for i, item := range batch {
			membershipBatch[i] = item.(*GroupMembership)
		}

		return m.processBatchRemoveMemberships(ctx, membershipBatch, options)
	})
}

// executeBulkOperation executes a generic bulk operation with batching and monitoring
func (m *DefaultBulkOperationManager) executeBulkOperation(
	ctx context.Context,
	operationType string,
	items interface{},
	options *BulkOptions,
	processor func(ctx context.Context, batch []interface{}) (*BatchResult, error),
) (*BulkResult, error) {
	startTime := time.Now()

	// Convert items to []interface{}
	itemSlice, err := m.convertToInterfaceSlice(items)
	if err != nil {
		return nil, fmt.Errorf("failed to convert items: %w", err)
	}

	totalItems := len(itemSlice)
	if totalItems == 0 {
		return &BulkResult{
			TotalItems:   0,
			SuccessCount: 0,
			ErrorCount:   0,
			Duration:     time.Since(startTime),
		}, nil
	}

	// Apply options defaults
	if options == nil {
		options = &BulkOptions{
			BatchSize:       m.config.DefaultBatchSize,
			ContinueOnError: true,
			RetryAttempts:   m.config.MaxRetries,
			RetryDelay:      m.config.RetryDelay,
		}
	}

	// Ensure batch size is within limits
	batchSize := options.BatchSize
	if batchSize <= 0 {
		batchSize = m.config.DefaultBatchSize
	}
	if batchSize > m.config.MaxBatchSize {
		batchSize = m.config.MaxBatchSize
	}
	if batchSize < m.config.MinBatchSize {
		batchSize = m.config.MinBatchSize
	}

	// Create operation ID and start tracking
	operationID := fmt.Sprintf("%s_%d", operationType, time.Now().UnixNano())
	status := m.operationTracker.StartOperation(operationID, totalItems)

	// Create operation context
	opCtx := ctx
	if m.config.OperationTimeout > 0 {
		var cancel context.CancelFunc
		opCtx, cancel = context.WithTimeout(ctx, m.config.OperationTimeout)
		defer cancel()
	}

	// Create batches
	batches := m.createBatches(itemSlice, batchSize)
	status.TotalBatches = len(batches)

	// Process batches
	result := &BulkResult{
		TotalItems:   totalItems,
		SuccessCount: 0,
		ErrorCount:   0,
		Duration:     0,
		ItemResults:  make([]BulkItemResult, 0, totalItems),
	}

	var wg sync.WaitGroup
	resultsChan := make(chan *BatchResult, len(batches))
	semaphore := make(chan struct{}, options.ConcurrentBatch)

	for i, batch := range batches {
		// Check if operation was cancelled
		if status.Status == OperationStatusCancelled {
			break
		}

		wg.Add(1)
		go func(batchNum int, batchItems []interface{}) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-opCtx.Done():
				return
			}

			// Rate limiting
			if err := m.rateLimiter.Wait(opCtx); err != nil {
				if err != context.Canceled {
					resultsChan <- &BatchResult{
						BatchID:        fmt.Sprintf("batch_%d", batchNum),
						Success:        false,
						ProcessedCount: 0,
						ErrorCount:     len(batchItems),
						Errors: []BulkItemError{{
							ItemIndex: -1,
							Error:     fmt.Sprintf("rate limit error: %v", err),
						}},
					}
				}
				return
			}

			// Process batch with retries
			batchResult := m.processBatchWithRetry(opCtx, batchItems, processor, options)
			batchResult.BatchID = fmt.Sprintf("batch_%d", batchNum)

			resultsChan <- batchResult

			// Update operation status
			m.operationTracker.UpdateOperation(operationID, func(status *BulkOperationStatus) {
				status.CurrentBatch = batchNum + 1
				status.ProcessedItems += batchResult.ProcessedCount
				status.SuccessCount += batchResult.SuccessCount
				status.ErrorCount += batchResult.ErrorCount
				status.Errors = append(status.Errors, batchResult.Errors...)
			})
		}(i, batch)
	}

	// Wait for all batches to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for batchResult := range resultsChan {
		result.SuccessCount += batchResult.SuccessCount
		result.ErrorCount += batchResult.ErrorCount
		result.Errors = append(result.Errors, batchResult.Errors...)
		result.ItemResults = append(result.ItemResults, batchResult.Results...)
	}

	result.Duration = time.Since(startTime)

	// Determine final status
	finalStatus := OperationStatusCompleted
	if result.ErrorCount > 0 {
		if result.SuccessCount > 0 {
			finalStatus = OperationStatusPartial
		} else {
			finalStatus = OperationStatusFailed
		}
	}

	// Complete operation tracking
	m.operationTracker.CompleteOperation(operationID, finalStatus)

	return result, nil
}

// convertToInterfaceSlice converts various slice types to []interface{}
func (m *DefaultBulkOperationManager) convertToInterfaceSlice(items interface{}) ([]interface{}, error) {
	switch v := items.(type) {
	case []*DirectoryUser:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = item
		}
		return result, nil
	case []*UserUpdate:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = item
		}
		return result, nil
	case []string:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = item
		}
		return result, nil
	case []*DirectoryGroup:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = item
		}
		return result, nil
	case []*GroupUpdate:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = item
		}
		return result, nil
	case []*GroupMembership:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = item
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported items type: %T", items)
	}
}

// createBatches splits items into batches of the specified size
func (m *DefaultBulkOperationManager) createBatches(items []interface{}, batchSize int) [][]interface{} {
	var batches [][]interface{}

	for i := 0; i < len(items); i += batchSize {
		end := i + batchSize
		if end > len(items) {
			end = len(items)
		}

		batch := make([]interface{}, end-i)
		copy(batch, items[i:end])
		batches = append(batches, batch)
	}

	return batches
}

// processBatchWithRetry processes a batch with retry logic
func (m *DefaultBulkOperationManager) processBatchWithRetry(
	ctx context.Context,
	batch []interface{},
	processor func(context.Context, []interface{}) (*BatchResult, error),
	options *BulkOptions,
) *BatchResult {
	var lastResult *BatchResult
	var lastErr error

	retryDelay := options.RetryDelay
	maxDelay := m.config.MaxRetryDelay
	backoffFactor := m.config.RetryBackoffFactor

	for attempt := 0; attempt <= options.RetryAttempts; attempt++ {
		if attempt > 0 {
			// Apply exponential backoff
			if retryDelay > maxDelay {
				retryDelay = maxDelay
			}

			select {
			case <-time.After(retryDelay):
			case <-ctx.Done():
				return &BatchResult{
					Success:        false,
					ProcessedCount: len(batch),
					ErrorCount:     len(batch),
					Errors: []BulkItemError{{
						ItemIndex: -1,
						Error:     "context cancelled during retry",
					}},
				}
			}

			retryDelay = time.Duration(float64(retryDelay) * backoffFactor)
		}

		result, err := processor(ctx, batch)
		if err == nil {
			return result
		}

		lastResult = result
		lastErr = err

		// Don't retry if context was cancelled
		if ctx.Err() != nil {
			break
		}

		// Don't retry if explicitly requested not to continue on error
		if !options.ContinueOnError {
			break
		}
	}

	// All retries failed
	if lastResult != nil {
		return lastResult
	}

	return &BatchResult{
		Success:        false,
		ProcessedCount: len(batch),
		ErrorCount:     len(batch),
		Errors: []BulkItemError{{
			ItemIndex: -1,
			Error:     fmt.Sprintf("batch failed after %d attempts: %v", options.RetryAttempts+1, lastErr),
		}},
	}
}

// Batch processing implementations for specific operations

// processBatchCreateUsers processes a batch of user creation operations
func (m *DefaultBulkOperationManager) processBatchCreateUsers(ctx context.Context, users []*DirectoryUser, options *BulkOptions) (*BatchResult, error) {
	result := &BatchResult{
		ProcessedCount: len(users),
		Results:        make([]BulkItemResult, 0, len(users)),
	}

	for i, user := range users {
		createdUser, err := m.provider.CreateUser(ctx, user)
		if err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, BulkItemError{
				ItemIndex: i,
				ItemID:    user.UserPrincipalName,
				Error:     err.Error(),
			})
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    user.UserPrincipalName,
				Success:   false,
				Error:     err.Error(),
			})
		} else {
			result.SuccessCount++
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    user.UserPrincipalName,
				Success:   true,
				Data:      createdUser,
			})
		}
	}

	result.Success = result.ErrorCount == 0
	return result, nil
}

// processBatchUpdateUsers processes a batch of user update operations
func (m *DefaultBulkOperationManager) processBatchUpdateUsers(ctx context.Context, updates []*UserUpdate, options *BulkOptions) (*BatchResult, error) {
	result := &BatchResult{
		ProcessedCount: len(updates),
		Results:        make([]BulkItemResult, 0, len(updates)),
	}

	for i, update := range updates {
		updatedUser, err := m.provider.UpdateUser(ctx, update.UserID, update.Updates)
		if err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, BulkItemError{
				ItemIndex: i,
				ItemID:    update.UserID,
				Error:     err.Error(),
			})
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    update.UserID,
				Success:   false,
				Error:     err.Error(),
			})
		} else {
			result.SuccessCount++
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    update.UserID,
				Success:   true,
				Data:      updatedUser,
			})
		}
	}

	result.Success = result.ErrorCount == 0
	return result, nil
}

// processBatchDeleteUsers processes a batch of user deletion operations
func (m *DefaultBulkOperationManager) processBatchDeleteUsers(ctx context.Context, userIDs []string, options *BulkOptions) (*BatchResult, error) {
	result := &BatchResult{
		ProcessedCount: len(userIDs),
		Results:        make([]BulkItemResult, 0, len(userIDs)),
	}

	for i, userID := range userIDs {
		err := m.provider.DeleteUser(ctx, userID)
		if err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, BulkItemError{
				ItemIndex: i,
				ItemID:    userID,
				Error:     err.Error(),
			})
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    userID,
				Success:   false,
				Error:     err.Error(),
			})
		} else {
			result.SuccessCount++
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    userID,
				Success:   true,
			})
		}
	}

	result.Success = result.ErrorCount == 0
	return result, nil
}

// processBatchCreateGroups processes a batch of group creation operations
func (m *DefaultBulkOperationManager) processBatchCreateGroups(ctx context.Context, groups []*DirectoryGroup, options *BulkOptions) (*BatchResult, error) {
	result := &BatchResult{
		ProcessedCount: len(groups),
		Results:        make([]BulkItemResult, 0, len(groups)),
	}

	for i, group := range groups {
		createdGroup, err := m.provider.CreateGroup(ctx, group)
		if err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, BulkItemError{
				ItemIndex: i,
				ItemID:    group.Name,
				Error:     err.Error(),
			})
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    group.Name,
				Success:   false,
				Error:     err.Error(),
			})
		} else {
			result.SuccessCount++
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    group.Name,
				Success:   true,
				Data:      createdGroup,
			})
		}
	}

	result.Success = result.ErrorCount == 0
	return result, nil
}

// processBatchUpdateGroups processes a batch of group update operations
func (m *DefaultBulkOperationManager) processBatchUpdateGroups(ctx context.Context, updates []*GroupUpdate, options *BulkOptions) (*BatchResult, error) {
	result := &BatchResult{
		ProcessedCount: len(updates),
		Results:        make([]BulkItemResult, 0, len(updates)),
	}

	for i, update := range updates {
		updatedGroup, err := m.provider.UpdateGroup(ctx, update.GroupID, update.Updates)
		if err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, BulkItemError{
				ItemIndex: i,
				ItemID:    update.GroupID,
				Error:     err.Error(),
			})
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    update.GroupID,
				Success:   false,
				Error:     err.Error(),
			})
		} else {
			result.SuccessCount++
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    update.GroupID,
				Success:   true,
				Data:      updatedGroup,
			})
		}
	}

	result.Success = result.ErrorCount == 0
	return result, nil
}

// processBatchDeleteGroups processes a batch of group deletion operations
func (m *DefaultBulkOperationManager) processBatchDeleteGroups(ctx context.Context, groupIDs []string, options *BulkOptions) (*BatchResult, error) {
	result := &BatchResult{
		ProcessedCount: len(groupIDs),
		Results:        make([]BulkItemResult, 0, len(groupIDs)),
	}

	for i, groupID := range groupIDs {
		err := m.provider.DeleteGroup(ctx, groupID)
		if err != nil {
			result.ErrorCount++
			result.Errors = append(result.Errors, BulkItemError{
				ItemIndex: i,
				ItemID:    groupID,
				Error:     err.Error(),
			})
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    groupID,
				Success:   false,
				Error:     err.Error(),
			})
		} else {
			result.SuccessCount++
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    groupID,
				Success:   true,
			})
		}
	}

	result.Success = result.ErrorCount == 0
	return result, nil
}

// processBatchAddMemberships processes a batch of group membership additions
func (m *DefaultBulkOperationManager) processBatchAddMemberships(ctx context.Context, memberships []*GroupMembership, options *BulkOptions) (*BatchResult, error) {
	result := &BatchResult{
		ProcessedCount: len(memberships),
		Results:        make([]BulkItemResult, 0, len(memberships)),
	}

	for i, membership := range memberships {
		err := m.provider.AddUserToGroup(ctx, membership.UserID, membership.GroupID)
		if err != nil {
			result.ErrorCount++
			membershipID := fmt.Sprintf("%s:%s", membership.UserID, membership.GroupID)
			result.Errors = append(result.Errors, BulkItemError{
				ItemIndex: i,
				ItemID:    membershipID,
				Error:     err.Error(),
			})
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    membershipID,
				Success:   false,
				Error:     err.Error(),
			})
		} else {
			result.SuccessCount++
			membershipID := fmt.Sprintf("%s:%s", membership.UserID, membership.GroupID)
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    membershipID,
				Success:   true,
			})
		}
	}

	result.Success = result.ErrorCount == 0
	return result, nil
}

// processBatchRemoveMemberships processes a batch of group membership removals
func (m *DefaultBulkOperationManager) processBatchRemoveMemberships(ctx context.Context, memberships []*GroupMembership, options *BulkOptions) (*BatchResult, error) {
	result := &BatchResult{
		ProcessedCount: len(memberships),
		Results:        make([]BulkItemResult, 0, len(memberships)),
	}

	for i, membership := range memberships {
		err := m.provider.RemoveUserFromGroup(ctx, membership.UserID, membership.GroupID)
		if err != nil {
			result.ErrorCount++
			membershipID := fmt.Sprintf("%s:%s", membership.UserID, membership.GroupID)
			result.Errors = append(result.Errors, BulkItemError{
				ItemIndex: i,
				ItemID:    membershipID,
				Error:     err.Error(),
			})
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    membershipID,
				Success:   false,
				Error:     err.Error(),
			})
		} else {
			result.SuccessCount++
			membershipID := fmt.Sprintf("%s:%s", membership.UserID, membership.GroupID)
			result.Results = append(result.Results, BulkItemResult{
				ItemIndex: i,
				ItemID:    membershipID,
				Success:   true,
			})
		}
	}

	result.Success = result.ErrorCount == 0
	return result, nil
}

// GetOperationStatus retrieves the status of a bulk operation
func (m *DefaultBulkOperationManager) GetOperationStatus(operationID string) (*BulkOperationStatus, error) {
	return m.operationTracker.GetOperation(operationID)
}

// CancelOperation attempts to cancel a bulk operation
func (m *DefaultBulkOperationManager) CancelOperation(operationID string) error {
	return m.operationTracker.CancelOperation(operationID)
}

// SetRateLimit updates the rate limiting configuration
func (m *DefaultBulkOperationManager) SetRateLimit(requests int, window time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Close existing rate limiter
	if m.rateLimiter != nil {
		m.rateLimiter.Close()
	}

	// Create new rate limiter
	m.rateLimiter = NewRateLimiter(requests, window, m.config.BurstSize)

	// Update config
	switch window {
	case time.Second:
		m.config.RequestsPerSecond = requests
	case time.Minute:
		m.config.RequestsPerMinute = requests
	case time.Hour:
		m.config.RequestsPerHour = requests
	}
}

// SetBatchSize updates the default batch size
func (m *DefaultBulkOperationManager) SetBatchSize(batchSize int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if batchSize > 0 && batchSize <= m.config.MaxBatchSize {
		m.config.DefaultBatchSize = batchSize
	}
}

// GetCapabilities returns the bulk operation capabilities
func (m *DefaultBulkOperationManager) GetCapabilities() *BulkCapabilities {
	providerCaps := m.provider.GetCapabilities()

	return &BulkCapabilities{
		MaxBatchSize:         m.config.MaxBatchSize,
		MaxConcurrentBatches: m.config.MaxConcurrentBatches,
		SupportedOperations: []string{
			"create_users", "update_users", "delete_users",
			"create_groups", "update_groups", "delete_groups",
			"add_memberships", "remove_memberships",
		},
		RateLimits: map[string]*RateLimit{
			"per_second": {
				Requests: m.config.RequestsPerSecond,
				Window:   time.Second,
				Burst:    m.config.BurstSize,
			},
			"per_minute": {
				Requests: m.config.RequestsPerMinute,
				Window:   time.Minute,
			},
			"per_hour": {
				Requests: m.config.RequestsPerHour,
				Window:   time.Hour,
			},
		},
		RequiresOrdering:     false, // Most directory operations don't require strict ordering
		SupportsTransactions: providerCaps.SupportsBulkOperations,
		SupportsCancellation: true,
	}
}
