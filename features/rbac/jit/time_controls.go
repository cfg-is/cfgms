package jit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TimeBasedAccessController manages time-based access controls and automatic expiration
type TimeBasedAccessController struct {
	accessManager       *JITAccessManager
	scheduledTasks      map[string]*ScheduledTask
	expirationWarnings  map[string]*ExpirationWarning
	mutex               sync.RWMutex
	stopChannel         chan struct{}
	tickerInterval      time.Duration
}

// NewTimeBasedAccessController creates a new time-based access controller
func NewTimeBasedAccessController(accessManager *JITAccessManager) *TimeBasedAccessController {
	return &TimeBasedAccessController{
		accessManager:      accessManager,
		scheduledTasks:     make(map[string]*ScheduledTask),
		expirationWarnings: make(map[string]*ExpirationWarning),
		mutex:              sync.RWMutex{},
		stopChannel:        make(chan struct{}),
		tickerInterval:     time.Minute, // Check every minute
	}
}

// ScheduledTask represents a scheduled task for JIT access management
type ScheduledTask struct {
	ID            string           `json:"id"`
	Type          TaskType         `json:"type"`
	ScheduledAt   time.Time        `json:"scheduled_at"`
	GrantID       string           `json:"grant_id,omitempty"`
	RequestID     string           `json:"request_id,omitempty"`
	Action        string           `json:"action"`
	Status        TaskStatus       `json:"status"`
	Retries       int              `json:"retries"`
	MaxRetries    int              `json:"max_retries"`
	LastAttempt   *time.Time       `json:"last_attempt,omitempty"`
	LastError     string           `json:"last_error,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ExpirationWarning represents a warning about upcoming access expiration
type ExpirationWarning struct {
	ID              string    `json:"id"`
	GrantID         string    `json:"grant_id"`
	WarningTime     time.Time `json:"warning_time"`
	ExpirationTime  time.Time `json:"expiration_time"`
	TimeUntilExpiry time.Duration `json:"time_until_expiry"`
	Sent            bool      `json:"sent"`
	SentAt          *time.Time `json:"sent_at,omitempty"`
}

// TaskType defines types of scheduled tasks
type TaskType string

const (
	TaskTypeExpireAccess        TaskType = "expire_access"
	TaskTypeWarningNotification TaskType = "warning_notification"
	TaskTypeCleanupRequest      TaskType = "cleanup_request"
	TaskTypeEscalateApproval    TaskType = "escalate_approval"
	TaskTypeAutoExtend          TaskType = "auto_extend"
)

// TaskStatus defines the status of scheduled tasks
type TaskStatus string

const (
	TaskStatusPending   TaskStatus = "pending"
	TaskStatusExecuting TaskStatus = "executing"
	TaskStatusCompleted TaskStatus = "completed"
	TaskStatusFailed    TaskStatus = "failed"
	TaskStatusCanceled  TaskStatus = "canceled"
)

// Start begins the time-based access controller
func (tbac *TimeBasedAccessController) Start(ctx context.Context) error {
	ticker := time.NewTicker(tbac.tickerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tbac.stopChannel:
			return nil
		case <-ticker.C:
			tbac.processTasks(ctx)
			tbac.checkExpirations(ctx)
			tbac.cleanupCompletedTasks()
		}
	}
}

// Stop stops the time-based access controller
func (tbac *TimeBasedAccessController) Stop() {
	close(tbac.stopChannel)
}

// ScheduleAccessExpiration schedules access expiration for a grant
func (tbac *TimeBasedAccessController) ScheduleAccessExpiration(ctx context.Context, grant *JITAccessGrant) error {
	tbac.mutex.Lock()
	defer tbac.mutex.Unlock()

	taskID := fmt.Sprintf("expire-%s", grant.ID)
	task := &ScheduledTask{
		ID:          taskID,
		Type:        TaskTypeExpireAccess,
		ScheduledAt: grant.ExpiresAt,
		GrantID:     grant.ID,
		Action:      "expire",
		Status:      TaskStatusPending,
		MaxRetries:  3,
		Metadata: map[string]interface{}{
			"original_expiry": grant.ExpiresAt,
		},
	}

	tbac.scheduledTasks[taskID] = task

	// Also schedule expiration warnings
	return tbac.scheduleExpirationWarnings(ctx, grant)
}

// scheduleExpirationWarnings schedules warnings before access expiration
func (tbac *TimeBasedAccessController) scheduleExpirationWarnings(ctx context.Context, grant *JITAccessGrant) error {
	// Schedule warnings at different intervals before expiration
	warningIntervals := []time.Duration{
		24 * time.Hour, // 24 hours before
		4 * time.Hour,  // 4 hours before
		1 * time.Hour,  // 1 hour before
		15 * time.Minute, // 15 minutes before
	}

	for i, interval := range warningIntervals {
		warningTime := grant.ExpiresAt.Add(-interval)
		
		// Only schedule if warning time is in the future
		if warningTime.After(time.Now()) {
			warningID := fmt.Sprintf("warning-%s-%d", grant.ID, i)
			warning := &ExpirationWarning{
				ID:              warningID,
				GrantID:         grant.ID,
				WarningTime:     warningTime,
				ExpirationTime:  grant.ExpiresAt,
				TimeUntilExpiry: interval,
				Sent:            false,
			}

			tbac.expirationWarnings[warningID] = warning

			// Schedule the notification task
			taskID := fmt.Sprintf("warn-%s-%d", grant.ID, i)
			task := &ScheduledTask{
				ID:          taskID,
				Type:        TaskTypeWarningNotification,
				ScheduledAt: warningTime,
				GrantID:     grant.ID,
				Action:      "warn",
				Status:      TaskStatusPending,
				MaxRetries:  2,
				Metadata: map[string]interface{}{
					"warning_id":     warningID,
					"time_remaining": interval,
				},
			}

			tbac.scheduledTasks[taskID] = task
		}
	}

	return nil
}

// ScheduleRequestCleanup schedules cleanup of expired requests
func (tbac *TimeBasedAccessController) ScheduleRequestCleanup(ctx context.Context, request *JITAccessRequest) error {
	tbac.mutex.Lock()
	defer tbac.mutex.Unlock()

	taskID := fmt.Sprintf("cleanup-req-%s", request.ID)
	task := &ScheduledTask{
		ID:          taskID,
		Type:        TaskTypeCleanupRequest,
		ScheduledAt: request.RequestTTL,
		RequestID:   request.ID,
		Action:      "cleanup",
		Status:      TaskStatusPending,
		MaxRetries:  1,
	}

	tbac.scheduledTasks[taskID] = task
	return nil
}

// ExtendAccess extends access and reschedules expiration
func (tbac *TimeBasedAccessController) ExtendAccess(ctx context.Context, grantID string, duration time.Duration) error {
	tbac.mutex.Lock()
	defer tbac.mutex.Unlock()

	// Cancel existing expiration task
	expireTaskID := fmt.Sprintf("expire-%s", grantID)
	if task, exists := tbac.scheduledTasks[expireTaskID]; exists {
		task.Status = TaskStatusCanceled
	}

	// Cancel existing warning tasks
	for _, task := range tbac.scheduledTasks {
		if task.GrantID == grantID && task.Type == TaskTypeWarningNotification {
			task.Status = TaskStatusCanceled
		}
	}

	// Get the grant to schedule new expiration
	grant, exists := tbac.accessManager.activeGrants[grantID]
	if !exists {
		return fmt.Errorf("grant %s not found", grantID)
	}

	// Schedule new expiration and warnings
	return tbac.ScheduleAccessExpiration(ctx, grant)
}

// CancelScheduledTasks cancels all scheduled tasks for a grant
func (tbac *TimeBasedAccessController) CancelScheduledTasks(ctx context.Context, grantID string) error {
	tbac.mutex.Lock()
	defer tbac.mutex.Unlock()

	for _, task := range tbac.scheduledTasks {
		if task.GrantID == grantID {
			task.Status = TaskStatusCanceled
		}
	}

	// Cancel warnings
	for _, warning := range tbac.expirationWarnings {
		if warning.GrantID == grantID {
			warning.Sent = true // Mark as sent to prevent processing
		}
	}

	return nil
}

// processTasks processes due scheduled tasks
func (tbac *TimeBasedAccessController) processTasks(ctx context.Context) {
	tbac.mutex.Lock()
	defer tbac.mutex.Unlock()

	now := time.Now()

	for _, task := range tbac.scheduledTasks {
		if task.Status != TaskStatusPending {
			continue
		}

		if task.ScheduledAt.After(now) {
			continue // Not yet due
		}

		// Execute the task
		task.Status = TaskStatusExecuting
		task.LastAttempt = &now

		err := tbac.executeTask(ctx, task)
		if err != nil {
			task.LastError = err.Error()
			task.Retries++

			if task.Retries >= task.MaxRetries {
				task.Status = TaskStatusFailed
			} else {
				task.Status = TaskStatusPending
				// Reschedule with exponential backoff
				backoff := time.Duration(task.Retries) * time.Minute
				task.ScheduledAt = now.Add(backoff)
			}
		} else {
			task.Status = TaskStatusCompleted
		}
	}
}

// executeTask executes a scheduled task
func (tbac *TimeBasedAccessController) executeTask(ctx context.Context, task *ScheduledTask) error {
	switch task.Type {
	case TaskTypeExpireAccess:
		return tbac.executeAccessExpiration(ctx, task)
	case TaskTypeWarningNotification:
		return tbac.executeWarningNotification(ctx, task)
	case TaskTypeCleanupRequest:
		return tbac.executeRequestCleanup(ctx, task)
	default:
		return fmt.Errorf("unknown task type: %s", task.Type)
	}
}

// executeAccessExpiration expires access for a grant
func (tbac *TimeBasedAccessController) executeAccessExpiration(ctx context.Context, task *ScheduledTask) error {
	grant, exists := tbac.accessManager.activeGrants[task.GrantID]
	if !exists {
		return nil // Grant already removed
	}

	if grant.Status != JITAccessGrantStatusActive {
		return nil // Grant already inactive
	}

	// Check if grant was extended after this task was scheduled
	if grant.ExpiresAt.After(task.ScheduledAt) {
		return nil // Grant was extended, this expiration is no longer valid
	}

	// Deactivate the access
	err := tbac.accessManager.deactivateAccess(ctx, grant)
	if err != nil {
		return fmt.Errorf("failed to deactivate access: %w", err)
	}

	// Update grant status to expired
	grant.Status = JITAccessGrantStatusExpired

	// Audit the expiration
	_ = tbac.accessManager.auditLogger.LogAccessUsage(ctx, grant, "expired", "", map[string]interface{}{
		"automatic_expiration": true,
		"scheduled_at":         task.ScheduledAt,
	})

	return nil
}

// executeWarningNotification sends expiration warnings
func (tbac *TimeBasedAccessController) executeWarningNotification(ctx context.Context, task *ScheduledTask) error {
	warningID, ok := task.Metadata["warning_id"].(string)
	if !ok {
		return fmt.Errorf("warning_id not found in task metadata")
	}

	warning, exists := tbac.expirationWarnings[warningID]
	if !exists {
		return nil // Warning already processed or canceled
	}

	if warning.Sent {
		return nil // Warning already sent
	}

	grant, exists := tbac.accessManager.activeGrants[warning.GrantID]
	if !exists || grant.Status != JITAccessGrantStatusActive {
		return nil // Grant no longer active
	}

	// Send the warning notification
	err := tbac.accessManager.notificationService.SendExpirationWarning(ctx, grant, warning.TimeUntilExpiry)
	if err != nil {
		return fmt.Errorf("failed to send expiration warning: %w", err)
	}

	// Mark warning as sent
	now := time.Now()
	warning.Sent = true
	warning.SentAt = &now

	return nil
}

// executeRequestCleanup cleans up expired requests
func (tbac *TimeBasedAccessController) executeRequestCleanup(ctx context.Context, task *ScheduledTask) error {
	request, exists := tbac.accessManager.requests[task.RequestID]
	if !exists {
		return nil // Request already removed
	}

	// Only clean up pending requests that have expired
	if request.Status == JITAccessRequestStatusPending && time.Now().After(request.RequestTTL) {
		request.Status = JITAccessRequestStatusExpired
		
		// Audit the expiration
		_ = tbac.accessManager.auditLogger.LogAccessRequest(ctx, request, "expired")
	}

	return nil
}

// checkExpirations performs additional expiration checks
func (tbac *TimeBasedAccessController) checkExpirations(ctx context.Context) {
	tbac.mutex.RLock()
	defer tbac.mutex.RUnlock()

	now := time.Now()

	// Check for any missed expirations (fallback mechanism)
	for _, grant := range tbac.accessManager.activeGrants {
		if grant.Status == JITAccessGrantStatusActive && grant.ExpiresAt.Before(now) {
			// This shouldn't happen if scheduling works correctly, but it's a safety net
			go func(g *JITAccessGrant) {
				tbac.mutex.Lock()
				_ = tbac.accessManager.deactivateAccess(ctx, g)
				g.Status = JITAccessGrantStatusExpired
				tbac.mutex.Unlock()
			}(grant)
		}
	}
}

// cleanupCompletedTasks removes completed and old tasks
func (tbac *TimeBasedAccessController) cleanupCompletedTasks() {
	tbac.mutex.Lock()
	defer tbac.mutex.Unlock()

	cutoff := time.Now().Add(-24 * time.Hour) // Keep tasks for 24 hours

	for taskID, task := range tbac.scheduledTasks {
		if (task.Status == TaskStatusCompleted || task.Status == TaskStatusFailed) && 
		   task.LastAttempt != nil && task.LastAttempt.Before(cutoff) {
			delete(tbac.scheduledTasks, taskID)
		}
	}

	// Also cleanup old warnings
	for warningID, warning := range tbac.expirationWarnings {
		if warning.Sent && warning.SentAt != nil && warning.SentAt.Before(cutoff) {
			delete(tbac.expirationWarnings, warningID)
		}
	}
}

// GetScheduledTasks returns scheduled tasks with optional filtering
func (tbac *TimeBasedAccessController) GetScheduledTasks(ctx context.Context, filter *TaskFilter) ([]*ScheduledTask, error) {
	tbac.mutex.RLock()
	defer tbac.mutex.RUnlock()

	var results []*ScheduledTask

	for _, task := range tbac.scheduledTasks {
		if tbac.matchesTaskFilter(task, filter) {
			results = append(results, task)
		}
	}

	return results, nil
}

// GetExpirationWarnings returns expiration warnings
func (tbac *TimeBasedAccessController) GetExpirationWarnings(ctx context.Context, grantID string) ([]*ExpirationWarning, error) {
	tbac.mutex.RLock()
	defer tbac.mutex.RUnlock()

	var results []*ExpirationWarning

	for _, warning := range tbac.expirationWarnings {
		if grantID == "" || warning.GrantID == grantID {
			results = append(results, warning)
		}
	}

	return results, nil
}

// Helper methods

func (tbac *TimeBasedAccessController) matchesTaskFilter(task *ScheduledTask, filter *TaskFilter) bool {
	if filter == nil {
		return true
	}

	if filter.Type != "" && task.Type != TaskType(filter.Type) {
		return false
	}
	if filter.Status != "" && task.Status != TaskStatus(filter.Status) {
		return false
	}
	if filter.GrantID != "" && task.GrantID != filter.GrantID {
		return false
	}

	return true
}

// Supporting types

// TaskFilter for filtering scheduled tasks
type TaskFilter struct {
	Type    string `json:"type,omitempty"`
	Status  string `json:"status,omitempty"`
	GrantID string `json:"grant_id,omitempty"`
}

// TimeBasedAccessStats provides statistics about time-based access control
type TimeBasedAccessStats struct {
	ActiveTasks           int                      `json:"active_tasks"`
	CompletedTasks        int                      `json:"completed_tasks"`
	FailedTasks          int                      `json:"failed_tasks"`
	PendingWarnings      int                      `json:"pending_warnings"`
	SentWarnings         int                      `json:"sent_warnings"`
	TaskTypeBreakdown    map[TaskType]int         `json:"task_type_breakdown"`
	TaskStatusBreakdown  map[TaskStatus]int       `json:"task_status_breakdown"`
	GeneratedAt          time.Time                `json:"generated_at"`
}

// GetTimeBasedAccessStats generates statistics about time-based access control
func (tbac *TimeBasedAccessController) GetTimeBasedAccessStats(ctx context.Context) (*TimeBasedAccessStats, error) {
	tbac.mutex.RLock()
	defer tbac.mutex.RUnlock()

	stats := &TimeBasedAccessStats{
		TaskTypeBreakdown:   make(map[TaskType]int),
		TaskStatusBreakdown: make(map[TaskStatus]int),
		GeneratedAt:         time.Now(),
	}

	for _, task := range tbac.scheduledTasks {
		stats.TaskTypeBreakdown[task.Type]++
		stats.TaskStatusBreakdown[task.Status]++

		switch task.Status {
		case TaskStatusPending, TaskStatusExecuting:
			stats.ActiveTasks++
		case TaskStatusCompleted:
			stats.CompletedTasks++
		case TaskStatusFailed:
			stats.FailedTasks++
		}
	}

	for _, warning := range tbac.expirationWarnings {
		if warning.Sent {
			stats.SentWarnings++
		} else {
			stats.PendingWarnings++
		}
	}

	return stats, nil
}