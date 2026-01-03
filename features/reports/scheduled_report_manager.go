// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package reports

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ScheduledReportManager implements the ScheduledReportManager interface
type ScheduledReportManager struct {
	store           interfaces.ScheduledReportStore
	templateManager interfaces.CustomTemplateManager
	reportBuilder   interfaces.CustomReportBuilder
	logger          logging.Logger
}

// NewScheduledReportManager creates a new scheduled report manager
func NewScheduledReportManager(
	store interfaces.ScheduledReportStore,
	templateManager interfaces.CustomTemplateManager,
	reportBuilder interfaces.CustomReportBuilder,
	logger logging.Logger,
) *ScheduledReportManager {
	return &ScheduledReportManager{
		store:           store,
		templateManager: templateManager,
		reportBuilder:   reportBuilder,
		logger:          logger,
	}
}

// ScheduleReport schedules a custom report for automatic generation
func (m *ScheduledReportManager) ScheduleReport(ctx context.Context, req interfaces.ScheduleReportRequest) (*interfaces.ScheduledReport, error) {
	m.logger.Info("Scheduling custom report", "name", req.Name, "template_id", req.TemplateID, "tenant_id", req.TenantID)

	// Validate request
	if err := m.validateScheduleRequest(req); err != nil {
		return nil, fmt.Errorf("invalid schedule request: %w", err)
	}

	// Verify template exists and is accessible
	template, err := m.templateManager.GetTemplate(ctx, req.TemplateID, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to verify template: %w", err)
	}

	// Validate parameters against template
	if len(req.Parameters) > 0 {
		// Create a custom report builder to validate parameters
		err = m.reportBuilder.ValidateParameters(template, req.Parameters)
		if err != nil {
			return nil, fmt.Errorf("parameter validation failed: %w", err)
		}
	}

	// Calculate next run time
	nextRun, err := m.calculateNextRun(req.Schedule)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate next run time: %w", err)
	}

	// Create scheduled report
	scheduledReport := &interfaces.ScheduledReport{
		ID:           uuid.New().String(),
		Name:         req.Name,
		TemplateID:   req.TemplateID,
		Parameters:   req.Parameters,
		Schedule:     req.Schedule,
		Format:       req.Format,
		DeliveryMode: req.DeliveryMode,
		Recipients:   req.Recipients,
		TenantID:     req.TenantID,
		CreatedBy:    req.CreatedBy,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		IsActive:     true,
		NextRun:      &nextRun,
		RunCount:     0,
		FailureCount: 0,
	}

	// Save to store
	savedSchedule, err := m.store.Save(ctx, scheduledReport)
	if err != nil {
		return nil, fmt.Errorf("failed to save scheduled report: %w", err)
	}

	m.logger.Info("Scheduled report created successfully",
		"schedule_id", savedSchedule.ID,
		"next_run", nextRun,
	)

	return savedSchedule, nil
}

// UpdateSchedule updates an existing scheduled report
func (m *ScheduledReportManager) UpdateSchedule(ctx context.Context, scheduleID string, req interfaces.ScheduleReportRequest) error {
	m.logger.Info("Updating scheduled report", "schedule_id", scheduleID, "tenant_id", req.TenantID)

	// Get existing schedule
	existing, err := m.store.GetByID(ctx, scheduleID)
	if err != nil {
		return fmt.Errorf("failed to get scheduled report: %w", err)
	}

	// Verify ownership
	if existing.TenantID != req.TenantID {
		return ErrTemplateAccessDenied
	}

	// Validate request
	if err := m.validateScheduleRequest(req); err != nil {
		return fmt.Errorf("invalid schedule request: %w", err)
	}

	// Update fields
	existing.Name = req.Name
	existing.TemplateID = req.TemplateID
	existing.Parameters = req.Parameters
	existing.Schedule = req.Schedule
	existing.Format = req.Format
	existing.DeliveryMode = req.DeliveryMode
	existing.Recipients = req.Recipients
	existing.UpdatedAt = time.Now()

	// Recalculate next run time
	nextRun, err := m.calculateNextRun(req.Schedule)
	if err != nil {
		return fmt.Errorf("failed to calculate next run time: %w", err)
	}
	existing.NextRun = &nextRun

	// Save updates
	_, err = m.store.Save(ctx, existing)
	if err != nil {
		return fmt.Errorf("failed to update scheduled report: %w", err)
	}

	m.logger.Info("Scheduled report updated successfully", "schedule_id", scheduleID)
	return nil
}

// DeleteSchedule deletes a scheduled report
func (m *ScheduledReportManager) DeleteSchedule(ctx context.Context, scheduleID, tenantID string) error {
	m.logger.Info("Deleting scheduled report", "schedule_id", scheduleID, "tenant_id", tenantID)

	// Verify ownership
	existing, err := m.store.GetByID(ctx, scheduleID)
	if err != nil {
		return fmt.Errorf("failed to get scheduled report: %w", err)
	}

	if existing.TenantID != tenantID {
		return ErrTemplateAccessDenied
	}

	// Delete from store
	err = m.store.Delete(ctx, scheduleID)
	if err != nil {
		return fmt.Errorf("failed to delete scheduled report: %w", err)
	}

	m.logger.Info("Scheduled report deleted successfully", "schedule_id", scheduleID)
	return nil
}

// GetScheduledReports retrieves all scheduled reports for a tenant
func (m *ScheduledReportManager) GetScheduledReports(ctx context.Context, tenantID string) ([]*interfaces.ScheduledReport, error) {
	m.logger.Debug("Getting scheduled reports", "tenant_id", tenantID)

	schedules, err := m.store.GetByTenant(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scheduled reports: %w", err)
	}

	m.logger.Debug("Found scheduled reports", "count", len(schedules), "tenant_id", tenantID)
	return schedules, nil
}

// ExecuteScheduledReport executes a scheduled report immediately
func (m *ScheduledReportManager) ExecuteScheduledReport(ctx context.Context, scheduleID string) (*interfaces.CustomReport, error) {
	m.logger.Info("Executing scheduled report", "schedule_id", scheduleID)

	// Get the scheduled report
	schedule, err := m.store.GetByID(ctx, scheduleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get scheduled report: %w", err)
	}

	// Get the template
	template, err := m.templateManager.GetTemplate(ctx, schedule.TemplateID, schedule.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	// Create report request
	reportReq := interfaces.CustomReportRequest{
		Name:        fmt.Sprintf("%s - %s", schedule.Name, time.Now().Format("2006-01-02 15:04:05")),
		Description: fmt.Sprintf("Scheduled execution of report: %s", schedule.Name),
		Query:       template.Query,
		Parameters:  template.Parameters,
		Format:      schedule.Format,
		TenantID:    schedule.TenantID,
		CreatedBy:   "system-scheduler",
		UserParams:  schedule.Parameters,
	}

	// Generate the report
	report, err := m.reportBuilder.GenerateReport(ctx, reportReq)
	if err != nil {
		// Update failure count
		schedule.FailureCount++
		schedule.LastError = err.Error()
		schedule.UpdatedAt = time.Now()
		if _, saveErr := m.store.Save(ctx, schedule); saveErr != nil {
			m.logger.Error("Failed to update schedule failure count", "schedule_id", scheduleID, "error", saveErr)
		}

		return nil, fmt.Errorf("failed to generate report: %w", err)
	}

	// Update execution tracking
	now := time.Now()
	schedule.LastRun = &now
	schedule.RunCount++
	schedule.LastError = ""

	// Calculate next run time
	nextRun, err := m.calculateNextRun(schedule.Schedule)
	if err == nil {
		schedule.NextRun = &nextRun
	}

	schedule.UpdatedAt = time.Now()
	if _, saveErr := m.store.Save(ctx, schedule); saveErr != nil {
		m.logger.Error("Failed to update schedule execution tracking", "schedule_id", scheduleID, "error", saveErr)
	}

	m.logger.Info("Scheduled report executed successfully",
		"schedule_id", scheduleID,
		"report_id", report.ID,
		"next_run", schedule.NextRun,
	)

	// TODO: Handle delivery based on DeliveryMode and Recipients
	// This would involve sending emails, posting to webhooks, or storing files

	return report, nil
}

// Helper methods

func (m *ScheduledReportManager) validateScheduleRequest(req interfaces.ScheduleReportRequest) error {
	if req.Name == "" {
		return fmt.Errorf("schedule name is required")
	}
	if req.TemplateID == "" {
		return fmt.Errorf("template ID is required")
	}
	if req.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if req.CreatedBy == "" {
		return fmt.Errorf("created by is required")
	}

	// Validate schedule
	if err := m.validateSchedule(req.Schedule); err != nil {
		return fmt.Errorf("invalid schedule: %w", err)
	}

	// Validate delivery mode
	if err := m.validateDeliveryMode(req.DeliveryMode, req.Recipients); err != nil {
		return fmt.Errorf("invalid delivery configuration: %w", err)
	}

	return nil
}

func (m *ScheduledReportManager) validateSchedule(schedule interfaces.ReportSchedule) error {
	if schedule.Expression == "" {
		return fmt.Errorf("schedule expression is required")
	}

	switch schedule.Type {
	case interfaces.ScheduleTypeCron:
		// Validate cron expression (basic validation)
		// In a real implementation, you'd use a cron parsing library
		if len(schedule.Expression) < 5 {
			return fmt.Errorf("invalid cron expression")
		}
	case interfaces.ScheduleTypeInterval:
		// Validate interval expression
		_, err := time.ParseDuration(schedule.Expression)
		if err != nil {
			return fmt.Errorf("invalid interval expression: %w", err)
		}
	default:
		return fmt.Errorf("unsupported schedule type: %s", schedule.Type)
	}

	// Validate timezone if provided
	if schedule.Timezone != "" {
		_, err := time.LoadLocation(schedule.Timezone)
		if err != nil {
			return fmt.Errorf("invalid timezone: %w", err)
		}
	}

	return nil
}

func (m *ScheduledReportManager) validateDeliveryMode(mode interfaces.DeliveryMode, recipients []interfaces.ReportRecipient) error {
	switch mode {
	case interfaces.DeliveryModeEmail:
		if len(recipients) == 0 {
			return fmt.Errorf("email recipients are required for email delivery")
		}
		for _, recipient := range recipients {
			if recipient.Type != "email" {
				return fmt.Errorf("invalid recipient type for email delivery: %s", recipient.Type)
			}
			if recipient.Address == "" {
				return fmt.Errorf("email address is required for email recipients")
			}
		}
	case interfaces.DeliveryModeWebhook:
		if len(recipients) == 0 {
			return fmt.Errorf("webhook URLs are required for webhook delivery")
		}
		for _, recipient := range recipients {
			if recipient.Type != "webhook" {
				return fmt.Errorf("invalid recipient type for webhook delivery: %s", recipient.Type)
			}
			if recipient.Address == "" {
				return fmt.Errorf("webhook URL is required for webhook recipients")
			}
		}
	case interfaces.DeliveryModeStorage:
		if len(recipients) == 0 {
			return fmt.Errorf("storage paths are required for storage delivery")
		}
		for _, recipient := range recipients {
			if recipient.Type != "storage_path" {
				return fmt.Errorf("invalid recipient type for storage delivery: %s", recipient.Type)
			}
			if recipient.Address == "" {
				return fmt.Errorf("storage path is required for storage recipients")
			}
		}
	default:
		return fmt.Errorf("unsupported delivery mode: %s", mode)
	}

	return nil
}

func (m *ScheduledReportManager) calculateNextRun(schedule interfaces.ReportSchedule) (time.Time, error) {
	now := time.Now()

	// Handle timezone
	if schedule.Timezone != "" {
		location, err := time.LoadLocation(schedule.Timezone)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid timezone: %w", err)
		}
		now = now.In(location)
	}

	// Check start/end dates
	if schedule.StartDate != nil && now.Before(*schedule.StartDate) {
		now = *schedule.StartDate
	}
	if schedule.EndDate != nil && now.After(*schedule.EndDate) {
		return time.Time{}, fmt.Errorf("schedule has expired")
	}

	switch schedule.Type {
	case interfaces.ScheduleTypeCron:
		// Simplified cron calculation - in reality you'd use a proper cron library
		// For now, assume expression is in format "0 H * * *" (daily at hour H)
		// This is just a placeholder implementation
		return now.Add(24 * time.Hour), nil

	case interfaces.ScheduleTypeInterval:
		interval, err := time.ParseDuration(schedule.Expression)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid interval: %w", err)
		}

		nextRun := now.Add(interval)

		// Check end date
		if schedule.EndDate != nil && nextRun.After(*schedule.EndDate) {
			return time.Time{}, fmt.Errorf("next run would exceed end date")
		}

		return nextRun, nil

	default:
		return time.Time{}, fmt.Errorf("unsupported schedule type: %s", schedule.Type)
	}
}
