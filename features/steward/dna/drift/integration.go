// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package drift provides integration with the DNA storage system for drift detection.

package drift

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/pkg/logging"
)

// DNADriftIntegrator provides integration between drift detection and DNA storage.
type DNADriftIntegrator struct {
	storage      *storage.Manager
	driftService *DriftService
	logger       logging.Logger
	config       *IntegrationConfig
}

// IntegrationConfig defines configuration for DNA-drift integration.
type IntegrationConfig struct {
	// Drift detection scheduling
	AutoDetectionEnabled bool          `json:"auto_detection_enabled" yaml:"auto_detection_enabled"`
	DetectionInterval    time.Duration `json:"detection_interval" yaml:"detection_interval"`
	ComparisonWindow     time.Duration `json:"comparison_window" yaml:"comparison_window"`

	// Event storage
	StoreEventsInDNA     bool          `json:"store_events_in_dna" yaml:"store_events_in_dna"`
	EventRetentionPeriod time.Duration `json:"event_retention_period" yaml:"event_retention_period"`

	// Performance
	MaxConcurrentDetections int `json:"max_concurrent_detections" yaml:"max_concurrent_detections"`
	BatchSize               int `json:"batch_size" yaml:"batch_size"`

	// Alerting
	EnableAlerts   bool          `json:"enable_alerts" yaml:"enable_alerts"`
	AlertThreshold DriftSeverity `json:"alert_threshold" yaml:"alert_threshold"`
}

// NewDNADriftIntegrator creates a new integrator for DNA storage and drift detection.
func NewDNADriftIntegrator(
	storageManager *storage.Manager,
	driftService *DriftService,
	config *IntegrationConfig,
	logger logging.Logger,
) (*DNADriftIntegrator, error) {

	if storageManager == nil {
		return nil, fmt.Errorf("storage manager is required")
	}

	if driftService == nil {
		return nil, fmt.Errorf("drift service is required")
	}

	if config == nil {
		config = DefaultIntegrationConfig()
	}

	integrator := &DNADriftIntegrator{
		storage:      storageManager,
		driftService: driftService,
		logger:       logger,
		config:       config,
	}

	logger.Info("DNA drift integrator initialized",
		"auto_detection", config.AutoDetectionEnabled,
		"detection_interval", config.DetectionInterval,
		"store_events", config.StoreEventsInDNA)

	return integrator, nil
}

// DetectDriftForDevice performs drift detection for a specific device using stored DNA history.
func (di *DNADriftIntegrator) DetectDriftForDevice(ctx context.Context, deviceID string) ([]*DriftEvent, error) {
	di.logger.Debug("Detecting drift for device", "device_id", deviceID)

	// Get current DNA
	currentRecord, err := di.storage.GetCurrent(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current DNA for device %s: %w", deviceID, err)
	}

	// Get previous DNA for comparison
	previousRecord, err := di.getPreviousDNAForComparison(ctx, deviceID)
	if err != nil {
		di.logger.Debug("No previous DNA found for comparison", "device_id", deviceID, "error", err)
		// This might be the first DNA record for this device
		return nil, nil
	}

	// Perform drift detection
	events, err := di.driftService.GetDetector().DetectDrift(ctx, previousRecord.DNA, currentRecord.DNA)
	if err != nil {
		return nil, fmt.Errorf("drift detection failed for device %s: %w", deviceID, err)
	}

	// Store events in DNA metadata if configured
	if di.config.StoreEventsInDNA && len(events) > 0 {
		if err := di.storeEventsInDNA(ctx, deviceID, events); err != nil {
			di.logger.Error("Failed to store drift events in DNA", "error", err, "device_id", deviceID)
		}
	}

	// Handle alerts if configured
	if di.config.EnableAlerts {
		di.handleAlerts(ctx, events)
	}

	di.logger.Debug("Drift detection completed",
		"device_id", deviceID,
		"events_detected", len(events))

	return events, nil
}

// DetectDriftForAllDevices performs drift detection for all devices with recent DNA updates.
func (di *DNADriftIntegrator) DetectDriftForAllDevices(ctx context.Context) (map[string][]*DriftEvent, error) {
	di.logger.Info("Starting drift detection for all devices")

	// Get list of devices with recent DNA updates
	devices, err := di.getRecentlyUpdatedDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get recently updated devices: %w", err)
	}

	// Process devices in batches if configured
	var results map[string][]*DriftEvent
	if di.config.BatchSize > 0 {
		results, err = di.processBatchedDetection(ctx, devices)
	} else {
		results, err = di.processSequentialDetection(ctx, devices)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to process drift detection: %w", err)
	}

	// Log summary
	totalEvents := 0
	devicesWithDrift := 0
	for deviceID, events := range results {
		if len(events) > 0 {
			devicesWithDrift++
			totalEvents += len(events)
			di.logger.Info("Drift detected for device",
				"device_id", deviceID,
				"event_count", len(events))
		}
	}

	di.logger.Info("Drift detection completed for all devices",
		"total_devices", len(devices),
		"devices_with_drift", devicesWithDrift,
		"total_events", totalEvents)

	return results, nil
}

// GetDriftHistory retrieves drift events for a device within a time range.
func (di *DNADriftIntegrator) GetDriftHistory(ctx context.Context, deviceID string, timeRange *storage.TimeRange) ([]*DriftEvent, error) {
	// This would typically query a separate drift events storage
	// For now, we'll reconstruct events from DNA history

	options := &storage.QueryOptions{
		TimeRange:   timeRange,
		IncludeData: true,
		Limit:       100, // Reasonable limit for drift analysis
	}

	history, err := di.storage.GetHistory(ctx, deviceID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNA history: %w", err)
	}

	if len(history.Records) < 2 {
		return nil, nil // Need at least 2 records to detect drift
	}

	var allEvents []*DriftEvent

	// Compare consecutive DNA records to identify drift events
	for i := 1; i < len(history.Records); i++ {
		previous := history.Records[i]  // Older record
		current := history.Records[i-1] // Newer record

		events, err := di.driftService.GetDetector().DetectDrift(ctx, previous.DNA, current.DNA)
		if err != nil {
			di.logger.Error("Failed to detect drift in historical data",
				"error", err,
				"device_id", deviceID,
				"previous_version", previous.Version,
				"current_version", current.Version)
			continue
		}

		// Adjust event timestamps to match DNA record timestamps
		for _, event := range events {
			event.Timestamp = current.StoredAt
		}

		allEvents = append(allEvents, events...)
	}

	return allEvents, nil
}

// StartAutoDetection begins automatic drift detection for all monitored devices.
func (di *DNADriftIntegrator) StartAutoDetection(ctx context.Context) error {
	if !di.config.AutoDetectionEnabled {
		return fmt.Errorf("auto detection is not enabled")
	}

	di.logger.Info("Starting automatic drift detection",
		"interval", di.config.DetectionInterval)

	ticker := time.NewTicker(di.config.DetectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			di.logger.Info("Auto detection stopped due to context cancellation")
			return ctx.Err()
		case <-ticker.C:
			// Perform detection for all devices
			results, err := di.DetectDriftForAllDevices(ctx)
			if err != nil {
				di.logger.Error("Auto detection failed", "error", err)
				continue
			}

			// Log summary
			totalEvents := 0
			for _, events := range results {
				totalEvents += len(events)
			}

			if totalEvents > 0 {
				di.logger.Info("Auto detection completed",
					"devices_checked", len(results),
					"total_events", totalEvents)
			}
		}
	}
}

// Private methods

func (di *DNADriftIntegrator) getPreviousDNAForComparison(ctx context.Context, deviceID string) (*storage.DNARecord, error) {
	// Get DNA from the comparison window ago
	comparisonTime := time.Now().Add(-di.config.ComparisonWindow)

	options := &storage.QueryOptions{
		TimeRange: &storage.TimeRange{
			Start: comparisonTime.Add(-time.Minute), // Small window around comparison time
			End:   comparisonTime.Add(time.Minute),
		},
		Limit:       1,
		IncludeData: true,
	}

	history, err := di.storage.GetHistory(ctx, deviceID, options)
	if err != nil {
		return nil, err
	}

	if len(history.Records) == 0 {
		// Try getting the most recent record before comparison time
		options.TimeRange = &storage.TimeRange{
			Start: time.Time{}, // Beginning of time
			End:   comparisonTime,
		}

		history, err = di.storage.GetHistory(ctx, deviceID, options)
		if err != nil {
			return nil, err
		}

		if len(history.Records) == 0 {
			return nil, fmt.Errorf("no previous DNA found for device %s", deviceID)
		}
	}

	return history.Records[0], nil
}

func (di *DNADriftIntegrator) getRecentlyUpdatedDevices(ctx context.Context) ([]string, error) {
	// This would typically query the storage system for devices with recent updates
	// For now, return empty list - would need to be implemented based on storage backend

	// In a real implementation, this might query:
	// - All devices with DNA updates in the last detection interval
	// - Devices that are actively monitored
	// - Devices based on priority or configuration

	di.logger.Debug("Getting recently updated devices")

	// Placeholder - would need actual implementation based on storage backend capabilities
	var devices []string

	return devices, nil
}

func (di *DNADriftIntegrator) processBatchedDetection(ctx context.Context, devices []string) (map[string][]*DriftEvent, error) {
	results := make(map[string][]*DriftEvent)
	batchSize := di.config.BatchSize

	for i := 0; i < len(devices); i += batchSize {
		end := i + batchSize
		if end > len(devices) {
			end = len(devices)
		}

		batch := devices[i:end]

		// Process batch
		for _, deviceID := range batch {
			events, err := di.DetectDriftForDevice(ctx, deviceID)
			if err != nil {
				di.logger.Error("Failed to detect drift for device",
					"error", err,
					"device_id", deviceID)
				continue
			}

			if len(events) > 0 {
				results[deviceID] = events
			}
		}

		// Check for context cancellation between batches
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}
	}

	return results, nil
}

func (di *DNADriftIntegrator) processSequentialDetection(ctx context.Context, devices []string) (map[string][]*DriftEvent, error) {
	results := make(map[string][]*DriftEvent)

	for _, deviceID := range devices {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		events, err := di.DetectDriftForDevice(ctx, deviceID)
		if err != nil {
			di.logger.Error("Failed to detect drift for device",
				"error", err,
				"device_id", deviceID)
			continue
		}

		if len(events) > 0 {
			results[deviceID] = events
		}
	}

	return results, nil
}

func (di *DNADriftIntegrator) storeEventsInDNA(ctx context.Context, deviceID string, events []*DriftEvent) error {
	// Store drift events as metadata in the DNA record
	// This could be done by adding drift event information to DNA attributes
	// or by extending the DNA schema to include drift events

	di.logger.Debug("Storing drift events in DNA metadata",
		"device_id", deviceID,
		"event_count", len(events))

	// Placeholder - would need actual implementation based on how events should be stored
	// This might involve:
	// 1. Adding drift event IDs to DNA attributes
	// 2. Storing event summaries in DNA metadata
	// 3. Creating separate drift event storage linked to DNA records

	return nil
}

func (di *DNADriftIntegrator) handleAlerts(ctx context.Context, events []*DriftEvent) {
	for _, event := range events {
		// Check if event meets alert threshold
		if di.shouldAlert(event) {
			di.logger.Warn("Drift alert triggered",
				"event_id", event.ID,
				"device_id", event.DeviceID,
				"severity", event.Severity,
				"change_count", event.ChangeCount)

			// In a real implementation, this would:
			// - Send notifications (email, Slack, etc.)
			// - Create tickets in ticketing systems
			// - Call webhooks
			// - Update dashboards
		}
	}
}

func (di *DNADriftIntegrator) shouldAlert(event *DriftEvent) bool {
	// Check if event severity meets alert threshold
	switch di.config.AlertThreshold {
	case SeverityCritical:
		return event.Severity == SeverityCritical
	case SeverityWarning:
		return event.Severity == SeverityCritical || event.Severity == SeverityWarning
	case SeverityInfo:
		return true // Alert on all events
	default:
		return event.Severity == SeverityCritical
	}
}

// DefaultIntegrationConfig returns default configuration for DNA-drift integration.
func DefaultIntegrationConfig() *IntegrationConfig {
	return &IntegrationConfig{
		AutoDetectionEnabled:    true,
		DetectionInterval:       5 * time.Minute,  // Meet 5-minute requirement
		ComparisonWindow:        10 * time.Minute, // Compare with DNA from 10 minutes ago
		StoreEventsInDNA:        true,
		EventRetentionPeriod:    30 * 24 * time.Hour, // 30 days
		MaxConcurrentDetections: 10,
		BatchSize:               50,
		EnableAlerts:            true,
		AlertThreshold:          SeverityWarning, // Alert on warning and critical events
	}
}
