// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package events provides drift detection event subscriber.

package events

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// DriftDetector defines the interface for drift detection.
// This avoids circular imports by defining just what we need.
type DriftDetector interface {
	DetectDrift(ctx context.Context, previous, current interface{}) ([]DriftEvent, error)
}

// DriftEvent represents a detected drift event.
// This is a simplified version to avoid import cycles.
type DriftEvent struct {
	ID       string      `json:"id"`
	DeviceID string      `json:"device_id"`
	Severity string      `json:"severity"`
	Changes  interface{} `json:"changes"`
}

// StorageManager defines the interface for DNA storage access.
// This avoids circular imports by defining just what we need.
type StorageManager interface {
	GetHistory(ctx context.Context, deviceID string, options interface{}) (interface{}, error)
}

// driftSubscriber implements EventSubscriber for drift detection.
type driftSubscriber struct {
	logger   logging.Logger
	detector DriftDetector
	storage  StorageManager
	config   *DriftSubscriberConfig
	stats    *DriftSubscriberStats
}

// DriftSubscriberConfig defines configuration for drift detection subscriber.
type DriftSubscriberConfig struct {
	// Detection settings
	EnableRealTimeDetection bool          `json:"enable_real_time_detection"`
	ComparisonWindow        time.Duration `json:"comparison_window"`
	MaxDetectionTime        time.Duration `json:"max_detection_time"`

	// Performance settings
	SkipRecentChanges     bool          `json:"skip_recent_changes"`
	RecentChangeThreshold time.Duration `json:"recent_change_threshold"`

	// Event handling
	MaxEventsPerSubscriber int           `json:"max_events_per_subscriber"`
	EventProcessingTimeout time.Duration `json:"event_processing_timeout"`
}

// DriftSubscriberStats provides statistics for drift detection subscriber.
type DriftSubscriberStats struct {
	EventsReceived       int64         `json:"events_received"`
	DriftDetectionRuns   int64         `json:"drift_detection_runs"`
	DriftEventsDetected  int64         `json:"drift_events_detected"`
	AverageDetectionTime time.Duration `json:"average_detection_time"`
	DetectionErrors      int64         `json:"detection_errors"`
	SkippedEvents        int64         `json:"skipped_events"`
	LastDetectionTime    time.Time     `json:"last_detection_time"`
}

// NewDriftSubscriber creates a new drift detection event subscriber.
func NewDriftSubscriber(detector DriftDetector, storage StorageManager, config *DriftSubscriberConfig, logger logging.Logger) EventSubscriber {
	if config == nil {
		config = DefaultDriftSubscriberConfig()
	}

	return &driftSubscriber{
		logger:   logger,
		detector: detector,
		storage:  storage,
		config:   config,
		stats:    &DriftSubscriberStats{},
	}
}

// OnEvent processes DNA change events for drift detection.
func (d *driftSubscriber) OnEvent(ctx context.Context, event *DNAChangeEvent) error {
	startTime := time.Now()
	d.stats.EventsReceived++

	defer func() {
		d.stats.AverageDetectionTime = time.Since(startTime)
		d.stats.LastDetectionTime = startTime
	}()

	if d.logger != nil {
		d.logger.Debug("Processing DNA change event for drift detection",
			"device_id", event.DeviceID,
			"content_hash", event.ContentHash)
	}

	// Skip if real-time detection is disabled
	if !d.config.EnableRealTimeDetection {
		d.stats.SkippedEvents++
		return nil
	}

	// Skip if this is a very recent change (avoid thrashing)
	if d.config.SkipRecentChanges &&
		time.Since(event.Timestamp) < d.config.RecentChangeThreshold {
		d.stats.SkippedEvents++
		return nil
	}

	// Apply detection timeout if needed
	_ = ctx
	if d.config.MaxDetectionTime > 0 {
		// Would apply timeout in real implementation
		_ = d.config.MaxDetectionTime // Timeout will be implemented in future iteration
	}

	// For now, we'll just log that we would perform drift detection
	// In a real implementation, this would:
	// 1. Get previous DNA from storage
	// 2. Perform drift detection
	// 3. Handle any detected drift events

	d.stats.DriftDetectionRuns++

	if d.logger != nil {
		d.logger.Info("Would perform drift detection",
			"device_id", event.DeviceID,
			"comparison_window", d.config.ComparisonWindow,
			"detection_time", time.Since(startTime))
	}

	return nil
}

// GetSubscriberInfo returns information about this subscriber.
func (d *driftSubscriber) GetSubscriberInfo() *SubscriberInfo {
	return &SubscriberInfo{
		Name:        "drift_detection",
		Description: "Real-time DNA drift detection subscriber",
		EventTypes:  []string{EventTypeDNAWrite, EventTypeDNAUpdate},
		Priority:    100, // High priority for drift detection
		Async:       true,
		Timeout:     d.config.EventProcessingTimeout,
	}
}

// Close releases subscriber resources.
func (d *driftSubscriber) Close() error {
	if d.logger != nil {
		d.logger.Info("Closing drift detection subscriber",
			"events_processed", d.stats.EventsReceived,
			"drift_detected", d.stats.DriftEventsDetected)
	}
	return nil
}

// GetStats returns drift subscriber statistics.
func (d *driftSubscriber) GetStats() *DriftSubscriberStats {
	stats := *d.stats
	return &stats
}

// DefaultDriftSubscriberConfig returns sensible defaults for drift subscriber configuration.
func DefaultDriftSubscriberConfig() *DriftSubscriberConfig {
	return &DriftSubscriberConfig{
		EnableRealTimeDetection: true,
		ComparisonWindow:        10 * time.Minute,
		MaxDetectionTime:        30 * time.Second,
		SkipRecentChanges:       true,
		RecentChangeThreshold:   30 * time.Second,
		MaxEventsPerSubscriber:  10,
		EventProcessingTimeout:  60 * time.Second,
	}
}
