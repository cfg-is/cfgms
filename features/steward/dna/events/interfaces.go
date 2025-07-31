// Package events provides DNA change event system for real-time processing.
//
// This package defines the event interfaces and types used for DNA change
// notifications, enabling loose coupling between storage, drift detection,
// and other DNA-related subsystems.
//
// Key Features:
//   - Event-driven architecture for DNA changes
//   - Publisher-subscriber pattern for notifications
//   - Extensible event types for different use cases
//   - Integration points for storage and analysis systems
//
// Architecture:
//   DNA Write → Event Publisher → Event Subscribers → Processing
//
// Example Usage:
//
//	publisher := events.NewPublisher(logger)
//	subscriber := events.NewDriftSubscriber(detector)
//	publisher.Subscribe("dna_write", subscriber)
//	
//	// Event automatically published on DNA writes
//	publisher.Publish(ctx, event)
package events

import (
	"context"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// DNAChangeEvent represents a DNA change event.
type DNAChangeEvent struct {
	// Device information
	DeviceID    string    `json:"device_id"`
	Timestamp   time.Time `json:"timestamp"`
	
	// DNA data
	DNA         *commonpb.DNA `json:"dna"`
	ContentHash string        `json:"content_hash"`
	ShardID     string        `json:"shard_id"`
	Version     int64         `json:"version"`
	
	// Storage information
	StorageSize int64  `json:"storage_size"`
	IsReference bool   `json:"is_reference"` // True if deduplicated
	
	// Change context
	PreviousHash string `json:"previous_hash,omitempty"`
	ChangeReason string `json:"change_reason,omitempty"` // "scheduled", "manual", "triggered"
	
	// Correlation tracking
	CorrelationID string `json:"correlation_id,omitempty"`
	TraceID       string `json:"trace_id,omitempty"`
}

// EventSubscriber defines the interface for DNA change event subscribers.
type EventSubscriber interface {
	// OnEvent is called when a DNA change event occurs
	OnEvent(ctx context.Context, event *DNAChangeEvent) error
	
	// GetSubscriberInfo returns information about this subscriber
	GetSubscriberInfo() *SubscriberInfo
	
	// Close releases subscriber resources
	Close() error
}

// SubscriberInfo provides metadata about an event subscriber.
type SubscriberInfo struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	EventTypes  []string      `json:"event_types"`  // Events this subscriber handles
	Priority    int           `json:"priority"`     // Higher number = higher priority
	Async       bool          `json:"async"`        // Whether to process asynchronously
	Timeout     time.Duration `json:"timeout"`      // Maximum processing time
}

// EventPublisher defines the interface for publishing DNA change events.
type EventPublisher interface {
	// Subscribe registers a subscriber for specific event types
	Subscribe(eventType string, subscriber EventSubscriber) error
	
	// Unsubscribe removes a subscriber
	Unsubscribe(eventType string, subscriberName string) error
	
	// Publish publishes an event to all subscribers
	Publish(ctx context.Context, eventType string, event *DNAChangeEvent) error
	
	// Start begins event processing
	Start(ctx context.Context) error
	
	// Stop gracefully shuts down event processing
	Stop(ctx context.Context) error
	
	// GetStats returns publishing statistics
	GetStats() *PublisherStats
}

// PublisherStats provides statistics about event publishing.
type PublisherStats struct {
	// Registration stats
	RegisteredSubscribers int `json:"registered_subscribers"`
	ActiveWorkers        int `json:"active_workers"`
	
	// Processing stats
	EventsPublished      int64         `json:"events_published"`
	EventsProcessed      int64         `json:"events_processed"`
	EventsFailed         int64         `json:"events_failed"`
	
	// Performance stats
	AverageProcessingTime time.Duration `json:"average_processing_time"`
	QueueDepth           int           `json:"queue_depth"`
	
	// Error tracking
	SubscriberFailures   map[string]int64 `json:"subscriber_failures"`
	
	// Timestamps
	LastEventTime        time.Time `json:"last_event_time"`
	StartTime            time.Time `json:"start_time"`
}

// Common event types
const (
	EventTypeDNAWrite   = "dna_write"
	EventTypeDNAUpdate  = "dna_update"
	EventTypeDNADelete  = "dna_delete"
	EventTypeDNAArchive = "dna_archive"
)

// PublisherConfig defines configuration for event publishers.
type PublisherConfig struct {
	// Worker configuration
	WorkerCount        int           `json:"worker_count"`
	QueueSize          int           `json:"queue_size"`
	WorkerTimeout      time.Duration `json:"worker_timeout"`
	
	// Queue management
	MaxQueueDepth      int           `json:"max_queue_depth"`
	QueueFullBehavior  string        `json:"queue_full_behavior"` // "block", "drop", "expand"
	
	// Performance tuning
	BatchSize          int           `json:"batch_size"`
	ProcessingDelay    time.Duration `json:"processing_delay"`
	
	// Health monitoring
	HealthCheckInterval time.Duration `json:"health_check_interval"`
	UnhealthyThreshold  int          `json:"unhealthy_threshold"`
}

// DefaultPublisherConfig returns sensible defaults for event publisher configuration.
func DefaultPublisherConfig() *PublisherConfig {
	return &PublisherConfig{
		WorkerCount:         3,
		QueueSize:          50,
		WorkerTimeout:      30 * time.Second,
		MaxQueueDepth:      500,
		QueueFullBehavior:  "expand",
		BatchSize:          1,
		ProcessingDelay:    100 * time.Millisecond,
		HealthCheckInterval: 30 * time.Second,
		UnhealthyThreshold:  5,
	}
}