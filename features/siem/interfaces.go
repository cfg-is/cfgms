// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package siem provides lightweight SIEM stream processing capabilities for CFGMS.
//
// This package implements a high-performance stream processing engine that can handle
// 10,000+ log entries per second with <100ms processing latency for real-time security
// event detection and automated workflow triggering.
package siem

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// StreamProcessor defines the core interface for SIEM stream processing
type StreamProcessor interface {
	// Start starts the stream processing engine
	Start(ctx context.Context) error

	// Stop stops the stream processing engine gracefully
	Stop(ctx context.Context) error

	// ProcessStream processes a stream of log entries
	ProcessStream(ctx context.Context, entries <-chan interfaces.LogEntry) error

	// GetMetrics returns current processing metrics
	GetMetrics(ctx context.Context) (*ProcessingMetrics, error)
}

// PatternMatcher defines the interface for log pattern matching
type PatternMatcher interface {
	// AddPattern adds a new pattern for detection
	AddPattern(pattern *DetectionPattern) error

	// RemovePattern removes a pattern by ID
	RemovePattern(patternID string) error

	// MatchEntry checks if a log entry matches any patterns
	MatchEntry(entry interfaces.LogEntry) ([]*PatternMatch, error)

	// MatchBatch processes a batch of log entries efficiently
	MatchBatch(entries []interfaces.LogEntry) ([]*PatternMatch, error)
}

// EventCorrelator defines the interface for correlating events across time windows
type EventCorrelator interface {
	// Start starts the event correlator
	Start(ctx context.Context) error

	// Stop stops the event correlator
	Stop(ctx context.Context) error

	// CorrelateEvents correlates events within specified time windows
	CorrelateEvents(ctx context.Context, events []*SecurityEvent, window time.Duration) ([]*CorrelatedEvent, error)

	// AddCorrelationRule adds a new correlation rule
	AddCorrelationRule(rule *CorrelationRule) error

	// RemoveCorrelationRule removes a correlation rule
	RemoveCorrelationRule(ruleID string) error

	// GetActiveCorrelations returns currently active event correlations
	GetActiveCorrelations(ctx context.Context) ([]*CorrelatedEvent, error)
}

// RuleManager defines the interface for managing SIEM detection rules
type RuleManager interface {
	// LoadRules loads rules from configuration
	LoadRules(ctx context.Context, config RuleConfig) error

	// AddRule adds a new detection rule
	AddRule(rule *DetectionRule) error

	// UpdateRule updates an existing detection rule
	UpdateRule(rule *DetectionRule) error

	// RemoveRule removes a detection rule
	RemoveRule(ruleID string) error

	// GetRule retrieves a rule by ID
	GetRule(ruleID string) (*DetectionRule, error)

	// ListRules lists all active detection rules
	ListRules(filter *RuleFilter) ([]*DetectionRule, error)

	// ValidateRule validates a rule configuration
	ValidateRule(rule *DetectionRule) error
}

// SecurityEvent represents a detected security event
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Severity    EventSeverity          `json:"severity"`
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	RuleID      string                 `json:"rule_id"`
	TenantID    string                 `json:"tenant_id"`
	Fields      map[string]interface{} `json:"fields"`
	RawLog      interfaces.LogEntry    `json:"raw_log"`
}

// EventSeverity defines the severity levels for security events
type EventSeverity string

const (
	SeverityCritical EventSeverity = "critical"
	SeverityHigh     EventSeverity = "high"
	SeverityMedium   EventSeverity = "medium"
	SeverityLow      EventSeverity = "low"
	SeverityInfo     EventSeverity = "info"
)

// CorrelatedEvent represents multiple related security events
type CorrelatedEvent struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"rule_id"`
	Events      []*SecurityEvent       `json:"events"`
	Timestamp   time.Time              `json:"timestamp"`
	WindowStart time.Time              `json:"window_start"`
	WindowEnd   time.Time              `json:"window_end"`
	Severity    EventSeverity          `json:"severity"`
	Description string                 `json:"description"`
	TenantID    string                 `json:"tenant_id"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DetectionPattern represents a pattern for matching log entries
type DetectionPattern struct {
	ID            string      `json:"id" yaml:"id"`
	Name          string      `json:"name" yaml:"name"`
	Description   string      `json:"description" yaml:"description"`
	Pattern       string      `json:"pattern" yaml:"pattern"` // Regex pattern
	PatternType   PatternType `json:"pattern_type" yaml:"pattern_type"`
	Fields        []string    `json:"fields" yaml:"fields"` // Fields to match against
	CaseSensitive bool        `json:"case_sensitive" yaml:"case_sensitive"`
	Enabled       bool        `json:"enabled" yaml:"enabled"`
	Priority      int         `json:"priority" yaml:"priority"` // Higher = more important
	TenantID      string      `json:"tenant_id" yaml:"tenant_id"`
	Tags          []string    `json:"tags" yaml:"tags"`
	CreatedAt     time.Time   `json:"created_at" yaml:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at" yaml:"updated_at"`
}

// PatternType defines types of patterns for matching
type PatternType string

const (
	PatternTypeRegex      PatternType = "regex"       // Regular expression pattern
	PatternTypeContains   PatternType = "contains"    // Simple string contains
	PatternTypeEquals     PatternType = "equals"      // Exact string match
	PatternTypeStartsWith PatternType = "starts_with" // String starts with
	PatternTypeEndsWith   PatternType = "ends_with"   // String ends with
)

// PatternMatch represents a successful pattern match
type PatternMatch struct {
	PatternID   string                 `json:"pattern_id"`
	LogEntry    interfaces.LogEntry    `json:"log_entry"`
	MatchedText string                 `json:"matched_text"`
	Field       string                 `json:"field"`
	Timestamp   time.Time              `json:"timestamp"`
	Confidence  float64                `json:"confidence"` // 0.0-1.0
	Metadata    map[string]interface{} `json:"metadata"`
}

// DetectionRule represents a complete SIEM detection rule
type DetectionRule struct {
	ID          string        `json:"id" yaml:"id"`
	Name        string        `json:"name" yaml:"name"`
	Description string        `json:"description" yaml:"description"`
	Enabled     bool          `json:"enabled" yaml:"enabled"`
	Severity    EventSeverity `json:"severity" yaml:"severity"`
	TenantID    string        `json:"tenant_id" yaml:"tenant_id"`

	// Pattern matching configuration
	Patterns []*DetectionPattern `json:"patterns" yaml:"patterns"`

	// Event correlation configuration
	Correlation *CorrelationRule `json:"correlation,omitempty" yaml:"correlation,omitempty"`

	// Threshold configuration
	Threshold *ThresholdRule `json:"threshold,omitempty" yaml:"threshold,omitempty"`

	// Time window for rule evaluation
	TimeWindow time.Duration `json:"time_window" yaml:"time_window"`

	// Actions to take when rule matches
	Actions []*RuleAction `json:"actions" yaml:"actions"`

	// Metadata
	Tags      []string  `json:"tags" yaml:"tags"`
	Category  string    `json:"category" yaml:"category"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
	CreatedBy string    `json:"created_by" yaml:"created_by"`
}

// CorrelationRule defines how to correlate multiple events
type CorrelationRule struct {
	ID         string        `json:"id" yaml:"id"`
	Name       string        `json:"name" yaml:"name"`
	EventTypes []string      `json:"event_types" yaml:"event_types"` // Types of events to correlate
	TimeWindow time.Duration `json:"time_window" yaml:"time_window"` // Correlation time window
	MinEvents  int           `json:"min_events" yaml:"min_events"`   // Minimum events to correlate
	MaxEvents  int           `json:"max_events" yaml:"max_events"`   // Maximum events to correlate
	GroupBy    []string      `json:"group_by" yaml:"group_by"`       // Fields to group by
	Conditions []*Condition  `json:"conditions" yaml:"conditions"`   // Additional conditions
	Enabled    bool          `json:"enabled" yaml:"enabled"`
}

// ThresholdRule defines threshold-based detection
type ThresholdRule struct {
	Type     ThresholdType `json:"type" yaml:"type"`
	Count    int           `json:"count,omitempty" yaml:"count,omitempty"`       // Event count
	Rate     float64       `json:"rate,omitempty" yaml:"rate,omitempty"`         // Events per minute
	Duration time.Duration `json:"duration,omitempty" yaml:"duration,omitempty"` // Duration threshold
	Field    string        `json:"field,omitempty" yaml:"field,omitempty"`       // Field to evaluate
	Operator string        `json:"operator,omitempty" yaml:"operator,omitempty"` // Comparison operator
	Value    interface{}   `json:"value,omitempty" yaml:"value,omitempty"`       // Threshold value
}

// ThresholdType defines types of threshold rules
type ThresholdType string

const (
	ThresholdTypeCount    ThresholdType = "count"    // Count-based threshold
	ThresholdTypeRate     ThresholdType = "rate"     // Rate-based threshold
	ThresholdTypeDuration ThresholdType = "duration" // Duration-based threshold
	ThresholdTypeValue    ThresholdType = "value"    // Value-based threshold
)

// RuleAction defines actions to take when a rule matches
type RuleAction struct {
	Type     ActionType             `json:"type" yaml:"type"`
	Config   map[string]interface{} `json:"config" yaml:"config"`
	Enabled  bool                   `json:"enabled" yaml:"enabled"`
	Priority int                    `json:"priority" yaml:"priority"`
	Timeout  time.Duration          `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// ActionType defines types of actions for rule matches
type ActionType string

const (
	ActionTypeWorkflow     ActionType = "workflow"     // Trigger workflow
	ActionTypeAlert        ActionType = "alert"        // Send alert
	ActionTypeLog          ActionType = "log"          // Log event
	ActionTypeBlock        ActionType = "block"        // Block source IP/user
	ActionTypeNotification ActionType = "notification" // Send notification
)

// Condition represents a logical condition for rules
type Condition struct {
	Field         string      `json:"field" yaml:"field"`
	Operator      string      `json:"operator" yaml:"operator"`
	Value         interface{} `json:"value" yaml:"value"`
	CaseSensitive bool        `json:"case_sensitive,omitempty" yaml:"case_sensitive,omitempty"`
}

// RuleFilter defines filtering options for listing rules
type RuleFilter struct {
	TenantID      string        `json:"tenant_id,omitempty"`
	Enabled       *bool         `json:"enabled,omitempty"`
	Severity      EventSeverity `json:"severity,omitempty"`
	Category      string        `json:"category,omitempty"`
	Tags          []string      `json:"tags,omitempty"`
	CreatedAfter  *time.Time    `json:"created_after,omitempty"`
	CreatedBefore *time.Time    `json:"created_before,omitempty"`
	Limit         int           `json:"limit,omitempty"`
	Offset        int           `json:"offset,omitempty"`
}

// RuleConfig defines configuration for loading rules
type RuleConfig struct {
	Source         string                 `json:"source" yaml:"source"` // file, database, etc.
	Path           string                 `json:"path,omitempty" yaml:"path,omitempty"`
	Format         string                 `json:"format,omitempty" yaml:"format,omitempty"` // yaml, json
	Enabled        bool                   `json:"enabled" yaml:"enabled"`
	AutoReload     bool                   `json:"auto_reload" yaml:"auto_reload"`
	ReloadInterval time.Duration          `json:"reload_interval,omitempty" yaml:"reload_interval,omitempty"`
	Config         map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
}

// ProcessingMetrics provides metrics about stream processing performance
type ProcessingMetrics struct {
	// Throughput metrics
	EntriesProcessed int64   `json:"entries_processed"`
	EntriesPerSecond float64 `json:"entries_per_second"`
	BatchesProcessed int64   `json:"batches_processed"`

	// Latency metrics (in milliseconds)
	AverageLatency float64 `json:"average_latency_ms"`
	P95Latency     float64 `json:"p95_latency_ms"`
	P99Latency     float64 `json:"p99_latency_ms"`

	// Detection metrics
	PatternsMatched         int64 `json:"patterns_matched"`
	EventsCorrelated        int64 `json:"events_correlated"`
	SecurityEventsGenerated int64 `json:"security_events_generated"`
	WorkflowsTriggered      int64 `json:"workflows_triggered"`

	// Performance metrics
	BufferUtilization float64 `json:"buffer_utilization_percent"`
	MemoryUsage       int64   `json:"memory_usage_bytes"`
	GoroutineCount    int     `json:"goroutine_count"`

	// Error metrics
	ProcessingErrors int64 `json:"processing_errors"`
	DroppedEntries   int64 `json:"dropped_entries"`

	// Time metrics
	StartTime         time.Time     `json:"start_time"`
	LastProcessedTime time.Time     `json:"last_processed_time"`
	Uptime            time.Duration `json:"uptime"`
}

// ProcessingConfig defines configuration for the stream processing engine
type ProcessingConfig struct {
	// Buffer configuration
	BufferSize   int           `json:"buffer_size" yaml:"buffer_size"`
	BatchSize    int           `json:"batch_size" yaml:"batch_size"`
	BatchTimeout time.Duration `json:"batch_timeout" yaml:"batch_timeout"`

	// Worker configuration
	WorkerCount     int `json:"worker_count" yaml:"worker_count"`
	WorkerQueueSize int `json:"worker_queue_size" yaml:"worker_queue_size"`

	// Performance configuration
	MaxLatency       time.Duration `json:"max_latency" yaml:"max_latency"`
	TargetThroughput int           `json:"target_throughput" yaml:"target_throughput"`

	// Correlation configuration
	CorrelationWindow    time.Duration `json:"correlation_window" yaml:"correlation_window"`
	MaxCorrelationEvents int           `json:"max_correlation_events" yaml:"max_correlation_events"`

	// Memory limits
	MaxMemoryUsage int64 `json:"max_memory_usage" yaml:"max_memory_usage"`

	// Feature flags
	EnablePatternMatching  bool `json:"enable_pattern_matching" yaml:"enable_pattern_matching"`
	EnableEventCorrelation bool `json:"enable_event_correlation" yaml:"enable_event_correlation"`
	EnableMetrics          bool `json:"enable_metrics" yaml:"enable_metrics"`

	// Tenant isolation
	TenantID string `json:"tenant_id,omitempty" yaml:"tenant_id,omitempty"`
}
