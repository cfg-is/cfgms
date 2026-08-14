// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package interfaces defines the logging provider system for time-series log data in CFGMS.
//
// This package provides a pluggable logging architecture similar to the storage provider system,
// but optimized for high-volume time-series logging data with different performance characteristics
// than configuration storage.
package interfaces

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// RegistrySink is the minimal logging surface the provider registry needs to
// report registration events.
//
// Declared here rather than reusing pkg/logging.Logger because pkg/logging
// imports THIS package — taking the dependency the other way is an import cycle.
// The method set is a subset of pkg/logging.Logger, so a real Logger satisfies
// this interface implicitly and callers can pass one straight in; that is what
// SetRegistryLogger is for. pkg/storage/interfaces solves the same problem with a
// direct pkg/logging import, which is available to it and not to us.
type RegistrySink interface {
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
}

// noopSink discards registration messages. It is the default deliberately: this
// registry is populated by package init() functions in every binary and in every
// test binary, and the previous default wrote to stdout with fmt.Printf. That put
// provider chatter into the output of every `go test` run — 701 such lines were
// measured being carried through agent context — and a library writing to a
// process's stdout is wrong regardless of who is reading it.
type noopSink struct{}

func (noopSink) Info(string, ...interface{}) {}
func (noopSink) Warn(string, ...interface{}) {}

var (
	registrySinkMu sync.RWMutex
	registrySink   RegistrySink = noopSink{}
)

// SetRegistryLogger routes logging-provider registration messages to a real
// logger. Safe to call concurrently with the Register* functions. Passing nil
// restores the no-op sink rather than panicking on the next registration.
func SetRegistryLogger(l RegistrySink) {
	registrySinkMu.Lock()
	defer registrySinkMu.Unlock()
	if l == nil {
		registrySink = noopSink{}
		return
	}
	registrySink = l
}

func getRegistrySink() RegistrySink {
	registrySinkMu.RLock()
	defer registrySinkMu.RUnlock()
	return registrySink
}

// LoggingProvider defines the interface that all logging backends must implement.
// Unlike storage providers which handle CRUD operations, logging providers are optimized
// for high-volume append-only writes with time-based queries and retention policies.
type LoggingProvider interface {
	// Identification
	Name() string
	Description() string
	Available() (bool, error) // Check dependencies, disk space, connectivity, etc.
	GetVersion() string
	GetCapabilities() LoggingCapabilities

	// Provider lifecycle
	Initialize(config map[string]interface{}) error
	Close() error

	// Core logging operations - optimized for high throughput
	WriteEntry(ctx context.Context, entry LogEntry) error
	WriteBatch(ctx context.Context, entries []LogEntry) error

	// Query operations - optimized for time-range queries
	QueryTimeRange(ctx context.Context, query TimeRangeQuery) ([]LogEntry, error)
	QueryCount(ctx context.Context, query CountQuery) (int64, error)
	QueryLevels(ctx context.Context, query LevelQuery) ([]LogEntry, error)

	// Maintenance operations
	ApplyRetentionPolicy(ctx context.Context, policy RetentionPolicy) error
	GetStats(ctx context.Context) (ProviderStats, error)
	Flush(ctx context.Context) error // Force flush pending writes
}

// LogEntry represents a structured log entry optimized for time-series storage
// with RFC5424 compliance for syslog compatibility
type LogEntry struct {
	// Core fields
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"` // DEBUG, INFO, WARN, ERROR, FATAL
	Message   string    `json:"message"`

	// RFC5424 compliance fields for syslog integration
	Priority int    `json:"priority,omitempty"` // Calculated: facility*8 + severity
	Version  int    `json:"version,omitempty"`  // Always 1 for RFC5424
	Hostname string `json:"hostname,omitempty"` // System hostname
	AppName  string `json:"app_name,omitempty"` // Application name
	ProcID   string `json:"proc_id,omitempty"`  // Process ID
	MsgID    string `json:"msg_id,omitempty"`   // Message type identifier

	// CFGMS context fields - critical for multi-tenant operations
	ServiceName string `json:"service_name,omitempty"` // controller, steward, cfg
	Component   string `json:"component,omitempty"`    // module name, service component
	TenantID    string `json:"tenant_id,omitempty"`    // Multi-tenant isolation

	// Distributed tracing fields
	SessionID     string `json:"session_id,omitempty"`     // Terminal sessions, workflows
	CorrelationID string `json:"correlation_id,omitempty"` // Request correlation
	TraceID       string `json:"trace_id,omitempty"`       // OpenTelemetry trace
	SpanID        string `json:"span_id,omitempty"`        // OpenTelemetry span

	// Structured data - provider-specific optimization
	Fields map[string]interface{} `json:"fields,omitempty"`
}

// TimeRangeQuery represents a time-based query for log entries
type TimeRangeQuery struct {
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Filters   map[string]interface{} `json:"filters,omitempty"`   // Field-based filters
	Limit     int                    `json:"limit,omitempty"`     // Max results (0 = no limit)
	Offset    int                    `json:"offset,omitempty"`    // Pagination offset
	OrderBy   string                 `json:"order_by,omitempty"`  // Field to sort by
	SortDesc  bool                   `json:"sort_desc,omitempty"` // Sort direction
}

// CountQuery represents a query for counting log entries
type CountQuery struct {
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Filters   map[string]interface{} `json:"filters,omitempty"`
	GroupBy   []string               `json:"group_by,omitempty"` // Group count by fields
}

// LevelQuery represents a query filtered by log level
type LevelQuery struct {
	TimeRangeQuery
	Levels []string `json:"levels"` // Filter by specific log levels
}

// RetentionPolicy defines how long to keep log entries
type RetentionPolicy struct {
	RetentionDays   int                        `json:"retention_days"`           // Days to keep logs
	CompressDays    int                        `json:"compress_days,omitempty"`  // Days before compression
	ArchiveDays     int                        `json:"archive_days,omitempty"`   // Days before archiving
	DeleteOlderThan time.Time                  `json:"delete_older_than"`        // Absolute cutoff
	LevelPolicies   map[string]RetentionPolicy `json:"level_policies,omitempty"` // Per-level policies
}

// ProviderStats provides operational statistics for monitoring
type ProviderStats struct {
	TotalEntries     int64     `json:"total_entries"`
	EntriesLastHour  int64     `json:"entries_last_hour"`
	EntriesLastDay   int64     `json:"entries_last_day"`
	StorageSize      int64     `json:"storage_size_bytes"`
	CompressedSize   int64     `json:"compressed_size_bytes,omitempty"`
	OldestEntry      time.Time `json:"oldest_entry"`
	LatestEntry      time.Time `json:"latest_entry"`
	WriteLatencyMs   float64   `json:"write_latency_ms"`   // Average write latency
	QueryLatencyMs   float64   `json:"query_latency_ms"`   // Average query latency
	ErrorRate        float64   `json:"error_rate"`         // Error rate (0.0-1.0)
	DiskUsagePercent float64   `json:"disk_usage_percent"` // Disk usage percentage
}

// LoggingCapabilities describes time-series logging specific capabilities
type LoggingCapabilities struct {
	// Performance characteristics
	SupportsCompression       bool `json:"supports_compression"`
	SupportsRetentionPolicies bool `json:"supports_retention_policies"`
	SupportsRealTimeQueries   bool `json:"supports_real_time_queries"`
	SupportsBatchWrites       bool `json:"supports_batch_writes"`
	SupportsTimeRangeQueries  bool `json:"supports_time_range_queries"`
	SupportsFullTextSearch    bool `json:"supports_full_text_search"`

	// Scale and performance limits
	MaxEntriesPerSecond  int     `json:"max_entries_per_second"` // Theoretical maximum throughput
	MaxBatchSize         int     `json:"max_batch_size"`         // Maximum batch write size
	DefaultRetentionDays int     `json:"default_retention_days"` // Default retention period
	CompressionRatio     float64 `json:"compression_ratio"`      // Expected compression ratio

	// Storage characteristics
	RequiresFlush        bool `json:"requires_flush"`        // Needs explicit flush for durability
	SupportsTransactions bool `json:"supports_transactions"` // ACID transaction support
	SupportsPartitioning bool `json:"supports_partitioning"` // Time-based partitioning
	SupportsIndexing     bool `json:"supports_indexing"`     // Field-based indexing
}

// LoggingSubscriber defines the interface for event-based log subscribers
// Subscribers receive log entries asynchronously for real-time forwarding/processing
type LoggingSubscriber interface {
	// Identification
	Name() string
	Description() string

	// Lifecycle management
	Initialize(config map[string]interface{}) error
	Close() error

	// Event handling - called asynchronously for each log entry
	HandleLogEntry(ctx context.Context, entry LogEntry) error

	// Filtering - determines if subscriber should handle this entry
	ShouldHandle(entry LogEntry) bool

	// Health check
	Available() (bool, error)
}

// SyslogFacility represents syslog facility codes per RFC5424
type SyslogFacility int

const (
	// Standard syslog facilities
	FacilityKernel   SyslogFacility = 0  // kernel messages
	FacilityUser     SyslogFacility = 1  // user-level messages
	FacilityMail     SyslogFacility = 2  // mail system
	FacilityDaemon   SyslogFacility = 3  // system daemons
	FacilitySyslog   SyslogFacility = 5  // messages generated internally by syslogd
	FacilityLPR      SyslogFacility = 6  // line printer subsystem
	FacilityNews     SyslogFacility = 7  // network news subsystem
	FacilityUUCP     SyslogFacility = 8  // UUCP subsystem
	FacilityCron     SyslogFacility = 9  // clock daemon
	FacilityAuthpriv SyslogFacility = 10 // security/authorization messages
	FacilityFTP      SyslogFacility = 11 // FTP daemon
	FacilityLocal0   SyslogFacility = 16 // local use facility 0
	FacilityLocal1   SyslogFacility = 17 // local use facility 1
	FacilityLocal2   SyslogFacility = 18 // local use facility 2
	FacilityLocal3   SyslogFacility = 19 // local use facility 3
	FacilityLocal4   SyslogFacility = 20 // local use facility 4
	FacilityLocal5   SyslogFacility = 21 // local use facility 5
	FacilityLocal6   SyslogFacility = 22 // local use facility 6
	FacilityLocal7   SyslogFacility = 23 // local use facility 7
)

// SyslogSeverity represents syslog severity levels per RFC5424
type SyslogSeverity int

const (
	// Standard syslog severity levels
	SeverityEmergency     SyslogSeverity = 0 // system is unusable
	SeverityAlert         SyslogSeverity = 1 // action must be taken immediately
	SeverityCritical      SyslogSeverity = 2 // critical conditions
	SeverityError         SyslogSeverity = 3 // error conditions
	SeverityWarning       SyslogSeverity = 4 // warning conditions
	SeverityNotice        SyslogSeverity = 5 // normal but significant condition
	SeverityInformational SyslogSeverity = 6 // informational messages
	SeverityDebug         SyslogSeverity = 7 // debug-level messages
)

// LogLevelToSyslogSeverity maps CFGMS log levels to syslog severity.
//
// The comparison is case-insensitive. It previously matched uppercase only and
// fell through to the informational default for anything else, which would
// silently downgrade a lowercase "debug" — the spelling used throughout
// docker-compose.test.yml and operator documentation.
//
// This function has no production callers today; it is exported for syslog
// subscribers and covered by its own test. The case-insensitivity here is
// hardening against that latent trap, not the fix for containers ignoring their
// configured level — that was parseLevel and configuredLoggerConfig in
// pkg/logging, which is where the level actually reaches a logger.
func LogLevelToSyslogSeverity(level string) SyslogSeverity {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "FATAL":
		return SeverityEmergency
	case "ERROR":
		return SeverityError
	case "WARN":
		return SeverityWarning
	case "INFO":
		return SeverityInformational
	case "DEBUG":
		return SeverityDebug
	default:
		return SeverityInformational
	}
}

// CalculateSyslogPriority calculates RFC5424 priority from facility and severity
func CalculateSyslogPriority(facility SyslogFacility, severity SyslogSeverity) int {
	return int(facility)*8 + int(severity)
}

// PopulateRFC5424Fields fills RFC5424 fields in a log entry for syslog compatibility
func PopulateRFC5424Fields(entry *LogEntry, hostname, appName, procID string, facility SyslogFacility) {
	if entry.Version == 0 {
		entry.Version = 1 // RFC5424 version
	}

	if entry.Hostname == "" {
		entry.Hostname = hostname
	}

	if entry.AppName == "" {
		entry.AppName = appName
	}

	if entry.ProcID == "" {
		entry.ProcID = procID
	}

	// Calculate priority from facility and log level
	severity := LogLevelToSyslogSeverity(entry.Level)
	entry.Priority = CalculateSyslogPriority(facility, severity)

	// Generate message ID from component and level
	if entry.MsgID == "" && entry.Component != "" {
		entry.MsgID = fmt.Sprintf("%s_%s", entry.Component, entry.Level)
	}
}

// ToSyslogFormat converts a LogEntry to RFC5424 syslog format
func (entry LogEntry) ToSyslogFormat() string {
	// Format timestamp as RFC3339
	timestamp := entry.Timestamp.Format(time.RFC3339)

	// Build structured data from CFGMS fields
	var structuredData strings.Builder
	structuredData.WriteString("[cfgms")

	if entry.TenantID != "" {
		fmt.Fprintf(&structuredData, ` tenant_id="%s"`, entry.TenantID)
	}
	if entry.SessionID != "" {
		fmt.Fprintf(&structuredData, ` session_id="%s"`, entry.SessionID)
	}
	if entry.CorrelationID != "" {
		fmt.Fprintf(&structuredData, ` correlation_id="%s"`, entry.CorrelationID)
	}
	if entry.TraceID != "" {
		fmt.Fprintf(&structuredData, ` trace_id="%s"`, entry.TraceID)
	}

	// Add custom fields in sorted order for deterministic output
	if len(entry.Fields) > 0 {
		// Get keys and sort them for deterministic output
		keys := make([]string, 0, len(entry.Fields))
		for key := range entry.Fields {
			keys = append(keys, key)
		}
		// Sort keys to ensure deterministic field order
		for i := 0; i < len(keys); i++ {
			for j := i + 1; j < len(keys); j++ {
				if keys[i] > keys[j] {
					keys[i], keys[j] = keys[j], keys[i]
				}
			}
		}

		for _, key := range keys {
			fmt.Fprintf(&structuredData, ` %s="%v"`, key, entry.Fields[key])
		}
	}

	structuredData.WriteString("]")

	// Handle missing fields with defaults
	hostname := entry.Hostname
	if hostname == "" {
		hostname = "-"
	}

	appName := entry.AppName
	if appName == "" {
		appName = entry.ServiceName
		if appName == "" {
			appName = "-"
		}
	}

	procID := entry.ProcID
	if procID == "" {
		procID = "-"
	}

	msgID := entry.MsgID
	if msgID == "" {
		msgID = "-"
	}

	// Format as RFC5424: <PRI>VER TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
	return fmt.Sprintf("<%d>%d %s %s %s %s %s %s %s",
		entry.Priority,
		entry.Version,
		timestamp,
		hostname,
		appName,
		procID,
		msgID,
		structuredData.String(),
		entry.Message)
}

// LoggingProviderFactory creates a fresh, uninitialized LoggingProvider instance.
// Register via RegisterLoggingProviderFactory so CreateLoggingProviderFromConfig
// returns a new instance on each call, preventing multiple LoggingManagers from
// sharing provider state (e.g., initialized flag, file handles) and racing.
type LoggingProviderFactory func() LoggingProvider

// Global logging provider registry (separate from storage providers)
var (
	globalLoggingRegistry = &loggingProviderRegistry{
		providers: make(map[string]LoggingProvider),
		factories: make(map[string]LoggingProviderFactory),
	}
)

type loggingProviderRegistry struct {
	providers map[string]LoggingProvider
	factories map[string]LoggingProviderFactory
	mutex     sync.RWMutex
}

// RegisterLoggingProvider registers a logging provider (called from provider init() functions)
// This function includes validation to ensure providers implement all required interfaces
func RegisterLoggingProvider(provider LoggingProvider) {
	if err := validateLoggingProvider(provider); err != nil {
		// Log the error but don't panic - allows system to start with other providers
		getRegistrySink().Warn(fmt.Sprintf("Failed to register logging provider '%s': %v", provider.Name(), err))
		return
	}

	globalLoggingRegistry.mutex.Lock()
	defer globalLoggingRegistry.mutex.Unlock()

	// Check for duplicate registration
	if existing, exists := globalLoggingRegistry.providers[provider.Name()]; exists {
		getRegistrySink().Warn(fmt.Sprintf("Overwriting existing logging provider '%s' (version %s) with version %s",
			provider.Name(), existing.GetVersion(), provider.GetVersion()))
	}

	globalLoggingRegistry.providers[provider.Name()] = provider
	getRegistrySink().Info(fmt.Sprintf("Registered logging provider: %s v%s - %s",
		provider.Name(), provider.GetVersion(), provider.Description()))
}

// validateLoggingProvider ensures a provider implements all required interfaces correctly
func validateLoggingProvider(provider LoggingProvider) error {
	if provider == nil {
		return fmt.Errorf("provider is nil")
	}

	// Validate basic provider interface
	if provider.Name() == "" {
		return fmt.Errorf("provider name cannot be empty")
	}

	if provider.Description() == "" {
		return fmt.Errorf("provider description cannot be empty")
	}

	if provider.GetVersion() == "" {
		return fmt.Errorf("provider version cannot be empty")
	}

	// Test provider availability (non-blocking)
	if available, err := provider.Available(); !available && err != nil {
		// Provider not available is OK (might need setup), but returning error suggests implementation issue
		getRegistrySink().Info(fmt.Sprintf("Logging provider '%s' reports as unavailable: %v", provider.Name(), err))
	}

	// Validate provider capabilities
	capabilities := provider.GetCapabilities()
	if capabilities.MaxEntriesPerSecond < 0 {
		return fmt.Errorf("provider MaxEntriesPerSecond cannot be negative")
	}

	if capabilities.MaxBatchSize < 0 {
		return fmt.Errorf("provider MaxBatchSize cannot be negative")
	}

	if capabilities.DefaultRetentionDays < 0 {
		return fmt.Errorf("provider DefaultRetentionDays cannot be negative")
	}

	if capabilities.CompressionRatio < 0.0 || capabilities.CompressionRatio > 1.0 {
		return fmt.Errorf("provider CompressionRatio must be between 0.0 and 1.0")
	}

	return nil
}

// RegisterLoggingProviderFactory registers a factory that creates fresh provider instances.
// Preferred over RegisterLoggingProvider when multiple LoggingManager instances may
// use the same provider type — each CreateLoggingProviderFromConfig call returns a
// distinct instance with no shared mutable state.
func RegisterLoggingProviderFactory(factory LoggingProviderFactory) {
	template := factory()
	if template == nil {
		getRegistrySink().Warn("LoggingProviderFactory returned nil instance")
		return
	}
	if err := validateLoggingProvider(template); err != nil {
		getRegistrySink().Warn(fmt.Sprintf("Failed to register logging provider factory '%s': %v", template.Name(), err))
		return
	}

	globalLoggingRegistry.mutex.Lock()
	defer globalLoggingRegistry.mutex.Unlock()

	name := template.Name()
	if existing, exists := globalLoggingRegistry.providers[name]; exists {
		getRegistrySink().Warn(fmt.Sprintf("Overwriting existing logging provider '%s' (version %s) with factory version %s",
			name, existing.GetVersion(), template.GetVersion()))
	}
	// Store the template for capability/availability introspection and the factory for instance creation.
	globalLoggingRegistry.providers[name] = template
	globalLoggingRegistry.factories[name] = factory
	getRegistrySink().Info(fmt.Sprintf("Registered logging provider factory: %s v%s - %s",
		name, template.GetVersion(), template.Description()))
}

// GetLoggingProvider retrieves a registered provider by name.
// For factory-registered providers the returned instance is an uninitialized template used
// only for capability introspection; use CreateLoggingProviderFromConfig to get a usable instance.
func GetLoggingProvider(name string) (LoggingProvider, error) {
	globalLoggingRegistry.mutex.RLock()
	defer globalLoggingRegistry.mutex.RUnlock()

	provider, exists := globalLoggingRegistry.providers[name]
	if !exists {
		return nil, fmt.Errorf("logging provider '%s' not found", name)
	}

	// Factory-registered providers store an uninitialized template; calling Available() on it
	// would always fail because no config has been applied. Skip the check — availability is
	// guaranteed once CreateLoggingProviderFromConfig successfully initializes a fresh instance.
	if _, hasFactory := globalLoggingRegistry.factories[name]; !hasFactory {
		if available, err := provider.Available(); !available {
			return nil, fmt.Errorf("logging provider '%s' not available: %v", name, err)
		}
	}

	return provider, nil
}

// GetRegisteredLoggingProviderNames returns a list of all registered provider names
func GetRegisteredLoggingProviderNames() []string {
	globalLoggingRegistry.mutex.RLock()
	defer globalLoggingRegistry.mutex.RUnlock()

	names := make([]string, 0, len(globalLoggingRegistry.providers))
	for name := range globalLoggingRegistry.providers {
		names = append(names, name)
	}

	return names
}

// GetRegisteredProviders returns a map of all registered providers
func GetRegisteredProviders() map[string]LoggingProvider {
	globalLoggingRegistry.mutex.RLock()
	defer globalLoggingRegistry.mutex.RUnlock()

	// Return a copy to prevent external modification
	providers := make(map[string]LoggingProvider)
	for name, provider := range globalLoggingRegistry.providers {
		providers[name] = provider
	}

	return providers
}

// GetAvailableLoggingProviders returns all providers that are currently available.
// Factory-registered providers are always included because their templates are uninitialized;
// use CreateLoggingProviderFromConfig to obtain a ready-to-use instance.
func GetAvailableLoggingProviders() map[string]LoggingProvider {
	globalLoggingRegistry.mutex.RLock()
	defer globalLoggingRegistry.mutex.RUnlock()

	available := make(map[string]LoggingProvider)
	for name, provider := range globalLoggingRegistry.providers {
		if _, hasFactory := globalLoggingRegistry.factories[name]; hasFactory {
			// Template is uninitialized by design; include it — the factory guarantees
			// a usable instance can be created on demand.
			available[name] = provider
			continue
		}
		if ok, err := provider.Available(); ok && err == nil {
			available[name] = provider
		}
	}

	return available
}

// LoggingProviderInfo provides information about a logging provider
type LoggingProviderInfo struct {
	Name              string              `json:"name"`
	Description       string              `json:"description"`
	Available         bool                `json:"available"`
	UnavailableReason string              `json:"unavailable_reason,omitempty"`
	Version           string              `json:"version"`
	Capabilities      LoggingCapabilities `json:"capabilities"`
}

// ListLoggingProviders returns information about all registered logging providers
func ListLoggingProviders() []LoggingProviderInfo {
	globalLoggingRegistry.mutex.RLock()
	defer globalLoggingRegistry.mutex.RUnlock()

	var providers []LoggingProviderInfo
	for name, provider := range globalLoggingRegistry.providers {
		available, err := provider.Available()

		info := LoggingProviderInfo{
			Name:         name,
			Description:  provider.Description(),
			Available:    available,
			Version:      provider.GetVersion(),
			Capabilities: provider.GetCapabilities(),
		}

		if err != nil {
			info.UnavailableReason = err.Error()
		}

		providers = append(providers, info)
	}

	return providers
}

// CreateLoggingProviderFromConfig creates and initializes a logging provider from configuration.
// When a factory was registered via RegisterLoggingProviderFactory, a fresh instance is created
// on every call so concurrent LoggingManagers each own an independent provider with no shared state.
func CreateLoggingProviderFromConfig(providerName string, config map[string]interface{}) (LoggingProvider, error) {
	globalLoggingRegistry.mutex.RLock()
	factory := globalLoggingRegistry.factories[providerName]
	singleton, exists := globalLoggingRegistry.providers[providerName]
	globalLoggingRegistry.mutex.RUnlock()

	if !exists {
		registeredNames := GetRegisteredLoggingProviderNames()
		return nil, fmt.Errorf("logging provider '%s' not found. Registered providers: %v", providerName, registeredNames)
	}

	// Prefer a factory so each caller gets its own instance with no shared mutable state.
	// Fall back to the singleton for providers registered without a factory (backward compat).
	var instance LoggingProvider
	if factory != nil {
		instance = factory()
	} else {
		instance = singleton
	}

	if err := instance.Initialize(config); err != nil {
		return nil, fmt.Errorf("failed to initialize logging provider '%s': %w", providerName, err)
	}

	if available, err := instance.Available(); !available {
		return nil, fmt.Errorf("logging provider '%s' not available after initialization: %v", providerName, err)
	}

	return instance, nil
}

// UnregisterLoggingProvider removes a provider from the registry (primarily for testing)
func UnregisterLoggingProvider(name string) bool {
	globalLoggingRegistry.mutex.Lock()
	defer globalLoggingRegistry.mutex.Unlock()

	if _, exists := globalLoggingRegistry.providers[name]; exists {
		delete(globalLoggingRegistry.providers, name)
		delete(globalLoggingRegistry.factories, name)
		return true
	}

	return false
}
