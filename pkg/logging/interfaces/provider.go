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
	Level     string    `json:"level"`     // DEBUG, INFO, WARN, ERROR, FATAL
	Message   string    `json:"message"`
	
	// RFC5424 compliance fields for syslog integration
	Priority int    `json:"priority,omitempty"`   // Calculated: facility*8 + severity
	Version  int    `json:"version,omitempty"`    // Always 1 for RFC5424
	Hostname string `json:"hostname,omitempty"`   // System hostname
	AppName  string `json:"app_name,omitempty"`   // Application name
	ProcID   string `json:"proc_id,omitempty"`    // Process ID
	MsgID    string `json:"msg_id,omitempty"`     // Message type identifier
	
	// CFGMS context fields - critical for multi-tenant operations
	ServiceName string `json:"service_name,omitempty"` // controller, steward, cfgctl
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
	StartTime time.Time                  `json:"start_time"`
	EndTime   time.Time                  `json:"end_time"`
	Filters   map[string]interface{}     `json:"filters,omitempty"`    // Field-based filters
	Limit     int                        `json:"limit,omitempty"`      // Max results (0 = no limit)
	Offset    int                        `json:"offset,omitempty"`     // Pagination offset
	OrderBy   string                     `json:"order_by,omitempty"`   // Field to sort by
	SortDesc  bool                      `json:"sort_desc,omitempty"`  // Sort direction
}

// CountQuery represents a query for counting log entries
type CountQuery struct {
	StartTime time.Time                  `json:"start_time"`
	EndTime   time.Time                  `json:"end_time"`
	Filters   map[string]interface{}     `json:"filters,omitempty"`
	GroupBy   []string                   `json:"group_by,omitempty"`   // Group count by fields
}

// LevelQuery represents a query filtered by log level
type LevelQuery struct {
	TimeRangeQuery
	Levels []string `json:"levels"` // Filter by specific log levels
}

// RetentionPolicy defines how long to keep log entries
type RetentionPolicy struct {
	RetentionDays   int                        `json:"retention_days"`             // Days to keep logs
	CompressDays    int                        `json:"compress_days,omitempty"`    // Days before compression
	ArchiveDays     int                        `json:"archive_days,omitempty"`     // Days before archiving
	DeleteOlderThan time.Time                  `json:"delete_older_than"`          // Absolute cutoff
	LevelPolicies   map[string]RetentionPolicy `json:"level_policies,omitempty"`   // Per-level policies
}

// ProviderStats provides operational statistics for monitoring
type ProviderStats struct {
	TotalEntries        int64     `json:"total_entries"`
	EntriesLastHour     int64     `json:"entries_last_hour"`
	EntriesLastDay      int64     `json:"entries_last_day"`
	StorageSize         int64     `json:"storage_size_bytes"`
	CompressedSize      int64     `json:"compressed_size_bytes,omitempty"`
	OldestEntry         time.Time `json:"oldest_entry"`
	LatestEntry         time.Time `json:"latest_entry"`
	WriteLatencyMs      float64   `json:"write_latency_ms"`       // Average write latency
	QueryLatencyMs      float64   `json:"query_latency_ms"`       // Average query latency
	ErrorRate           float64   `json:"error_rate"`             // Error rate (0.0-1.0)
	DiskUsagePercent    float64   `json:"disk_usage_percent"`     // Disk usage percentage
}

// LoggingCapabilities describes time-series logging specific capabilities
type LoggingCapabilities struct {
	// Performance characteristics
	SupportsCompression       bool    `json:"supports_compression"`
	SupportsRetentionPolicies bool    `json:"supports_retention_policies"`
	SupportsRealTimeQueries   bool    `json:"supports_real_time_queries"`
	SupportsBatchWrites       bool    `json:"supports_batch_writes"`
	SupportsTimeRangeQueries  bool    `json:"supports_time_range_queries"`
	SupportsFullTextSearch    bool    `json:"supports_full_text_search"`
	
	// Scale and performance limits
	MaxEntriesPerSecond int     `json:"max_entries_per_second"`     // Theoretical maximum throughput
	MaxBatchSize        int     `json:"max_batch_size"`             // Maximum batch write size
	DefaultRetentionDays int    `json:"default_retention_days"`     // Default retention period
	CompressionRatio    float64 `json:"compression_ratio"`          // Expected compression ratio
	
	// Storage characteristics
	RequiresFlush          bool `json:"requires_flush"`           // Needs explicit flush for durability
	SupportsTransactions   bool `json:"supports_transactions"`    // ACID transaction support
	SupportsPartitioning   bool `json:"supports_partitioning"`   // Time-based partitioning
	SupportsIndexing       bool `json:"supports_indexing"`       // Field-based indexing
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
	FacilityKernel     SyslogFacility = 0  // kernel messages
	FacilityUser       SyslogFacility = 1  // user-level messages  
	FacilityMail       SyslogFacility = 2  // mail system
	FacilityDaemon     SyslogFacility = 3  // system daemons
	FacilitySyslog     SyslogFacility = 5  // messages generated internally by syslogd
	FacilityLPR        SyslogFacility = 6  // line printer subsystem
	FacilityNews       SyslogFacility = 7  // network news subsystem
	FacilityUUCP       SyslogFacility = 8  // UUCP subsystem
	FacilityCron       SyslogFacility = 9  // clock daemon
	FacilityAuthpriv   SyslogFacility = 10 // security/authorization messages
	FacilityFTP        SyslogFacility = 11 // FTP daemon
	FacilityLocal0     SyslogFacility = 16 // local use facility 0
	FacilityLocal1     SyslogFacility = 17 // local use facility 1  
	FacilityLocal2     SyslogFacility = 18 // local use facility 2
	FacilityLocal3     SyslogFacility = 19 // local use facility 3
	FacilityLocal4     SyslogFacility = 20 // local use facility 4
	FacilityLocal5     SyslogFacility = 21 // local use facility 5
	FacilityLocal6     SyslogFacility = 22 // local use facility 6
	FacilityLocal7     SyslogFacility = 23 // local use facility 7
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

// LogLevelToSyslogSeverity maps CFGMS log levels to syslog severity
func LogLevelToSyslogSeverity(level string) SyslogSeverity {
	switch level {
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
		structuredData.WriteString(fmt.Sprintf(` tenant_id="%s"`, entry.TenantID))
	}
	if entry.SessionID != "" {
		structuredData.WriteString(fmt.Sprintf(` session_id="%s"`, entry.SessionID))
	}
	if entry.CorrelationID != "" {
		structuredData.WriteString(fmt.Sprintf(` correlation_id="%s"`, entry.CorrelationID))
	}
	if entry.TraceID != "" {
		structuredData.WriteString(fmt.Sprintf(` trace_id="%s"`, entry.TraceID))
	}
	
	// Add custom fields
	for key, value := range entry.Fields {
		structuredData.WriteString(fmt.Sprintf(` %s="%v"`, key, value))
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

// Global logging provider registry (separate from storage providers)
var (
	globalLoggingRegistry = &loggingProviderRegistry{
		providers: make(map[string]LoggingProvider),
	}
)

type loggingProviderRegistry struct {
	providers map[string]LoggingProvider
	mutex     sync.RWMutex
}

// RegisterLoggingProvider registers a logging provider (called from provider init() functions)
// This function includes validation to ensure providers implement all required interfaces
func RegisterLoggingProvider(provider LoggingProvider) {
	if err := validateLoggingProvider(provider); err != nil {
		// Log the error but don't panic - allows system to start with other providers
		fmt.Printf("Warning: Failed to register logging provider '%s': %v\n", provider.Name(), err)
		return
	}
	
	globalLoggingRegistry.mutex.Lock()
	defer globalLoggingRegistry.mutex.Unlock()
	
	// Check for duplicate registration
	if existing, exists := globalLoggingRegistry.providers[provider.Name()]; exists {
		fmt.Printf("Warning: Overwriting existing logging provider '%s' (version %s) with version %s\n", 
			provider.Name(), existing.GetVersion(), provider.GetVersion())
	}
	
	globalLoggingRegistry.providers[provider.Name()] = provider
	fmt.Printf("Registered logging provider: %s v%s - %s\n", 
		provider.Name(), provider.GetVersion(), provider.Description())
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
		fmt.Printf("Note: Logging provider '%s' reports as unavailable: %v\n", provider.Name(), err)
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

// GetLoggingProvider retrieves a registered provider by name
func GetLoggingProvider(name string) (LoggingProvider, error) {
	globalLoggingRegistry.mutex.RLock()
	defer globalLoggingRegistry.mutex.RUnlock()
	
	provider, exists := globalLoggingRegistry.providers[name]
	if !exists {
		return nil, fmt.Errorf("logging provider '%s' not found", name)
	}
	
	// Check availability
	if available, err := provider.Available(); !available {
		return nil, fmt.Errorf("logging provider '%s' not available: %v", name, err)
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

// GetAvailableLoggingProviders returns all providers that are currently available
func GetAvailableLoggingProviders() map[string]LoggingProvider {
	globalLoggingRegistry.mutex.RLock()
	defer globalLoggingRegistry.mutex.RUnlock()
	
	available := make(map[string]LoggingProvider)
	for name, provider := range globalLoggingRegistry.providers {
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

// CreateLoggingProviderFromConfig creates and initializes a logging provider from configuration
func CreateLoggingProviderFromConfig(providerName string, config map[string]interface{}) (LoggingProvider, error) {
	// Get provider from registry without checking availability (since it's not initialized yet)
	globalLoggingRegistry.mutex.RLock()
	provider, exists := globalLoggingRegistry.providers[providerName]
	globalLoggingRegistry.mutex.RUnlock()
	
	if !exists {
		// Provide helpful error with available options
		registeredNames := GetRegisteredLoggingProviderNames()
		return nil, fmt.Errorf("logging provider '%s' not found. Registered providers: %v", providerName, registeredNames)
	}
	
	// Initialize the provider with the given configuration
	if err := provider.Initialize(config); err != nil {
		return nil, fmt.Errorf("failed to initialize logging provider '%s': %w", providerName, err)
	}
	
	// Now check availability after initialization
	if available, err := provider.Available(); !available {
		return nil, fmt.Errorf("logging provider '%s' not available after initialization: %v", providerName, err)
	}
	
	return provider, nil
}

// UnregisterLoggingProvider removes a provider from the registry (primarily for testing)
func UnregisterLoggingProvider(name string) bool {
	globalLoggingRegistry.mutex.Lock()
	defer globalLoggingRegistry.mutex.Unlock()
	
	if _, exists := globalLoggingRegistry.providers[name]; exists {
		delete(globalLoggingRegistry.providers, name)
		return true
	}
	
	return false
}