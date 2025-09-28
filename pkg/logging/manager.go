// Package logging - Global logging provider manager for CFGMS time-series logging
package logging

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
	"github.com/cfgis/cfgms/pkg/logging/subscribers/syslog"
)

// LoggingManager manages the global logging provider and subscribers
// for all CFGMS components to write structured logs
type LoggingManager struct {
	provider         interfaces.LoggingProvider
	subscribers      []interfaces.LoggingSubscriber
	config          *LoggingConfig
	batchBuffer     []interfaces.LogEntry
	batchMutex      sync.Mutex
	stopBatching    chan struct{}
	
	// Event subscriber support
	eventChan       chan interfaces.LogEntry
	stopEvents      chan struct{}
	
	initialized     bool
	defaultFields   map[string]interface{}
}

// LoggingConfig holds configuration for the logging system
type LoggingConfig struct {
	// Provider selection
	Provider string                 `yaml:"provider" json:"provider"`             // Provider name (e.g., "file", "timescale")
	Config   map[string]interface{} `yaml:"config" json:"config"`                 // Provider-specific configuration
	
	// Global logging settings
	Level         string        `yaml:"level" json:"level"`                       // Minimum log level (DEBUG, INFO, WARN, ERROR, FATAL)
	ServiceName   string        `yaml:"service_name" json:"service_name"`         // Service identifier
	Component     string        `yaml:"component" json:"component"`               // Component identifier
	
	// Performance settings
	BatchSize      int           `yaml:"batch_size" json:"batch_size"`             // Batch size for bulk writes
	FlushInterval  time.Duration `yaml:"flush_interval" json:"flush_interval"`     // Auto-flush interval
	AsyncWrites    bool          `yaml:"async_writes" json:"async_writes"`         // Enable asynchronous writes
	BufferSize     int           `yaml:"buffer_size" json:"buffer_size"`           // Internal buffer size
	
	// Retention settings (provider-dependent)
	RetentionDays  int           `yaml:"retention_days" json:"retention_days"`     // Log retention period
	CompressLogs   bool          `yaml:"compress_logs" json:"compress_logs"`       // Enable log compression
	
	// Multi-tenant settings
	TenantIsolation bool         `yaml:"tenant_isolation" json:"tenant_isolation"` // Enable tenant isolation in logs
	
	// Enhanced correlation tracking
	EnableCorrelation bool        `yaml:"enable_correlation" json:"enable_correlation"` // Enable automatic correlation IDs
	EnableTracing     bool        `yaml:"enable_tracing" json:"enable_tracing"`         // Enable OpenTelemetry integration
	
	// Event subscriber configuration (optional)
	Subscribers []SubscriberConfig `yaml:"subscribers" json:"subscribers"` // Event subscribers for real-time forwarding
}

// SubscriberConfig holds configuration for event subscribers
type SubscriberConfig struct {
	Type    string                 `yaml:"type" json:"type"`       // Subscriber type (e.g., "syslog", "webhook")
	Config  map[string]interface{} `yaml:"config" json:"config"`   // Subscriber-specific configuration
	Enabled bool                  `yaml:"enabled" json:"enabled"` // Enable/disable subscriber
}

// DefaultLoggingConfig returns a sensible default configuration
func DefaultLoggingConfig(serviceName, component string) *LoggingConfig {
	return &LoggingConfig{
		Provider:          "file",         // Default to file-based logging
		Config:            make(map[string]interface{}),
		Level:             "INFO",
		ServiceName:       serviceName,
		Component:         component,
		BatchSize:         100,
		FlushInterval:     5 * time.Second,
		AsyncWrites:       true,
		BufferSize:        1000,
		RetentionDays:     30,
		CompressLogs:      true,
		TenantIsolation:   true,
		EnableCorrelation: true,
		EnableTracing:     true,
	}
}

// GlobalLoggingManager is the singleton instance for global logging
var (
	globalManager *LoggingManager
	managerMutex  sync.RWMutex
)

// InitializeGlobalLogging initializes the global logging provider system
func InitializeGlobalLogging(config *LoggingConfig) error {
	managerMutex.Lock()
	defer managerMutex.Unlock()
	
	if globalManager != nil && globalManager.initialized {
		// Close existing provider before initializing new one
		if err := globalManager.Close(); err != nil {
			fmt.Printf("Warning: failed to close existing logging provider: %v\n", err)
		}
	}
	
	manager, err := NewLoggingManager(config)
	if err != nil {
		return fmt.Errorf("failed to create logging manager: %w", err)
	}
	
	globalManager = manager
	return nil
}

// GetGlobalLoggingManager returns the global logging manager
func GetGlobalLoggingManager() *LoggingManager {
	managerMutex.RLock()
	defer managerMutex.RUnlock()
	return globalManager
}

// NewLoggingManager creates a new logging manager with the specified configuration
func NewLoggingManager(config *LoggingConfig) (*LoggingManager, error) {
	if config == nil {
		config = DefaultLoggingConfig("cfgms", "unknown")
	}
	
	// Create the logging provider
	provider, err := interfaces.CreateLoggingProviderFromConfig(config.Provider, config.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to create logging provider: %w", err)
	}
	
	// Create manager
	manager := &LoggingManager{
		provider:      provider,
		subscribers:   make([]interfaces.LoggingSubscriber, 0),
		config:        config,
		batchBuffer:   make([]interfaces.LogEntry, 0, config.BatchSize),
		stopBatching:  make(chan struct{}),
		defaultFields: make(map[string]interface{}),
	}
	
	// Set default fields
	manager.defaultFields["service_name"] = config.ServiceName
	manager.defaultFields["component"] = config.Component
	
	// Initialize subscribers
	if err := manager.initializeSubscribers(); err != nil {
		_ = provider.Close() // Clean up provider if subscriber initialization fails
		return nil, fmt.Errorf("failed to initialize subscribers: %w", err)
	}
	
	// Initialize event channels only if we have subscribers
	if len(manager.subscribers) > 0 {
		manager.eventChan = make(chan interfaces.LogEntry, config.BufferSize)
		manager.stopEvents = make(chan struct{})
		go manager.eventLoop()
	}
	
	// Start batching routine if async writes are enabled
	if config.AsyncWrites && config.BatchSize > 1 {
		go manager.batchingRoutine()
	}
	
	manager.initialized = true
	return manager, nil
}

// WriteEntry writes a single log entry using the global provider
func (m *LoggingManager) WriteEntry(ctx context.Context, entry interfaces.LogEntry) error {
	if !m.initialized {
		return fmt.Errorf("logging manager not initialized")
	}
	
	// Enhance entry with default fields
	m.enhanceLogEntry(&entry, ctx)
	
	// Check log level filtering
	if !m.shouldLog(entry.Level) {
		return nil
	}
	
	var err error
	
	// Use batching for async writes
	if m.config.AsyncWrites && m.config.BatchSize > 1 {
		err = m.addToBatch(entry)
	} else {
		// Direct write for synchronous mode
		err = m.provider.WriteEntry(ctx, entry)
	}
	
	// If primary storage succeeded, notify subscribers (best effort)
	if err == nil && len(m.subscribers) > 0 && m.eventChan != nil {
		select {
		case m.eventChan <- entry:
			// Event queued for subscribers
		default:
			// Buffer full, drop event (primary storage still succeeded)
		}
	}
	
	return err
}

// WriteBatch writes multiple log entries efficiently
func (m *LoggingManager) WriteBatch(ctx context.Context, entries []interfaces.LogEntry) error {
	if !m.initialized {
		return fmt.Errorf("logging manager not initialized")
	}
	
	// Enhance all entries
	filteredEntries := make([]interfaces.LogEntry, 0, len(entries))
	for _, entry := range entries {
		m.enhanceLogEntry(&entry, ctx)
		if m.shouldLog(entry.Level) {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	
	if len(filteredEntries) == 0 {
		return nil
	}
	
	return m.provider.WriteBatch(ctx, filteredEntries)
}

// QueryTimeRange queries log entries within a time range
func (m *LoggingManager) QueryTimeRange(ctx context.Context, query interfaces.TimeRangeQuery) ([]interfaces.LogEntry, error) {
	if !m.initialized {
		return nil, fmt.Errorf("logging manager not initialized")
	}
	
	return m.provider.QueryTimeRange(ctx, query)
}

// QueryCount returns count of log entries matching criteria
func (m *LoggingManager) QueryCount(ctx context.Context, query interfaces.CountQuery) (int64, error) {
	if !m.initialized {
		return 0, fmt.Errorf("logging manager not initialized")
	}
	
	return m.provider.QueryCount(ctx, query)
}

// GetStats returns operational statistics
func (m *LoggingManager) GetStats(ctx context.Context) (interfaces.ProviderStats, error) {
	if !m.initialized {
		return interfaces.ProviderStats{}, fmt.Errorf("logging manager not initialized")
	}
	
	return m.provider.GetStats(ctx)
}

// Flush forces all pending writes to be committed
func (m *LoggingManager) Flush(ctx context.Context) error {
	if !m.initialized {
		return fmt.Errorf("logging manager not initialized")
	}
	
	// Flush any pending batch
	if err := m.flushBatch(ctx); err != nil {
		return err
	}
	
	return m.provider.Flush(ctx)
}

// Close shuts down the logging manager
func (m *LoggingManager) Close() error {
	if !m.initialized {
		return nil
	}
	
	// Stop batching routine
	if m.stopBatching != nil {
		close(m.stopBatching)
	}
	
	// Stop event loop for subscribers
	if m.stopEvents != nil {
		close(m.stopEvents)
	}
	
	// Close all subscribers
	for _, subscriber := range m.subscribers {
		if err := subscriber.Close(); err != nil {
			fmt.Printf("Warning: failed to close subscriber %s: %v\n", subscriber.Name(), err)
		}
	}
	
	// Flush any remaining entries
	if err := m.flushBatch(context.Background()); err != nil {
		fmt.Printf("Warning: failed to flush batch during shutdown: %v\n", err)
	}
	
	// Close provider
	if err := m.provider.Close(); err != nil {
		return fmt.Errorf("failed to close logging provider: %w", err)
	}
	
	m.initialized = false
	return nil
}

// GetProvider returns the underlying logging provider
func (m *LoggingManager) GetProvider() interfaces.LoggingProvider {
	return m.provider
}

// GetConfig returns the logging configuration
func (m *LoggingManager) GetConfig() *LoggingConfig {
	return m.config
}

// SetDefaultField sets a default field that will be added to all log entries
func (m *LoggingManager) SetDefaultField(key string, value interface{}) {
	m.defaultFields[key] = value
}

// enhanceLogEntry adds default fields and correlation information to log entries
func (m *LoggingManager) enhanceLogEntry(entry *interfaces.LogEntry, ctx context.Context) {
	// Set timestamp if not already set
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	
	// Add default fields
	if entry.Fields == nil {
		entry.Fields = make(map[string]interface{})
	}
	
	// Add service and component if not already set
	if entry.ServiceName == "" {
		entry.ServiceName = m.config.ServiceName
	}
	
	if entry.Component == "" {
		entry.Component = m.config.Component
	}
	
	// Add correlation information if enabled and context is available
	if m.config.EnableCorrelation && ctx != nil {
		if entry.CorrelationID == "" {
			entry.CorrelationID = extractCorrelationID(ctx)
		}
		
		if m.config.EnableTracing {
			if entry.TraceID == "" || entry.SpanID == "" {
				traceID, spanID := extractTraceInfo(ctx)
				if entry.TraceID == "" {
					entry.TraceID = traceID
				}
				if entry.SpanID == "" {
					entry.SpanID = spanID
				}
			}
		}
	}
	
	// Add tenant isolation if enabled
	if m.config.TenantIsolation && entry.TenantID == "" {
		// Try to extract tenant ID from context
		if tenantID := extractTenantID(ctx); tenantID != "" {
			entry.TenantID = tenantID
		}
	}

	// Extract session ID from context if not already set
	if entry.SessionID == "" && ctx != nil {
		if sessionID := extractSessionID(ctx); sessionID != "" {
			entry.SessionID = sessionID
		}
	}

	// Extract operation from context and add to fields if not present
	if ctx != nil {
		if operation := extractOperationFromContext(ctx); operation != "" {
			if _, exists := entry.Fields["operation"]; !exists {
				entry.Fields["operation"] = operation
			}
		}
	}

	// Merge default fields (don't override existing fields)
	for key, value := range m.defaultFields {
		if _, exists := entry.Fields[key]; !exists {
			entry.Fields[key] = value
		}
	}
}

// shouldLog checks if the entry should be logged based on configured level
func (m *LoggingManager) shouldLog(level string) bool {
	levelPriority := map[string]int{
		"DEBUG": 0,
		"INFO":  1,
		"WARN":  2,
		"ERROR": 3,
		"FATAL": 4,
	}
	
	configuredLevel := levelPriority[m.config.Level]
	entryLevel := levelPriority[level]
	
	return entryLevel >= configuredLevel
}

// addToBatch adds an entry to the batch buffer
func (m *LoggingManager) addToBatch(entry interfaces.LogEntry) error {
	m.batchMutex.Lock()
	defer m.batchMutex.Unlock()
	
	m.batchBuffer = append(m.batchBuffer, entry)
	
	// Trigger immediate flush if batch is full
	if len(m.batchBuffer) >= m.config.BatchSize {
		return m.flushBatchLocked(context.Background())
	}
	
	return nil
}

// flushBatch flushes the current batch
func (m *LoggingManager) flushBatch(ctx context.Context) error {
	m.batchMutex.Lock()
	defer m.batchMutex.Unlock()
	
	return m.flushBatchLocked(ctx)
}

// flushBatchLocked flushes the current batch (must be called with lock held)
func (m *LoggingManager) flushBatchLocked(ctx context.Context) error {
	if len(m.batchBuffer) == 0 {
		return nil
	}
	
	// Create copy of batch to avoid holding lock during I/O
	batch := make([]interfaces.LogEntry, len(m.batchBuffer))
	copy(batch, m.batchBuffer)
	
	// Clear buffer
	m.batchBuffer = m.batchBuffer[:0]
	
	// Write batch (release lock during I/O)
	m.batchMutex.Unlock()
	err := m.provider.WriteBatch(ctx, batch)
	m.batchMutex.Lock()
	
	return err
}

// batchingRoutine runs the periodic batch flushing
func (m *LoggingManager) batchingRoutine() {
	ticker := time.NewTicker(m.config.FlushInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if err := m.flushBatch(context.Background()); err != nil {
				fmt.Printf("Warning: failed to flush batch: %v\n", err)
			}
		case <-m.stopBatching:
			// Final flush before stopping
			if err := m.flushBatch(context.Background()); err != nil {
				fmt.Printf("Warning: failed to flush batch during shutdown: %v\n", err)
			}
			return
		}
	}
}

// extractTenantID attempts to extract tenant ID from context
func extractTenantID(ctx context.Context) string {
	// Try to extract tenant ID using the same key as injection.go
	if value := ctx.Value(tenantIDKey{}); value != nil {
		if tenantID, ok := value.(string); ok {
			return tenantID
		}
	}

	// Alternative context keys for backward compatibility
	for _, key := range []interface{}{
		"tenant_id",
		"cfgms_tenant_id",
	} {
		if value := ctx.Value(key); value != nil {
			if tenantID, ok := value.(string); ok {
				return tenantID
			}
		}
	}

	return ""
}

// Global convenience functions that use the global manager

// WriteLog writes a log entry using the global logging manager
func WriteLog(ctx context.Context, level, message string, fields map[string]interface{}) error {
	manager := GetGlobalLoggingManager()
	if manager == nil {
		// Fallback to standard logging if global manager is not initialized
		fmt.Printf("[%s] %s %v\n", level, message, fields)
		return nil
	}
	
	entry := interfaces.LogEntry{
		Level:   level,
		Message: message,
		Fields:  fields,
	}
	
	return manager.WriteEntry(ctx, entry)
}

// Debug writes a debug log entry
func Debug(ctx context.Context, message string, fields map[string]interface{}) error {
	return WriteLog(ctx, "DEBUG", message, fields)
}

// Info writes an info log entry
func Info(ctx context.Context, message string, fields map[string]interface{}) error {
	return WriteLog(ctx, "INFO", message, fields)
}

// Warn writes a warning log entry
func Warn(ctx context.Context, message string, fields map[string]interface{}) error {
	return WriteLog(ctx, "WARN", message, fields)
}

// Error writes an error log entry
func Error(ctx context.Context, message string, fields map[string]interface{}) error {
	return WriteLog(ctx, "ERROR", message, fields)
}

// Fatal writes a fatal log entry
func Fatal(ctx context.Context, message string, fields map[string]interface{}) error {
	return WriteLog(ctx, "FATAL", message, fields)
}

// initializeSubscribers creates and initializes configured subscribers
func (m *LoggingManager) initializeSubscribers() error {
	for i, subscriberConfig := range m.config.Subscribers {
		if !subscriberConfig.Enabled {
			continue // Skip disabled subscribers
		}
		
		subscriber, err := m.createSubscriber(subscriberConfig.Type)
		if err != nil {
			return fmt.Errorf("failed to create subscriber %d (%s): %w", i, subscriberConfig.Type, err)
		}
		
		if err := subscriber.Initialize(subscriberConfig.Config); err != nil {
			return fmt.Errorf("failed to initialize subscriber %d (%s): %w", i, subscriberConfig.Type, err)
		}
		
		m.subscribers = append(m.subscribers, subscriber)
		fmt.Printf("Initialized logging subscriber: %s - %s\n", subscriber.Name(), subscriber.Description())
	}
	
	return nil
}

// createSubscriber creates a subscriber instance by type
func (m *LoggingManager) createSubscriber(subscriberType string) (interfaces.LoggingSubscriber, error) {
	// Check for test mock subscribers first
	if mockFactory != nil {
		if mock, err := mockFactory(subscriberType); err == nil {
			return mock, nil
		}
	}
	
	switch subscriberType {
	case "syslog":
		return syslog.NewSyslogSubscriber(), nil
	default:
		return nil, fmt.Errorf("unknown subscriber type: %s", subscriberType)
	}
}

// mockFactory is used for testing - set to nil in production
var mockFactory func(string) (interfaces.LoggingSubscriber, error)

// eventLoop processes log entries for subscribers in background
func (m *LoggingManager) eventLoop() {
	for {
		select {
		case entry := <-m.eventChan:
			// Send to all subscribers in parallel
			for _, subscriber := range m.subscribers {
				if subscriber.ShouldHandle(entry) {
					go func(s interfaces.LoggingSubscriber) {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						
						if err := s.HandleLogEntry(ctx, entry); err != nil {
							// Log subscriber failure, but don't fail primary logging
							fmt.Printf("Warning: Subscriber %s failed: %v\n", s.Name(), err)
						}
					}(subscriber)
				}
			}
			
		case <-m.stopEvents:
			return
		}
	}
}

// extractSessionID attempts to extract session ID from context
func extractSessionID(ctx context.Context) string {
	if value := ctx.Value(sessionIDKey{}); value != nil {
		if sessionID, ok := value.(string); ok {
			return sessionID
		}
	}

	// Alternative context keys for backward compatibility
	for _, key := range []interface{}{
		"session_id",
		"cfgms_session_id",
	} {
		if value := ctx.Value(key); value != nil {
			if sessionID, ok := value.(string); ok {
				return sessionID
			}
		}
	}

	return ""
}

// extractOperationFromContext attempts to extract operation from context
func extractOperationFromContext(ctx context.Context) string {
	if value := ctx.Value(operationKey{}); value != nil {
		if operation, ok := value.(string); ok {
			return operation
		}
	}

	// Alternative context keys for backward compatibility
	for _, key := range []interface{}{
		"operation",
		"cfgms_operation",
	} {
		if value := ctx.Value(key); value != nil {
			if operation, ok := value.(string); ok {
				return operation
			}
		}
	}

	return ""
}