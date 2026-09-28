// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package logging - Dependency injection mechanisms for module logging integration
package logging

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// ModuleLogger provides a specialized logger interface for CFGMS modules
// It automatically adds module-specific context and integrates with the global provider system
//
// A ModuleLogger is immutable once returned by a constructor or a With* method, which
// is what makes it safe to share one instance across goroutines. defaultFields is
// never written after the logger is published: every With* method derives a new
// ModuleLogger over a copied map (see derive). Before that, WithTenant/WithField wrote
// straight into the receiver's map, so a component that held one logger and called
// `sp.logger.WithTenant(id)` from two goroutines — the shape of every Start method that
// spawns workers, e.g. SIEMProcessor.Start and CronScheduler.Start — performed
// concurrent map writes against it, while logWithProvider ranged over the same map from
// a third. That was latent only because the tenant ID was always empty (Issue #4326) and
// the `tenantID != ""` guard skipped the write; returning a real tenant made it fire
// under -race. Mutating the shared receiver also leaked tenancy: a tenant_id written by
// one request stayed on the shared logger and tagged the next tenant's log lines.
type ModuleLogger struct {
	moduleName     string
	component      string
	defaultFields  map[string]interface{}
	manager        *LoggingManager
	fallbackLogger Logger // Legacy logger for fallback
}

// NewModuleLogger creates a logger specifically configured for a CFGMS module
func NewModuleLogger(moduleName, component string) *ModuleLogger {
	// Get global manager if available
	manager := GetGlobalLoggingManager()

	// Create fallback logger for compatibility. Same level sourcing as
	// LoggerFactory.CreateLogger: a hardcoded InfoLevel here silently discarded
	// Debug records whenever the provider path was unavailable.
	fallback := NewLoggerWithConfig(configuredLoggerConfig("cfgms", component))

	return &ModuleLogger{
		moduleName: moduleName,
		component:  component,
		defaultFields: map[string]interface{}{
			"module":    moduleName,
			"component": component,
		},
		manager:        manager,
		fallbackLogger: fallback,
	}
}

// derive returns a copy of ml carrying an independent defaultFields map, so that the
// caller can add fields to the copy without writing to a map the receiver — which may
// be shared with other goroutines — is still reading from. Sized for one extra entry
// because every caller is about to add at least one field.
func (ml *ModuleLogger) derive() *ModuleLogger {
	fields := make(map[string]interface{}, len(ml.defaultFields)+1)
	for key, value := range ml.defaultFields {
		fields[key] = value
	}

	return &ModuleLogger{
		moduleName:     ml.moduleName,
		component:      ml.component,
		defaultFields:  fields,
		manager:        ml.manager,
		fallbackLogger: ml.fallbackLogger,
	}
}

// WithField returns a derived logger that includes the field in all of its log entries.
// The receiver is left unchanged; use the returned logger.
func (ml *ModuleLogger) WithField(key string, value interface{}) *ModuleLogger {
	derived := ml.derive()
	derived.defaultFields[key] = value
	return derived
}

// WithFields returns a derived logger that includes the fields in all of its log
// entries. The receiver is left unchanged; use the returned logger.
func (ml *ModuleLogger) WithFields(fields map[string]interface{}) *ModuleLogger {
	derived := ml.derive()
	for key, value := range fields {
		derived.defaultFields[key] = value
	}
	return derived
}

// WithTenant returns a derived logger that tags all of its log entries with the tenant
// (for multi-tenant logging). The receiver is left unchanged; use the returned logger.
// An empty tenant ID adds no tenancy and returns the receiver, which callers that cannot
// resolve a tenant rely on — it is not an authorization decision either way, see
// ExtractTenantFromContext.
func (ml *ModuleLogger) WithTenant(tenantID string) *ModuleLogger {
	if tenantID == "" {
		return ml
	}

	derived := ml.derive()
	derived.defaultFields["tenant_id"] = tenantID
	return derived
}

// WithSession returns a derived logger that tags all of its log entries with the
// session. The receiver is left unchanged; use the returned logger.
func (ml *ModuleLogger) WithSession(sessionID string) *ModuleLogger {
	if sessionID == "" {
		return ml
	}

	derived := ml.derive()
	derived.defaultFields["session_id"] = sessionID
	return derived
}

// logWithProvider logs using the global provider system with module context
func (ml *ModuleLogger) logWithProvider(ctx context.Context, level, message string, keysAndValues ...interface{}) error {
	if ml.manager == nil {
		return fmt.Errorf("global logging manager not available")
	}

	// Convert keysAndValues to map and merge with default fields
	fields := keysAndValuesToMap(keysAndValues)

	// Add default module fields (don't override if already present)
	for key, value := range ml.defaultFields {
		if _, exists := fields[key]; !exists {
			fields[key] = value
		}
	}

	// Create log entry
	entry := interfaces.LogEntry{
		Level:   level,
		Message: message,
		Fields:  fields,
	}

	// Add component info if not already set by global manager
	if entry.ServiceName == "" {
		entry.ServiceName = "cfgms"
	}
	if entry.Component == "" {
		entry.Component = ml.component
	}

	// Extract special fields and set them directly on the LogEntry
	if tenantID, ok := ml.defaultFields["tenant_id"].(string); ok && tenantID != "" {
		entry.TenantID = tenantID
		// Remove from fields to avoid duplication
		delete(fields, "tenant_id")
	}

	if sessionID, ok := ml.defaultFields["session_id"].(string); ok && sessionID != "" {
		entry.SessionID = sessionID
		// Remove from fields to avoid duplication
		delete(fields, "session_id")
	}

	return ml.manager.WriteEntry(ctx, entry)
}

// Debug logs a debug message with module context
func (ml *ModuleLogger) Debug(msg string, keysAndValues ...interface{}) {
	ml.DebugCtx(context.Background(), msg, keysAndValues...)
}

// Info logs an info message with module context
func (ml *ModuleLogger) Info(msg string, keysAndValues ...interface{}) {
	ml.InfoCtx(context.Background(), msg, keysAndValues...)
}

// Warn logs a warning message with module context
func (ml *ModuleLogger) Warn(msg string, keysAndValues ...interface{}) {
	ml.WarnCtx(context.Background(), msg, keysAndValues...)
}

// Error logs an error message with module context
func (ml *ModuleLogger) Error(msg string, keysAndValues ...interface{}) {
	ml.ErrorCtx(context.Background(), msg, keysAndValues...)
}

// Fatal logs a fatal message with module context
func (ml *ModuleLogger) Fatal(msg string, keysAndValues ...interface{}) {
	ml.FatalCtx(context.Background(), msg, keysAndValues...)
}

// DebugCtx logs a debug message with context and module context
func (ml *ModuleLogger) DebugCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	// Try provider system first
	if err := ml.logWithProvider(ctx, "DEBUG", msg, keysAndValues...); err != nil {
		// Fallback to legacy logger
		ml.fallbackLogger.DebugCtx(ctx, msg, keysAndValues...)
	}
}

// InfoCtx logs an info message with context and module context
func (ml *ModuleLogger) InfoCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	// Try provider system first
	if err := ml.logWithProvider(ctx, "INFO", msg, keysAndValues...); err != nil {
		// Fallback to legacy logger
		ml.fallbackLogger.InfoCtx(ctx, msg, keysAndValues...)
	}
}

// WarnCtx logs a warning message with context and module context
func (ml *ModuleLogger) WarnCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	// Try provider system first
	if err := ml.logWithProvider(ctx, "WARN", msg, keysAndValues...); err != nil {
		// Fallback to legacy logger
		ml.fallbackLogger.WarnCtx(ctx, msg, keysAndValues...)
	}
}

// ErrorCtx logs an error message with context and module context
func (ml *ModuleLogger) ErrorCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	// Try provider system first
	if err := ml.logWithProvider(ctx, "ERROR", msg, keysAndValues...); err != nil {
		// Fallback to legacy logger
		ml.fallbackLogger.ErrorCtx(ctx, msg, keysAndValues...)
	}
}

// FatalCtx logs a fatal message with context and module context
func (ml *ModuleLogger) FatalCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	// Try provider system first
	if err := ml.logWithProvider(ctx, "FATAL", msg, keysAndValues...); err != nil {
		// Fallback to legacy logger
		ml.fallbackLogger.FatalCtx(ctx, msg, keysAndValues...)
		return
	}

	// If provider system is available, we still need to exit for fatal logs
	if ml.manager != nil {
		// Flush any pending logs before exiting
		if err := ml.manager.Flush(context.Background()); err != nil {
			fmt.Printf("Warning: failed to flush logs before fatal exit: %v\n", err)
		}
	}

	// Exit for fatal logs
	os.Exit(1)
}

// GetUnderlyingLogger returns the underlying Logger interface for compatibility
// This allows ModuleLogger to be used where the legacy Logger interface is expected
func (ml *ModuleLogger) GetUnderlyingLogger() Logger {
	return ml.fallbackLogger
}

// IsProviderAvailable returns true if the global logging provider system is available
func (ml *ModuleLogger) IsProviderAvailable() bool {
	return ml.manager != nil
}

// Flush forces any buffered log entries to be written (if provider supports it)
func (ml *ModuleLogger) Flush(ctx context.Context) error {
	if ml.manager != nil {
		return ml.manager.Flush(ctx)
	}
	return nil
}

// LoggerFactory provides factory methods for creating properly configured loggers
type LoggerFactory struct {
	defaultServiceName string
	defaultComponent   string
}

// NewLoggerFactory creates a new logger factory with default service and component names
func NewLoggerFactory(serviceName, component string) *LoggerFactory {
	return &LoggerFactory{
		defaultServiceName: serviceName,
		defaultComponent:   component,
	}
}

// CreateModuleLogger creates a logger for a specific module
func (lf *LoggerFactory) CreateModuleLogger(moduleName string) *ModuleLogger {
	return NewModuleLogger(moduleName, lf.defaultComponent)
}

// CreateComponentLogger creates a logger for a specific component
func (lf *LoggerFactory) CreateComponentLogger(componentName string) *ModuleLogger {
	return NewModuleLogger(componentName, componentName)
}

// CreateLogger creates a legacy Logger interface for backward compatibility.
//
// The level comes from the initialised global logging manager when there is
// one. DefaultConfig hardcodes InfoLevel, and DefaultLogger.logEntry drops
// anything below its own level before the entry ever reaches the manager — so
// every logger built from this factory discarded Debug records no matter what
// the operator configured. The controller passes exactly such a logger into its
// server and HA subsystem, which is why an HA cluster configured with
// `logging.level: DEBUG` still emitted nothing below INFO.
func (lf *LoggerFactory) CreateLogger() Logger {
	return NewLoggerWithConfig(configuredLoggerConfig(lf.defaultServiceName, lf.defaultComponent))
}

// configuredLoggerConfig returns a logger Config seeded from the global logging
// manager's configured level, falling back to DefaultConfig when no manager has
// been initialised yet.
func configuredLoggerConfig(serviceName, component string) *Config {
	cfg := DefaultConfig(serviceName, component)
	if manager := GetGlobalLoggingManager(); manager != nil {
		if managerCfg := manager.GetConfig(); managerCfg != nil && managerCfg.Level != "" {
			cfg.Level = parseLevel(managerCfg.Level)
		}
	}
	return cfg
}

// Global factory instance for convenience.
//
// factoryMutex guards it. Every exported convenience function in this file
// (ForModule, ForComponent, GetLogger) funnels through GetGlobalLoggerFactory, which
// lazily initialises the global on first use — so two goroutines constructing loggers
// concurrently raced on the nil check and the assignment. This is the same guard
// GetGlobalLoggingManager already applies to globalManager (manager.go:122); the
// factory was the one global here left unprotected.
var (
	factoryMutex        sync.RWMutex
	globalLoggerFactory *LoggerFactory
)

// InitializeGlobalLoggerFactory initializes the global logger factory
func InitializeGlobalLoggerFactory(serviceName, component string) {
	// Construct outside the lock: NewLoggerFactory reads configuration and must not
	// run while writers are blocked behind it.
	factory := NewLoggerFactory(serviceName, component)

	factoryMutex.Lock()
	defer factoryMutex.Unlock()
	globalLoggerFactory = factory
}

// GetGlobalLoggerFactory returns the global logger factory, creating a default one on
// first use. Safe for concurrent use.
func GetGlobalLoggerFactory() *LoggerFactory {
	factoryMutex.RLock()
	factory := globalLoggerFactory
	factoryMutex.RUnlock()
	if factory != nil {
		return factory
	}

	factoryMutex.Lock()
	defer factoryMutex.Unlock()
	// Re-check: another goroutine may have initialised it between the read unlock and
	// the write lock.
	if globalLoggerFactory == nil {
		// Create default factory if none exists
		globalLoggerFactory = NewLoggerFactory("cfgms", "unknown")
	}
	return globalLoggerFactory
}

// Convenience functions using the global factory

// ForModule creates a logger for the specified module using the global factory
func ForModule(moduleName string) *ModuleLogger {
	return GetGlobalLoggerFactory().CreateModuleLogger(moduleName)
}

// ForComponent creates a logger for the specified component using the global factory
func ForComponent(componentName string) *ModuleLogger {
	return GetGlobalLoggerFactory().CreateComponentLogger(componentName)
}

// GetLogger creates a legacy logger using the global factory (for backward compatibility)
func GetLogger() Logger {
	return GetGlobalLoggerFactory().CreateLogger()
}

// Context utility functions for structured logging

// ExtractTenantFromContext reads the tenant ID from ctxkeys.TenantID for tagging
// log lines. It is a logging convenience only — never use its return value for an
// authorization decision (Issue #4326). A caller making an authorization decision
// must read ctxkeys.TenantID directly and fail closed when it is absent;
// make check-architecture's TestNoLoggingTenantForAuthorization fails the build if
// this accessor's result feeds a tenant-equality check anywhere outside pkg/logging.
func ExtractTenantFromContext(ctx context.Context) string {
	return extractTenantID(ctx)
}

// WithTenant adds the tenant ID to context under ctxkeys.TenantID for downstream
// logging, mirroring WithCorrelation's use of ctxkeys.CorrelationIDKey below — both
// store under the single canonical key their respective packages share, rather than
// a package-local key that authentication middleware and consumers could never agree
// on (Issue #4326).
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, ctxkeys.TenantID, tenantID)
}

// WithSession adds session ID to context for downstream logging
func WithSession(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionIDKey{}, sessionID)
}

// WithCorrelation adds correlation ID to context for downstream logging
func WithCorrelation(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, ctxkeys.CorrelationIDKey, correlationID)
}

// WithOperation adds operation context for structured logging
func WithOperation(ctx context.Context, operation string) context.Context {
	return context.WithValue(ctx, operationKey{}, operation)
}

// ExtractOperation extracts operation from context
func ExtractOperation(ctx context.Context) string {
	if value := ctx.Value(operationKey{}); value != nil {
		if operation, ok := value.(string); ok {
			return operation
		}
	}
	return ""
}
