// Package logging - Dependency injection mechanisms for module logging integration
package logging

import (
	"context"
	"fmt"
	"os"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// ModuleLogger provides a specialized logger interface for CFGMS modules
// It automatically adds module-specific context and integrates with the global provider system
type ModuleLogger struct {
	moduleName      string
	component       string
	defaultFields   map[string]interface{}
	manager         *LoggingManager
	fallbackLogger  Logger // Legacy logger for fallback
}

// NewModuleLogger creates a logger specifically configured for a CFGMS module
func NewModuleLogger(moduleName, component string) *ModuleLogger {
	// Get global manager if available
	manager := GetGlobalLoggingManager()
	
	// Create fallback logger for compatibility
	fallback := NewLoggerWithConfig(DefaultConfig("cfgms", component))
	
	logger := &ModuleLogger{
		moduleName:     moduleName,
		component:      component,
		defaultFields:  make(map[string]interface{}),
		manager:        manager,
		fallbackLogger: fallback,
	}
	
	// Set default fields for the module
	logger.defaultFields["module"] = moduleName
	logger.defaultFields["component"] = component
	
	return logger
}

// WithField adds a default field that will be included in all log entries from this module
func (ml *ModuleLogger) WithField(key string, value interface{}) *ModuleLogger {
	ml.defaultFields[key] = value
	return ml
}

// WithFields adds multiple default fields that will be included in all log entries from this module  
func (ml *ModuleLogger) WithFields(fields map[string]interface{}) *ModuleLogger {
	for key, value := range fields {
		ml.defaultFields[key] = value
	}
	return ml
}

// WithTenant adds tenant context to all log entries from this module (for multi-tenant logging)
func (ml *ModuleLogger) WithTenant(tenantID string) *ModuleLogger {
	if tenantID != "" {
		ml.defaultFields["tenant_id"] = tenantID
	}
	return ml
}

// WithSession adds session context to all log entries from this module
func (ml *ModuleLogger) WithSession(sessionID string) *ModuleLogger {
	if sessionID != "" {
		ml.defaultFields["session_id"] = sessionID
	}
	return ml
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

// CreateLogger creates a legacy Logger interface for backward compatibility
func (lf *LoggerFactory) CreateLogger() Logger {
	return NewLoggerWithConfig(DefaultConfig(lf.defaultServiceName, lf.defaultComponent))
}

// Global factory instance for convenience
var globalLoggerFactory *LoggerFactory

// InitializeGlobalLoggerFactory initializes the global logger factory
func InitializeGlobalLoggerFactory(serviceName, component string) {
	globalLoggerFactory = NewLoggerFactory(serviceName, component)
}

// GetGlobalLoggerFactory returns the global logger factory
func GetGlobalLoggerFactory() *LoggerFactory {
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

// ExtractTenantFromContext extracts tenant ID from context for external use
func ExtractTenantFromContext(ctx context.Context) string {
	return extractTenantID(ctx)
}

// WithTenant adds tenant ID to context for downstream logging
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDKey{}, tenantID)
}

// WithSession adds session ID to context for downstream logging
func WithSession(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionIDKey{}, sessionID)
}

// WithCorrelation adds correlation ID to context for downstream logging
func WithCorrelation(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, correlationIDKey{}, correlationID)
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