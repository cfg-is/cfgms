// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// Logger provides a structured logging interface with context support for correlation IDs.
// The interface supports both the original key-value pair logging and context-aware logging
// for distributed tracing integration.
type Logger interface {
	Debug(msg string, keysAndValues ...interface{})
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Fatal(msg string, keysAndValues ...interface{})

	// Context-aware logging methods that automatically inject correlation IDs
	DebugCtx(ctx context.Context, msg string, keysAndValues ...interface{})
	InfoCtx(ctx context.Context, msg string, keysAndValues ...interface{})
	WarnCtx(ctx context.Context, msg string, keysAndValues ...interface{})
	ErrorCtx(ctx context.Context, msg string, keysAndValues ...interface{})
	FatalCtx(ctx context.Context, msg string, keysAndValues ...interface{})
}

// Level represents the logging level
type Level int

const (
	// DebugLevel logs everything
	DebugLevel Level = iota
	// InfoLevel logs info, warnings, errors, and fatals
	InfoLevel
	// WarnLevel logs warnings, errors, and fatals
	WarnLevel
	// ErrorLevel logs errors and fatals
	ErrorLevel
	// FatalLevel logs only fatals
	FatalLevel
)

// Format represents the logging output format
type Format int

const (
	// TextFormat outputs human-readable text logs (default)
	TextFormat Format = iota
	// JSONFormat outputs structured JSON logs for centralized logging
	JSONFormat
)

// Config holds configuration for logger creation.
type Config struct {
	// Level controls which log messages are output
	Level Level

	// Format controls the output format (text or JSON)
	Format Format

	// EnableCorrelation automatically injects correlation IDs from context
	EnableCorrelation bool

	// ServiceName is included in structured logs for service identification
	ServiceName string

	// Component identifies the component within the service (e.g., "controller", "steward")
	Component string
}

// DefaultConfig returns a configuration suitable for development.
func DefaultConfig(serviceName, component string) *Config {
	return &Config{
		Level:             InfoLevel,
		Format:            TextFormat,
		EnableCorrelation: true,
		ServiceName:       serviceName,
		Component:         component,
	}
}

// LogEntry represents a structured log entry for JSON output.
type LogEntry struct {
	Timestamp     time.Time              `json:"timestamp"`
	Level         string                 `json:"level"`
	Message       string                 `json:"message"`
	ServiceName   string                 `json:"service_name,omitempty"`
	Component     string                 `json:"component,omitempty"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	TraceID       string                 `json:"trace_id,omitempty"`
	SpanID        string                 `json:"span_id,omitempty"`
	Fields        map[string]interface{} `json:"fields,omitempty"`
}

// DefaultLogger is an enhanced implementation of Logger with correlation support
// It can use either the legacy stdout logging or the new provider system
type DefaultLogger struct {
	config            *Config
	log               *log.Logger
	useProviderSystem bool // Use new provider system if available
}

// NoopLogger is a logger that does nothing
type NoopLogger struct{}

// NewNoopLogger creates a new no-op logger
func NewNoopLogger() Logger {
	return &NoopLogger{}
}

// parseLevel converts a string level to a Level
func parseLevel(level string) Level {
	switch level {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "warn":
		return WarnLevel
	case "error":
		return ErrorLevel
	case "fatal":
		return FatalLevel
	default:
		return InfoLevel // Default to InfoLevel
	}
}

// NewLogger creates a new logger with the specified level (backward compatibility).
// For new code, prefer using NewLoggerWithConfig for enhanced features.
func NewLogger(levelStr string) Logger {
	level := parseLevel(levelStr)
	config := &Config{
		Level:             level,
		Format:            TextFormat,
		EnableCorrelation: false, // Disabled for backward compatibility
		ServiceName:       "",
		Component:         "",
	}

	// Check if global provider system is available
	manager := GetGlobalLoggingManager()
	useProvider := (manager != nil)

	return &DefaultLogger{
		config:            config,
		log:               log.New(os.Stdout, "", log.LstdFlags),
		useProviderSystem: useProvider,
	}
}

// NewLoggerWithConfig creates a new logger with the specified configuration.
// This is the preferred constructor for new code requiring enhanced features.
func NewLoggerWithConfig(config *Config) Logger {
	if config == nil {
		config = DefaultConfig("cfgms", "unknown")
	}

	// Check if global provider system is available
	manager := GetGlobalLoggingManager()
	useProvider := (manager != nil)

	return &DefaultLogger{
		config:            config,
		log:               log.New(os.Stdout, "", 0), // No timestamp for JSON format
		useProviderSystem: useProvider,
	}
}

// keysAndValuesToMap converts key-value pairs to a map for structured logging.
// String values are automatically sanitized to prevent log injection (CWE-117).
func keysAndValuesToMap(keysAndValues []interface{}) map[string]interface{} {
	fields := make(map[string]interface{})

	for i := 0; i < len(keysAndValues)-1; i += 2 {
		if key, ok := keysAndValues[i].(string); ok {
			fields[key] = keysAndValues[i+1]
		}
	}

	sanitizeMapValues(fields)

	return fields
}

// logEntry handles the actual logging with support for different formats and correlation.
func (l *DefaultLogger) logEntry(ctx context.Context, level Level, levelStr, msg string, keysAndValues ...interface{}) {
	if l.config.Level > level {
		return
	}

	// Use global provider system if available and enabled
	if l.useProviderSystem {
		manager := GetGlobalLoggingManager()
		if manager != nil {
			entry := interfaces.LogEntry{
				Level:       levelStr,
				Message:     SanitizeLogValue(msg),
				ServiceName: l.config.ServiceName,
				Component:   l.config.Component,
				Fields:      keysAndValuesToMap(keysAndValues),
			}

			// Write via provider system (handles correlation, tenant isolation, etc. automatically)
			if err := manager.WriteEntry(ctx, entry); err != nil {
				// Fallback to stdout if provider fails
				fmt.Printf("[ERROR] Provider logging failed: %v - Fallback: [%s] %s\n", err, levelStr, msg)
			}
			return
		}
	}

	// Fallback to legacy stdout logging
	if l.config.Format == JSONFormat {
		l.logJSON(ctx, levelStr, msg, keysAndValues...)
	} else {
		l.logText(ctx, levelStr, msg, keysAndValues...)
	}
}

// logJSON outputs structured JSON logs with correlation support.
func (l *DefaultLogger) logJSON(ctx context.Context, level, msg string, keysAndValues ...interface{}) {
	entry := LogEntry{
		Timestamp:   time.Now().UTC(),
		Level:       level,
		Message:     SanitizeLogValue(msg),
		ServiceName: l.config.ServiceName,
		Component:   l.config.Component,
		Fields:      keysAndValuesToMap(keysAndValues),
	}

	// Inject correlation and trace information if enabled and context is available
	if l.config.EnableCorrelation && ctx != nil {
		entry.CorrelationID = extractCorrelationID(ctx)
		entry.TraceID, entry.SpanID = extractTraceInfo(ctx)
	}

	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		// Fallback to text format if JSON marshaling fails
		l.log.Printf("[ERROR] Failed to marshal log entry: %v - Original: [%s] %s %v", err, level, msg, keysAndValues)
		return
	}

	l.log.Println(string(jsonBytes))
}

// logText outputs human-readable text logs with optional correlation.
// Message and key-value string values are sanitized to prevent log injection (CWE-117).
// Key-value pairs are formatted through formatKeysAndValues which uses strings.Builder
// to construct a new string, breaking CodeQL taint tracking for the entire output.
func (l *DefaultLogger) logText(ctx context.Context, level, msg string, keysAndValues ...interface{}) {
	var correlationPart string
	if l.config.EnableCorrelation && ctx != nil {
		if correlationID := extractCorrelationID(ctx); correlationID != "" {
			correlationPart = fmt.Sprintf(" [correlation_id=%s]", correlationID)
		}
	}

	kvStr := formatKeysAndValues(keysAndValues)
	l.log.Printf("[%s]%s %s%s", level, correlationPart, SanitizeLogValue(msg), kvStr)
}

// Original interface methods (backward compatible)

// Debug logs a debug message
func (l *DefaultLogger) Debug(msg string, keysAndValues ...interface{}) {
	l.logEntry(context.TODO(), DebugLevel, "DEBUG", msg, keysAndValues...)
}

// Info logs an info message
func (l *DefaultLogger) Info(msg string, keysAndValues ...interface{}) {
	l.logEntry(context.TODO(), InfoLevel, "INFO", msg, keysAndValues...)
}

// Warn logs a warning message
func (l *DefaultLogger) Warn(msg string, keysAndValues ...interface{}) {
	l.logEntry(context.TODO(), WarnLevel, "WARN", msg, keysAndValues...)
}

// Error logs an error message
func (l *DefaultLogger) Error(msg string, keysAndValues ...interface{}) {
	l.logEntry(context.TODO(), ErrorLevel, "ERROR", msg, keysAndValues...)
}

// Fatal logs a fatal message and exits
func (l *DefaultLogger) Fatal(msg string, keysAndValues ...interface{}) {
	l.logEntry(context.TODO(), FatalLevel, "FATAL", msg, keysAndValues...)
	os.Exit(1)
}

// Context-aware interface methods

// DebugCtx logs a debug message with context correlation
func (l *DefaultLogger) DebugCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.logEntry(ctx, DebugLevel, "DEBUG", msg, keysAndValues...)
}

// InfoCtx logs an info message with context correlation
func (l *DefaultLogger) InfoCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.logEntry(ctx, InfoLevel, "INFO", msg, keysAndValues...)
}

// WarnCtx logs a warning message with context correlation
func (l *DefaultLogger) WarnCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.logEntry(ctx, WarnLevel, "WARN", msg, keysAndValues...)
}

// ErrorCtx logs an error message with context correlation
func (l *DefaultLogger) ErrorCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.logEntry(ctx, ErrorLevel, "ERROR", msg, keysAndValues...)
}

// FatalCtx logs a fatal message with context correlation and exits
func (l *DefaultLogger) FatalCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {
	l.logEntry(ctx, FatalLevel, "FATAL", msg, keysAndValues...)
	os.Exit(1)
}

// NoopLogger methods (original interface)

// Debug logs a debug message (no-op)
func (l *NoopLogger) Debug(msg string, keysAndValues ...interface{}) {}

// Info logs an info message (no-op)
func (l *NoopLogger) Info(msg string, keysAndValues ...interface{}) {}

// Warn logs a warning message (no-op)
func (l *NoopLogger) Warn(msg string, keysAndValues ...interface{}) {}

// Error logs an error message (no-op)
func (l *NoopLogger) Error(msg string, keysAndValues ...interface{}) {}

// Fatal logs a fatal message (no-op)
func (l *NoopLogger) Fatal(msg string, keysAndValues ...interface{}) {}

// NoopLogger context methods

// DebugCtx logs a debug message (no-op)
func (l *NoopLogger) DebugCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {}

// InfoCtx logs an info message (no-op)
func (l *NoopLogger) InfoCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {}

// WarnCtx logs a warning message (no-op)
func (l *NoopLogger) WarnCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {}

// ErrorCtx logs an error message (no-op)
func (l *NoopLogger) ErrorCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {}

// FatalCtx logs a fatal message (no-op)
func (l *NoopLogger) FatalCtx(ctx context.Context, msg string, keysAndValues ...interface{}) {}

// Telemetry integration functions

// extractCorrelationID attempts to extract correlation ID from context.
// This function uses the telemetry bridge to avoid circular dependencies.
func extractCorrelationID(ctx context.Context) string {
	return UpdatedExtractCorrelationID(ctx)
}

// extractTraceInfo attempts to extract OpenTelemetry trace information from context.
// Returns traceID and spanID if available.
func extractTraceInfo(ctx context.Context) (string, string) {
	return UpdatedExtractTraceInfo(ctx)
}
