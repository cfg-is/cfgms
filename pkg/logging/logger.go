package logging

import (
	"log"
	"os"
)

// Logger provides a structured logging interface
type Logger interface {
	Debug(msg string, keysAndValues ...interface{})
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Fatal(msg string, keysAndValues ...interface{})
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

// DefaultLogger is a simple implementation of Logger
type DefaultLogger struct {
	level Level
	log   *log.Logger
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

// NewLogger creates a new logger with the specified level
func NewLogger(levelStr string) Logger {
	level := parseLevel(levelStr)
	return &DefaultLogger{
		level: level,
		log:   log.New(os.Stdout, "", log.LstdFlags),
	}
}

// Debug logs a debug message
func (l *DefaultLogger) Debug(msg string, keysAndValues ...interface{}) {
	if l.level <= DebugLevel {
		l.log.Printf("[DEBUG] %s %v", msg, keysAndValues)
	}
}

// Info logs an info message
func (l *DefaultLogger) Info(msg string, keysAndValues ...interface{}) {
	if l.level <= InfoLevel {
		l.log.Printf("[INFO] %s %v", msg, keysAndValues)
	}
}

// Warn logs a warning message
func (l *DefaultLogger) Warn(msg string, keysAndValues ...interface{}) {
	if l.level <= WarnLevel {
		l.log.Printf("[WARN] %s %v", msg, keysAndValues)
	}
}

// Error logs an error message
func (l *DefaultLogger) Error(msg string, keysAndValues ...interface{}) {
	if l.level <= ErrorLevel {
		l.log.Printf("[ERROR] %s %v", msg, keysAndValues)
	}
}

// Fatal logs a fatal message and exits
func (l *DefaultLogger) Fatal(msg string, keysAndValues ...interface{}) {
	if l.level <= FatalLevel {
		l.log.Fatalf("[FATAL] %s %v", msg, keysAndValues)
	}
}

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
