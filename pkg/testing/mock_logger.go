package testing

import (
	"sync"

	"github.com/cfgis/cfgms/pkg/logging"
)

// MockLogger provides a mock implementation of logging.Logger for testing
type MockLogger struct {
	mu     sync.Mutex
	Logs   map[string][]LogEntry
	Silent bool
}

// LogEntry represents a single log entry
type LogEntry struct {
	Message string
	Data    []interface{}
}

// NewMockLogger creates a new mock logger
func NewMockLogger(silent bool) *MockLogger {
	return &MockLogger{
		Logs: map[string][]LogEntry{
			"debug": {},
			"info":  {},
			"warn":  {},
			"error": {},
			"fatal": {},
		},
		Silent: silent,
	}
}

// Debug logs a debug message
func (l *MockLogger) Debug(msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Logs["debug"] = append(l.Logs["debug"], LogEntry{
		Message: msg,
		Data:    keysAndValues,
	})
}

// Info logs an info message
func (l *MockLogger) Info(msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Logs["info"] = append(l.Logs["info"], LogEntry{
		Message: msg,
		Data:    keysAndValues,
	})
}

// Warn logs a warning message
func (l *MockLogger) Warn(msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Logs["warn"] = append(l.Logs["warn"], LogEntry{
		Message: msg,
		Data:    keysAndValues,
	})
}

// Error logs an error message
func (l *MockLogger) Error(msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Logs["error"] = append(l.Logs["error"], LogEntry{
		Message: msg,
		Data:    keysAndValues,
	})
}

// Fatal logs a fatal message but doesn't exit in the mock implementation
func (l *MockLogger) Fatal(msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Logs["fatal"] = append(l.Logs["fatal"], LogEntry{
		Message: msg,
		Data:    keysAndValues,
	})
}

// GetLogs returns all logs of a specific level
func (l *MockLogger) GetLogs(level string) []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Logs[level]
}

// Reset clears all logged messages
func (l *MockLogger) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for level := range l.Logs {
		l.Logs[level] = []LogEntry{}
	}
}

// Ensure MockLogger implements Logger interface
var _ logging.Logger = (*MockLogger)(nil)
