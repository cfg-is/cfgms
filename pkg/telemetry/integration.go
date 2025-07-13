package telemetry

import (
	"context"
	"sync"
)

// LoggingIntegration provides integration between telemetry and logging packages.
// This interface allows the telemetry package to interact with logging without
// creating circular dependencies.
type LoggingIntegration interface {
	// InitializeBridge sets up the telemetry bridge in the logging package
	InitializeBridge()
	
	// ExtractCorrelationID extracts correlation ID from context
	ExtractCorrelationID(ctx context.Context) string
	
	// ExtractTraceInfo extracts trace information from context
	ExtractTraceInfo(ctx context.Context) (traceID, spanID string)
}

// DefaultLoggingIntegration provides the standard integration implementation.
type DefaultLoggingIntegration struct {
	initialized bool
	mu          sync.RWMutex
}

// InitializeBridge sets up the telemetry bridge in the logging package.
// This should be called after both telemetry and logging packages are initialized.
func (d *DefaultLoggingIntegration) InitializeBridge() {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	if d.initialized {
		return
	}
	
	// Initialize the bridge (this will be implemented when we connect the packages)
	d.initialized = true
}

// ExtractCorrelationID extracts correlation ID from context using telemetry methods.
func (d *DefaultLoggingIntegration) ExtractCorrelationID(ctx context.Context) string {
	return GetCorrelationID(ctx)
}

// ExtractTraceInfo extracts trace information from context.
func (d *DefaultLoggingIntegration) ExtractTraceInfo(ctx context.Context) (string, string) {
	propCtx := ExtractPropagationContext(ctx)
	if propCtx != nil {
		return propCtx.TraceID, propCtx.SpanID
	}
	return "", ""
}

// Global integration instance
var defaultIntegration = &DefaultLoggingIntegration{}

// SetupLoggingIntegration initializes the integration between telemetry and logging.
// This should be called during application startup after both packages are configured.
func SetupLoggingIntegration() {
	defaultIntegration.InitializeBridge()
}

// GetLoggingIntegration returns the current logging integration instance.
func GetLoggingIntegration() LoggingIntegration {
	return defaultIntegration
}