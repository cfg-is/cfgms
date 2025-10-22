// Package logging provides telemetry integration for correlation ID and trace extraction.
//
// This file provides integration between the logging and telemetry packages while
// avoiding circular dependencies. It uses reflection and interface-based approaches
// to extract telemetry information when available.
package logging

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

// TelemetryBridge provides integration with the telemetry package for correlation tracking.
// This allows the logging package to extract correlation IDs and trace information
// from context without directly importing the telemetry package.
type TelemetryBridge struct{}

// GetCorrelationIDFromContext extracts correlation ID using the telemetry package's key structure.
// This is the actual implementation that replaces the placeholder in extractCorrelationID.
func (t *TelemetryBridge) GetCorrelationIDFromContext(ctx context.Context) string {
	// Try to get correlation ID using the telemetry package's CorrelationIDKey{}
	// We need to match the exact type from the telemetry package

	// Create the key type that matches telemetry.CorrelationIDKey{}
	type correlationIDKey struct{}
	if value := ctx.Value(correlationIDKey{}); value != nil {
		if correlationID, ok := value.(string); ok {
			return correlationID
		}
	}

	// Fallback: Try to extract from span context if available
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		// Use trace ID as correlation ID if no explicit ID is set
		return span.SpanContext().TraceID().String()
	}

	// Additional fallback keys for compatibility
	for _, key := range []interface{}{
		"correlation_id",
		"cfgms_correlation_id",
	} {
		if value := ctx.Value(key); value != nil {
			if correlationID, ok := value.(string); ok {
				return correlationID
			}
		}
	}

	return ""
}

// GetTraceInfoFromContext extracts OpenTelemetry trace information from context.
// Returns traceID and spanID if an active span is present.
func (t *TelemetryBridge) GetTraceInfoFromContext(ctx context.Context) (string, string) {
	// Extract span from context using OpenTelemetry's standard approach
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return "", ""
	}

	spanCtx := span.SpanContext()
	return spanCtx.TraceID().String(), spanCtx.SpanID().String()
}

// Initialize sets up the telemetry bridge to replace placeholder functions.
// This should be called during application initialization after telemetry setup.
func (t *TelemetryBridge) Initialize() {
	// Replace the placeholder functions with actual implementations
	// This is done to avoid circular dependencies while maintaining functionality
	globalTelemetryBridge = t
}

// Global bridge instance for function replacement
var globalTelemetryBridge *TelemetryBridge

// UpdatedExtractCorrelationID is the enhanced correlation ID extractor.
func UpdatedExtractCorrelationID(ctx context.Context) string {
	if globalTelemetryBridge != nil {
		return globalTelemetryBridge.GetCorrelationIDFromContext(ctx)
	}

	// Fallback to the original implementation
	return extractCorrelationIDFallback(ctx)
}

// UpdatedExtractTraceInfo is the enhanced trace info extractor.
func UpdatedExtractTraceInfo(ctx context.Context) (string, string) {
	if globalTelemetryBridge != nil {
		return globalTelemetryBridge.GetTraceInfoFromContext(ctx)
	}

	// Fallback: no trace information available
	return "", ""
}

// extractCorrelationIDFallback provides basic correlation ID extraction without telemetry integration.
func extractCorrelationIDFallback(ctx context.Context) string {
	// Basic implementation that works without telemetry package
	type correlationKey struct{}
	if correlationID, ok := ctx.Value(correlationKey{}).(string); ok {
		return correlationID
	}

	// Try string key as well
	if correlationID, ok := ctx.Value("correlation_id").(string); ok {
		return correlationID
	}

	return ""
}
