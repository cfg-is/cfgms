package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// CorrelationIDKey is the context key for correlation IDs.
// This enables correlation tracking across distributed operations.
type CorrelationIDKey struct{}

// GetCorrelationID extracts the correlation ID from the context.
// If no correlation ID is present, it returns an empty string.
//
// Correlation IDs enable tracking related operations across multiple services
// and are essential for centralized logging and debugging.
//
// Example:
//
//	correlationID := telemetry.GetCorrelationID(ctx)
//	if correlationID != "" {
//	    logger.InfoCtx(ctx, "Processing request", "correlation_id", correlationID)
//	}
func GetCorrelationID(ctx context.Context) string {
	if correlationID, ok := ctx.Value(CorrelationIDKey{}).(string); ok {
		return correlationID
	}

	// Try to extract from span context if available
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		// Use trace ID as correlation ID if no explicit ID is set
		return span.SpanContext().TraceID().String()
	}

	return ""
}

// WithCorrelationID adds a correlation ID to the context.
// This is typically called at request boundaries to establish correlation tracking.
//
// Example:
//
//	correlationID := "req-" + uuid.New().String()
//	ctx = telemetry.WithCorrelationID(ctx, correlationID)
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	ctx = context.WithValue(ctx, CorrelationIDKey{}, correlationID)

	// Also add to active span if present
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		span.SetAttributes(attribute.String("cfgms.correlation_id", correlationID))
	}

	return ctx
}

// GenerateCorrelationID creates a new unique correlation ID.
// The ID is generated using cryptographically secure random bytes for uniqueness.
//
// Format: 16 hex characters (64 bits of entropy)
// Example: "a1b2c3d4e5f6g7h8"
func GenerateCorrelationID() string {
	bytes := make([]byte, 8) // 8 bytes = 16 hex characters
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a simple counter-based approach if crypto/rand fails
		// This should rarely happen but provides resilience
		return "fallback-" + hex.EncodeToString([]byte{0x1, 0x2, 0x3, 0x4})
	}
	return hex.EncodeToString(bytes)
}

// ensureCorrelationID ensures that a correlation ID is present in the context.
// If no correlation ID exists, it generates one and adds it to both context and span.
// This is called automatically during span creation to maintain correlation tracking.
func ensureCorrelationID(ctx context.Context, span trace.Span) context.Context {
	// Check if correlation ID already exists
	if GetCorrelationID(ctx) != "" {
		return ctx
	}

	// Generate new correlation ID
	correlationID := GenerateCorrelationID()

	// Add to context
	ctx = context.WithValue(ctx, CorrelationIDKey{}, correlationID)

	// Add to span attributes
	if span.SpanContext().IsValid() {
		span.SetAttributes(attribute.String("cfgms.correlation_id", correlationID))
	}

	return ctx
}

// PropagationContext contains trace and correlation context for cross-service communication.
// This is used to maintain tracing context when making gRPC calls or HTTP requests.
type PropagationContext struct {
	// TraceID from the OpenTelemetry span context
	TraceID string `json:"trace_id,omitempty"`

	// SpanID from the OpenTelemetry span context  
	SpanID string `json:"span_id,omitempty"`

	// CorrelationID for request correlation
	CorrelationID string `json:"correlation_id,omitempty"`

	// TraceFlags from the OpenTelemetry span context
	TraceFlags byte `json:"trace_flags,omitempty"`
}

// ExtractPropagationContext extracts tracing context for cross-service propagation.
// This is used when making outbound requests to maintain distributed tracing.
//
// Example:
//
//	propCtx := telemetry.ExtractPropagationContext(ctx)
//	// Add to gRPC metadata or HTTP headers
//	md := metadata.Pairs(
//	    "x-correlation-id", propCtx.CorrelationID,
//	    "x-trace-id", propCtx.TraceID,
//	)
func ExtractPropagationContext(ctx context.Context) *PropagationContext {
	span := trace.SpanFromContext(ctx)
	spanCtx := span.SpanContext()

	propCtx := &PropagationContext{
		CorrelationID: GetCorrelationID(ctx),
	}

	if spanCtx.IsValid() {
		propCtx.TraceID = spanCtx.TraceID().String()
		propCtx.SpanID = spanCtx.SpanID().String()
		propCtx.TraceFlags = byte(spanCtx.TraceFlags())
	}

	return propCtx
}

// InjectPropagationContext creates a context with the provided propagation context.
// This is used when receiving requests to restore distributed tracing context.
//
// Example:
//
//	// Extract from gRPC metadata or HTTP headers
//	correlationID := getHeaderValue("x-correlation-id")
//	traceID := getHeaderValue("x-trace-id")
//	
//	propCtx := &telemetry.PropagationContext{
//	    CorrelationID: correlationID,
//	    TraceID: traceID,
//	}
//	ctx = telemetry.InjectPropagationContext(ctx, propCtx)
func InjectPropagationContext(ctx context.Context, propCtx *PropagationContext) context.Context {
	if propCtx == nil {
		return ctx
	}

	// Inject correlation ID
	if propCtx.CorrelationID != "" {
		ctx = WithCorrelationID(ctx, propCtx.CorrelationID)
	}

	// Note: For full trace context restoration, OpenTelemetry's propagation
	// mechanisms should be used with the actual trace headers. This method
	// primarily handles correlation ID injection for logging purposes.

	return ctx
}