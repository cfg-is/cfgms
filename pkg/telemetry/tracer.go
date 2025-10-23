// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package telemetry provides OpenTelemetry tracing and correlation capabilities for CFGMS.
//
// This package enables distributed tracing across steward-controller communications and provides
// correlation ID management for centralized logging. It builds upon the existing OpenTelemetry
// dependencies to deliver comprehensive observability.
//
// Key Features:
//   - Distributed tracing with correlation IDs
//   - Context propagation across gRPC calls
//   - Trace span management and lifecycle
//   - Integration with existing logging infrastructure
//
// Example Usage:
//
//	// Initialize telemetry in main application
//	tracer, cleanup, err := telemetry.Initialize(ctx, "cfgms-controller", "v0.2.0")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer cleanup()
//
//	// Create traced operation
//	ctx, span := tracer.Start(ctx, "steward.register")
//	defer span.End()
//
//	// Get correlation ID for logging
//	correlationID := telemetry.GetCorrelationID(ctx)
//	logger.Info("Processing request", "correlation_id", correlationID)
package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Tracer provides distributed tracing capabilities with correlation ID support.
// It wraps OpenTelemetry's tracer interface and provides CFGMS-specific functionality.
type Tracer struct {
	tracer   trace.Tracer
	provider *sdktrace.TracerProvider
}

// Config holds configuration for telemetry initialization.
// It supports various export backends and sampling strategies.
type Config struct {
	// ServiceName identifies the service in distributed traces (e.g., "cfgms-controller", "cfgms-steward")
	ServiceName string

	// ServiceVersion provides version information for trace metadata
	ServiceVersion string

	// Environment identifies the deployment environment (e.g., "development", "staging", "production")
	Environment string

	// OTLPEndpoint specifies the OpenTelemetry collector endpoint for trace export
	// If empty, traces will only be available in memory for debugging
	OTLPEndpoint string

	// SampleRate controls the percentage of traces to sample (0.0 to 1.0)
	// 1.0 samples all traces, 0.1 samples 10% of traces
	SampleRate float64

	// Enabled controls whether tracing is active
	// Useful for disabling tracing in testing or low-resource environments
	Enabled bool
}

// DefaultConfig returns a configuration suitable for development environments.
// It enables all tracing with console output and no remote export.
func DefaultConfig(serviceName, version string) *Config {
	return &Config{
		ServiceName:    serviceName,
		ServiceVersion: version,
		Environment:    "development",
		OTLPEndpoint:   "",  // No remote export by default
		SampleRate:     1.0, // Sample all traces in development
		Enabled:        true,
	}
}

// Initialize sets up OpenTelemetry tracing for the application.
// It configures trace providers, propagators, and exporters based on the provided configuration.
//
// Returns a tracer instance and a cleanup function that must be called when the application shuts down.
// The cleanup function ensures proper flushing of pending traces and resource cleanup.
//
// Example:
//
//	config := telemetry.DefaultConfig("cfgms-controller", "v0.2.0")
//	tracer, cleanup, err := telemetry.Initialize(ctx, config)
//	if err != nil {
//	    return fmt.Errorf("failed to initialize telemetry: %w", err)
//	}
//	defer cleanup()
func Initialize(ctx context.Context, config *Config) (*Tracer, func(), error) {
	if config == nil {
		config = DefaultConfig("cfgms", "v0.2.0")
	}

	if !config.Enabled {
		// Return a no-op tracer when disabled
		noopTracer := &Tracer{
			tracer:   noop.NewTracerProvider().Tracer(config.ServiceName),
			provider: nil,
		}
		return noopTracer, func() {}, nil
	}

	// Create resource with service information
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(config.ServiceName),
			semconv.ServiceVersionKey.String(config.ServiceVersion),
			semconv.DeploymentEnvironmentKey.String(config.Environment),
			attribute.String("cfgms.component", getComponentType(config.ServiceName)),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create telemetry resource: %w", err)
	}

	// Configure trace provider options
	var opts []sdktrace.TracerProviderOption

	// Add resource
	opts = append(opts, sdktrace.WithResource(res))

	// Configure sampling
	if config.SampleRate < 1.0 {
		sampler := sdktrace.TraceIDRatioBased(config.SampleRate)
		opts = append(opts, sdktrace.WithSampler(sampler))
	}

	// Configure exporter if endpoint is provided
	if config.OTLPEndpoint != "" {
		exporter, err := createOTLPExporter(ctx, config.OTLPEndpoint)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
		}
		opts = append(opts, sdktrace.WithBatcher(exporter))
	}

	// Create trace provider
	provider := sdktrace.NewTracerProvider(opts...)

	// Set global trace provider and propagator
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Create tracer instance
	tracer := &Tracer{
		tracer:   provider.Tracer(config.ServiceName),
		provider: provider,
	}

	// Create cleanup function
	cleanup := func() {
		if provider != nil {
			_ = provider.Shutdown(context.Background())
		}
	}

	return tracer, cleanup, nil
}

// Start begins a new span with the given name and returns the updated context and span.
// The span must be ended by calling span.End() to ensure proper trace completion.
//
// This method automatically injects correlation ID attributes and CFGMS-specific metadata.
//
// Example:
//
//	ctx, span := tracer.Start(ctx, "steward.registration")
//	defer span.End()
//
//	// Add additional attributes
//	span.SetAttributes(
//	    attribute.String("steward.id", stewardID),
//	    attribute.String("tenant.id", tenantID),
//	)
func (t *Tracer) Start(ctx context.Context, operationName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	// Add default CFGMS attributes
	defaultOpts := []trace.SpanStartOption{
		trace.WithAttributes(
			attribute.String("cfgms.operation", operationName),
		),
	}

	// Combine with user-provided options
	allOpts := append(defaultOpts, opts...)

	// Start span with correlation ID injection
	ctx, span := t.tracer.Start(ctx, operationName, allOpts...)

	// Inject correlation ID into context if not present
	ctx = ensureCorrelationID(ctx, span)

	return ctx, span
}

// GetTracer returns the underlying OpenTelemetry tracer for advanced usage.
// This allows direct access to OpenTelemetry APIs when needed.
func (t *Tracer) GetTracer() trace.Tracer {
	return t.tracer
}

// createOTLPExporter creates an OTLP HTTP exporter for the given endpoint.
// This enables sending traces to OpenTelemetry collectors or compatible backends.
func createOTLPExporter(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error) {
	// Configure OTLP HTTP exporter
	// NOTE: Using insecure HTTP for development/testing environments.
	// Production deployments should configure TLS via endpoint configuration (https://).
	// When OTLPEndpoint is empty (default), no remote export occurs and this is unused.
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
	}

	// Create HTTP client
	client := otlptracehttp.NewClient(opts...)

	// Create exporter
	exporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	return exporter, nil
}

// getComponentType determines the CFGMS component type from service name.
// This provides consistent component labeling for trace analysis.
func getComponentType(serviceName string) string {
	switch serviceName {
	case "cfgms-controller":
		return "controller"
	case "cfgms-steward":
		return "steward"
	case "cfgms-cli":
		return "cli"
	default:
		return "unknown"
	}
}

// Attribute creation helpers for common types
// These provide convenient wrappers around OpenTelemetry attributes

// AttributeString creates a string attribute.
func AttributeString(key, value string) attribute.KeyValue {
	return attribute.String(key, value)
}

// AttributeInt creates an integer attribute.
func AttributeInt(key string, value int) attribute.KeyValue {
	return attribute.Int(key, value)
}

// AttributeFloat creates a float64 attribute.
func AttributeFloat(key string, value float64) attribute.KeyValue {
	return attribute.Float64(key, value)
}

// AttributeBool creates a boolean attribute.
func AttributeBool(key string, value bool) attribute.KeyValue {
	return attribute.Bool(key, value)
}

// Span status constants
const (
	StatusOK    = codes.Ok
	StatusError = codes.Error
)
