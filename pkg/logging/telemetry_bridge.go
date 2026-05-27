// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package logging provides telemetry integration for correlation ID and trace extraction.
//
// This file provides integration between the logging and telemetry packages while
// avoiding circular dependencies. It uses reflection and interface-based approaches
// to extract telemetry information when available.
package logging

import (
	"context"
	"sync/atomic"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"go.opentelemetry.io/otel/trace"
)

// TelemetryBridge provides integration with the telemetry package for correlation tracking.
// This allows the logging package to extract correlation IDs and trace information
// from context without directly importing the telemetry package.
type TelemetryBridge struct{}

// GetCorrelationIDFromContext extracts correlation ID using the canonical ctxkeys.CorrelationIDKey.
func (t *TelemetryBridge) GetCorrelationIDFromContext(ctx context.Context) string {
	if correlationID, ok := ctx.Value(ctxkeys.CorrelationIDKey).(string); ok {
		return correlationID
	}

	// Fallback: extract from OTel span context if available
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
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

// Initialize activates the telemetry bridge for correlation ID and trace extraction.
// This should be called during application initialization after telemetry setup.
// It is safe to call concurrently and from multiple goroutines.
func (t *TelemetryBridge) Initialize() {
	globalTelemetryBridge.Store(t)
}

// globalTelemetryBridge is the atomic bridge instance. Atomic access ensures
// Initialize() and the extractor functions are race-free when called concurrently.
var globalTelemetryBridge atomic.Pointer[TelemetryBridge]

// UpdatedExtractCorrelationID is the enhanced correlation ID extractor.
func UpdatedExtractCorrelationID(ctx context.Context) string {
	if b := globalTelemetryBridge.Load(); b != nil {
		return b.GetCorrelationIDFromContext(ctx)
	}

	// Direct read from the canonical key — no bridge required.
	if correlationID, ok := ctx.Value(ctxkeys.CorrelationIDKey).(string); ok {
		return correlationID
	}
	return ""
}

// UpdatedExtractTraceInfo is the enhanced trace info extractor.
func UpdatedExtractTraceInfo(ctx context.Context) (string, string) {
	if b := globalTelemetryBridge.Load(); b != nil {
		return b.GetTraceInfoFromContext(ctx)
	}

	// Fallback: no trace information available
	return "", ""
}
