// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// TraceManager manages request tracing and performance tracking
type TraceManager interface {
	// StartTrace begins a new request trace
	StartTrace(operation, component string) (*RequestTrace, context.Context)

	// StartSpan begins a new span within a trace
	StartSpan(ctx context.Context, operation string) (*RequestSpan, context.Context)

	// EndTrace completes a request trace
	EndTrace(trace *RequestTrace, status, errorMsg string)

	// EndSpan completes a span
	EndSpan(span *RequestSpan, status string)

	// GetTrace retrieves a trace by request ID
	GetTrace(requestID string) (*RequestTrace, error)

	// GetTraces retrieves traces within a time range
	GetTraces(start, end time.Time) ([]*RequestTrace, error)
}

type contextKey string

const (
	traceKey contextKey = "trace"
	spanKey  contextKey = "span"
)

// DefaultTraceManager implements TraceManager
type DefaultTraceManager struct {
	mu              sync.RWMutex
	traces          map[string]*RequestTrace
	retentionPeriod time.Duration
}

// NewTraceManager creates a new trace manager
func NewTraceManager(retentionPeriod time.Duration) *DefaultTraceManager {
	return &DefaultTraceManager{
		traces:          make(map[string]*RequestTrace),
		retentionPeriod: retentionPeriod,
	}
}

// StartTrace begins a new request trace
func (m *DefaultTraceManager) StartTrace(operation, component string) (*RequestTrace, context.Context) {
	trace := &RequestTrace{
		RequestID: uuid.New().String(),
		TraceID:   uuid.New().String(),
		StartTime: time.Now(),
		Operation: operation,
		Component: component,
		Status:    "in_progress",
		Metadata:  make(map[string]interface{}),
		Spans:     make([]RequestSpan, 0),
	}

	m.mu.Lock()
	m.traces[trace.RequestID] = trace
	m.mu.Unlock()

	ctx := context.WithValue(context.Background(), traceKey, trace)
	return trace, ctx
}

// StartSpan begins a new span within a trace
func (m *DefaultTraceManager) StartSpan(ctx context.Context, operation string) (*RequestSpan, context.Context) {
	trace, ok := ctx.Value(traceKey).(*RequestTrace)
	if !ok {
		// No trace in context, return empty span
		return nil, ctx
	}

	span := &RequestSpan{
		SpanID:    uuid.New().String(),
		Operation: operation,
		StartTime: time.Now(),
		Status:    "in_progress",
		Tags:      make(map[string]string),
	}

	// Check if there's a parent span
	if parentSpan, ok := ctx.Value(spanKey).(*RequestSpan); ok {
		span.ParentSpanID = parentSpan.SpanID
	}

	// Add span to trace - store pointer in context to track the index
	m.mu.Lock()
	trace.Spans = append(trace.Spans, *span)
	spanIndex := len(trace.Spans) - 1
	m.mu.Unlock()

	// Store span index in the span for later updates
	span.Tags["__span_index"] = fmt.Sprintf("%d", spanIndex)

	newCtx := context.WithValue(ctx, spanKey, span)
	return span, newCtx
}

// EndTrace completes a request trace
func (m *DefaultTraceManager) EndTrace(trace *RequestTrace, status, errorMsg string) {
	if trace == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	endTime := time.Now()
	trace.EndTime = &endTime
	trace.Status = status
	trace.Error = errorMsg
	trace.DurationMs = float64(endTime.Sub(trace.StartTime).Milliseconds())

	// Update stored trace
	m.traces[trace.RequestID] = trace

	// Cleanup old traces
	m.cleanupOldTraces()
}

// EndSpan completes a span
func (m *DefaultTraceManager) EndSpan(span *RequestSpan, status string) {
	if span == nil {
		return
	}

	endTime := time.Now()
	span.EndTime = &endTime
	span.Status = status
	span.DurationMs = float64(endTime.Sub(span.StartTime).Milliseconds())

	// Find the trace containing this span and update it
	// We need to iterate through all traces to find the one with this span ID
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, trace := range m.traces {
		for i := range trace.Spans {
			if trace.Spans[i].SpanID == span.SpanID {
				trace.Spans[i].EndTime = span.EndTime
				trace.Spans[i].Status = span.Status
				trace.Spans[i].DurationMs = span.DurationMs
				return
			}
		}
	}
}

// GetTrace retrieves a trace by request ID
func (m *DefaultTraceManager) GetTrace(requestID string) (*RequestTrace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	trace, exists := m.traces[requestID]
	if !exists {
		return nil, fmt.Errorf("trace not found: %s", requestID)
	}

	return trace, nil
}

// GetTraces retrieves traces within a time range
func (m *DefaultTraceManager) GetTraces(start, end time.Time) ([]*RequestTrace, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	traces := make([]*RequestTrace, 0)
	for _, trace := range m.traces {
		if trace.StartTime.After(start) && trace.StartTime.Before(end) {
			traces = append(traces, trace)
		}
	}

	return traces, nil
}

// cleanupOldTraces removes traces older than the retention period
func (m *DefaultTraceManager) cleanupOldTraces() {
	cutoff := time.Now().Add(-m.retentionPeriod)

	for requestID, trace := range m.traces {
		if trace.StartTime.Before(cutoff) {
			delete(m.traces, requestID)
		}
	}
}

// WithTrace extracts the trace from context
func WithTrace(ctx context.Context) *RequestTrace {
	trace, ok := ctx.Value(traceKey).(*RequestTrace)
	if !ok {
		return nil
	}
	return trace
}

// WithSpan extracts the current span from context
func WithSpan(ctx context.Context) *RequestSpan {
	span, ok := ctx.Value(spanKey).(*RequestSpan)
	if !ok {
		return nil
	}
	return span
}

// AddMetadata adds metadata to a trace
func AddMetadata(ctx context.Context, key string, value interface{}) {
	trace := WithTrace(ctx)
	if trace != nil {
		trace.Metadata[key] = value
	}
}

// AddTag adds a tag to the current span
func AddTag(ctx context.Context, key, value string) {
	span := WithSpan(ctx)
	if span != nil {
		span.Tags[key] = value
	}
}
