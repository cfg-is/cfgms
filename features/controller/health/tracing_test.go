package health_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/health"
)

func TestNewTraceManager(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)
	assert.NotNil(t, manager)
}

func TestTraceManager_StartTrace(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	trace, ctx := manager.StartTrace("test_operation", "test_component")

	assert.NotNil(t, trace)
	assert.NotNil(t, ctx)
	assert.NotEmpty(t, trace.RequestID)
	assert.NotEmpty(t, trace.TraceID)
	assert.Equal(t, "test_operation", trace.Operation)
	assert.Equal(t, "test_component", trace.Component)
	assert.Equal(t, "in_progress", trace.Status)
}

func TestTraceManager_EndTrace(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	trace, _ := manager.StartTrace("test_operation", "test_component")

	// Simulate some work
	time.Sleep(50 * time.Millisecond)

	manager.EndTrace(trace, "success", "")

	assert.Equal(t, "success", trace.Status)
	assert.NotNil(t, trace.EndTime)
	assert.Greater(t, trace.DurationMs, float64(0))
	assert.GreaterOrEqual(t, trace.DurationMs, float64(50))
}

func TestTraceManager_EndTraceWithError(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	trace, _ := manager.StartTrace("test_operation", "test_component")

	manager.EndTrace(trace, "error", "something went wrong")

	assert.Equal(t, "error", trace.Status)
	assert.Equal(t, "something went wrong", trace.Error)
	assert.NotNil(t, trace.EndTime)
}

func TestTraceManager_StartSpan(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	trace, ctx := manager.StartTrace("test_operation", "test_component")

	span, spanCtx := manager.StartSpan(ctx, "sub_operation")

	assert.NotNil(t, span)
	assert.NotNil(t, spanCtx)
	assert.NotEmpty(t, span.SpanID)
	assert.Equal(t, "sub_operation", span.Operation)
	assert.Equal(t, "in_progress", span.Status)
	assert.Equal(t, 1, len(trace.Spans))
}

func TestTraceManager_EndSpan(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	_, ctx := manager.StartTrace("test_operation", "test_component")
	span, _ := manager.StartSpan(ctx, "sub_operation")

	// Simulate some work
	time.Sleep(50 * time.Millisecond)

	manager.EndSpan(span, "success")

	assert.Equal(t, "success", span.Status)
	assert.NotNil(t, span.EndTime)
	assert.Greater(t, span.DurationMs, float64(0))
}

func TestTraceManager_NestedSpans(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	trace, ctx := manager.StartTrace("test_operation", "test_component")

	// First level span
	span1, ctx1 := manager.StartSpan(ctx, "operation1")

	// Second level span (child of span1)
	span2, _ := manager.StartSpan(ctx1, "operation2")

	assert.Equal(t, "", span1.ParentSpanID, "First span should have no parent")
	assert.Equal(t, span1.SpanID, span2.ParentSpanID, "Second span should have first span as parent")
	assert.Equal(t, 2, len(trace.Spans))
}

func TestTraceManager_GetTrace(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	trace, _ := manager.StartTrace("test_operation", "test_component")
	manager.EndTrace(trace, "success", "")

	retrieved, err := manager.GetTrace(trace.RequestID)
	require.NoError(t, err)
	assert.Equal(t, trace.RequestID, retrieved.RequestID)
	assert.Equal(t, trace.Operation, retrieved.Operation)
}

func TestTraceManager_GetTraceNotFound(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	_, err := manager.GetTrace("nonexistent")
	assert.Error(t, err)
}

func TestTraceManager_GetTraces(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	// Create multiple traces
	trace1, _ := manager.StartTrace("operation1", "component1")
	manager.EndTrace(trace1, "success", "")

	time.Sleep(10 * time.Millisecond)

	trace2, _ := manager.StartTrace("operation2", "component2")
	manager.EndTrace(trace2, "success", "")

	// Get traces
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)

	traces, err := manager.GetTraces(start, end)
	require.NoError(t, err)
	assert.Equal(t, 2, len(traces))
}

func TestTraceManager_GetTracesEmptyRange(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	trace, _ := manager.StartTrace("test_operation", "test_component")
	manager.EndTrace(trace, "success", "")

	// Query with range that doesn't include the trace
	start := time.Now().Add(-2 * time.Hour)
	end := time.Now().Add(-1 * time.Hour)

	traces, err := manager.GetTraces(start, end)
	require.NoError(t, err)
	assert.Equal(t, 0, len(traces))
}

func TestWithTrace(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	trace, ctx := manager.StartTrace("test_operation", "test_component")

	extracted := health.WithTrace(ctx)
	assert.NotNil(t, extracted)
	assert.Equal(t, trace.RequestID, extracted.RequestID)
}

func TestWithSpan(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	_, ctx := manager.StartTrace("test_operation", "test_component")
	span, spanCtx := manager.StartSpan(ctx, "sub_operation")

	extracted := health.WithSpan(spanCtx)
	assert.NotNil(t, extracted)
	assert.Equal(t, span.SpanID, extracted.SpanID)
}

func TestAddMetadata(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	trace, ctx := manager.StartTrace("test_operation", "test_component")

	health.AddMetadata(ctx, "user_id", "user123")
	health.AddMetadata(ctx, "request_size", 1024)

	assert.Equal(t, "user123", trace.Metadata["user_id"])
	assert.Equal(t, 1024, trace.Metadata["request_size"])
}

func TestAddTag(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	_, ctx := manager.StartTrace("test_operation", "test_component")
	span, spanCtx := manager.StartSpan(ctx, "sub_operation")

	health.AddTag(spanCtx, "db_query", "SELECT * FROM users")
	health.AddTag(spanCtx, "cache_hit", "true")

	assert.Equal(t, "SELECT * FROM users", span.Tags["db_query"])
	assert.Equal(t, "true", span.Tags["cache_hit"])
}

func TestTraceManager_RetentionCleanup(t *testing.T) {
	// Use short retention for testing
	manager := health.NewTraceManager(100 * time.Millisecond)

	// Create a trace
	trace1, _ := manager.StartTrace("operation1", "component1")
	manager.EndTrace(trace1, "success", "")

	// Verify it exists
	_, err := manager.GetTrace(trace1.RequestID)
	require.NoError(t, err)

	// Wait for retention period to expire
	time.Sleep(150 * time.Millisecond)

	// Create another trace to trigger cleanup
	trace2, _ := manager.StartTrace("operation2", "component2")
	manager.EndTrace(trace2, "success", "")

	// Old trace should be cleaned up
	_, err = manager.GetTrace(trace1.RequestID)
	assert.Error(t, err, "Old trace should be cleaned up")

	// New trace should still exist
	_, err = manager.GetTrace(trace2.RequestID)
	require.NoError(t, err, "New trace should still exist")
}

func TestTraceManager_CompleteWorkflow(t *testing.T) {
	manager := health.NewTraceManager(24 * time.Hour)

	// Start main trace
	trace, ctx := manager.StartTrace("handle_request", "api_server")
	health.AddMetadata(ctx, "client_ip", "192.168.1.100")

	// Database operation
	dbSpan, dbCtx := manager.StartSpan(ctx, "database_query")
	health.AddTag(dbCtx, "query_type", "SELECT")
	time.Sleep(20 * time.Millisecond)
	manager.EndSpan(dbSpan, "success")

	// Cache operation
	cacheSpan, cacheCtx := manager.StartSpan(ctx, "cache_lookup")
	health.AddTag(cacheCtx, "cache_key", "user:123")
	time.Sleep(5 * time.Millisecond)
	manager.EndSpan(cacheSpan, "success")

	// End main trace
	manager.EndTrace(trace, "success", "")

	// Verify complete trace
	retrieved, err := manager.GetTrace(trace.RequestID)
	require.NoError(t, err)

	assert.Equal(t, "success", retrieved.Status)
	assert.Equal(t, 2, len(retrieved.Spans))
	assert.Greater(t, retrieved.DurationMs, float64(20)) // Should be at least 25ms
	assert.Equal(t, "192.168.1.100", retrieved.Metadata["client_ip"])

	// Verify spans
	for _, span := range retrieved.Spans {
		assert.Equal(t, "success", span.Status)
		assert.Greater(t, span.DurationMs, float64(0))
	}
}
