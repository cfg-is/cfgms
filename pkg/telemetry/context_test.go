package telemetry_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/pkg/telemetry"
)

// Context key type to avoid collisions
type contextKey string

const testKey contextKey = "test"

func TestCorrelationID(t *testing.T) {
	t.Run("generate correlation ID", func(t *testing.T) {
		id1 := telemetry.GenerateCorrelationID()
		id2 := telemetry.GenerateCorrelationID()

		// Should be unique
		assert.NotEqual(t, id1, id2)

		// Should be valid format
		assert.Regexp(t, `^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`, id1)
		assert.Regexp(t, `^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`, id2)
	})

	t.Run("correlation ID in context", func(t *testing.T) {
		ctx := context.Background()
		correlationID := telemetry.GenerateCorrelationID()

		// Add to context
		ctxWithID := telemetry.WithCorrelationID(ctx, correlationID)

		// Retrieve from context
		retrievedID := telemetry.GetCorrelationID(ctxWithID)
		assert.Equal(t, correlationID, retrievedID)
	})

	t.Run("missing correlation ID returns empty", func(t *testing.T) {
		ctx := context.Background()
		
		// Should return empty string when not set
		retrievedID := telemetry.GetCorrelationID(ctx)
		assert.Empty(t, retrievedID)
	})

	t.Run("correlation ID propagation", func(t *testing.T) {
		ctx := context.Background()
		correlationID := telemetry.GenerateCorrelationID()

		// Create parent context with ID
		parentCtx := telemetry.WithCorrelationID(ctx, correlationID)

		// Create child context
		childCtx := context.WithValue(parentCtx, testKey, "value")

		// Correlation ID should be preserved
		assert.Equal(t, correlationID, telemetry.GetCorrelationID(childCtx))
	})
}

func TestTraceID(t *testing.T) {
	t.Run("generate trace ID", func(t *testing.T) {
		id1 := telemetry.GenerateTraceID()
		id2 := telemetry.GenerateTraceID()

		// Should be unique
		assert.NotEqual(t, id1, id2)

		// Should be 32 character hex string
		assert.Len(t, id1, 32)
		assert.Len(t, id2, 32)
		assert.Regexp(t, `^[a-f0-9]{32}$`, id1)
		assert.Regexp(t, `^[a-f0-9]{32}$`, id2)
	})

	t.Run("trace ID in context", func(t *testing.T) {
		ctx := context.Background()
		traceID := telemetry.GenerateTraceID()

		// Add to context
		ctxWithID := telemetry.WithTraceID(ctx, traceID)

		// Retrieve from context
		retrievedID := telemetry.GetTraceID(ctxWithID)
		assert.Equal(t, traceID, retrievedID)
	})

	t.Run("missing trace ID returns empty", func(t *testing.T) {
		ctx := context.Background()
		
		// Should return empty string when not set
		retrievedID := telemetry.GetTraceID(ctx)
		assert.Empty(t, retrievedID)
	})
}

func TestSpanID(t *testing.T) {
	t.Run("generate span ID", func(t *testing.T) {
		id1 := telemetry.GenerateSpanID()
		id2 := telemetry.GenerateSpanID()

		// Should be unique
		assert.NotEqual(t, id1, id2)

		// Should be 16 character hex string
		assert.Len(t, id1, 16)
		assert.Len(t, id2, 16)
		assert.Regexp(t, `^[a-f0-9]{16}$`, id1)
		assert.Regexp(t, `^[a-f0-9]{16}$`, id2)
	})

	t.Run("span ID in context", func(t *testing.T) {
		ctx := context.Background()
		spanID := telemetry.GenerateSpanID()

		// Add to context
		ctxWithID := telemetry.WithSpanID(ctx, spanID)

		// Retrieve from context
		retrievedID := telemetry.GetSpanID(ctxWithID)
		assert.Equal(t, spanID, retrievedID)
	})
}

func TestMultipleIDs(t *testing.T) {
	t.Run("all IDs in same context", func(t *testing.T) {
		ctx := context.Background()
		
		correlationID := telemetry.GenerateCorrelationID()
		traceID := telemetry.GenerateTraceID()
		spanID := telemetry.GenerateSpanID()

		// Add all IDs to context
		ctx = telemetry.WithCorrelationID(ctx, correlationID)
		ctx = telemetry.WithTraceID(ctx, traceID)
		ctx = telemetry.WithSpanID(ctx, spanID)

		// Retrieve all IDs
		assert.Equal(t, correlationID, telemetry.GetCorrelationID(ctx))
		assert.Equal(t, traceID, telemetry.GetTraceID(ctx))
		assert.Equal(t, spanID, telemetry.GetSpanID(ctx))
	})

	t.Run("update individual IDs", func(t *testing.T) {
		ctx := context.Background()
		
		// Set initial IDs
		ctx = telemetry.WithCorrelationID(ctx, "initial-correlation")
		ctx = telemetry.WithTraceID(ctx, "initial-trace")
		
		// Update correlation ID
		newCorrelationID := telemetry.GenerateCorrelationID()
		ctx = telemetry.WithCorrelationID(ctx, newCorrelationID)

		// Original trace ID should be preserved
		assert.Equal(t, newCorrelationID, telemetry.GetCorrelationID(ctx))
		assert.Equal(t, "initial-trace", telemetry.GetTraceID(ctx))
	})
}

func TestContextPropagation(t *testing.T) {
	t.Run("propagate through function calls", func(t *testing.T) {
		ctx := context.Background()
		correlationID := telemetry.GenerateCorrelationID()
		ctx = telemetry.WithCorrelationID(ctx, correlationID)

		// Simulate function that uses context
		processWithContext := func(ctx context.Context) string {
			return telemetry.GetCorrelationID(ctx)
		}

		// Correlation ID should be available in function
		assert.Equal(t, correlationID, processWithContext(ctx))
	})

	t.Run("goroutine propagation", func(t *testing.T) {
		ctx := context.Background()
		correlationID := telemetry.GenerateCorrelationID()
		ctx = telemetry.WithCorrelationID(ctx, correlationID)

		done := make(chan string)
		go func(ctx context.Context) {
			done <- telemetry.GetCorrelationID(ctx)
		}(ctx)

		// Correlation ID should be available in goroutine
		assert.Equal(t, correlationID, <-done)
	})
}

func TestEnsureCorrelationID(t *testing.T) {
	t.Run("add correlation ID if missing", func(t *testing.T) {
		ctx := context.Background()
		
		// Ensure correlation ID exists
		ctx = telemetry.EnsureCorrelationID(ctx)
		
		// Should have a correlation ID now
		id := telemetry.GetCorrelationID(ctx)
		assert.NotEmpty(t, id)
	})

	t.Run("preserve existing correlation ID", func(t *testing.T) {
		ctx := context.Background()
		existingID := telemetry.GenerateCorrelationID()
		ctx = telemetry.WithCorrelationID(ctx, existingID)
		
		// Ensure should not change existing ID
		ctx = telemetry.EnsureCorrelationID(ctx)
		
		assert.Equal(t, existingID, telemetry.GetCorrelationID(ctx))
	})
}

func BenchmarkGenerateCorrelationID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = telemetry.GenerateCorrelationID()
	}
}

func BenchmarkGenerateTraceID(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = telemetry.GenerateTraceID()
	}
}

func BenchmarkContextWithCorrelationID(b *testing.B) {
	ctx := context.Background()
	correlationID := telemetry.GenerateCorrelationID()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = telemetry.WithCorrelationID(ctx, correlationID)
	}
}

func BenchmarkGetCorrelationID(b *testing.B) {
	ctx := context.Background()
	ctx = telemetry.WithCorrelationID(ctx, telemetry.GenerateCorrelationID())
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = telemetry.GetCorrelationID(ctx)
	}
}

func TestCorrelationIDUniqueness(t *testing.T) {
	// Generate many IDs to test uniqueness
	ids := make(map[string]bool)
	count := 1000

	for i := 0; i < count; i++ {
		id := telemetry.GenerateCorrelationID()
		if ids[id] {
			t.Errorf("Duplicate correlation ID generated: %s", id)
		}
		ids[id] = true
	}

	assert.Len(t, ids, count)
}

func TestIDFormats(t *testing.T) {
	t.Run("correlation ID format", func(t *testing.T) {
		id := telemetry.GenerateCorrelationID()
		parts := strings.Split(id, "-")
		
		// UUID format: 8-4-4-4-12
		assert.Len(t, parts, 5)
		assert.Len(t, parts[0], 8)
		assert.Len(t, parts[1], 4)
		assert.Len(t, parts[2], 4)
		assert.Len(t, parts[3], 4)
		assert.Len(t, parts[4], 12)
	})

	t.Run("trace ID format", func(t *testing.T) {
		id := telemetry.GenerateTraceID()
		
		// Should be 32 hex characters
		assert.Len(t, id, 32)
		for _, char := range id {
			assert.Contains(t, "0123456789abcdef", string(char))
		}
	})

	t.Run("span ID format", func(t *testing.T) {
		id := telemetry.GenerateSpanID()
		
		// Should be 16 hex characters
		assert.Len(t, id, 16)
		for _, char := range id {
			assert.Contains(t, "0123456789abcdef", string(char))
		}
	})
}