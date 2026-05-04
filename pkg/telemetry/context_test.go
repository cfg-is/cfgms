// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package telemetry_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/pkg/logging"
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

// TestCrossPackageCorrelationIDRoundtrip verifies that logging.WithCorrelation and
// telemetry.GetCorrelationID share the same context slot via ctxkeys.CorrelationIDKey.
func TestCrossPackageCorrelationIDRoundtrip(t *testing.T) {
	ctx := context.Background()
	ctx = logging.WithCorrelation(ctx, "cross-pkg-test-id")

	got := telemetry.GetCorrelationID(ctx)
	assert.Equal(t, "cross-pkg-test-id", got, "telemetry.GetCorrelationID must read value set by logging.WithCorrelation")
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

}
