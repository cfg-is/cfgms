package telemetry_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/telemetry"
)

func TestTracerInitialization(t *testing.T) {
	tests := []struct {
		name    string
		config  *telemetry.Config
		wantErr bool
	}{
		{
			name: "successful initialization with default config",
			config: &telemetry.Config{
				ServiceName:    "test-service",
				ServiceVersion: "v1.0.0",
				Environment:    "test",
				Enabled:        true,
			},
			wantErr: false,
		},
		{
			name: "initialization with disabled tracing",
			config: &telemetry.Config{
				ServiceName: "test-service",
				Enabled:     false,
			},
			wantErr: false,
		},
		{
			name:    "initialization with nil config uses defaults",
			config:  nil,
			wantErr: false,
		},
		{
			name: "initialization with OTLP endpoint",
			config: &telemetry.Config{
				ServiceName:  "test-service",
				Enabled:      true,
				OTLPEndpoint: "localhost:4317",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			tracer, cleanup, err := telemetry.Initialize(ctx, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, tracer)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tracer)
				assert.NotNil(t, cleanup)

				// Clean up
				cleanup()
			}
		})
	}
}

func TestTracerStartSpan(t *testing.T) {
	ctx := context.Background()
	config := &telemetry.Config{
		ServiceName: "test-service",
		Enabled:     true,
	}

	tracer, cleanup, err := telemetry.Initialize(ctx, config)
	require.NoError(t, err)
	defer cleanup()

	t.Run("start basic span", func(t *testing.T) {
		spanCtx, span := tracer.Start(ctx, "test.operation")
		assert.NotNil(t, spanCtx)
		assert.NotNil(t, span)

		// Verify context has span
		assert.NotEqual(t, ctx, spanCtx)

		span.End()
	})

	t.Run("start span with attributes", func(t *testing.T) {
		spanCtx, span := tracer.Start(ctx, "test.operation.with.attrs")
		assert.NotNil(t, span)

		// Add attributes
		span.SetAttributes(
			telemetry.AttributeString("user.id", "12345"),
			telemetry.AttributeInt("request.size", 1024),
		)

		span.End()
		_ = spanCtx
	})

	t.Run("nested spans", func(t *testing.T) {
		// Create parent span
		parentCtx, parentSpan := tracer.Start(ctx, "parent.operation")
		defer parentSpan.End()

		// Create child span
		childCtx, childSpan := tracer.Start(parentCtx, "child.operation")
		defer childSpan.End()

		assert.NotEqual(t, parentCtx, childCtx)
	})
}

func TestTracerWithDisabledTracing(t *testing.T) {
	ctx := context.Background()
	config := &telemetry.Config{
		ServiceName: "test-service",
		Enabled:     false,
	}

	tracer, cleanup, err := telemetry.Initialize(ctx, config)
	require.NoError(t, err)
	defer cleanup()

	t.Run("spans are no-op when disabled", func(t *testing.T) {
		spanCtx, span := tracer.Start(ctx, "test.operation")
		assert.NotNil(t, spanCtx)
		assert.NotNil(t, span)

		// Even when disabled, should return valid (no-op) span
		span.End()
	})
}

func TestSpanWithContext(t *testing.T) {
	ctx := context.Background()
	config := &telemetry.Config{
		ServiceName: "test-service",
		Enabled:     true,
	}

	tracer, cleanup, err := telemetry.Initialize(ctx, config)
	require.NoError(t, err)
	defer cleanup()

	t.Run("span with correlation ID", func(t *testing.T) {
		// Add correlation ID to context
		correlationID := telemetry.GenerateCorrelationID()
		ctx = telemetry.WithCorrelationID(ctx, correlationID)

		spanCtx, span := tracer.Start(ctx, "test.correlated.operation")
		defer span.End()

		// Verify correlation ID is preserved
		assert.Equal(t, correlationID, telemetry.GetCorrelationID(spanCtx))
	})

	t.Run("span timing", func(t *testing.T) {
		startTime := time.Now()
		_, span := tracer.Start(ctx, "test.timed.operation")

		// Simulate some work
		time.Sleep(10 * time.Millisecond)

		span.End()
		duration := time.Since(startTime)

		// Verify timing is reasonable
		assert.GreaterOrEqual(t, duration, 10*time.Millisecond)
	})
}

func TestTracerConcurrency(t *testing.T) {
	ctx := context.Background()
	config := &telemetry.Config{
		ServiceName: "test-service",
		Enabled:     true,
	}

	tracer, cleanup, err := telemetry.Initialize(ctx, config)
	require.NoError(t, err)
	defer cleanup()

	// Run concurrent span operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			spanCtx, span := tracer.Start(ctx, "concurrent.operation")
			defer span.End()

			// Add unique attributes
			span.SetAttributes(
				telemetry.AttributeInt("goroutine.id", id),
			)

			// Simulate work
			time.Sleep(time.Duration(id) * time.Millisecond)
			_ = spanCtx
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestSpanRecordError(t *testing.T) {
	ctx := context.Background()
	config := &telemetry.Config{
		ServiceName: "test-service",
		Enabled:     true,
	}

	tracer, cleanup, err := telemetry.Initialize(ctx, config)
	require.NoError(t, err)
	defer cleanup()

	t.Run("record error in span", func(t *testing.T) {
		_, span := tracer.Start(ctx, "test.error.operation")
		defer span.End()

		// Record an error
		testErr := assert.AnError
		span.RecordError(testErr)

		// Set status to error
		span.SetStatus(telemetry.StatusError, testErr.Error())
	})
}

func TestSamplingConfiguration(t *testing.T) {
	tests := []struct {
		name         string
		samplingRate float64
	}{
		{
			name:         "full sampling",
			samplingRate: 1.0,
		},
		{
			name:         "half sampling",
			samplingRate: 0.5,
		},
		{
			name:         "no sampling",
			samplingRate: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			config := &telemetry.Config{
				ServiceName: "test-service",
				Enabled:     true,
				SampleRate:  tt.samplingRate,
			}

			tracer, cleanup, err := telemetry.Initialize(ctx, config)
			require.NoError(t, err)
			defer cleanup()

			// Create spans
			_, span := tracer.Start(ctx, "test.sampled.operation")
			span.End()
		})
	}
}

func TestTracerPropagation(t *testing.T) {
	ctx := context.Background()
	config := &telemetry.Config{
		ServiceName: "test-service",
		Enabled:     true,
	}

	tracer, cleanup, err := telemetry.Initialize(ctx, config)
	require.NoError(t, err)
	defer cleanup()

	t.Run("extract and inject context", func(t *testing.T) {
		// Create a span
		spanCtx, span := tracer.Start(ctx, "test.propagation")
		defer span.End()

		// In a real scenario, you would:
		// 1. Inject context into carrier (e.g., HTTP headers)
		// 2. Extract context from carrier in another service
		// For testing, we just verify the context is valid
		assert.NotNil(t, spanCtx)
	})
}

func BenchmarkTracerStart(b *testing.B) {
	ctx := context.Background()
	config := &telemetry.Config{
		ServiceName: "bench-service",
		Enabled:     true,
	}

	tracer, cleanup, err := telemetry.Initialize(ctx, config)
	require.NoError(b, err)
	defer cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := tracer.Start(ctx, "bench.operation")
		span.End()
	}
}

func BenchmarkTracerStartDisabled(b *testing.B) {
	ctx := context.Background()
	config := &telemetry.Config{
		ServiceName: "bench-service",
		Enabled:     false,
	}

	tracer, cleanup, err := telemetry.Initialize(ctx, config)
	require.NoError(b, err)
	defer cleanup()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := tracer.Start(ctx, "bench.operation")
		span.End()
	}
}
