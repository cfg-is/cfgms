package steward

import (
	"context"
	"testing"
	"time"
	
	"github.com/stretchr/testify/assert"
	
	"cfgms/pkg/logging"
)

func TestStewardCreation(t *testing.T) {
	// Create a test logger
	logger := logging.NewLogger("debug")
	
	// Create a steward with default config
	steward, err := New(DefaultConfig(), logger)
	assert.NoError(t, err)
	assert.NotNil(t, steward)
	
	// Create a steward with nil config (should use defaults)
	steward, err = New(nil, logger)
	assert.NoError(t, err)
	assert.NotNil(t, steward)
}

func TestStewardLifecycle(t *testing.T) {
	// Create a test logger
	logger := logging.NewLogger("debug")
	
	// Create a steward
	steward, err := New(DefaultConfig(), logger)
	assert.NoError(t, err)
	
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	// Start the steward
	err = steward.Start(ctx)
	assert.NoError(t, err)
	
	// Stop the steward
	err = steward.Stop(ctx)
	assert.NoError(t, err)
}

func TestHealthMonitor(t *testing.T) {
	// Create a test logger
	logger := logging.NewLogger("debug")
	
	// Create a health monitor
	monitor := NewHealthMonitor(logger)
	assert.NotNil(t, monitor)
	
	// Initial status should be healthy
	assert.Equal(t, StatusHealthy, monitor.GetStatus())
	
	// Record a task latency
	testLatency := 100 * time.Millisecond
	monitor.RecordTaskLatency(testLatency)
	
	// Verify metrics were updated
	metrics := monitor.GetMetrics()
	assert.Equal(t, testLatency, metrics.TaskLatency)
	
	// Record a config error
	monitor.RecordConfigError()
	
	// Verify error count was incremented
	metrics = monitor.GetMetrics()
	assert.Equal(t, 1, metrics.ConfigErrors)
	
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	
	// Start the monitor in a goroutine
	go monitor.Start(ctx)
	
	// Let it run for a bit
	time.Sleep(500 * time.Millisecond)
	
	// Stop the monitor
	monitor.Stop()
}

// TODO: Add more comprehensive tests 