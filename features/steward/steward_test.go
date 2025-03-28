package steward

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testutil "cfgms/pkg/testing"
)

func TestStewardCreation(t *testing.T) {
	// Test cases
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name:    "with default config",
			cfg:     DefaultConfig(),
			wantErr: false,
		},
		{
			name:    "with nil config",
			cfg:     nil,
			wantErr: false,
		},
		{
			name: "with custom config",
			cfg: &Config{
				ControllerAddr: "localhost:9090",
				CertPath:       "/custom/certs",
				DataDir:        "/custom/data",
				LogLevel:       "debug",
				ID:             "test-steward-1",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test logger
			logger := testutil.NewMockLogger(true)

			steward, err := New(tt.cfg, logger)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, steward)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, steward)

				// Verify config
				if tt.cfg == nil {
					// Should use defaults
					assert.Equal(t, DefaultConfig().ControllerAddr, steward.config.ControllerAddr)
				} else {
					assert.Equal(t, tt.cfg.ControllerAddr, steward.config.ControllerAddr)
					assert.Equal(t, tt.cfg.ID, steward.config.ID)
				}
			}
		})
	}
}

func TestStewardLifecycle(t *testing.T) {
	// Create a test logger
	logger := testutil.NewMockLogger(false)

	// Create a steward with a specific ID for testing
	cfg := DefaultConfig()
	cfg.ID = "test-steward-lifecycle"

	steward, err := New(cfg, logger)
	require.NoError(t, err)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Start the steward
	err = steward.Start(ctx)
	assert.NoError(t, err)

	// Verify start logged properly
	infoLogs := logger.GetLogs("info")
	assert.GreaterOrEqual(t, len(infoLogs), 1)
	assert.Contains(t, infoLogs[0].Message, "Starting steward")

	// Stop the steward
	err = steward.Stop(ctx)
	assert.NoError(t, err)

	// Verify stop logged properly
	infoLogs = logger.GetLogs("info")
	assert.GreaterOrEqual(t, len(infoLogs), 3) // Should have at least 3 info logs
	var foundStopLog bool
	for _, log := range infoLogs {
		if log.Message == "Stopping steward" {
			foundStopLog = true
			break
		}
	}
	assert.True(t, foundStopLog, "Should have logged 'Stopping steward'")
}

func TestHealthMonitor(t *testing.T) {
	// Test cases for health monitor
	tests := []struct {
		name        string
		setupFn     func(*HealthMonitor)
		checkStatus HealthStatus
	}{
		{
			name: "default is healthy",
			setupFn: func(hm *HealthMonitor) {
				// No setup, should be healthy by default
			},
			checkStatus: StatusHealthy,
		},
		{
			name: "record error changes metrics",
			setupFn: func(hm *HealthMonitor) {
				hm.RecordConfigError()
				hm.RecordConfigError()
				hm.RecordConfigError()
			},
			checkStatus: StatusHealthy, // Status doesn't change automatically
		},
		{
			name: "record latency updates metrics",
			setupFn: func(hm *HealthMonitor) {
				hm.RecordTaskLatency(500 * time.Millisecond)
			},
			checkStatus: StatusHealthy, // Status doesn't change automatically
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test logger
			logger := testutil.NewMockLogger(true)

			// Create a health monitor
			monitor := NewHealthMonitor(logger)

			// Apply setup function
			if tt.setupFn != nil {
				tt.setupFn(monitor)
			}

			// Check status
			assert.Equal(t, tt.checkStatus, monitor.GetStatus())

			// Create context for monitor
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			// Start the monitor
			go monitor.Start(ctx)

			// Let it run briefly
			time.Sleep(50 * time.Millisecond)

			// Stop the monitor
			monitor.Stop()
		})
	}
}

// TODO: Add more comprehensive tests
