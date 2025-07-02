package steward

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
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
			logger := logging.NewLogger("info")

			steward, err := New(tt.cfg, logger)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, steward)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, steward)

				// Verify config (using legacyConfig field)
				if tt.cfg == nil {
					// Should use defaults
					assert.Equal(t, DefaultConfig().ControllerAddr, steward.legacyConfig.ControllerAddr)
				} else {
					assert.Equal(t, tt.cfg.ControllerAddr, steward.legacyConfig.ControllerAddr)
					assert.Equal(t, tt.cfg.ID, steward.legacyConfig.ID)
				}
			}
		})
	}
}

func TestStewardLifecycle(t *testing.T) {
	// Create a test logger
	logger := logging.NewLogger("info")

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

	// Stop the steward
	err = steward.Stop(ctx)
	assert.NoError(t, err)
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
			checkStatus: StatusDegraded, // Status changes to degraded after errors
		},
		{
			name: "record latency updates metrics",
			setupFn: func(hm *HealthMonitor) {
				hm.RecordTaskLatency(500 * time.Millisecond)
			},
			checkStatus: StatusDegraded, // Status changes to degraded after high latency
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test logger
			logger := logging.NewLogger("info")

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

func TestNewStandalone(t *testing.T) {
	// Test standalone creation with empty config (should fail)
	logger := logging.NewLogger("info")

	steward, err := NewStandalone("", logger)

	// Should fail because no config found
	assert.Error(t, err)
	assert.Nil(t, steward)
	assert.Contains(t, err.Error(), "no configuration file found")
}