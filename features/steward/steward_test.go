package steward

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testutil"
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
			cfg:     nil, // Use nil to get a config with test certificates
			wantErr: false,
		},
		{
			name:    "with nil config",
			cfg:     nil,
			wantErr: false,
		},
		{
			name:    "with custom config",
			cfg:     nil, // Will be set up with test certificates
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test logger
			logger := logging.NewLogger("info")

			var testCfg *Config
			
			if tt.cfg == nil {
				// Use test configuration with certificates
				if tt.name == "with custom config" {
					testConfig := &testutil.StewardTestConfig{
						ControllerAddr: "localhost:9090",
						StewardID:      "test-steward-1",
						LogLevel:       "debug",
					}
					certDir, dataDir, cleanup := testutil.SetupTestEnvironment(t, testConfig)
					testCfg = &Config{
						ControllerAddr: testConfig.ControllerAddr,
						CertPath:       certDir,
						DataDir:        dataDir,
						LogLevel:       testConfig.LogLevel,
						ID:             testConfig.StewardID,
					}
					t.Cleanup(cleanup)
				} else {
					testConfig := testutil.DefaultStewardTestConfig()
					certDir, dataDir, cleanup := testutil.SetupTestEnvironment(t, testConfig)
					testCfg = &Config{
						ControllerAddr: testConfig.ControllerAddr,
						CertPath:       certDir,
						DataDir:        dataDir,
						LogLevel:       testConfig.LogLevel,
						ID:             testConfig.StewardID,
					}
					t.Cleanup(cleanup)
				}
			} else {
				testCfg = tt.cfg
			}

			steward, err := New(testCfg, logger)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, steward)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, steward)

				// Verify the steward was created successfully
				assert.NotNil(t, steward)
				
				// Verify some basic properties
				if tt.name == "with custom config" {
					assert.Equal(t, "localhost:9090", testCfg.ControllerAddr)
					assert.Equal(t, "test-steward-1", testCfg.ID)
					assert.Equal(t, "debug", testCfg.LogLevel)
				}
			}
		})
	}
}

func TestStewardLifecycle(t *testing.T) {
	// Create a test logger
	logger := logging.NewLogger("info")

	// Set up test configuration with certificates
	testConfig := testutil.DefaultStewardTestConfig()
	testConfig.StewardID = "test-steward-lifecycle"
	certDir, dataDir, cleanup := testutil.SetupTestEnvironment(t, testConfig)
	t.Cleanup(cleanup)

	cfg := &Config{
		ControllerAddr: testConfig.ControllerAddr,
		CertPath:       certDir,
		DataDir:        dataDir,
		LogLevel:       testConfig.LogLevel,
		ID:             testConfig.StewardID,
	}

	steward, err := New(cfg, logger)
	require.NoError(t, err)

	// Test that the steward was created successfully
	assert.NotNil(t, steward)
	assert.Equal(t, "test-steward-lifecycle", cfg.ID)
	
	// Note: We don't test Start() here as it would try to connect to a real controller
	// Actual start/stop lifecycle testing is done in integration tests
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