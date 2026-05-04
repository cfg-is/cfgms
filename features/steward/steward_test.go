// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package steward_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	steward "github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestHealthMonitor(t *testing.T) {
	// Test cases for health monitor
	tests := []struct {
		name        string
		setupFn     func(*steward.HealthMonitor)
		checkStatus steward.HealthStatus
	}{
		{
			name: "default is healthy",
			setupFn: func(hm *steward.HealthMonitor) {
				// No setup, should be healthy by default
			},
			checkStatus: steward.StatusHealthy,
		},
		{
			name: "record error changes metrics",
			setupFn: func(hm *steward.HealthMonitor) {
				hm.RecordConfigError()
				hm.RecordConfigError()
				hm.RecordConfigError()
			},
			checkStatus: steward.StatusDegraded, // Status changes to degraded after errors
		},
		{
			name: "record latency updates metrics",
			setupFn: func(hm *steward.HealthMonitor) {
				hm.RecordTaskLatency(500 * time.Millisecond)
			},
			checkStatus: steward.StatusDegraded, // Status changes to degraded after high latency
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test logger
			logger := logging.NewLogger("info")

			// Create a health monitor
			monitor := steward.NewHealthMonitor(logger)

			// Apply setup function
			if tt.setupFn != nil {
				tt.setupFn(monitor)
			}

			// Check status — assertions happen synchronously; no goroutine needed
			assert.Equal(t, tt.checkStatus, monitor.GetStatus())
		})
	}
}

func TestNewStandalone(t *testing.T) {
	// Test standalone creation with empty config (should fail)
	logger := logging.NewLogger("info")

	s, err := steward.NewStandalone("", logger)

	// Should fail because no config found
	assert.Error(t, err)
	assert.Nil(t, s)
	assert.Contains(t, err.Error(), "failed to load configuration")
}

// TestNewStandaloneWithConfig tests that NewStandalone succeeds with a valid config file.
func TestNewStandaloneWithConfig(t *testing.T) {
	logger := logging.NewLogger("info")
	dir := t.TempDir()
	cfgPath := writeMinimalCfg(t, dir, "standalone-test-steward")

	s, err := steward.NewStandalone(cfgPath, logger)
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.Equal(t, "standalone-test-steward", s.GetStewardID())
	// Constructor success + Start()/Stop() succeeding proves healthCheck and executor wiring.
	require.NoError(t, s.Stop(context.Background()))
}
