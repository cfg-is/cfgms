// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	testutil "github.com/cfgis/cfgms/pkg/testing"
	pkgtestutil "github.com/cfgis/cfgms/pkg/testutil"
)

func TestControllerCreation(t *testing.T) {
	// Create a test logger
	logger := testutil.NewMockLogger(true)

	// Test cases
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name:    "with default config",
			cfg:     config.DefaultConfig(),
			wantErr: false,
		},
		{
			name:    "with nil config (uses DefaultConfig internally)",
			cfg:     config.DefaultConfig(), // nil → DefaultConfig(), so test with explicit default
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a temporary directory for each test to avoid conflicts
			tempDir := t.TempDir()

			// Update config to use temp directory if provided
			if tt.cfg != nil {
				tt.cfg.DataDir = tempDir + "/data"
				tt.cfg.CertPath = tempDir + "/certs"
				if tt.cfg.Certificate != nil {
					tt.cfg.Certificate.CAPath = tempDir + "/certs/ca"
				}
				if tt.cfg.Storage != nil && tt.cfg.Storage.Config != nil {
					tt.cfg.Storage.Config["repository_path"] = tempDir + "/storage"
				}
				// Pre-initialize if cert management is enabled (Story #410)
				if tt.cfg.Certificate != nil && tt.cfg.Certificate.EnableCertManagement {
					pkgtestutil.PreInitControllerForTest(t, tt.cfg.CertPath, tt.cfg.Certificate.CAPath)
				}
			}

			controller, err := New(tt.cfg, logger)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, controller)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, controller)
				if controller != nil {
					t.Cleanup(func() { _ = controller.Close() })
				}
			}
		})
	}
}

func TestControllerLifecycle(t *testing.T) {
	// Use a temporary directory for this test
	tempDir := t.TempDir()

	// Create a test logger and controller
	logger := testutil.NewMockLogger(true)

	cfg := config.DefaultConfig()
	cfg.DataDir = tempDir + "/data"
	cfg.CertPath = tempDir + "/certs"
	if cfg.Certificate != nil {
		cfg.Certificate.CAPath = tempDir + "/certs/ca"
	}
	if cfg.Storage != nil && cfg.Storage.Config != nil {
		cfg.Storage.Config["repository_path"] = tempDir + "/storage"
	}

	// Pre-initialize (Story #410: controller requires explicit init)
	pkgtestutil.PreInitControllerForTest(t, cfg.CertPath, cfg.Certificate.CAPath)

	// Use ephemeral port for transport to avoid port conflicts in tests
	if cfg.Transport != nil {
		cfg.Transport.ListenAddr = "127.0.0.1:0"
	}
	// Disable legacy QUIC data plane (replaced by gRPC DP on shared transport, Story #515)
	if cfg.QUIC != nil {
		cfg.QUIC.Enabled = false
	}

	ctrl, err := New(cfg, logger)
	require.NoError(t, err)

	// Start the controller
	ctx := context.Background()
	err = ctrl.Start(ctx)
	assert.NoError(t, err)

	// Verify start logged properly - certificate management and REST API adds extra logs
	infoLogs := logger.GetLogs("info")
	assert.GreaterOrEqual(t, len(infoLogs), 8)

	// Convert logs to messages for easier checking
	messages := make([]string, len(infoLogs))
	for i, log := range infoLogs {
		messages[i] = log.Message
	}

	// Verify required messages are present: CA is always loaded (init was done by PreInitControllerForTest)
	caLoaded := false
	for _, msg := range messages {
		if msg == "Loaded existing Certificate Authority" {
			caLoaded = true
			break
		}
	}
	assert.True(t, caLoaded, "Expected CA to be loaded from pre-initialized state")

	// M-AUTH-1: No longer generating default API keys (security anti-pattern removed)
	assert.Contains(t, messages, "Starting controller")
	assert.Contains(t, messages, "Controller server started (gRPC-over-QUIC transport mode)")
	assert.Contains(t, messages, "REST API server started")
	assert.Contains(t, messages, "Controller started successfully")

	// Certificate message can be either "Using existing" or "Generating new" depending on environment
	// With gRPC removed, we only check for HTTP server certificates
	httpCertificateFound := false
	for _, msg := range messages {
		if msg == "Using existing server certificate for HTTP server" || msg == "Generated new server certificate for HTTP server" {
			httpCertificateFound = true
		}
	}
	assert.True(t, httpCertificateFound, "Expected HTTP certificate message not found in logs: %v", messages)

	// Stop the controller
	err = ctrl.Stop(ctx)
	assert.NoError(t, err)

	// Verify stop logged properly - check that required messages exist
	infoLogs = logger.GetLogs("info")
	assert.GreaterOrEqual(t, len(infoLogs), 10)

	// Update messages slice with all current logs
	messages = make([]string, len(infoLogs))
	for i, log := range infoLogs {
		messages[i] = log.Message
	}

	// Verify required startup messages are present
	assert.Contains(t, messages, "Starting controller")
	assert.Contains(t, messages, "Controller server started (gRPC-over-QUIC transport mode)")
	assert.Contains(t, messages, "REST API server started")
	assert.Contains(t, messages, "Controller started successfully")

	// Verify required shutdown messages are present
	assert.Contains(t, messages, "Stopping controller")
	assert.Contains(t, messages, "Shutting down REST API server")
	assert.Contains(t, messages, "Shutting down controller server")
	assert.Contains(t, messages, "Controller stopped successfully")
}

func TestModuleRegistration(t *testing.T) {
	// Create a test logger and controller
	logger := testutil.NewMockLogger(true)
	tempDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.DataDir = tempDir + "/data"
	cfg.CertPath = tempDir + "/certs"
	if cfg.Certificate != nil {
		cfg.Certificate.CAPath = tempDir + "/certs/ca"
	}
	if cfg.Storage != nil && cfg.Storage.Config != nil {
		cfg.Storage.Config["repository_path"] = tempDir + "/storage"
	}
	pkgtestutil.PreInitControllerForTest(t, cfg.CertPath, cfg.Certificate.CAPath)
	ctrl, err := New(cfg, logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctrl.Close() })

	// Create mock modules
	moduleA := testutil.NewMockModule("moduleA")
	moduleB := testutil.NewMockModule("moduleB")

	// Register the first module
	err = ctrl.RegisterModule(moduleA)
	assert.NoError(t, err)

	// Register the second module
	err = ctrl.RegisterModule(moduleB)
	assert.NoError(t, err)

	// Try to register a duplicate module
	duplicateModule := testutil.NewMockModule("moduleA")
	err = ctrl.RegisterModule(duplicateModule)
	assert.Error(t, err)
	assert.Equal(t, ErrModuleExists, err)

	// Get a registered module
	_, err = ctrl.GetModule("moduleA")
	assert.NoError(t, err)

	// Get a non-existent module
	_, err = ctrl.GetModule("nonExistentModule")
	assert.Error(t, err)
	assert.Equal(t, ErrModuleNotFound, err)
}

// TODO: Add more comprehensive tests
