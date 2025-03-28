package controller

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"cfgms/features/controller/config"
	testutil "cfgms/pkg/testing"
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
			name:    "with nil config",
			cfg:     nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller, err := New(tt.cfg, logger)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, controller)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, controller)
			}
		})
	}
}

func TestControllerLifecycle(t *testing.T) {
	// Create a test logger
	logger := testutil.NewMockLogger(false)

	// Create a controller
	ctrl, err := New(config.DefaultConfig(), logger)
	require.NoError(t, err)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Start the controller
	err = ctrl.Start(ctx)
	assert.NoError(t, err)

	// Verify start logged properly
	infoLogs := logger.GetLogs("info")
	assert.GreaterOrEqual(t, len(infoLogs), 1)
	assert.Equal(t, "Starting controller", infoLogs[0].Message)

	// Stop the controller
	err = ctrl.Stop(ctx)
	assert.NoError(t, err)

	// Verify stop logged properly
	infoLogs = logger.GetLogs("info")
	assert.GreaterOrEqual(t, len(infoLogs), 2)
	assert.Equal(t, "Stopping controller", infoLogs[1].Message)
}

func TestModuleRegistration(t *testing.T) {
	// Create a test logger and controller
	logger := testutil.NewMockLogger(true)
	ctrl, err := New(config.DefaultConfig(), logger)
	require.NoError(t, err)

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
