package controller

import (
	"context"
	"testing"
	
	"github.com/stretchr/testify/assert"
	
	"cfgms/features/controller/config"
	"cfgms/pkg/logging"
)

func TestControllerCreation(t *testing.T) {
	// Create a test logger
	logger := logging.NewLogger("debug")
	
	// Create a controller with default config
	controller, err := New(config.DefaultConfig(), logger)
	assert.NoError(t, err)
	assert.NotNil(t, controller)
	
	// Create a controller with nil config (should use defaults)
	controller, err = New(nil, logger)
	assert.NoError(t, err)
	assert.NotNil(t, controller)
}

func TestControllerLifecycle(t *testing.T) {
	// Create a test logger
	logger := logging.NewLogger("debug")
	
	// Create a controller
	controller, err := New(config.DefaultConfig(), logger)
	assert.NoError(t, err)
	
	// Create a context with timeout
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Start the controller
	err = controller.Start(ctx)
	assert.NoError(t, err)
	
	// Stop the controller
	err = controller.Stop(ctx)
	assert.NoError(t, err)
}

// TODO: Add more comprehensive tests 