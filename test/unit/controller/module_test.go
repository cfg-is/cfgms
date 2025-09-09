package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller"
	testutil "github.com/cfgis/cfgms/pkg/testing"
	unit "github.com/cfgis/cfgms/test/unit"
)

func TestModuleInterface(t *testing.T) {
	// Create a test logger
	logger := unit.NewTestLogger(t)

	// Create a controller
	ctrl, err := controller.New(nil, logger)
	require.NoError(t, err)

	// Create a mock module
	module := testutil.NewMockModule("test-module")

	// Register the module
	err = ctrl.RegisterModule(module)
	assert.NoError(t, err)

	// Get the module
	retrievedModule, err := ctrl.GetModule("test-module")
	assert.NoError(t, err)
	assert.Equal(t, module, retrievedModule)

	// Test module methods
	ctx, cancel := unit.TestContext(t)
	defer cancel()

	// Test Get method
	config, err := retrievedModule.Get(ctx, "test-resource")
	assert.NoError(t, err)
	assert.Equal(t, "", config)

	// Test Set method
	err = retrievedModule.Set(ctx, "test-resource", "test-config")
	assert.NoError(t, err)

	// Test Test method
	matches, err := retrievedModule.Test(ctx, "test-resource", "test-config")
	assert.NoError(t, err)
	assert.True(t, matches)

	// Verify module calls were recorded
	assert.Len(t, module.GetCalls, 1)
	assert.Len(t, module.SetCalls, 1)
	assert.Len(t, module.TestCalls, 1)

	// Verify Get call
	assert.Equal(t, "test-resource", module.GetCalls[0].ResourceID)
	assert.Equal(t, "", module.GetCalls[0].Result)
	assert.Nil(t, module.GetCalls[0].Error)

	// Verify Set call
	assert.Equal(t, "test-resource", module.SetCalls[0].ResourceID)
	assert.Equal(t, "test-config", module.SetCalls[0].ConfigData)
	assert.Nil(t, module.SetCalls[0].Error)

	// Verify Test call
	assert.Equal(t, "test-resource", module.TestCalls[0].ResourceID)
	assert.Equal(t, "test-config", module.TestCalls[0].ConfigData)
	assert.True(t, module.TestCalls[0].Result)
	assert.Nil(t, module.TestCalls[0].Error)
}

func TestModuleCustomBehavior(t *testing.T) {
	// Create a test logger
	logger := unit.NewTestLogger(t)

	// Create a controller
	ctrl, err := controller.New(nil, logger)
	require.NoError(t, err)

	// Create a mock module with custom behavior
	module := testutil.NewMockModule("custom-module")

	// Set custom Get behavior
	module.SetGetFunc(func(ctx context.Context, resourceID string) (string, error) {
		return "custom-config", nil
	})

	// Set custom Set behavior
	module.SetSetFunc(func(ctx context.Context, resourceID string, configData string) error {
		return assert.AnError
	})

	// Set custom Test behavior
	module.SetTestFunc(func(ctx context.Context, resourceID string, configData string) (bool, error) {
		return false, assert.AnError
	})

	// Register the module
	err = ctrl.RegisterModule(module)
	assert.NoError(t, err)

	// Get the module
	retrievedModule, err := ctrl.GetModule("custom-module")
	assert.NoError(t, err)
	assert.Equal(t, module, retrievedModule)

	// Test module methods
	ctx, cancel := unit.TestContext(t)
	defer cancel()

	// Test Get method
	config, err := retrievedModule.Get(ctx, "test-resource")
	assert.NoError(t, err)
	assert.Equal(t, "custom-config", config)

	// Test Set method
	err = retrievedModule.Set(ctx, "test-resource", "test-config")
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)

	// Test Test method
	matches, err := retrievedModule.Test(ctx, "test-resource", "test-config")
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
	assert.False(t, matches)

	// Verify module calls were recorded
	assert.Len(t, module.GetCalls, 1)
	assert.Len(t, module.SetCalls, 1)
	assert.Len(t, module.TestCalls, 1)

	// Verify Get call
	assert.Equal(t, "test-resource", module.GetCalls[0].ResourceID)
	assert.Equal(t, "custom-config", module.GetCalls[0].Result)
	assert.Nil(t, module.GetCalls[0].Error)

	// Verify Set call
	assert.Equal(t, "test-resource", module.SetCalls[0].ResourceID)
	assert.Equal(t, "test-config", module.SetCalls[0].ConfigData)
	assert.Equal(t, assert.AnError, module.SetCalls[0].Error)

	// Verify Test call
	assert.Equal(t, "test-resource", module.TestCalls[0].ResourceID)
	assert.Equal(t, "test-config", module.TestCalls[0].ConfigData)
	assert.False(t, module.TestCalls[0].Result)
	assert.Equal(t, assert.AnError, module.TestCalls[0].Error)
}
