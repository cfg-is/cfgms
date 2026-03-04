// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/pkg/cert"
	testutil "github.com/cfgis/cfgms/pkg/testing"
	unit "github.com/cfgis/cfgms/test/unit"
)

// newTestController creates a controller with pre-initialized CA and init marker
// in a temp directory, matching the Story #410 requirement that controllers must
// be explicitly initialized before startup.
func newTestController(t *testing.T) *controller.Controller {
	t.Helper()
	tempDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.DataDir = tempDir + "/data"
	cfg.CertPath = tempDir + "/certs"
	cfg.Certificate.CAPath = tempDir + "/certs/ca"
	cfg.Storage.Config["repository_path"] = tempDir + "/storage"

	// Pre-initialize: create CA and write init marker
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: cfg.CertPath,
		CAConfig: &cert.CAConfig{
			Organization: "Test Org",
			Country:      "US",
			ValidityDays: 3650,
			StoragePath:  cfg.Certificate.CAPath,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "failed to create test CA")
	require.NoError(t, initialization.CreateLegacyMarker(cfg.Certificate.CAPath), "failed to write init marker")

	logger := unit.NewTestLogger(t)
	ctrl, err := controller.New(cfg, logger)
	require.NoError(t, err)
	return ctrl
}

func TestModuleInterface(t *testing.T) {
	// Create a pre-initialized controller (Story #410: explicit init required)
	ctrl := newTestController(t)

	// Create a mock module
	module := testutil.NewMockModule("test-module")

	// Register the module
	err := ctrl.RegisterModule(module)
	assert.NoError(t, err)

	// Get the module using the typed method
	retrievedModule, err := ctrl.GetModuleTyped("test-module")
	assert.NoError(t, err)
	assert.NotNil(t, retrievedModule)

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
	// Create a pre-initialized controller (Story #410: explicit init required)
	ctrl := newTestController(t)

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
	err := ctrl.RegisterModule(module)
	assert.NoError(t, err)

	// Get the module using the typed method
	retrievedModule, err := ctrl.GetModuleTyped("custom-module")
	assert.NoError(t, err)
	assert.NotNil(t, retrievedModule)

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
