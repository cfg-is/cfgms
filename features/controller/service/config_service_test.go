// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Import storage provider for testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func createTestStewardConfig(stewardID string) *stewardconfig.StewardConfig {
	return &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   stewardID,
			Mode: stewardconfig.ModeController,
			Logging: stewardconfig.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
			ErrorHandling: stewardconfig.ErrorHandlingConfig{
				ModuleLoadFailure:  stewardconfig.ActionContinue,
				ResourceFailure:    stewardconfig.ActionWarn,
				ConfigurationError: stewardconfig.ActionFail,
			},
		},
		// Modules map must include all modules referenced in Resources to prevent
		// MISSING_MODULES validation warnings (map value is the custom module path)
		Modules: map[string]string{
			"directory": "directory",
			"file":      "file",
		},
		Resources: []stewardconfig.ResourceConfig{
			{
				Name:   "test-directory",
				Module: "directory",
				Config: map[string]interface{}{
					"path":        "/tmp/test",
					"permissions": "755",
				},
			},
			{
				Name:   "test-file",
				Module: "file",
				Config: map[string]interface{}{
					"path":    "/tmp/test/test.txt",
					"content": "Hello World",
				},
			},
		},
	}
}

// createTestServiceV2 creates a ConfigurationServiceV2 backed by a real git StorageManager
func createTestServiceV2(t *testing.T) *ConfigurationServiceV2 {
	t.Helper()

	logger := logging.NewNoopLogger()
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)

	return NewConfigurationServiceV2(logger, storageManager, nil)
}

func TestNewConfigurationServiceV2(t *testing.T) {
	svc := createTestServiceV2(t)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.storageManager)
}

func TestSetConfiguration(t *testing.T) {
	ctx := context.Background()
	svc := createTestServiceV2(t)

	stewardID := "test-steward"
	cfg := createTestStewardConfig(stewardID)

	// Test setting configuration
	err := svc.SetConfiguration(ctx, "default", stewardID, cfg)
	require.NoError(t, err)

	// Test retrieving configuration via GetConfiguration (protobuf path)
	req := &controller.ConfigRequest{StewardId: stewardID}
	resp, err := svc.GetConfiguration(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, common.Status_OK, resp.Status.Code)
	assert.NotEmpty(t, resp.Version)

	// Verify content round-trips through protobuf
	require.NotNil(t, resp.Config)
	require.NotNil(t, resp.Config.Config)
	retrieved, err := stewardconfig.FromProto(resp.Config.Config)
	require.NoError(t, err)
	assert.Equal(t, cfg.Steward.ID, retrieved.Steward.ID)
	assert.Len(t, retrieved.Resources, 2)

	// Test updating configuration
	cfg.Resources[0].Config["permissions"] = "644"
	err = svc.SetConfiguration(ctx, "default", stewardID, cfg)
	require.NoError(t, err)

	// Verify update
	resp2, err := svc.GetConfiguration(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, common.Status_OK, resp2.Status.Code)
}

func TestGetConfiguration(t *testing.T) {
	ctx := context.Background()
	svc := createTestServiceV2(t)

	stewardID := "test-steward"
	cfg := createTestStewardConfig(stewardID)

	t.Run("configuration not found", func(t *testing.T) {
		req := &controller.ConfigRequest{StewardId: stewardID}
		resp, err := svc.GetConfiguration(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_NOT_FOUND, resp.Status.Code)
		assert.Contains(t, resp.Status.Message, "No configuration found")
	})

	t.Run("successful configuration retrieval", func(t *testing.T) {
		err := svc.SetConfiguration(ctx, "default", stewardID, cfg)
		require.NoError(t, err)

		req := &controller.ConfigRequest{StewardId: stewardID}
		resp, err := svc.GetConfiguration(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_OK, resp.Status.Code)
		assert.NotEmpty(t, resp.Config)
		assert.NotEmpty(t, resp.Version)

		require.NotNil(t, resp.Config)
		require.NotNil(t, resp.Config.Config)
		retrieved, err := stewardconfig.FromProto(resp.Config.Config)
		require.NoError(t, err)
		assert.Equal(t, cfg.Steward.ID, retrieved.Steward.ID)
		assert.Len(t, retrieved.Resources, 2)
	})

	t.Run("configuration with module filtering", func(t *testing.T) {
		err := svc.SetConfiguration(ctx, "default", stewardID, cfg)
		require.NoError(t, err)

		req := &controller.ConfigRequest{
			StewardId: stewardID,
			Modules:   []string{"directory"},
		}
		resp, err := svc.GetConfiguration(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_OK, resp.Status.Code)

		require.NotNil(t, resp.Config)
		require.NotNil(t, resp.Config.Config)
		retrieved, err := stewardconfig.FromProto(resp.Config.Config)
		require.NoError(t, err)
		assert.Len(t, retrieved.Resources, 1)
		assert.Equal(t, "directory", retrieved.Resources[0].Module)
	})

	t.Run("configuration with multiple module filtering", func(t *testing.T) {
		err := svc.SetConfiguration(ctx, "default", stewardID, cfg)
		require.NoError(t, err)

		req := &controller.ConfigRequest{
			StewardId: stewardID,
			Modules:   []string{"directory", "file"},
		}
		resp, err := svc.GetConfiguration(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_OK, resp.Status.Code)

		require.NotNil(t, resp.Config)
		require.NotNil(t, resp.Config.Config)
		retrieved, err := stewardconfig.FromProto(resp.Config.Config)
		require.NoError(t, err)
		assert.Len(t, retrieved.Resources, 2)
	})

	t.Run("configuration with non-existent module filtering", func(t *testing.T) {
		err := svc.SetConfiguration(ctx, "default", stewardID, cfg)
		require.NoError(t, err)

		req := &controller.ConfigRequest{
			StewardId: stewardID,
			Modules:   []string{"non-existent"},
		}
		resp, err := svc.GetConfiguration(ctx, req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_OK, resp.Status.Code)

		require.NotNil(t, resp.Config)
		require.NotNil(t, resp.Config.Config)
		retrieved, err := stewardconfig.FromProto(resp.Config.Config)
		require.NoError(t, err)
		assert.Len(t, retrieved.Resources, 0)
	})
}

func TestValidateConfig(t *testing.T) {
	svc := createTestServiceV2(t)

	stewardID := "test-steward"
	cfg := createTestStewardConfig(stewardID)

	t.Run("successful validation", func(t *testing.T) {
		configData, err := json.Marshal(cfg)
		require.NoError(t, err)

		req := &controller.ConfigValidationRequest{
			Config:  configData,
			Version: "v1",
		}

		resp, err := svc.ValidateConfig(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_OK, resp.Status.Code)
		assert.Contains(t, resp.Status.Message, "valid")
		assert.Empty(t, resp.Errors)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := &controller.ConfigValidationRequest{
			Config:  []byte("invalid json"),
			Version: "v1",
		}

		resp, err := svc.ValidateConfig(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_ERROR, resp.Status.Code)
		assert.Contains(t, resp.Status.Message, "Invalid configuration format")
		assert.Len(t, resp.Errors, 1)
		assert.Equal(t, "config", resp.Errors[0].Field)
		assert.Contains(t, resp.Errors[0].Message, "JSON parsing error")
	})

	t.Run("validation failure", func(t *testing.T) {
		// Create invalid configuration (missing required fields)
		invalidConfig := &stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				// Missing ID field
				Mode: stewardconfig.ModeController,
			},
			Resources: []stewardconfig.ResourceConfig{
				{
					Name:   "test-resource",
					Module: "directory",
					// Missing Config field
				},
			},
		}

		configData, err := json.Marshal(invalidConfig)
		require.NoError(t, err)

		req := &controller.ConfigValidationRequest{
			Config:  configData,
			Version: "v1",
		}

		resp, err := svc.ValidateConfig(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_ERROR, resp.Status.Code)
		assert.Contains(t, resp.Status.Message, "critical errors")
		assert.Greater(t, len(resp.Errors), 0)
		// Check that we have at least one critical error
		hasCriticalError := false
		for _, validationErr := range resp.Errors {
			if validationErr.Level == controller.ValidationError_CRITICAL {
				hasCriticalError = true
				break
			}
		}
		assert.True(t, hasCriticalError, "Should have at least one critical validation error")
	})
}

func TestFilterConfigByModules(t *testing.T) {
	svc := createTestServiceV2(t)

	cfg := createTestStewardConfig("test-steward")

	t.Run("no module filtering", func(t *testing.T) {
		filtered := svc.filterConfigByModules(cfg, nil)
		assert.Equal(t, cfg, filtered)

		filtered = svc.filterConfigByModules(cfg, []string{})
		assert.Equal(t, cfg, filtered)
	})

	t.Run("single module filtering", func(t *testing.T) {
		filtered := svc.filterConfigByModules(cfg, []string{"directory"})
		assert.Equal(t, cfg.Steward, filtered.Steward)
		assert.Len(t, filtered.Resources, 1)
		assert.Equal(t, "directory", filtered.Resources[0].Module)
	})

	t.Run("multiple module filtering", func(t *testing.T) {
		filtered := svc.filterConfigByModules(cfg, []string{"directory", "file"})
		assert.Equal(t, cfg.Steward, filtered.Steward)
		assert.Len(t, filtered.Resources, 2)
	})

	t.Run("non-existent module filtering", func(t *testing.T) {
		filtered := svc.filterConfigByModules(cfg, []string{"non-existent"})
		assert.Equal(t, cfg.Steward, filtered.Steward)
		assert.Len(t, filtered.Resources, 0)
	})
}

func TestConfigurationServiceV2Concurrency(t *testing.T) {
	ctx := context.Background()
	svc := createTestServiceV2(t)

	stewardID := "test-steward"

	// Seed initial config
	cfg := createTestStewardConfig(stewardID)
	err := svc.SetConfiguration(ctx, "default", stewardID, cfg)
	require.NoError(t, err)

	errs := make(chan error, 10)

	// Goroutine 1: Set configuration
	go func() {
		for i := 0; i < 5; i++ {
			newConfig := createTestStewardConfig(stewardID)
			newConfig.Resources[0].Config["permissions"] = "755"
			if err := svc.SetConfiguration(ctx, "default", stewardID, newConfig); err != nil {
				errs <- fmt.Errorf("SetConfiguration iteration %d: %w", i, err)
				return
			}
		}
		errs <- nil
	}()

	// Goroutine 2: Get configuration
	go func() {
		for i := 0; i < 5; i++ {
			req := &controller.ConfigRequest{StewardId: stewardID}
			if _, err := svc.GetConfiguration(ctx, req); err != nil {
				errs <- fmt.Errorf("GetConfiguration iteration %d: %w", i, err)
				return
			}
		}
		errs <- nil
	}()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Errorf("Concurrent operation failed: %v", err)
		}
	}

	// Verify final state is retrievable
	req := &controller.ConfigRequest{StewardId: stewardID}
	resp, err := svc.GetConfiguration(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, common.Status_OK, resp.Status.Code)
}
