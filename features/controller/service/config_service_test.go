// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
)

// mockLogger implements a thread-safe logger for testing
type mockLogger struct {
	mu   sync.Mutex
	logs []string
}

func (m *mockLogger) appendLog(msg string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append(m.logs, msg)
}

func (m *mockLogger) Debug(msg string, fields ...interface{}) { m.appendLog(msg) }
func (m *mockLogger) Info(msg string, fields ...interface{})  { m.appendLog(msg) }
func (m *mockLogger) Warn(msg string, fields ...interface{})  { m.appendLog(msg) }
func (m *mockLogger) Error(msg string, fields ...interface{}) { m.appendLog(msg) }
func (m *mockLogger) Fatal(msg string, fields ...interface{}) { m.appendLog(msg) }
func (m *mockLogger) DebugCtx(ctx context.Context, msg string, fields ...interface{}) {
	m.Debug(msg, fields...)
}
func (m *mockLogger) InfoCtx(ctx context.Context, msg string, fields ...interface{}) {
	m.Info(msg, fields...)
}
func (m *mockLogger) WarnCtx(ctx context.Context, msg string, fields ...interface{}) {
	m.Warn(msg, fields...)
}
func (m *mockLogger) ErrorCtx(ctx context.Context, msg string, fields ...interface{}) {
	m.Error(msg, fields...)
}
func (m *mockLogger) FatalCtx(ctx context.Context, msg string, fields ...interface{}) {
	m.Fatal(msg, fields...)
}

func newMockLogger() *mockLogger {
	return &mockLogger{logs: make([]string, 0)}
}

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

func TestNewConfigurationService(t *testing.T) {
	logger := newMockLogger()

	service := NewConfigurationService(logger, nil)

	assert.NotNil(t, service)
	assert.Equal(t, logger, service.logger)
	assert.NotNil(t, service.configurations)
	assert.Len(t, service.configurations, 0)
}

func TestSetConfiguration(t *testing.T) {
	logger := newMockLogger()
	service := NewConfigurationService(logger, nil)

	stewardID := "test-steward"
	config := createTestStewardConfig(stewardID)

	// Test setting configuration
	err := service.SetConfiguration(stewardID, config)
	require.NoError(t, err)

	// Verify configuration was stored
	storedConfig, exists := service.GetStoredConfiguration(stewardID)
	require.True(t, exists)
	assert.Equal(t, stewardID, storedConfig.StewardID)
	assert.Equal(t, config, storedConfig.Config)
	assert.NotEmpty(t, storedConfig.Version)
	assert.NotZero(t, storedConfig.CreatedAt)
	assert.NotZero(t, storedConfig.LastUpdated)

	// Test updating configuration
	time.Sleep(time.Second) // Ensure different timestamp for version generation
	config.Resources[0].Config["permissions"] = "644"
	err = service.SetConfiguration(stewardID, config)
	require.NoError(t, err)

	// Verify update preserved CreatedAt but updated LastUpdated and Version
	updatedConfig, exists := service.GetStoredConfiguration(stewardID)
	require.True(t, exists)
	assert.Equal(t, storedConfig.CreatedAt, updatedConfig.CreatedAt)
	assert.True(t, updatedConfig.LastUpdated.After(storedConfig.LastUpdated) || updatedConfig.LastUpdated.Equal(storedConfig.LastUpdated))
	// Version should be different (time-based) or at least not empty
	assert.NotEmpty(t, updatedConfig.Version)
	assert.NotEqual(t, storedConfig.Version, updatedConfig.Version)
}

func TestGetConfiguration(t *testing.T) {
	logger := newMockLogger()
	service := NewConfigurationService(logger, nil)

	stewardID := "test-steward"
	config := createTestStewardConfig(stewardID)

	t.Run("configuration not found", func(t *testing.T) {
		req := &controller.ConfigRequest{
			StewardId: stewardID,
		}

		resp, err := service.GetConfiguration(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_NOT_FOUND, resp.Status.Code)
		assert.Contains(t, resp.Status.Message, "No configuration found")
	})

	t.Run("successful configuration retrieval", func(t *testing.T) {
		// Store configuration
		err := service.SetConfiguration(stewardID, config)
		require.NoError(t, err)

		req := &controller.ConfigRequest{
			StewardId: stewardID,
		}

		resp, err := service.GetConfiguration(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_OK, resp.Status.Code)
		assert.NotEmpty(t, resp.Config)
		assert.NotEmpty(t, resp.Version)

		// Verify configuration content
		var retrievedConfig stewardconfig.StewardConfig
		err = json.Unmarshal(resp.Config, &retrievedConfig)
		require.NoError(t, err)
		assert.Equal(t, config.Steward.ID, retrievedConfig.Steward.ID)
		assert.Len(t, retrievedConfig.Resources, 2)
	})

	t.Run("configuration with module filtering", func(t *testing.T) {
		// Store configuration
		err := service.SetConfiguration(stewardID, config)
		require.NoError(t, err)

		req := &controller.ConfigRequest{
			StewardId: stewardID,
			Modules:   []string{"directory"}, // Only request directory module
		}

		resp, err := service.GetConfiguration(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_OK, resp.Status.Code)

		// Verify only directory module is returned
		var retrievedConfig stewardconfig.StewardConfig
		err = json.Unmarshal(resp.Config, &retrievedConfig)
		require.NoError(t, err)
		assert.Len(t, retrievedConfig.Resources, 1)
		assert.Equal(t, "directory", retrievedConfig.Resources[0].Module)
	})

	t.Run("configuration with multiple module filtering", func(t *testing.T) {
		// Store configuration
		err := service.SetConfiguration(stewardID, config)
		require.NoError(t, err)

		req := &controller.ConfigRequest{
			StewardId: stewardID,
			Modules:   []string{"directory", "file"},
		}

		resp, err := service.GetConfiguration(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_OK, resp.Status.Code)

		// Verify both modules are returned
		var retrievedConfig stewardconfig.StewardConfig
		err = json.Unmarshal(resp.Config, &retrievedConfig)
		require.NoError(t, err)
		assert.Len(t, retrievedConfig.Resources, 2)
	})

	t.Run("configuration with non-existent module filtering", func(t *testing.T) {
		// Store configuration
		err := service.SetConfiguration(stewardID, config)
		require.NoError(t, err)

		req := &controller.ConfigRequest{
			StewardId: stewardID,
			Modules:   []string{"non-existent"},
		}

		resp, err := service.GetConfiguration(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_OK, resp.Status.Code)

		// Verify no resources are returned
		var retrievedConfig stewardconfig.StewardConfig
		err = json.Unmarshal(resp.Config, &retrievedConfig)
		require.NoError(t, err)
		assert.Len(t, retrievedConfig.Resources, 0)
	})
}

func TestReportConfigStatus(t *testing.T) {
	logger := newMockLogger()
	service := NewConfigurationService(logger, nil)

	stewardID := "test-steward"

	t.Run("successful status report", func(t *testing.T) {

		moduleStatuses := []*controller.ModuleStatus{
			{
				Name:      "directory",
				Status:    &common.Status{Code: common.Status_OK, Message: "Directory created successfully"},
				Message:   "Directory created successfully",
				Timestamp: timestamppb.Now(),
			},
			{
				Name:      "file",
				Status:    &common.Status{Code: common.Status_OK, Message: "File created successfully"},
				Message:   "File created successfully",
				Timestamp: timestamppb.Now(),
			},
		}

		req := &controller.ConfigStatusReport{
			StewardId:     stewardID,
			ConfigVersion: "v1",
			Status: &common.Status{
				Code:    common.Status_OK,
				Message: "Configuration applied successfully",
			},
			Modules: moduleStatuses,
		}

		resp, err := service.ReportConfigStatus(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_OK, resp.Code)
		assert.Contains(t, resp.Message, "processed successfully")
	})

	t.Run("error status report", func(t *testing.T) {

		moduleStatuses := []*controller.ModuleStatus{
			{
				Name:      "directory",
				Status:    &common.Status{Code: common.Status_ERROR, Message: "Permission denied"},
				Message:   "Permission denied",
				Timestamp: timestamppb.Now(),
			},
		}

		req := &controller.ConfigStatusReport{
			StewardId:     stewardID,
			ConfigVersion: "v1",
			Status: &common.Status{
				Code:    common.Status_ERROR,
				Message: "Configuration failed",
			},
			Modules: moduleStatuses,
		}

		resp, err := service.ReportConfigStatus(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_OK, resp.Code)
		assert.Contains(t, resp.Message, "processed successfully")
	})
}

func TestValidateConfig(t *testing.T) {
	logger := newMockLogger()
	service := NewConfigurationService(logger, nil)

	stewardID := "test-steward"
	config := createTestStewardConfig(stewardID)

	t.Run("successful validation", func(t *testing.T) {
		configData, err := json.Marshal(config)
		require.NoError(t, err)

		req := &controller.ConfigValidationRequest{
			Config:  configData,
			Version: "v1",
		}

		resp, err := service.ValidateConfig(context.Background(), req)
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

		resp, err := service.ValidateConfig(context.Background(), req)
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

		resp, err := service.ValidateConfig(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, common.Status_ERROR, resp.Status.Code)
		assert.Contains(t, resp.Status.Message, "Configuration has critical errors")
		assert.Greater(t, len(resp.Errors), 0) // Should have multiple validation errors
		// Check that we have at least one critical error (the missing steward ID)
		hasCriticalError := false
		for _, err := range resp.Errors {
			if err.Level == controller.ValidationError_CRITICAL {
				hasCriticalError = true
				break
			}
		}
		assert.True(t, hasCriticalError, "Should have at least one critical validation error")
	})
}

func TestFilterConfigByModules(t *testing.T) {
	logger := newMockLogger()
	service := NewConfigurationService(logger, nil)

	config := createTestStewardConfig("test-steward")

	t.Run("no module filtering", func(t *testing.T) {
		filtered := service.filterConfigByModules(config, nil)
		assert.Equal(t, config, filtered)

		filtered = service.filterConfigByModules(config, []string{})
		assert.Equal(t, config, filtered)
	})

	t.Run("single module filtering", func(t *testing.T) {
		filtered := service.filterConfigByModules(config, []string{"directory"})
		assert.Equal(t, config.Steward, filtered.Steward)
		assert.Len(t, filtered.Resources, 1)
		assert.Equal(t, "directory", filtered.Resources[0].Module)
	})

	t.Run("multiple module filtering", func(t *testing.T) {
		filtered := service.filterConfigByModules(config, []string{"directory", "file"})
		assert.Equal(t, config.Steward, filtered.Steward)
		assert.Len(t, filtered.Resources, 2)
	})

	t.Run("non-existent module filtering", func(t *testing.T) {
		filtered := service.filterConfigByModules(config, []string{"non-existent"})
		assert.Equal(t, config.Steward, filtered.Steward)
		assert.Len(t, filtered.Resources, 0)
	})
}

func TestConfigurationServiceConcurrency(t *testing.T) {
	logger := newMockLogger()
	service := NewConfigurationService(logger, nil)

	stewardID := "test-steward"

	// Test concurrent access
	done := make(chan bool)

	// Goroutine 1: Set configuration
	go func() {
		for i := 0; i < 10; i++ {
			// Create a new config for each operation to avoid data races
			newConfig := createTestStewardConfig(stewardID)
			newConfig.Resources[0].Config["permissions"] = "755"
			_ = service.SetConfiguration(stewardID, newConfig)
			time.Sleep(time.Millisecond)
		}
		done <- true
	}()

	// Goroutine 2: Get configuration
	go func() {
		for i := 0; i < 10; i++ {
			req := &controller.ConfigRequest{StewardId: stewardID}
			_, _ = service.GetConfiguration(context.Background(), req)
			time.Sleep(time.Millisecond)
		}
		done <- true
	}()

	// Wait for both goroutines to complete
	<-done
	<-done

	// Verify final state
	storedConfig, exists := service.GetStoredConfiguration(stewardID)
	assert.True(t, exists)
	assert.Equal(t, stewardID, storedConfig.StewardID)
}
