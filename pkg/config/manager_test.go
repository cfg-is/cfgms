// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newTestManager creates a Manager backed by a real OSS storage stack for testing.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	return NewManagerWithStorageManager(sm)
}

// newTestValidationManager creates a ValidationManager backed by a real OSS storage stack.
func newTestValidationManager(t *testing.T) *ValidationManager {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	return NewValidationManager(sm.GetConfigStore(), sm.GetTenantStore())
}

func TestManagerStoreAndGetConfiguration(t *testing.T) {
	manager := newTestManager(t)
	ctx := context.Background()

	testConfig := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
			Logging: stewardconfig.LoggingConfig{
				Level: "info",
			},
		},
		Resources: []stewardconfig.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "directory",
				Config: map[string]interface{}{
					"path": "/opt/test",
				},
			},
		},
	}

	err := manager.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig)
	require.NoError(t, err)

	retrievedConfig, err := manager.GetConfiguration(ctx, "test-tenant", "test-steward")
	require.NoError(t, err)

	assert.Equal(t, testConfig.Steward.ID, retrievedConfig.Steward.ID)
	assert.Equal(t, testConfig.Steward.Mode, retrievedConfig.Steward.Mode)
	assert.Len(t, retrievedConfig.Resources, 1)
	assert.Equal(t, "test-resource", retrievedConfig.Resources[0].Name)
	assert.Equal(t, "directory", retrievedConfig.Resources[0].Module)
}

func TestManagerGetConfigurationNotFound(t *testing.T) {
	manager := newTestManager(t)
	ctx := context.Background()

	_, err := manager.GetConfiguration(ctx, "test-tenant", "non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration not found")
}

func TestManagerConfigurationHistory(t *testing.T) {
	manager := newTestManager(t)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		testConfig := &stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				ID:   "test-steward",
				Mode: stewardconfig.ModeStandalone,
				Logging: stewardconfig.LoggingConfig{
					Level: "info",
				},
			},
			Resources: []stewardconfig.ResourceConfig{
				{
					Name:   "test-resource",
					Module: "directory",
					Config: map[string]interface{}{
						"path": fmt.Sprintf("/opt/test%d", i),
					},
				},
			},
		}

		err := manager.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig)
		require.NoError(t, err)
	}

	history, err := manager.GetConfigurationHistory(ctx, "test-tenant", "test-steward", 5)
	require.NoError(t, err)
	// Flatfile store returns only the current version; no historical snapshots are retained.
	assert.Len(t, history, 1)
}

func TestManagerGetConfigurationVersion(t *testing.T) {
	manager := newTestManager(t)
	ctx := context.Background()

	testConfig1 := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
			Logging: stewardconfig.LoggingConfig{
				Level: "info",
			},
		},
		Resources: []stewardconfig.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "directory",
				Config: map[string]interface{}{
					"path": "/opt/test1",
				},
			},
		},
	}

	err := manager.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig1)
	require.NoError(t, err)

	// Flatfile store assigns version 1 on first write; retrieval by current version succeeds.
	versionConfig, err := manager.GetConfigurationVersion(ctx, "test-tenant", "test-steward", 1)
	require.NoError(t, err)
	pathValue := versionConfig.Resources[0].Config["path"]
	assert.Equal(t, "/opt/test1", pathValue)

	testConfig2 := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
			Logging: stewardconfig.LoggingConfig{
				Level: "info",
			},
		},
		Resources: []stewardconfig.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "directory",
				Config: map[string]interface{}{
					"path": "/opt/test2",
				},
			},
		},
	}

	err = manager.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig2)
	require.NoError(t, err)

	// After second write version becomes 2; that is the only version available.
	versionConfig, err = manager.GetConfigurationVersion(ctx, "test-tenant", "test-steward", 2)
	require.NoError(t, err)
	pathValue = versionConfig.Resources[0].Config["path"]
	assert.Equal(t, "/opt/test2", pathValue)

	// Version 1 is no longer available once version 2 is the current head.
	_, err = manager.GetConfigurationVersion(ctx, "test-tenant", "test-steward", 1)
	assert.Error(t, err)
}

func TestManagerListConfigurations(t *testing.T) {
	manager := newTestManager(t)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		testConfig := &stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				ID:   fmt.Sprintf("steward-%d", i),
				Mode: stewardconfig.ModeStandalone,
				Logging: stewardconfig.LoggingConfig{
					Level: "info",
				},
			},
		}

		err := manager.StoreConfiguration(ctx, "test-tenant", fmt.Sprintf("steward-%d", i), testConfig)
		require.NoError(t, err)
	}

	summaries, err := manager.ListConfigurations(ctx, "test-tenant")
	require.NoError(t, err)
	assert.Len(t, summaries, 3)

	for _, summary := range summaries {
		assert.Equal(t, "test-tenant", summary.TenantID)
		assert.NotEmpty(t, summary.StewardID)
		assert.NotZero(t, summary.Version)
		assert.NotZero(t, summary.UpdatedAt)
	}
}

func TestManagerBatchStoreConfigurations(t *testing.T) {
	manager := newTestManager(t)
	ctx := context.Background()

	var batchConfigs []*BatchConfigurationEntry

	for i := 1; i <= 3; i++ {
		testConfig := &stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				ID:   fmt.Sprintf("steward-%d", i),
				Mode: stewardconfig.ModeStandalone,
				Logging: stewardconfig.LoggingConfig{
					Level: "info",
				},
			},
		}

		batchConfigs = append(batchConfigs, &BatchConfigurationEntry{
			TenantID:  "test-tenant",
			StewardID: fmt.Sprintf("steward-%d", i),
			Config:    testConfig,
		})
	}

	err := manager.BatchStoreConfigurations(ctx, batchConfigs)
	require.NoError(t, err)

	for i := 1; i <= 3; i++ {
		config, err := manager.GetConfiguration(ctx, "test-tenant", fmt.Sprintf("steward-%d", i))
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("steward-%d", i), config.Steward.ID)
	}
}

func TestManagerValidateConfiguration(t *testing.T) {
	manager := newTestManager(t)
	ctx := context.Background()

	validConfig := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
			Logging: stewardconfig.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
		},
		Resources: []stewardconfig.ResourceConfig{
			{
				Name:   "test-resource",
				Module: "directory",
				Config: map[string]interface{}{
					"path": "/opt/test",
				},
			},
		},
	}

	err := manager.ValidateConfiguration(ctx, validConfig)
	assert.NoError(t, err)

	// Empty steward ID is rejected by stewardconfig.ValidateConfiguration.
	invalidConfig := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "",
			Mode: stewardconfig.ModeStandalone,
		},
	}

	err = manager.ValidateConfiguration(ctx, invalidConfig)
	assert.Error(t, err)
}

func TestManagerDeleteConfiguration(t *testing.T) {
	manager := newTestManager(t)
	ctx := context.Background()

	testConfig := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
			Logging: stewardconfig.LoggingConfig{
				Level: "info",
			},
		},
	}

	err := manager.StoreConfiguration(ctx, "test-tenant", "test-steward", testConfig)
	require.NoError(t, err)

	_, err = manager.GetConfiguration(ctx, "test-tenant", "test-steward")
	assert.NoError(t, err)

	err = manager.DeleteConfiguration(ctx, "test-tenant", "test-steward")
	assert.NoError(t, err)

	_, err = manager.GetConfiguration(ctx, "test-tenant", "test-steward")
	assert.Error(t, err)
}

func TestManagerGetConfigurationStats(t *testing.T) {
	manager := newTestManager(t)
	ctx := context.Background()

	for i := 1; i <= 2; i++ {
		testConfig := &stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				ID:   fmt.Sprintf("steward-%d", i),
				Mode: stewardconfig.ModeStandalone,
				Logging: stewardconfig.LoggingConfig{
					Level: "info",
				},
			},
		}

		err := manager.StoreConfiguration(ctx, "test-tenant", fmt.Sprintf("steward-%d", i), testConfig)
		require.NoError(t, err)
	}

	stats, err := manager.GetConfigurationStats(ctx)
	require.NoError(t, err)

	assert.Equal(t, int64(2), stats.TotalConfigs)
	assert.Greater(t, stats.TotalSize, int64(0))
	assert.Greater(t, stats.AverageSize, int64(0))
	assert.NotZero(t, stats.LastUpdated)
}

// ValidationManager tests verify that ValidateConfiguration still rejects
// invalid configs after the removal of the duplicate validateStewardSettings.

func TestValidationManagerRejectsInvalidLogLevel(t *testing.T) {
	vm := newTestValidationManager(t)
	ctx := context.Background()

	config := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
			Logging: stewardconfig.LoggingConfig{
				Level: "verbose", // not a valid level
			},
		},
	}

	result := vm.ValidateConfiguration(ctx, "test-tenant", "test-steward", config)
	assert.False(t, result.Valid)
	require.NotEmpty(t, result.Errors)
	assert.Equal(t, "BASIC_VALIDATION_FAILED", result.Errors[0].Code)
}

func TestValidationManagerRejectsInvalidMode(t *testing.T) {
	vm := newTestValidationManager(t)
	ctx := context.Background()

	config := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: "unknown-mode", // not a valid mode
			Logging: stewardconfig.LoggingConfig{
				Level: "info",
			},
		},
	}

	result := vm.ValidateConfiguration(ctx, "test-tenant", "test-steward", config)
	assert.False(t, result.Valid)
	require.NotEmpty(t, result.Errors)
	assert.Equal(t, "BASIC_VALIDATION_FAILED", result.Errors[0].Code)
}

func TestValidationManagerRejectsDuplicateResourceNames(t *testing.T) {
	vm := newTestValidationManager(t)
	ctx := context.Background()

	config := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "test-steward",
			Mode: stewardconfig.ModeStandalone,
			Logging: stewardconfig.LoggingConfig{
				Level: "info",
			},
		},
		Modules: map[string]string{
			"file": "file",
		},
		Resources: []stewardconfig.ResourceConfig{
			{Name: "dup", Module: "file", Config: map[string]interface{}{"path": "/tmp/a"}},
			{Name: "dup", Module: "file", Config: map[string]interface{}{"path": "/tmp/b"}},
		},
	}

	result := vm.ValidateConfiguration(ctx, "test-tenant", "test-steward", config)
	assert.False(t, result.Valid)

	// Verify validateResources in pkg/config specifically catches the duplicate
	// (stewardconfig.ValidateConfiguration also catches it, but we want to confirm
	// the local validateResources path is exercised and emits DUPLICATE_RESOURCE_NAME).
	codes := make([]string, 0, len(result.Errors))
	for _, e := range result.Errors {
		codes = append(codes, e.Code)
	}
	assert.Contains(t, codes, "DUPLICATE_RESOURCE_NAME")
}
