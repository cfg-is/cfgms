// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

var configSvcTestSeq int64

func createTestStewardConfig(stewardID string) *stewardtypes.StewardConfig {
	return &stewardtypes.StewardConfig{
		Steward: stewardtypes.StewardSettings{
			ID:   stewardID,
			Mode: stewardtypes.ModeController,
			Logging: stewardtypes.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
			ErrorHandling: stewardtypes.ErrorHandlingConfig{
				ModuleLoadFailure:  stewardtypes.ActionContinue,
				ResourceFailure:    stewardtypes.ActionWarn,
				ConfigurationError: stewardtypes.ActionFail,
			},
		},
		// Modules map must include all modules referenced in Resources to prevent
		// MISSING_MODULES validation warnings (map value is the custom module path)
		Modules: map[string]string{
			"directory": "directory",
			"file":      "file",
		},
		Resources: []stewardtypes.ResourceConfig{
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

// createTestServiceV2 creates a ConfigurationServiceV2 backed by a real git StorageManager.
// A "default" tenant is seeded so that single-tenant tests can call GetConfiguration
// (which now routes through InheritanceResolver and requires the tenant to exist).
func createTestServiceV2(t *testing.T) *ConfigurationServiceV2 {
	t.Helper()
	logger := logging.NewNoopLogger()
	storageManager := pkgtesting.SetupTestStorage(t)
	svc := NewConfigurationServiceV2(logger, storageManager, nil)
	require.NoError(t, storageManager.GetTenantStore().CreateTenant(
		context.Background(),
		&business.TenantData{ID: "default", Name: "Default", Status: business.TenantStatusActive},
	))
	return svc
}

// createTestServiceV2WithFlatfileRoot creates a ConfigurationServiceV2 backed by real
// git storage at rootDir. Use this when a test needs to manipulate the storage directory
// (e.g. chmod to read-only) to simulate storage write errors.
// A "default" tenant is seeded in the SQLite business store so that any GetConfiguration
// calls work correctly with the InheritanceResolver.
func createTestServiceV2WithFlatfileRoot(t *testing.T, rootDir string) *ConfigurationServiceV2 {
	t.Helper()
	seq := atomic.AddInt64(&configSvcTestSeq, 1)
	sqlitePath := fmt.Sprintf("file:cfgms-test-svc-%d?mode=memory&cache=shared", seq)
	storageManager, err := interfaces.CreateOSSStorageManager(rootDir, sqlitePath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })
	svc := NewConfigurationServiceV2(logging.NewNoopLogger(), storageManager, nil)
	require.NoError(t, storageManager.GetTenantStore().CreateTenant(
		context.Background(),
		&business.TenantData{ID: "default", Name: "Default", Status: business.TenantStatusActive},
	))
	return svc
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
	retrieved, err := stewardtypes.FromProto(resp.Config.Config)
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
		retrieved, err := stewardtypes.FromProto(resp.Config.Config)
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
		retrieved, err := stewardtypes.FromProto(resp.Config.Config)
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
		retrieved, err := stewardtypes.FromProto(resp.Config.Config)
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
		retrieved, err := stewardtypes.FromProto(resp.Config.Config)
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
		invalidConfig := &stewardtypes.StewardConfig{
			Steward: stewardtypes.StewardSettings{
				// Missing ID field
				Mode: stewardtypes.ModeController,
			},
			Resources: []stewardtypes.ResourceConfig{
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

func TestSetConfiguration_FiresFanoutCallback_OnSuccess(t *testing.T) {
	ctx := context.Background()
	svc := createTestServiceV2(t)

	var callCount int
	var gotTenantID, gotCfgID string
	svc.RegisterFanoutCallback(func(_ context.Context, tenantID, cfgID string) {
		callCount++
		gotTenantID = tenantID
		gotCfgID = cfgID
	})

	err := svc.SetConfiguration(ctx, "tenant-a", "steward-1", createTestStewardConfig("steward-1"))
	require.NoError(t, err)

	assert.Equal(t, 1, callCount)
	assert.Equal(t, "tenant-a", gotTenantID)
	assert.Equal(t, "steward-1", gotCfgID)
}

func TestSetConfiguration_DoesNotFireFanoutCallback_OnError(t *testing.T) {
	ctx := context.Background()

	t.Run("validation error", func(t *testing.T) {
		svc := createTestServiceV2(t)
		var callCount int
		svc.RegisterFanoutCallback(func(_ context.Context, _, _ string) { callCount++ })

		// Empty StewardConfig fails validation (missing ID, invalid mode)
		err := svc.SetConfiguration(ctx, "tenant-a", "steward-1", &stewardtypes.StewardConfig{})
		require.Error(t, err)
		assert.Equal(t, 0, callCount, "callback must not fire on validation error")
	})

	t.Run("storage error", func(t *testing.T) {
		rootDir := t.TempDir()
		svc := createTestServiceV2WithFlatfileRoot(t, rootDir)
		var callCount int
		svc.RegisterFanoutCallback(func(_ context.Context, _, _ string) { callCount++ })

		// Replace the storage root with a regular file so that writeAtomic's
		// os.MkdirAll call fails with ENOTDIR on all platforms.  os.Chmod
		// read-only is not honoured by the Windows filesystem layer, making
		// this the only reliable cross-platform approach.
		require.NoError(t, os.RemoveAll(rootDir))
		f, ferr := os.Create(rootDir)
		require.NoError(t, ferr)
		require.NoError(t, f.Close())

		writeErr := svc.SetConfiguration(ctx, "tenant-a", "steward-1", createTestStewardConfig("steward-1"))
		require.Error(t, writeErr, "storage write should fail when rootDir is a file not a directory")
		assert.Equal(t, 0, callCount, "callback must not fire on storage error")
	})
}

func TestSetConfiguration_FanoutCallback_IsTenantScoped(t *testing.T) {
	ctx := context.Background()
	svc := createTestServiceV2(t)

	var gotTenantIDs []string
	svc.RegisterFanoutCallback(func(_ context.Context, tenantID, _ string) {
		gotTenantIDs = append(gotTenantIDs, tenantID)
	})

	err := svc.SetConfiguration(ctx, "tenant-a", "steward-1", createTestStewardConfig("steward-1"))
	require.NoError(t, err)

	err = svc.SetConfiguration(ctx, "tenant-b", "steward-2", createTestStewardConfig("steward-2"))
	require.NoError(t, err)

	require.Len(t, gotTenantIDs, 2)
	assert.Equal(t, "tenant-a", gotTenantIDs[0], "first callback must receive tenant-a")
	assert.Equal(t, "tenant-b", gotTenantIDs[1], "second callback must receive tenant-b; cross-tenant fanout is structurally impossible from a single write")
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

// marshalStewardConfigYAML encodes a StewardConfig to YAML bytes for direct config-store writes.
func marshalStewardConfigYAML(t *testing.T, cfg stewardtypes.StewardConfig) []byte {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	return data
}

// seedTwoLevelTenants creates a two-level tenant hierarchy: mspID (root) → childID.
func seedTwoLevelTenants(t *testing.T, ctx context.Context, sm interface{ GetTenantStore() business.TenantStore }, mspID, childID string) {
	t.Helper()
	ts := sm.GetTenantStore()
	require.NoError(t, ts.CreateTenant(ctx, &business.TenantData{
		ID: mspID, Name: mspID, Status: business.TenantStatusActive,
	}))
	require.NoError(t, ts.CreateTenant(ctx, &business.TenantData{
		ID: childID, Name: childID, ParentID: mspID, Status: business.TenantStatusActive,
	}))
}

// TestGetConfiguration_CascadeMergedDelivery verifies that GetConfiguration (the steward
// delivery path) performs a full tenant-cascade merge, not a most-specific-wins lookup.
//
// AC covered:
//   - A steward in a child tenant receives a parent-tenant policy resource for which it has
//     no device-level override.
//   - A device-level resource with the same name overrides the parent resource.
func TestGetConfiguration_CascadeMergedDelivery(t *testing.T) {
	ctx := context.Background()
	sm := pkgtesting.SetupTestStorage(t)
	svc := NewConfigurationServiceV2(logging.NewNoopLogger(), sm, nil)

	// Two-level hierarchy: msp (root) → client (child)
	seedTwoLevelTenants(t, ctx, sm, "msp", "client")

	cs := sm.GetConfigStore()

	// MSP-level policy: two resources — one the device will inherit without override,
	// one the device will override with its own version.
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "msp", Namespace: "msp-policies", Name: "global"},
		Data: marshalStewardConfigYAML(t, stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "msp-inherited", Module: "file", Config: map[string]interface{}{"path": "/etc/inherited.conf"}},
				{Name: "shared-resource", Module: "file", Config: map[string]interface{}{"path": "/etc/parent.conf"}},
			},
		}),
	}))

	// Device-level config for steward-1 under client tenant.
	// Includes "shared-resource" to test child-overrides-parent behaviour.
	deviceCfg := createTestStewardConfig("steward-1")
	deviceCfg.Resources = append(deviceCfg.Resources, stewardtypes.ResourceConfig{
		Name: "shared-resource", Module: "file",
		Config: map[string]interface{}{"path": "/etc/device.conf"},
	})
	// "file" is already in the Modules map from createTestStewardConfig; no missing-module error.
	require.NoError(t, svc.SetConfiguration(ctx, "client", "steward-1", deviceCfg))

	// Request config for steward-1 with the client tenant in context.
	// controllerSvc is nil, so tenantID is read from ctxkeys.TenantID.
	clientCtx := context.WithValue(ctx, ctxkeys.TenantID, "client")
	resp, err := svc.GetConfiguration(clientCtx, &controller.ConfigRequest{StewardId: "steward-1"})
	require.NoError(t, err)
	require.Equal(t, common.Status_OK, resp.Status.Code)

	retrieved, err := stewardtypes.FromProto(resp.Config.Config)
	require.NoError(t, err)

	byName := make(map[string]stewardtypes.ResourceConfig)
	for _, r := range retrieved.Resources {
		byName[r.Name] = r
	}

	t.Run("parent resource delivered when steward has no device-level override", func(t *testing.T) {
		_, ok := byName["msp-inherited"]
		assert.True(t, ok, "MSP-level resource 'msp-inherited' must be delivered to steward in child tenant")
	})

	t.Run("device-level resource overrides same-named parent resource", func(t *testing.T) {
		r, ok := byName["shared-resource"]
		require.True(t, ok, "'shared-resource' must appear in delivered config")
		assert.Equal(t, "/etc/device.conf", r.Config["path"],
			"device-level 'shared-resource' must override the MSP-level version")
	})
}

// TestGetConfiguration_TenantWithoutHierarchyRecord verifies that a steward whose tenant
// exists only as an identifier — e.g. registered via a registration token but never
// promoted to a full TenantData hierarchy record — still receives its device-level
// config from the delivery path.
//
// Regression: routing GetConfiguration through InheritanceResolver.ResolveConfiguration
// makes it walk the tenant ancestor chain, which fails when the tenant has no
// TenantData record. The fleet E2E stewards register under registration-token tenants
// with no hierarchy record, so the delivery path must degrade gracefully instead of
// returning NOT_FOUND for an already-configured steward.
func TestGetConfiguration_TenantWithoutHierarchyRecord(t *testing.T) {
	ctx := context.Background()
	sm := pkgtesting.SetupTestStorage(t)
	svc := NewConfigurationServiceV2(logging.NewNoopLogger(), sm, nil)

	// Deliberately do NOT create a TenantData record for this tenant — it exists
	// only as the identifier carried by the steward's registration.
	const tenantID = "registration-token-tenant"
	tenantCtx := context.WithValue(ctx, ctxkeys.TenantID, tenantID)

	t.Run("device config delivered when tenant has no hierarchy record", func(t *testing.T) {
		deviceCfg := createTestStewardConfig("fleet-steward-1")
		require.NoError(t, svc.SetConfiguration(ctx, tenantID, "fleet-steward-1", deviceCfg))

		resp, err := svc.GetConfiguration(tenantCtx, &controller.ConfigRequest{StewardId: "fleet-steward-1"})
		require.NoError(t, err)
		require.Equal(t, common.Status_OK, resp.Status.Code,
			"steward must receive device config even when its tenant has no hierarchy record")

		require.NotNil(t, resp.Config)
		require.NotNil(t, resp.Config.Config)
		retrieved, err := stewardtypes.FromProto(resp.Config.Config)
		require.NoError(t, err)
		assert.Equal(t, "fleet-steward-1", retrieved.Steward.ID)
		assert.Len(t, retrieved.Resources, 2)
	})

	t.Run("NOT_FOUND when tenant has no hierarchy record and steward has no config", func(t *testing.T) {
		resp, err := svc.GetConfiguration(tenantCtx, &controller.ConfigRequest{StewardId: "unconfigured-steward"})
		require.NoError(t, err)
		assert.Equal(t, common.Status_NOT_FOUND, resp.Status.Code,
			"an unconfigured steward must still resolve to NOT_FOUND, not a device-level fallback")
	})
}

// TestGetConfiguration_TenantIsolation verifies that the cascade merges only the steward's
// own ancestor chain and never includes resources from sibling or unrelated tenants.
//
// AC covered: a test asserts tenant isolation.
func TestGetConfiguration_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	sm := pkgtesting.SetupTestStorage(t)
	svc := NewConfigurationServiceV2(logging.NewNoopLogger(), sm, nil)

	ts := sm.GetTenantStore()
	// Two independent root tenants — no shared ancestry.
	require.NoError(t, ts.CreateTenant(ctx, &business.TenantData{
		ID: "msp-a", Name: "MSP A", Status: business.TenantStatusActive,
	}))
	require.NoError(t, ts.CreateTenant(ctx, &business.TenantData{
		ID: "msp-b", Name: "MSP B", Status: business.TenantStatusActive,
	}))

	cs := sm.GetConfigStore()

	// msp-a has an MSP-level policy that should be invisible to msp-b stewards.
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "msp-a", Namespace: "msp-policies", Name: "global"},
		Data: marshalStewardConfigYAML(t, stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "msp-a-policy", Module: "file", Config: map[string]interface{}{"path": "/etc/msp-a.conf"}},
			},
		}),
	}))

	// steward-b lives entirely within the msp-b tree; no relationship to msp-a.
	stewardBCfg := createTestStewardConfig("steward-b")
	require.NoError(t, svc.SetConfiguration(ctx, "msp-b", "steward-b", stewardBCfg))

	mspBCtx := context.WithValue(ctx, ctxkeys.TenantID, "msp-b")
	resp, err := svc.GetConfiguration(mspBCtx, &controller.ConfigRequest{StewardId: "steward-b"})
	require.NoError(t, err)
	require.Equal(t, common.Status_OK, resp.Status.Code)

	retrieved, err := stewardtypes.FromProto(resp.Config.Config)
	require.NoError(t, err)

	// steward-b must receive its own device config — without this the isolation
	// loop below would pass vacuously on an empty resource slice.
	require.NotEmpty(t, retrieved.Resources, "steward-b must receive its own device config")

	for _, r := range retrieved.Resources {
		assert.NotEqual(t, "msp-a-policy", r.Name,
			"steward-b must not receive resources from msp-a's ancestor chain (tenant isolation violated)")
	}
}
