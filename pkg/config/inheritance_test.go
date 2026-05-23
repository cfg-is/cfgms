// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// seedThreeLevelTenants creates root → msp → client tenant hierarchy in the store.
func seedThreeLevelTenants(t *testing.T, ctx context.Context, sm interface{ GetTenantStore() business.TenantStore }) {
	t.Helper()
	ts := sm.GetTenantStore()
	require.NotNil(t, ts)

	for _, td := range []*business.TenantData{
		{ID: "root", Name: "Root", Status: business.TenantStatusActive},
		{ID: "msp", Name: "MSP", ParentID: "root", Status: business.TenantStatusActive},
		{ID: "client", Name: "Client", ParentID: "msp", Status: business.TenantStatusActive},
	} {
		require.NoError(t, ts.CreateTenant(ctx, td))
	}
}

// marshalStewardConfig encodes a StewardConfig to YAML bytes.
func marshalStewardConfig(t *testing.T, cfg stewardconfig.StewardConfig) []byte {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	return data
}

func TestGetTenantPath_Returns3LevelAncestorChain(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)

	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	ir := NewInheritanceResolverWithStorageManager(sm)

	path, err := ir.getTenantPath(ctx, "client")
	require.NoError(t, err)
	assert.Equal(t, []string{"root", "msp", "client"}, path)
}

func TestGetTenantPath_ErrorOnUnknownTenant(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)

	ctx := context.Background()
	ir := NewInheritanceResolverWithStorageManager(sm)

	_, err := ir.getTenantPath(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestResolveConfiguration_3LevelHierarchy(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)

	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()
	require.NotNil(t, cs)

	// Level 0 (root, LevelMSP): sets Steward.ID
	rootCfg := stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{ID: "inherited-id"},
	}
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:  &cfgconfig.ConfigKey{TenantID: "root", Namespace: "msp-policies", Name: "global"},
		Data: marshalStewardConfig(t, rootCfg),
	}))

	// Level 1 (msp, LevelClient): overrides Steward.Mode
	mspCfg := stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{Mode: stewardconfig.ModeController},
	}
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:  &cfgconfig.ConfigKey{TenantID: "msp", Namespace: "client-policies", Name: "msp"},
		Data: marshalStewardConfig(t, mspCfg),
	}))

	// Level 2 (client, LevelGroup): adds a resource
	clientCfg := stewardconfig.StewardConfig{
		Resources: []stewardconfig.ResourceConfig{
			{Name: "client-resource", Module: "directory"},
		},
	}
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:  &cfgconfig.ConfigKey{TenantID: "client", Namespace: "group-policies", Name: "client-groups"},
		Data: marshalStewardConfig(t, clientCfg),
	}))

	ir := NewInheritanceResolverWithStorageManager(sm)
	effective, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	// All 3 levels must have contributed.
	assert.Equal(t, "inherited-id", effective.Config.Steward.ID, "root level must contribute Steward.ID")
	assert.Equal(t, stewardconfig.ModeController, effective.Config.Steward.Mode, "msp level must contribute Steward.Mode")
	require.Len(t, effective.Config.Resources, 1, "client level must contribute the resource")
	assert.Equal(t, "client-resource", effective.Config.Resources[0].Name)
}

func TestResolveConfiguration_ErrorOnUnknownTenant(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)

	ctx := context.Background()
	ir := NewInheritanceResolverWithStorageManager(sm)

	// Tenant "ghost" does not exist in the store — ResolveConfiguration must propagate the error.
	_, err := ir.ResolveConfiguration(ctx, "ghost", "steward-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve tenant hierarchy")
}

func TestResolveConfiguration_LaterLevelOverridesEarlier(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)

	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()
	require.NotNil(t, cs)

	// Level 0 (root): sets Steward.ID = "root-id"
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "root", Namespace: "msp-policies", Name: "global"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{ID: "root-id"},
		}),
	}))

	// Level 1 (msp): overrides Steward.ID = "msp-id"
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "msp", Namespace: "client-policies", Name: "msp"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{ID: "msp-id"},
		}),
	}))

	ir := NewInheritanceResolverWithStorageManager(sm)
	effective, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	assert.Equal(t, "msp-id", effective.Config.Steward.ID, "later level must override earlier level")
}

// TestResolveConfiguration_PropagatesConvergeIntervalFromParent verifies that a
// converge_interval set at an ancestor level reaches the steward via cascade.
// Without propagation, cascade-enabled tenants fell back to the 30-minute
// steward default — breaking drift-correction SLAs inside tenant hierarchies.
func TestResolveConfiguration_PropagatesConvergeIntervalFromParent(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)

	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()
	require.NotNil(t, cs)

	// Parent policy sets converge_interval; child has no config at all.
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "root", Namespace: "msp-policies", Name: "global"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{ConvergeInterval: "10s"},
		}),
	}))

	ir := NewInheritanceResolverWithStorageManager(sm)
	effective, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	assert.Equal(t, "10s", effective.Config.Steward.ConvergeInterval,
		"converge_interval set at parent tenant must cascade to descendant stewards")
	assert.NotNil(t, effective.Sources["steward.converge_interval"],
		"inheritance source for converge_interval must be recorded")
}

// TestResolveConfiguration_ChildOverridesConvergeInterval verifies that a child-level
// converge_interval takes precedence over a parent-level value.
func TestResolveConfiguration_ChildOverridesConvergeInterval(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)

	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()
	require.NotNil(t, cs)

	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "root", Namespace: "msp-policies", Name: "global"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{ConvergeInterval: "30m"},
		}),
	}))
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "group-policies", Name: "client-groups"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{ConvergeInterval: "5s"},
		}),
	}))

	ir := NewInheritanceResolverWithStorageManager(sm)
	effective, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	assert.Equal(t, "5s", effective.Config.Steward.ConvergeInterval,
		"child-level converge_interval must override parent value")
}

// TestResolveConfiguration_PropagatesDriftModeFromParent verifies that drift_mode
// cascades from an ancestor tenant. drift_mode is security-sensitive (steward
// trusts controller-delivered value only) so silently dropping it on cascade
// would leave stewards on the apply-mode default regardless of policy.
func TestResolveConfiguration_PropagatesDriftModeFromParent(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)

	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()
	require.NotNil(t, cs)

	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "root", Namespace: "msp-policies", Name: "global"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{DriftMode: stewardconfig.DriftModeMonitor},
		}),
	}))

	ir := NewInheritanceResolverWithStorageManager(sm)
	effective, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	assert.Equal(t, stewardconfig.DriftModeMonitor, effective.Config.Steward.DriftMode,
		"drift_mode set at parent tenant must cascade to descendant stewards")
	assert.NotNil(t, effective.Sources["steward.drift_mode"],
		"inheritance source for drift_mode must be recorded")
}
