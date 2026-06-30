// SPDX-License-Identifier: AGPL-3.0-only
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

func resourceNames(resources []stewardconfig.ResourceConfig) []string {
	names := make([]string, len(resources))
	for i, r := range resources {
		names[i] = r.Name
	}
	return names
}

// TestApplyConfigurationWithSource_PreservesResourceOrder pins that resource
// declaration order survives inheritance merging. The order is load-bearing for
// dependency chains: the steward executor applies resources in slice order, so a
// vSwitch must come before the VM that attaches to it (create) and a VM must come
// before its vSwitch (delete — Hyper-V refuses to remove an in-use switch).
// Rebuilding the slice from a Go map (the prior implementation) randomised the
// order and made those chains fail intermittently. Eight resources make a
// stale-map regression astronomically unlikely to pass by chance (1/8!).
func TestApplyConfigurationWithSource_PreservesResourceOrder(t *testing.T) {
	ir := &InheritanceResolver{}
	effective := &EffectiveConfiguration{Sources: make(map[string]*InheritanceSource)}
	src := &InheritanceSource{Source: "test"}

	declared := []string{"sw-a", "sw-b", "vm-1", "vm-2", "vm-3", "vm-4", "vm-5", "vm-6"}
	resources := make([]stewardconfig.ResourceConfig, len(declared))
	for i, name := range declared {
		resources[i] = stewardconfig.ResourceConfig{Name: name, Module: "hyperv.vm"}
	}

	ir.applyConfigurationWithSource(effective, &stewardconfig.StewardConfig{Resources: resources}, src)

	assert.Equal(t, declared, resourceNames(effective.Config.Resources),
		"resource declaration order must be preserved through inheritance merging")
}

// TestApplyConfigurationWithSource_OverrideKeepsPositionAppendsNew verifies the
// declarative-merge semantics under order preservation: a later layer that
// overrides an existing resource replaces it IN PLACE (keeping the base
// position), while genuinely new resources append in declaration order.
func TestApplyConfigurationWithSource_OverrideKeepsPositionAppendsNew(t *testing.T) {
	ir := &InheritanceResolver{}
	effective := &EffectiveConfiguration{Sources: make(map[string]*InheritanceSource)}

	// Base layer (e.g. parent tenant): switch then VM.
	base := &stewardconfig.StewardConfig{Resources: []stewardconfig.ResourceConfig{
		{Name: "sw-a", Module: "hyperv.vswitch"},
		{Name: "vm-1", Module: "hyperv.vm"},
	}}
	ir.applyConfigurationWithSource(effective, base, &InheritanceSource{Source: "base"})

	// Child layer: overrides vm-1 and adds a new vm-2.
	child := &stewardconfig.StewardConfig{Resources: []stewardconfig.ResourceConfig{
		{Name: "vm-1", Module: "hyperv.vm", Config: map[string]interface{}{"cpu_count": 4}},
		{Name: "vm-2", Module: "hyperv.vm"},
	}}
	ir.applyConfigurationWithSource(effective, child, &InheritanceSource{Source: "child"})

	assert.Equal(t, []string{"sw-a", "vm-1", "vm-2"}, resourceNames(effective.Config.Resources),
		"override must keep the base position; new resources append")
	// The override must have taken effect (child value), not the base.
	var vm1 stewardconfig.ResourceConfig
	for _, r := range effective.Config.Resources {
		if r.Name == "vm-1" {
			vm1 = r
		}
	}
	assert.Equal(t, 4, vm1.Config["cpu_count"], "child layer must override the base resource in place")
}

// TestResolveConfiguration_PropagatesDesiredVersionFromParent verifies that
// steward.upgrade.desired_version set at a parent tenant cascades to child
// stewards via applyConfigurationWithSource. (Issue #2260)
func TestResolveConfiguration_PropagatesDesiredVersionFromParent(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)

	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()
	require.NotNil(t, cs)

	// Parent (root) sets desired_version; child tenant has no upgrade config.
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "root", Namespace: "msp-policies", Name: "global"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Steward: stewardconfig.StewardSettings{
				Upgrade: stewardconfig.UpgradeConfig{DesiredVersion: "v0.5.21"},
			},
		}),
	}))

	ir := NewInheritanceResolverWithStorageManager(sm)
	effective, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	assert.Equal(t, "v0.5.21", effective.Config.Steward.Upgrade.DesiredVersion,
		"desired_version set at parent tenant must cascade to descendant stewards")
	assert.NotNil(t, effective.Sources["steward.upgrade.desired_version"],
		"inheritance source for desired_version must be recorded")
}

// TestApplyConfigurationWithSource_DesiredVersionInherited verifies the
// applyConfigurationWithSource primitive: a parent config's desired_version is
// carried into the effective config and its source is tracked. (Issue #2260)
func TestApplyConfigurationWithSource_DesiredVersionInherited(t *testing.T) {
	ir := &InheritanceResolver{}
	effective := &EffectiveConfiguration{Sources: make(map[string]*InheritanceSource)}

	parentSrc := &InheritanceSource{Source: "parent", TenantID: "root"}
	parentCfg := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			Upgrade: stewardconfig.UpgradeConfig{
				DesiredVersion: "v0.5.21",
				AllowDowngrade: true,
			},
		},
	}
	ir.applyConfigurationWithSource(effective, parentCfg, parentSrc)

	assert.Equal(t, "v0.5.21", effective.Config.Steward.Upgrade.DesiredVersion,
		"desired_version must be applied from parent config")
	assert.True(t, effective.Config.Steward.Upgrade.AllowDowngrade,
		"allow_downgrade must be applied from parent config")
	assert.Equal(t, parentSrc, effective.Sources["steward.upgrade.desired_version"],
		"desired_version source must be tracked")
	assert.Equal(t, parentSrc, effective.Sources["steward.upgrade.allow_downgrade"],
		"allow_downgrade source must be tracked")

	// A child config with no desired_version must not clobber the inherited value.
	childSrc := &InheritanceSource{Source: "child", TenantID: "client"}
	childCfg := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{ID: "child-steward"},
	}
	ir.applyConfigurationWithSource(effective, childCfg, childSrc)

	assert.Equal(t, "v0.5.21", effective.Config.Steward.Upgrade.DesiredVersion,
		"child with empty desired_version must not clobber inherited value")
}

// TestApplyConfigurationWithSource_AllowDowngrade_MorePermissiveWins pins the
// intentional "more-permissive-wins" semantics: once a parent sets allow_downgrade=true
// a child that sets allow_downgrade=false cannot revoke it within the same inheritance
// pass. This is consistent with other bool fields in applyConfigurationWithSource and
// is deliberate policy for this security control. (Issue #2260)
func TestApplyConfigurationWithSource_AllowDowngrade_MorePermissiveWins(t *testing.T) {
	ir := &InheritanceResolver{}
	effective := &EffectiveConfiguration{Sources: make(map[string]*InheritanceSource)}

	parentSrc := &InheritanceSource{Source: "root", TenantID: "root"}
	parentCfg := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			Upgrade: stewardconfig.UpgradeConfig{AllowDowngrade: true},
		},
	}
	ir.applyConfigurationWithSource(effective, parentCfg, parentSrc)
	require.True(t, effective.Config.Steward.Upgrade.AllowDowngrade, "parent sets allow_downgrade=true")

	// Child explicitly sets allow_downgrade=false (zero-value for bool) — it cannot
	// revoke the parent-granted permission via applyConfigurationWithSource.
	childSrc := &InheritanceSource{Source: "child", TenantID: "client"}
	childCfg := &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			Upgrade: stewardconfig.UpgradeConfig{AllowDowngrade: false},
		},
	}
	ir.applyConfigurationWithSource(effective, childCfg, childSrc)

	assert.True(t, effective.Config.Steward.Upgrade.AllowDowngrade,
		"more-permissive-wins: child false cannot revoke parent true")
	assert.Equal(t, parentSrc, effective.Sources["steward.upgrade.allow_downgrade"],
		"source must remain the parent that set the permissive value")
}
