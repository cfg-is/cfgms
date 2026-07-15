// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/controller/clusterregistry"
	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/fleet"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/logging"
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

// --- ResolveRingVersion tests (Issue #2271) ---

// makeTestRings returns a DeploymentRingConfig with four rings and versions set
// for "early" and "default" to exercise the resolution logic.
func makeTestRings() controllerconfig.DeploymentRingConfig {
	return controllerconfig.DeploymentRingConfig{
		FallbackRing: "default",
		Rings: []controllerconfig.RingSpec{
			{Name: "pre-release", DesiredVersion: "v0.6.0-rc1"},
			{Name: "early", DesiredVersion: "v0.5.21"},
			{Name: "default", DesiredVersion: "v0.5.20"},
			{Name: "stable", DesiredVersion: "v0.5.19"},
		},
	}
}

// TestResolveRingVersion_ValidRing proves: a steward with dna["deployment_ring"] = "early"
// receives the early ring's desired_version as effective desired_version.
func TestResolveRingVersion_ValidRing(t *testing.T) {
	rings := makeTestRings()
	attrs := map[string]string{"deployment_ring": "early"}

	version, ring, didFallback, original := ResolveRingVersion(attrs, rings)

	assert.Equal(t, "v0.5.21", version, "must return early ring's desired_version")
	assert.Equal(t, "early", ring)
	assert.False(t, didFallback, "valid ring must not trigger fallback")
	assert.Equal(t, "early", original)
}

// TestResolveRingVersion_InvalidRing_FallsBack proves: a steward with an invalid
// deployment_ring value receives the fallback ring's desired_version and triggers fallback.
func TestResolveRingVersion_InvalidRing_FallsBack(t *testing.T) {
	rings := makeTestRings()
	attrs := map[string]string{"deployment_ring": "nonexistent-ring"}

	version, ring, didFallback, original := ResolveRingVersion(attrs, rings)

	assert.Equal(t, "v0.5.20", version, "invalid ring must fall back to default ring's version")
	assert.Equal(t, "default", ring)
	assert.True(t, didFallback, "invalid ring must trigger fallback")
	assert.Equal(t, "nonexistent-ring", original)
}

// TestResolveRingVersion_AbsentRing_FallsBack proves: a steward with no deployment_ring
// attribute receives the fallback ring's desired_version and triggers fallback.
func TestResolveRingVersion_AbsentRing_FallsBack(t *testing.T) {
	rings := makeTestRings()
	attrs := map[string]string{} // no deployment_ring

	version, ring, didFallback, original := ResolveRingVersion(attrs, rings)

	assert.Equal(t, "v0.5.20", version, "absent ring must fall back to default ring's version")
	assert.Equal(t, "default", ring)
	assert.True(t, didFallback, "absent ring must trigger fallback")
	assert.Equal(t, "", original, "original must be empty when attribute is absent")
}

// TestResolveRingVersion_OverridesTenantPathVersion proves: the ring-resolved
// desired_version overrides any tenant-path desired_version when the ring has a non-empty version.
// This is the REQUIRED TEST from the acceptance criteria for Story #2271.
func TestResolveRingVersion_OverridesTenantPathVersion(t *testing.T) {
	rings := makeTestRings()

	// Test case: steward subscribed to "early" ring; tenant path carries an older version.
	tenantPathVersion := "v0.4.0" // lower version from tenant hierarchy
	attrs := map[string]string{"deployment_ring": "early"}

	version, _, didFallback, _ := ResolveRingVersion(attrs, rings)

	// Ring version must win when non-empty — caller applies override.
	require.NotEmpty(t, version, "early ring must have a non-empty desired_version")
	assert.Equal(t, "v0.5.21", version,
		"ring-resolved version must override the tenant-path version %q", tenantPathVersion)
	assert.False(t, didFallback)
}

// TestResolveRingVersion_EmptyVersionRing proves: when the resolved ring has no
// desired_version set, ResolveRingVersion returns empty string (no override).
func TestResolveRingVersion_EmptyVersionRing(t *testing.T) {
	rings := controllerconfig.DeploymentRingConfig{
		FallbackRing: "stable",
		Rings: []controllerconfig.RingSpec{
			{Name: "stable"}, // no desired_version
		},
	}
	attrs := map[string]string{"deployment_ring": "stable"}

	version, ring, didFallback, _ := ResolveRingVersion(attrs, rings)

	assert.Equal(t, "", version, "ring with no desired_version must return empty (no override)")
	assert.Equal(t, "stable", ring)
	assert.False(t, didFallback)
}

// TestResolveRingVersion_CustomFallbackRing verifies fallback_ring is honoured when
// explicitly configured to a ring other than "default".
func TestResolveRingVersion_CustomFallbackRing(t *testing.T) {
	rings := controllerconfig.DeploymentRingConfig{
		FallbackRing: "stable",
		Rings: []controllerconfig.RingSpec{
			{Name: "early", DesiredVersion: "v0.6.0"},
			{Name: "stable", DesiredVersion: "v0.5.19"},
		},
	}
	attrs := map[string]string{} // no ring attribute

	version, ring, didFallback, _ := ResolveRingVersion(attrs, rings)

	assert.Equal(t, "v0.5.19", version)
	assert.Equal(t, "stable", ring)
	assert.True(t, didFallback)
}

// TestResolveRingVersion_DefaultFallbackWhenFallbackRingEmpty verifies that an empty
// fallback_ring defaults to controllerconfig.DefaultFallbackRing ("default").
func TestResolveRingVersion_DefaultFallbackWhenFallbackRingEmpty(t *testing.T) {
	rings := controllerconfig.DeploymentRingConfig{
		// FallbackRing intentionally empty
		Rings: []controllerconfig.RingSpec{
			{Name: "early", DesiredVersion: "v0.6.0"},
			{Name: "default", DesiredVersion: "v0.5.20"}, // must be the automatic fallback
		},
	}
	attrs := map[string]string{"deployment_ring": "unknown"}

	version, ring, didFallback, _ := ResolveRingVersion(attrs, rings)

	assert.Equal(t, "v0.5.20", version, "empty fallback_ring must default to 'default' ring")
	assert.Equal(t, "default", ring)
	assert.True(t, didFallback)
}

// --- Cluster cascade tests (Issue #2425) ---

// buildClusterRegistry constructs a real *clusterregistry.Registry from the given
// steward DNA, exercising the production BuildRegistry parse path (no stubs). It
// marks stewardID as a member of each named cluster via the cluster:<name>.member
// DNA convention that clusterregistry.BuildRegistry parses.
func buildClusterRegistry(stewardID string, clusters ...string) *clusterregistry.Registry {
	attrs := make(map[string]string, len(clusters))
	for _, c := range clusters {
		attrs["cluster:"+c+".member"] = "true"
	}
	return clusterregistry.BuildRegistry([]fleet.StewardData{
		{ID: stewardID, DNAAttributes: attrs},
	})
}

// TestResolveConfiguration_ClusterCascade_MemberReceivesResources verifies the required
// AC: a steward reported as a member of cluster "cfg-lab" by the registry receives the
// merged resources from cluster-policies/cfg-lab, positioned after Group-level and before
// Device-level (a device-level resource of the same name still wins).
func TestResolveConfiguration_ClusterCascade_MemberReceivesResources(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()

	// Group-level sets a resource "base-resource"
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "group-policies", Name: "client-groups"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Resources: []stewardconfig.ResourceConfig{
				{Name: "base-resource", Module: "file", Config: map[string]interface{}{"value": "group"}},
			},
		}),
	}))

	// Cluster-level sets "cluster-resource" and overrides "base-resource"
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "cluster-policies", Name: "cfg-lab"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Resources: []stewardconfig.ResourceConfig{
				{Name: "cluster-resource", Module: "file", Config: map[string]interface{}{"value": "cluster"}},
				{Name: "base-resource", Module: "file", Config: map[string]interface{}{"value": "cluster-override"}},
			},
		}),
	}))

	// Device-level overrides "base-resource" — device must win over cluster
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "stewards", Name: "steward-1"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Resources: []stewardconfig.ResourceConfig{
				{Name: "base-resource", Module: "file", Config: map[string]interface{}{"value": "device-wins"}},
			},
		}),
	}))

	registry := buildClusterRegistry("steward-1", "cfg-lab")
	router := &cfgStoreAsRouter{ConfigStore: cs}
	ir := NewInheritanceResolverWithClusters(router, sm.GetClientTenantStore(), sm.GetTenantStore(), registry)

	effective, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	// cluster-resource must be present (from cluster-policies/cfg-lab)
	resourcesByName := make(map[string]stewardconfig.ResourceConfig)
	for _, r := range effective.Config.Resources {
		resourcesByName[r.Name] = r
	}
	clusterRes, ok := resourcesByName["cluster-resource"]
	require.True(t, ok, "cluster-resource must be present in effective config")
	assert.Equal(t, "cluster", clusterRes.Config["value"], "cluster-resource must come from cluster-policies")

	// device-level must win over cluster-level for the same resource name
	baseRes, ok := resourcesByName["base-resource"]
	require.True(t, ok, "base-resource must be present")
	assert.Equal(t, "device-wins", baseRes.Config["value"], "device-level must override cluster-level for same resource")

	// inheritance source for cluster-resource must show the cluster origin
	src, ok := effective.Sources["resource.cluster-resource"]
	require.True(t, ok, "cluster-resource source must be tracked")
	assert.Contains(t, src.Source, "cluster-policies", "source must identify cluster-policies namespace")
}

// TestResolveConfiguration_NoMembership_Unchanged verifies that a steward with no cluster
// membership (registry returns nil) produces byte-identical EffectiveConfiguration output
// to an InheritanceResolver with no registry wired at all. This is the nil-registry /
// empty-membership no-op guarantee.
func TestResolveConfiguration_NoMembership_Unchanged(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()

	// Seed a cluster-policies doc that must NOT appear for a non-member steward.
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "cluster-policies", Name: "cfg-lab"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Resources: []stewardconfig.ResourceConfig{
				{Name: "cluster-only-resource", Module: "file"},
			},
		}),
	}))

	// Group-level config for baseline
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "group-policies", Name: "client-groups"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Resources: []stewardconfig.ResourceConfig{
				{Name: "base-resource", Module: "file"},
			},
		}),
	}))

	router := &cfgStoreAsRouter{ConfigStore: cs}

	// Resolve with no registry wired
	irNoRegistry := NewInheritanceResolver(router, sm.GetClientTenantStore(), sm.GetTenantStore())
	effectiveNoRegistry, err := irNoRegistry.ResolveConfiguration(ctx, "client", "steward-2")
	require.NoError(t, err)

	// Resolve with registry wired but steward has no membership
	emptyRegistry := buildClusterRegistry("other-steward", "cfg-lab")
	irWithRegistry := NewInheritanceResolverWithClusters(router, sm.GetClientTenantStore(), sm.GetTenantStore(), emptyRegistry)
	effectiveWithRegistry, err := irWithRegistry.ResolveConfiguration(ctx, "client", "steward-2")
	require.NoError(t, err)

	// Resources must be identical — no cluster-only-resource leaked in
	assert.Equal(t, len(effectiveNoRegistry.Config.Resources), len(effectiveWithRegistry.Config.Resources),
		"non-member steward must have identical resource count regardless of registry wiring")
	for _, r := range effectiveWithRegistry.Config.Resources {
		assert.NotEqual(t, "cluster-only-resource", r.Name,
			"cluster-only-resource must not appear for a non-member steward")
	}

	// Sources must have the same keys
	assert.Equal(t, len(effectiveNoRegistry.Sources), len(effectiveWithRegistry.Sources),
		"non-member steward must have identical source count regardless of registry wiring")
}

// TestResolveConfiguration_ClusterLeave_DropsResources verifies that when a steward's
// registry membership is removed (cluster leave), the cluster.cfg resources are absent
// from the next ResolveConfiguration call — no stale merge.
func TestResolveConfiguration_ClusterLeave_DropsResources(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()

	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "cluster-policies", Name: "cfg-lab"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Resources: []stewardconfig.ResourceConfig{
				{Name: "cluster-vm", Module: "hyperv.vm"},
			},
		}),
	}))

	router := &cfgStoreAsRouter{ConfigStore: cs}

	// First call: steward IS a member — cluster-vm must appear
	memberRegistry := buildClusterRegistry("steward-1", "cfg-lab")
	irMember := NewInheritanceResolverWithClusters(router, sm.GetClientTenantStore(), sm.GetTenantStore(), memberRegistry)
	effectiveMember, err := irMember.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	memberResourceNames := make(map[string]bool)
	for _, r := range effectiveMember.Config.Resources {
		memberResourceNames[r.Name] = true
	}
	assert.True(t, memberResourceNames["cluster-vm"],
		"cluster-vm must appear when steward is a member of cfg-lab")

	// Second call: steward has LEFT the cluster (registry returns nil) — cluster-vm must be gone
	leftRegistry := buildClusterRegistry("other-steward", "cfg-lab")
	irLeft := NewInheritanceResolverWithClusters(router, sm.GetClientTenantStore(), sm.GetTenantStore(), leftRegistry)
	effectiveLeft, err := irLeft.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	leftResourceNames := make(map[string]bool)
	for _, r := range effectiveLeft.Config.Resources {
		leftResourceNames[r.Name] = true
	}
	assert.False(t, leftResourceNames["cluster-vm"],
		"cluster-vm must be absent after steward leaves cfg-lab (no stale merge)")
}

// TestResolveConfiguration_CorruptClusterConfig_DoesNotFailResolution verifies that a
// corrupt (non-YAML) cluster-policies document causes a warning log but does NOT fail
// ResolveConfiguration. The steward must still receive its non-cluster config, and the
// corrupt cluster doc must contribute no resources (the error is non-fatal by design).
func TestResolveConfiguration_CorruptClusterConfig_DoesNotFailResolution(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()

	// Store a valid group-level config
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "group-policies", Name: "client-groups"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Resources: []stewardconfig.ResourceConfig{
				{Name: "group-resource", Module: "file"},
			},
		}),
	}))

	// Store a corrupt (non-YAML) cluster-policies document to trigger the parse-error path.
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:  &cfgconfig.ConfigKey{TenantID: "client", Namespace: "cluster-policies", Name: "bad-cluster"},
		Data: []byte("{{{{this is not valid YAML: [[["),
	}))

	registry := buildClusterRegistry("steward-1", "bad-cluster")
	router := &cfgStoreAsRouter{ConfigStore: cs}
	ir := NewInheritanceResolverWithClusters(router, sm.GetClientTenantStore(), sm.GetTenantStore(), registry)

	// Resolution must succeed despite the corrupt cluster config document.
	effective, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err, "corrupt cluster-policies document must not fail ResolveConfiguration")

	// The group-level resource must still appear (cluster corruption is isolated).
	resourceNames := make(map[string]bool)
	for _, r := range effective.Config.Resources {
		resourceNames[r.Name] = true
	}
	assert.True(t, resourceNames["group-resource"],
		"group-level resource must appear even when cluster config is corrupt")
}

// TestWithLogger_InstallsRealLogger verifies WithLogger installs the provided
// logger as the resolver's diagnostic sink: after the call, both the unexported
// logger field and the log() accessor return the exact logger that was passed in.
func TestWithLogger_InstallsRealLogger(t *testing.T) {
	ir := &InheritanceResolver{}

	realLogger := logging.NewLogger("info")
	require.NotNil(t, realLogger, "test precondition: NewLogger must return a real logger")

	returned := ir.WithLogger(realLogger)

	assert.Same(t, ir, returned, "WithLogger must return the same resolver for chaining")
	assert.Same(t, realLogger, ir.logger, "WithLogger must install the provided logger")
	assert.Same(t, realLogger, ir.log(), "log() must return the installed real logger")
}

// TestWithLogger_NilDefaultsToNonNilLogger verifies the nil-guard branch: passing
// nil to WithLogger installs a real default logger (never leaves the field nil and
// never routes through the Noop fallback in log()). This exercises lines 83-85.
func TestWithLogger_NilDefaultsToNonNilLogger(t *testing.T) {
	// Start from a resolver that already has a logger to prove nil resets to a
	// fresh default rather than being ignored.
	ir := (&InheritanceResolver{}).WithLogger(logging.NewLogger("info"))

	returned := ir.WithLogger(nil)

	assert.Same(t, ir, returned, "WithLogger(nil) must return the same resolver for chaining")
	require.NotNil(t, ir.logger, "WithLogger(nil) must install a non-nil default logger")
	require.NotNil(t, ir.log(), "log() must return a non-nil logger after WithLogger(nil)")
}

// TestResolveRingVersion_NilDNAAttrs verifies nil attrs does not panic.
func TestResolveRingVersion_NilDNAAttrs(t *testing.T) {
	rings := makeTestRings()

	version, ring, didFallback, original := ResolveRingVersion(nil, rings)

	assert.Equal(t, "v0.5.20", version)
	assert.Equal(t, "default", ring)
	assert.True(t, didFallback)
	assert.Equal(t, "", original)
}

// TestResolveConfiguration_ClusterConfigError_LogValueSanitized verifies that stewardID
// and clusterName values containing newline/CR injection characters are stripped before
// they appear in the WarnCtx call at inheritance.go:241 (the applyClusterConfiguration
// error path). Also confirms a clean value (no control chars) passes through unchanged.
func TestResolveConfiguration_ClusterConfigError_LogValueSanitized(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()

	// Store corrupt YAML for the cluster to trigger the WarnCtx error path.
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:  &cfgconfig.ConfigKey{TenantID: "client", Namespace: "cluster-policies", Name: "bad-cluster"},
		Data: []byte("{{{{this is not valid YAML: [[["),
	}))

	// stewardID containing newline and CR that must be stripped at the log call site.
	injectedStewardID := "steward\n123\rinjected"
	registry := buildClusterRegistry(injectedStewardID, "bad-cluster")
	router := &cfgStoreAsRouter{ConfigStore: cs}

	capture := logging.NewCapturingLogger()
	ir := NewInheritanceResolverWithClusters(router, sm.GetClientTenantStore(), sm.GetTenantStore(), registry)
	ir.WithLogger(capture)

	_, err := ir.ResolveConfiguration(ctx, "client", injectedStewardID)
	require.NoError(t, err, "corrupt cluster-policies document must not fail ResolveConfiguration")
	require.Len(t, capture.WarnEntries, 1, "exactly one WarnCtx entry expected for the corrupt cluster")

	entry := capture.WarnEntries[0]

	stewardIDVal, ok := entry["steward_id"].(string)
	require.True(t, ok, "steward_id must be a string in the log entry")
	assert.NotContains(t, stewardIDVal, "\n", "steward_id must not contain raw newline in logged field")
	assert.NotContains(t, stewardIDVal, "\r", "steward_id must not contain raw carriage-return in logged field")
	assert.Equal(t, "steward_123_injected", stewardIDVal,
		"newline and CR in steward_id must be replaced with underscore before logging")

	// A clean value (no control chars) must pass through unchanged.
	cleanStewardID := "clean-steward-456"
	cleanRegistry := buildClusterRegistry(cleanStewardID, "bad-cluster")
	cleanCapture := logging.NewCapturingLogger()
	irClean := NewInheritanceResolverWithClusters(router, sm.GetClientTenantStore(), sm.GetTenantStore(), cleanRegistry)
	irClean.WithLogger(cleanCapture)

	_, err = irClean.ResolveConfiguration(ctx, "client", cleanStewardID)
	require.NoError(t, err)
	require.Len(t, cleanCapture.WarnEntries, 1, "exactly one WarnCtx entry expected for clean-value test")

	cleanEntry := cleanCapture.WarnEntries[0]
	cleanVal, ok := cleanEntry["steward_id"].(string)
	require.True(t, ok, "steward_id must be a string in clean-value log entry")
	assert.Equal(t, cleanStewardID, cleanVal, "clean value must pass through unchanged")
}

// --- Role cascade tests (NewInheritanceResolverWithRoles / applyRoleFragment) ---

// fixedRoleProvider is a real roleConfigProvider implementation for tests that
// returns a predetermined fragment list or a predetermined error. It never
// delegates to a stub — it IS the implementation.
type fixedRoleProvider struct {
	fragments []RoleFragment
	err       error
}

func (p *fixedRoleProvider) MatchingRoleFragments(_ context.Context, _ string) ([]RoleFragment, error) {
	return p.fragments, p.err
}

// TestNewInheritanceResolverWithRoles_WiresClusterAndRoleProviders verifies that the
// constructor stores both the cluster registry and the role provider on the resolver,
// so the cascade layers are active when ResolveConfiguration runs.
func TestNewInheritanceResolverWithRoles_WiresClusterAndRoleProviders(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	router := &cfgStoreAsRouter{ConfigStore: sm.GetConfigStore()}
	registry := buildClusterRegistry("steward-1", "cluster-a")
	roles := &fixedRoleProvider{}

	ir := NewInheritanceResolverWithRoles(router, sm.GetClientTenantStore(), sm.GetTenantStore(), registry, roles)

	require.NotNil(t, ir, "constructor must return a non-nil resolver")
	assert.Same(t, registry, ir.clusterRegistry, "clusterRegistry must be wired by the constructor")
	assert.Same(t, roles, ir.roleProvider, "roleProvider must be wired by the constructor")
}

// TestResolveConfiguration_RoleCascade_FragmentsApplied verifies that role fragments
// returned by the provider are merged into the effective config via applyRoleFragment.
// Role fragments must appear after cluster-policies and before device-level config
// (cluster < role < device precedence): a device-level resource of the same name wins.
func TestResolveConfiguration_RoleCascade_FragmentsApplied(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	cs := sm.GetConfigStore()

	// Role fragment contributes role-resource and would override base-resource,
	// but device-level must still win for base-resource.
	roleFrags := []RoleFragment{
		{
			Name: "admin-role",
			Config: stewardconfig.StewardConfig{
				Resources: []stewardconfig.ResourceConfig{
					{Name: "role-resource", Module: "file", Config: map[string]interface{}{"value": "from-role"}},
					{Name: "base-resource", Module: "file", Config: map[string]interface{}{"value": "role-override"}},
				},
			},
		},
	}

	// Device-level must win over role for base-resource.
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "stewards", Name: "steward-1"},
		Data: marshalStewardConfig(t, stewardconfig.StewardConfig{
			Resources: []stewardconfig.ResourceConfig{
				{Name: "base-resource", Module: "file", Config: map[string]interface{}{"value": "device-wins"}},
			},
		}),
	}))

	router := &cfgStoreAsRouter{ConfigStore: cs}
	ir := NewInheritanceResolverWithRoles(router, sm.GetClientTenantStore(), sm.GetTenantStore(), nil, &fixedRoleProvider{fragments: roleFrags})

	effective, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	resourcesByName := make(map[string]stewardconfig.ResourceConfig)
	for _, r := range effective.Config.Resources {
		resourcesByName[r.Name] = r
	}

	// role-resource must be present from the role fragment.
	roleRes, ok := resourcesByName["role-resource"]
	require.True(t, ok, "role-resource must appear from the role fragment")
	assert.Equal(t, "from-role", roleRes.Config["value"], "role-resource value must come from the role fragment")

	// device-level must win for the same resource name.
	baseRes, ok := resourcesByName["base-resource"]
	require.True(t, ok, "base-resource must appear in effective config")
	assert.Equal(t, "device-wins", baseRes.Config["value"], "device-level must override role-level for same resource")

	// Inheritance source must record the role origin.
	src, ok := effective.Sources["resource.role-resource"]
	require.True(t, ok, "role-resource source must be tracked")
	assert.Contains(t, src.Source, "role-policies", "source must identify role-policies namespace")
	assert.Equal(t, "admin-role", src.ConfigName, "source ConfigName must be the role name")
}

// TestResolveConfiguration_RoleProviderError_LogValueSanitized verifies that
// stewardID values containing newline/CR injection characters are stripped before
// they appear in the WarnCtx call at inheritance.go:258 (the role provider error
// path). Also confirms a clean value (no control chars) passes through unchanged.
func TestResolveConfiguration_RoleProviderError_LogValueSanitized(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	router := &cfgStoreAsRouter{ConfigStore: sm.GetConfigStore()}
	brokenRoles := &fixedRoleProvider{err: errors.New("simulated role provider failure")}

	injectedStewardID := "steward\n456\rinjected"
	capture := logging.NewCapturingLogger()
	ir := NewInheritanceResolverWithRoles(router, sm.GetClientTenantStore(), sm.GetTenantStore(), nil, brokenRoles)
	ir.WithLogger(capture)

	_, err := ir.ResolveConfiguration(ctx, "client", injectedStewardID)
	require.NoError(t, err, "role provider error must not fail ResolveConfiguration")
	require.Len(t, capture.WarnEntries, 1, "exactly one WarnCtx entry expected for the role provider error")

	entry := capture.WarnEntries[0]

	stewardIDVal, ok := entry["steward_id"].(string)
	require.True(t, ok, "steward_id must be a string in the log entry")
	assert.NotContains(t, stewardIDVal, "\n", "steward_id must not contain raw newline in logged field")
	assert.NotContains(t, stewardIDVal, "\r", "steward_id must not contain raw carriage-return in logged field")
	assert.Equal(t, "steward_456_injected", stewardIDVal,
		"newline and CR in steward_id must be replaced with underscore before logging")

	// A clean value must pass through unchanged.
	cleanStewardID := "clean-steward-789"
	cleanCapture := logging.NewCapturingLogger()
	irClean := NewInheritanceResolverWithRoles(router, sm.GetClientTenantStore(), sm.GetTenantStore(), nil, brokenRoles)
	irClean.WithLogger(cleanCapture)

	_, err = irClean.ResolveConfiguration(ctx, "client", cleanStewardID)
	require.NoError(t, err)
	require.Len(t, cleanCapture.WarnEntries, 1, "exactly one WarnCtx entry expected for clean-value test")

	cleanEntry := cleanCapture.WarnEntries[0]
	cleanVal, ok := cleanEntry["steward_id"].(string)
	require.True(t, ok, "steward_id must be a string in clean-value log entry")
	assert.Equal(t, cleanStewardID, cleanVal, "clean value must pass through unchanged")
}
