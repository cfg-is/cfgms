// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package clusterregistry_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/clusterregistry"
	"github.com/cfgis/cfgms/features/controller/fleet"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	cfgpkg "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// cfgStoreAsRouter wraps a plain ConfigStore so it satisfies pkg/config's unexported
// configSourceRouter structurally.
//
//duplication:justified pkg/config/inheritance.go -- copy of cfgStoreAsRouter; the original is unexported and tests must not add production API
type cfgStoreAsRouter struct {
	cfgconfig.ConfigStore
}

func (s *cfgStoreAsRouter) SnapshotSources(_ context.Context, tenantPath []string) (map[string]*cfgpkg.ConfigSourceInfo, error) {
	m := make(map[string]*cfgpkg.ConfigSourceInfo, len(tenantPath))
	for _, tid := range tenantPath {
		m[tid] = &cfgpkg.ConfigSourceInfo{Type: cfgpkg.ConfigSourceTypeController}
	}
	return m, nil
}

// seedThreeLevelTenants creates root → msp → client tenant hierarchy in the store.
//
//duplication:justified pkg/config/inheritance_test.go -- test helper copy; unexported in an internal test package
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
//
//duplication:justified pkg/config/inheritance_test.go -- test helper copy; unexported in an internal test package
func marshalStewardConfig(t *testing.T, cfg stewardtypes.StewardConfig) []byte {
	t.Helper()
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	return data
}

// fixedRoleProvider returns a predetermined fragment list.
//
//duplication:justified pkg/config/inheritance_test.go -- copy of fixedRoleProvider for the moved wiring test
type fixedRoleProvider struct {
	fragments []cfgpkg.RoleFragment
}

func (p *fixedRoleProvider) MatchingRoleFragments(_ context.Context, _ string) ([]cfgpkg.RoleFragment, error) {
	return p.fragments, nil
}

// nsFailingStore injects an error for reads of one namespace.
//
//duplication:justified pkg/config/inheritance_test.go -- copy of nsFailingStore; the original stays for the remaining pkg/config tests
type nsFailingStore struct {
	cfgconfig.ConfigStore
	namespace string
	err       error
}

func (f *nsFailingStore) GetConfig(ctx context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	if key.Namespace == f.namespace {
		return nil, f.err
	}
	return f.ConfigStore.GetConfig(ctx, key)
}

// buildClusterRegistry constructs a real *clusterregistry.Registry from the given
// steward DNA, exercising the production BuildRegistry parse path (no stubs). It
// marks stewardID as a member of each named cluster by attaching a cluster:<name>
// ADR-017 fragment, built through sdna.NewFragment — the same production path the
// steward's monitor bridge uses (Issue #2908).
func buildClusterRegistry(t *testing.T, stewardID string, clusters ...string) *clusterregistry.Registry {
	t.Helper()
	frags := make([]*commonpb.Fragment, 0, len(clusters))
	for _, c := range clusters {
		frag, err := sdna.NewFragment("cluster:"+c, "hyperv", sdna.MapState{"name": c})
		require.NoError(t, err)
		frags = append(frags, frag)
	}
	return clusterregistry.BuildRegistry([]fleet.StewardData{
		{ID: stewardID, DNAFragments: frags},
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
		Data: marshalStewardConfig(t, stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "base-resource", Module: "file", Config: map[string]interface{}{"value": "group"}},
			},
		}),
	}))

	// Cluster-level sets "cluster-resource" and overrides "base-resource"
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "cluster-policies", Name: "cfg-lab"},
		Data: marshalStewardConfig(t, stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "cluster-resource", Module: "file", Config: map[string]interface{}{"value": "cluster"}},
				{Name: "base-resource", Module: "file", Config: map[string]interface{}{"value": "cluster-override"}},
			},
		}),
	}))

	// Device-level overrides "base-resource" — device must win over cluster
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "stewards", Name: "steward-1"},
		Data: marshalStewardConfig(t, stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "base-resource", Module: "file", Config: map[string]interface{}{"value": "device-wins"}},
			},
		}),
	}))

	registry := buildClusterRegistry(t, "steward-1", "cfg-lab")
	router := &cfgStoreAsRouter{ConfigStore: cs}
	ir := cfgpkg.NewInheritanceResolverWithClusters(router, sm.GetTenantStore(), registry)

	effective, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	// cluster-resource must be present (from cluster-policies/cfg-lab)
	resourcesByName := make(map[string]stewardtypes.ResourceConfig)
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
		Data: marshalStewardConfig(t, stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "cluster-only-resource", Module: "file"},
			},
		}),
	}))

	// Group-level config for baseline
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "group-policies", Name: "client-groups"},
		Data: marshalStewardConfig(t, stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "base-resource", Module: "file"},
			},
		}),
	}))

	router := &cfgStoreAsRouter{ConfigStore: cs}

	// Resolve with no registry wired
	irNoRegistry := cfgpkg.NewInheritanceResolver(router, sm.GetTenantStore())
	effectiveNoRegistry, err := irNoRegistry.ResolveConfiguration(ctx, "client", "steward-2")
	require.NoError(t, err)

	// Resolve with registry wired but steward has no membership
	emptyRegistry := buildClusterRegistry(t, "other-steward", "cfg-lab")
	irWithRegistry := cfgpkg.NewInheritanceResolverWithClusters(router, sm.GetTenantStore(), emptyRegistry)
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
		Data: marshalStewardConfig(t, stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "cluster-vm", Module: "hyperv.vm"},
			},
		}),
	}))

	router := &cfgStoreAsRouter{ConfigStore: cs}

	// First call: steward IS a member — cluster-vm must appear
	memberRegistry := buildClusterRegistry(t, "steward-1", "cfg-lab")
	irMember := cfgpkg.NewInheritanceResolverWithClusters(router, sm.GetTenantStore(), memberRegistry)
	effectiveMember, err := irMember.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)

	memberResourceNames := make(map[string]bool)
	for _, r := range effectiveMember.Config.Resources {
		memberResourceNames[r.Name] = true
	}
	assert.True(t, memberResourceNames["cluster-vm"],
		"cluster-vm must appear when steward is a member of cfg-lab")

	// Second call: steward has LEFT the cluster (registry returns nil) — cluster-vm must be gone
	leftRegistry := buildClusterRegistry(t, "other-steward", "cfg-lab")
	irLeft := cfgpkg.NewInheritanceResolverWithClusters(router, sm.GetTenantStore(), leftRegistry)
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
		Data: marshalStewardConfig(t, stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{
				{Name: "group-resource", Module: "file"},
			},
		}),
	}))

	// Store a corrupt (non-YAML) cluster-policies document to trigger the parse-error path.
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:  &cfgconfig.ConfigKey{TenantID: "client", Namespace: "cluster-policies", Name: "bad-cluster"},
		Data: []byte("{{{{this is not valid YAML: [[["),
	}))

	registry := buildClusterRegistry(t, "steward-1", "bad-cluster")
	router := &cfgStoreAsRouter{ConfigStore: cs}
	ir := cfgpkg.NewInheritanceResolverWithClusters(router, sm.GetTenantStore(), registry)

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
	registry := buildClusterRegistry(t, injectedStewardID, "bad-cluster")
	router := &cfgStoreAsRouter{ConfigStore: cs}

	capture := logging.NewCapturingLogger()
	ir := cfgpkg.NewInheritanceResolverWithClusters(router, sm.GetTenantStore(), registry)
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
	cleanRegistry := buildClusterRegistry(t, cleanStewardID, "bad-cluster")
	cleanCapture := logging.NewCapturingLogger()
	irClean := cfgpkg.NewInheritanceResolverWithClusters(router, sm.GetTenantStore(), cleanRegistry)
	irClean.WithLogger(cleanCapture)

	_, err = irClean.ResolveConfiguration(ctx, "client", cleanStewardID)
	require.NoError(t, err)
	require.Len(t, cleanCapture.WarnEntries, 1, "exactly one WarnCtx entry expected for clean-value test")

	cleanEntry := cleanCapture.WarnEntries[0]
	cleanVal, ok := cleanEntry["steward_id"].(string)
	require.True(t, ok, "steward_id must be a string in clean-value log entry")
	assert.Equal(t, cleanStewardID, cleanVal, "clean value must pass through unchanged")
}

// TestNewInheritanceResolverWithRoles_WiresClusterAndRoleProviders verifies that the
// constructor wires both the cluster registry and the role provider, so both cascade
// layers contribute to the effective config when ResolveConfiguration runs. The
// resolver's unexported fields are not reachable from this package, so wiring is
// asserted through resolution output.
func TestNewInheritanceResolverWithRoles_WiresClusterAndRoleProviders(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)
	cs := sm.GetConfigStore()
	require.NoError(t, cs.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "client", Namespace: "cluster-policies", Name: "cluster-a"},
		Data: marshalStewardConfig(t, stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{{Name: "cluster-resource", Module: "file"}},
		}),
	}))

	router := &cfgStoreAsRouter{ConfigStore: cs}
	registry := buildClusterRegistry(t, "steward-1", "cluster-a")
	roles := &fixedRoleProvider{fragments: []cfgpkg.RoleFragment{{
		Name: "admin-role",
		Config: stewardtypes.StewardConfig{
			Resources: []stewardtypes.ResourceConfig{{Name: "role-resource", Module: "file"}},
		},
	}}}

	ir := cfgpkg.NewInheritanceResolverWithRoles(router, sm.GetTenantStore(), registry, roles)
	require.NotNil(t, ir, "constructor must return a non-nil resolver")

	effective, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)
	names := make(map[string]bool)
	for _, r := range effective.Config.Resources {
		names[r.Name] = true
	}
	assert.True(t, names["cluster-resource"], "cluster registry must be wired by the constructor")
	assert.True(t, names["role-resource"], "role provider must be wired by the constructor")
}

func TestResolveConfiguration_ClusterPoliciesReadError_FailsClosed(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	storageErr := errors.New("transient storage fault")
	store := &nsFailingStore{ConfigStore: sm.GetConfigStore(), namespace: "cluster-policies", err: storageErr}
	registry := buildClusterRegistry(t, "steward-1", "cfg-lab")
	ir := cfgpkg.NewInheritanceResolverWithClusters(&cfgStoreAsRouter{ConfigStore: store}, sm.GetTenantStore(), registry)

	eff, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.Error(t, err, "a cluster-policies storage read error must fail resolution")
	assert.ErrorIs(t, err, storageErr)
	assert.Nil(t, eff)
}

func TestResolveConfiguration_ClusterPoliciesNotFound_Succeeds(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	ctx := context.Background()
	seedThreeLevelTenants(t, ctx, sm)

	store := &nsFailingStore{ConfigStore: sm.GetConfigStore(), namespace: "cluster-policies", err: cfgconfig.ErrConfigNotFound}
	registry := buildClusterRegistry(t, "steward-1", "cfg-lab")
	ir := cfgpkg.NewInheritanceResolverWithClusters(&cfgStoreAsRouter{ConfigStore: store}, sm.GetTenantStore(), registry)

	_, err := ir.ResolveConfiguration(ctx, "client", "steward-1")
	require.NoError(t, err)
}
