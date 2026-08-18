// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	common "github.com/cfgis/cfgms/api/proto/common"
	controllerFleet "github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/controller/tagstore"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/logging"
)

// mustFrag builds a DNA fragment from a field map.
func mustFrag(t *testing.T, kind string, fields map[string]interface{}) *common.Fragment {
	t.Helper()
	frag, err := sdna.NewFragment(kind, "test", sdna.MapState(fields))
	require.NoError(t, err)
	return frag
}

// newFleetQueryTestService builds a real ControllerService with three registered
// stewards spanning two tenants and distinct DNA fragments, exercising the same
// registry path the production server uses.
func newFleetQueryTestService(t *testing.T) *service.ControllerService {
	t.Helper()
	svc := service.NewControllerService(logging.NewNoopLogger())

	require.NoError(t, svc.RegisterSteward("s-linux", "tenant-a", "addr-1", "online"))
	require.True(t, svc.SetStewardDNA("s-linux", &common.DNA{
		Id: "s-linux",
		Fragments: []*common.Fragment{
			mustFrag(t, "host:os", map[string]interface{}{"os": "linux", "arch": "amd64"}),
			mustFrag(t, "hostname", map[string]interface{}{"hostname": "web-01"}),
		},
	}))

	require.NoError(t, svc.RegisterSteward("s-windows", "tenant-a", "addr-2", "online"))
	require.True(t, svc.SetStewardDNA("s-windows", &common.DNA{
		Id: "s-windows",
		Fragments: []*common.Fragment{
			mustFrag(t, "host:os", map[string]interface{}{"os": "windows", "arch": "amd64"}),
			mustFrag(t, "hostname", map[string]interface{}{"hostname": "dc-01"}),
		},
	}))

	// Different tenant, also linux — used to prove tenant scoping excludes it.
	require.NoError(t, svc.RegisterSteward("s-other", "tenant-b", "addr-3", "online"))
	require.True(t, svc.SetStewardDNA("s-other", &common.DNA{
		Id: "s-other",
		Fragments: []*common.Fragment{
			mustFrag(t, "host:os", map[string]interface{}{"os": "linux", "arch": "arm64"}),
			mustFrag(t, "hostname", map[string]interface{}{"hostname": "edge-01"}),
		},
	}))

	return svc
}

// TestServerFleetStewardProvider_GetAllStewards verifies the adapter converts every
// registered steward (including nil-DNA entries) into a controllerFleet.StewardData
// with flattened DNA attributes.
func TestServerFleetStewardProvider_GetAllStewards(t *testing.T) {
	svc := newFleetQueryTestService(t)

	// Register a steward with nil DNA to exercise the nil-guard branch.
	require.NoError(t, svc.RegisterSteward("s-nildna", "tenant-a", "addr-4", "offline"))
	require.True(t, svc.SetStewardDNA("s-nildna", nil))

	provider := &serverFleetStewardProvider{svc: svc}
	stewards := provider.GetAllStewards()

	require.Len(t, stewards, 4)

	byID := make(map[string]controllerFleet.StewardData, len(stewards))
	for _, s := range stewards {
		byID[s.ID] = s
	}

	linux, ok := byID["s-linux"]
	require.True(t, ok)
	assert.Equal(t, "tenant-a", linux.TenantID)
	assert.Equal(t, "online", linux.Status)
	assert.Equal(t, "linux", linux.DNAAttributes["os"])
	assert.Equal(t, "amd64", linux.DNAAttributes["arch"])

	nildna, ok := byID["s-nildna"]
	require.True(t, ok)
	assert.Nil(t, nildna.DNAAttributes, "nil DNA must yield nil attributes, not a panic")
	assert.Equal(t, "offline", nildna.Status)
}

// TestServerBatchjobFleetQuery_Search_TenantScoped verifies that Search parses the
// selector, scopes results to the given tenant, and returns batchjob.StewardMeta
// entries carrying the flattened DNA attributes.
func TestServerBatchjobFleetQuery_Search_TenantScoped(t *testing.T) {
	svc := newFleetQueryTestService(t)
	adapter := &serverBatchjobFleetQuery{svc: svc}

	// os:linux exists in both tenant-a and tenant-b, but tenant scoping must
	// exclude tenant-b's steward.
	metas, err := adapter.Search(context.Background(), "os:linux", "tenant-a")
	require.NoError(t, err)
	require.Len(t, metas, 1)
	assert.Equal(t, "s-linux", metas[0].ID)
	assert.Equal(t, "linux", metas[0].DNAAttributes["os"])

	// The same selector under tenant-b returns only tenant-b's steward.
	metasB, err := adapter.Search(context.Background(), "os:linux", "tenant-b")
	require.NoError(t, err)
	require.Len(t, metasB, 1)
	assert.Equal(t, "s-other", metasB[0].ID)
}

// TestServerBatchjobFleetQuery_Search_All verifies the "all" selector returns every
// steward in the requested tenant.
func TestServerBatchjobFleetQuery_Search_All(t *testing.T) {
	svc := newFleetQueryTestService(t)
	adapter := &serverBatchjobFleetQuery{svc: svc}

	metas, err := adapter.Search(context.Background(), "all", "tenant-a")
	require.NoError(t, err)
	require.Len(t, metas, 2)

	ids := map[string]bool{}
	for _, m := range metas {
		ids[m.ID] = true
	}
	assert.True(t, ids["s-linux"])
	assert.True(t, ids["s-windows"])
	assert.False(t, ids["s-other"], "tenant-b steward must not appear under tenant-a scope")
}

// TestServerBatchjobFleetQuery_Search_InvalidSelector verifies that an empty
// selector fails closed with a wrapped parse error rather than fanning out.
func TestServerBatchjobFleetQuery_Search_InvalidSelector(t *testing.T) {
	svc := newFleetQueryTestService(t)
	adapter := &serverBatchjobFleetQuery{svc: svc}

	metas, err := adapter.Search(context.Background(), "", "tenant-a")
	require.Error(t, err)
	assert.Nil(t, metas)
	assert.Contains(t, err.Error(), "invalid selector")
}

// newTestTagStore opens a temporary SQLite-backed tag store suitable for use in unit tests.
func newTestTagStore(t *testing.T) *tagstore.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "tags_test.db")
	store, err := tagstore.NewFromDSN("file:"+dbPath, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(context.Background()))
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestServerFleetStewardProvider_TagSelector verifies that after tagging steward S
// with "github-runner" (via the #2542 store), a fleet query with parsed selector
// tag:github-runner returns S through serverFleetStewardProvider; an untagged
// steward is not returned. (Issue #2544 AC1)
func TestServerFleetStewardProvider_TagSelector(t *testing.T) {
	svc := newFleetQueryTestService(t)
	ts := newTestTagStore(t)
	svc.SetTagStore(ts)

	// Tag only s-linux; s-windows and s-other are untagged.
	require.NoError(t, ts.Set(context.Background(), "s-linux", []string{"github-runner"}))

	provider := &serverFleetStewardProvider{svc: svc}
	stewards := provider.GetAllStewards()

	byID := make(map[string]controllerFleet.StewardData, len(stewards))
	for _, s := range stewards {
		byID[s.ID] = s
	}

	// s-linux must have the tag merged into its attribute map.
	linux := byID["s-linux"]
	assert.Equal(t, "github-runner", linux.DNAAttributes["tags"],
		"s-linux must have tags=github-runner after merge")

	// s-windows must not have any tags key.
	windows := byID["s-windows"]
	_, hasTag := windows.DNAAttributes["tags"]
	assert.False(t, hasTag, "untagged steward must not have a tags attribute")

	// Drive the full tag: selector path through MemoryQuery to confirm end-to-end resolution.
	adapter := &serverBatchjobFleetQuery{svc: svc}
	metas, err := adapter.Search(context.Background(), "tag:github-runner", "tenant-a")
	require.NoError(t, err)
	require.Len(t, metas, 1, "only s-linux is tagged; s-windows must not match")
	assert.Equal(t, "s-linux", metas[0].ID)
}

// TestServerFleetStewardProvider_TagsSurviveDNARefresh verifies that controller-stored
// tags remain resolvable after a steward's DNA is replaced wholesale. Tags are
// controller-owned and must not be clobbered by DNA updates. (Issue #2544 AC2)
func TestServerFleetStewardProvider_TagsSurviveDNARefresh(t *testing.T) {
	svc := service.NewControllerService(logging.NewNoopLogger())
	require.NoError(t, svc.RegisterSteward("s-refresh", "tenant-a", "addr-1", "online"))
	require.True(t, svc.SetStewardDNA("s-refresh", &common.DNA{
		Id: "s-refresh",
		Fragments: []*common.Fragment{
			mustFrag(t, "host:os", map[string]interface{}{"os": "linux"}),
			mustFrag(t, "hostname", map[string]interface{}{"hostname": "before-refresh"}),
		},
	}))

	ts := newTestTagStore(t)
	svc.SetTagStore(ts)
	require.NoError(t, ts.Set(context.Background(), "s-refresh", []string{"github-runner"}))

	// Wholesale DNA replacement simulates the DNA refresh cycle.
	require.True(t, svc.SetStewardDNA("s-refresh", &common.DNA{
		Id: "s-refresh",
		Fragments: []*common.Fragment{
			mustFrag(t, "host:os", map[string]interface{}{"os": "linux"}),
			mustFrag(t, "hostname", map[string]interface{}{"hostname": "after-refresh"}),
		},
	}))

	adapter := &serverBatchjobFleetQuery{svc: svc}
	metas, err := adapter.Search(context.Background(), "tag:github-runner", "tenant-a")
	require.NoError(t, err)
	require.Len(t, metas, 1, "tag must survive DNA refresh")
	assert.Equal(t, "s-refresh", metas[0].ID)
	assert.Equal(t, "after-refresh", metas[0].DNAAttributes["hostname"],
		"refreshed hostname must be visible after DNA update")
}

// TestServerFleetStewardProvider_NoDNAAttributeMutation verifies that merging
// controller-stored tags does not mutate the FlattenDNAFragments output map in
// place. A second call must return the same fragment-sourced attributes
// without any controller-tag bleed from the first call. (Issue #2544 AC3)
func TestServerFleetStewardProvider_NoDNAAttributeMutation(t *testing.T) {
	svc := service.NewControllerService(logging.NewNoopLogger())
	require.NoError(t, svc.RegisterSteward("s-mut", "tenant-a", "addr-1", "online"))
	require.True(t, svc.SetStewardDNA("s-mut", &common.DNA{
		Id: "s-mut",
		Fragments: []*common.Fragment{
			mustFrag(t, "host:os", map[string]interface{}{"os": "linux"}),
			mustFrag(t, "hostname", map[string]interface{}{"hostname": "web-01"}),
		},
	}))

	ts := newTestTagStore(t)
	svc.SetTagStore(ts)
	require.NoError(t, ts.Set(context.Background(), "s-mut", []string{"github-runner"}))

	provider := &serverFleetStewardProvider{svc: svc}

	// First call: tags must be merged into the returned attrs.
	stewards := provider.GetAllStewards()
	require.Len(t, stewards, 1)
	assert.Equal(t, "github-runner", stewards[0].DNAAttributes["tags"],
		"returned attrs must carry merged tags")
	assert.Equal(t, "linux", stewards[0].DNAAttributes["os"],
		"fragment-sourced os must be present alongside merged tags")

	// Second call: mergeControllerTags must not have mutated any shared state,
	// so the fragment-sourced attributes appear intact on every call.
	stewards2 := provider.GetAllStewards()
	require.Len(t, stewards2, 1)
	assert.Equal(t, "github-runner", stewards2[0].DNAAttributes["tags"],
		"tags must be present on repeated calls")
	assert.Equal(t, "linux", stewards2[0].DNAAttributes["os"],
		"fragment-sourced os must not be lost between calls")
}

// TestServerFleetStewardProvider_DNATagsUnion verifies that when a steward
// already reports a "tags" attribute in its DNA fragments, controller-stored
// tags are unioned (not replaced). DNA tags appear first; duplicates are dropped.
// (Issue #2544 implementation note)
func TestServerFleetStewardProvider_DNATagsUnion(t *testing.T) {
	svc := service.NewControllerService(logging.NewNoopLogger())
	require.NoError(t, svc.RegisterSteward("s-union", "tenant-a", "addr-1", "online"))
	require.True(t, svc.SetStewardDNA("s-union", &common.DNA{
		Id: "s-union",
		Fragments: []*common.Fragment{
			mustFrag(t, "host:os", map[string]interface{}{"os": "linux", "tags": "dna-tag,shared-tag"}),
		},
	}))

	ts := newTestTagStore(t)
	svc.SetTagStore(ts)
	// "shared-tag" is in both DNA and controller store — must appear exactly once.
	require.NoError(t, ts.Set(context.Background(), "s-union", []string{"ctrl-tag", "shared-tag"}))

	provider := &serverFleetStewardProvider{svc: svc}
	stewards := provider.GetAllStewards()
	require.Len(t, stewards, 1)

	raw := stewards[0].DNAAttributes["tags"]
	// Split and verify each expected tag is present, with no duplicates.
	parts := make(map[string]int)
	for _, tag := range splitTrimTags(raw) {
		parts[tag]++
	}
	assert.Equal(t, 1, parts["dna-tag"], "dna-tag must appear once")
	assert.Equal(t, 1, parts["ctrl-tag"], "ctrl-tag must appear once")
	assert.Equal(t, 1, parts["shared-tag"], "shared-tag must appear exactly once (no duplicate)")
}

// splitTrimTags splits a comma-separated tag string, trims whitespace, and drops empties.
func splitTrimTags(raw string) []string {
	if raw == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(raw, ",") {
		if t := strings.TrimSpace(part); t != "" {
			result = append(result, t)
		}
	}
	return result
}
