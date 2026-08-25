// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/controller/tagstore"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/logging"
)

// mustAPIFrag builds a DNA fragment from a field map for api-package tests.
func mustAPIFrag(t *testing.T, kind string, fields map[string]interface{}) *commonpb.Fragment {
	t.Helper()
	frag, err := sdna.NewFragment(kind, "test", sdna.MapState(fields))
	require.NoError(t, err)
	return frag
}

// TestControllerServiceAdapter_GetAllStewards verifies that the adapter builds
// DNAAttributes from DNA.Fragments via FlattenDNAFragments — the only carrier of
// host facts since the flat DNA.Attributes field was removed (Issue #3331).
func TestControllerServiceAdapter_GetAllStewards(t *testing.T) {
	svc := service.NewControllerService(logging.NewNoopLogger())

	require.NoError(t, svc.RegisterSteward("s1", "tenant-a", "addr-1", "online"))
	require.True(t, svc.SetStewardDNA("s1", &commonpb.DNA{
		Id: "s1",
		Fragments: []*commonpb.Fragment{
			mustAPIFrag(t, "host:os", map[string]interface{}{"os": "linux", "arch": "amd64"}),
			mustAPIFrag(t, "hostname", map[string]interface{}{"hostname": "web-01"}),
		},
	}))

	// Nil DNA steward — must not panic and must yield nil attributes.
	require.NoError(t, svc.RegisterSteward("s-nil", "tenant-a", "addr-2", "offline"))
	require.True(t, svc.SetStewardDNA("s-nil", nil))

	adapter := &controllerServiceAdapter{svc: svc}
	stewards := adapter.GetAllStewards()

	require.Len(t, stewards, 2)

	byID := make(map[string]fleet.StewardData, len(stewards))
	for _, s := range stewards {
		byID[s.ID] = s
	}

	s1 := byID["s1"]
	assert.Equal(t, "tenant-a", s1.TenantID)
	assert.Equal(t, "online", s1.Status)
	assert.Equal(t, "linux", s1.DNAAttributes["os"])
	assert.Equal(t, "amd64", s1.DNAAttributes["arch"])
	assert.Equal(t, "web-01", s1.DNAAttributes["hostname"])
	assert.NotNil(t, s1.DNAFragments, "DNAFragments must be forwarded")

	sNil := byID["s-nil"]
	assert.Nil(t, sNil.DNAAttributes, "nil DNA must yield nil attributes, not a panic")
	assert.Nil(t, sNil.DNAFragments)
}

// TestControllerServiceAdapter_GetAllStewards_NoFragmentsYieldsNoAttributes verifies
// that DNAAttributes is sourced from Fragments alone (Issue #3331 removed the flat
// DNA.Attributes field). A steward whose DNA carries no fragments must yield empty
// DNAAttributes rather than a fabricated map.
func TestControllerServiceAdapter_GetAllStewards_NoFragmentsYieldsNoAttributes(t *testing.T) {
	svc := service.NewControllerService(logging.NewNoopLogger())

	require.NoError(t, svc.RegisterSteward("s1", "tenant-a", "addr-1", "online"))
	// DNA with an ID and nothing else — no fragments to project from.
	require.True(t, svc.SetStewardDNA("s1", &commonpb.DNA{Id: "s1"}))

	adapter := &controllerServiceAdapter{svc: svc}
	stewards := adapter.GetAllStewards()

	require.Len(t, stewards, 1)
	assert.Empty(t, stewards[0].DNAAttributes,
		"DNAAttributes must come from Fragments only; a fragment-less DNA must project nothing")
}

// newAPITestTagStore opens a temporary SQLite-backed tag store for api-package tests.
func newAPITestTagStore(t *testing.T) *tagstore.Store {
	t.Helper()
	store, err := tagstore.NewFromDSN(
		"file:"+filepath.Join(t.TempDir(), "tags.db"), logging.NewNoopLogger())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(context.Background()))
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestControllerServiceAdapter_TagsMerged is REQUIRED TEST part 1 (Issue #3495):
// proves that controllerServiceAdapter.GetAllStewards() now merges controller-stored
// tags into DNAAttributes. Pre-story code built DNAAttributes from DNA fragments only
// and never consulted the tag store, so a tagged steward carried no "tags" attribute
// here — unlike serverFleetStewardProvider, which already merged them. The two adapters
// must compose identical fields for any steward both can see.
func TestControllerServiceAdapter_TagsMerged(t *testing.T) {
	ctx := context.Background()
	svc := service.NewControllerService(logging.NewNoopLogger())

	require.NoError(t, svc.RegisterSteward("s-tagged", "tenant-a", "addr-1", "online"))
	require.True(t, svc.SetStewardDNA("s-tagged", &commonpb.DNA{
		Id: "s-tagged",
		Fragments: []*commonpb.Fragment{
			mustAPIFrag(t, "host:os", map[string]interface{}{"os": "linux"}),
		},
	}))
	// Second steward stays untagged to prove the merge is per-steward, not global.
	require.NoError(t, svc.RegisterSteward("s-untagged", "tenant-a", "addr-2", "online"))
	require.True(t, svc.SetStewardDNA("s-untagged", &commonpb.DNA{
		Id: "s-untagged",
		Fragments: []*commonpb.Fragment{
			mustAPIFrag(t, "host:os", map[string]interface{}{"os": "linux"}),
		},
	}))

	ts := newAPITestTagStore(t)
	svc.SetTagStore(ts)
	require.NoError(t, ts.Set(ctx, "s-tagged", []string{"my-tag"}))

	stewards := (&controllerServiceAdapter{svc: svc}).GetAllStewards()
	require.Len(t, stewards, 2)

	byID := make(map[string]fleet.StewardData, len(stewards))
	for _, s := range stewards {
		byID[s.ID] = s
	}

	assert.Equal(t, "my-tag", byID["s-tagged"].DNAAttributes["tags"],
		"controller-stored tags must be merged into DNAAttributes by controllerServiceAdapter")
	assert.Equal(t, "linux", byID["s-tagged"].DNAAttributes["os"],
		"fragment-sourced attributes must survive the tag merge")

	_, hasTags := byID["s-untagged"].DNAAttributes["tags"]
	assert.False(t, hasTags, "an untagged steward must not gain a tags attribute")
}

// TestClusterServiceAdapter_GetAllStewards verifies that clusterServiceAdapter reads
// from the cluster-wide inventory: it returns nothing until StartClusterRefresh has
// populated the cache, then returns every steward with identity fields intact
// (Issue #3495).
func TestClusterServiceAdapter_GetAllStewards(t *testing.T) {
	svc := service.NewControllerService(logging.NewNoopLogger())

	require.NoError(t, svc.RegisterSteward("c1", "tenant-a", "addr-1", "online"))
	require.True(t, svc.SetStewardDNA("c1", &commonpb.DNA{
		Id: "c1",
		Fragments: []*commonpb.Fragment{
			mustAPIFrag(t, "host:os", map[string]interface{}{"os": "linux"}),
			mustAPIFrag(t, "hostname", map[string]interface{}{"hostname": "cluster-host-1"}),
		},
	}))
	require.NoError(t, svc.RegisterSteward("c2", "tenant-b", "addr-2", "offline"))

	// Before the first refresh the cluster cache is empty by contract.
	require.Nil(t, svc.GetAllStewardsCluster(context.Background()),
		"cluster inventory must be nil before the first refresh")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// A long interval keeps the ticker out of the way: StartClusterRefresh performs the
	// first refresh immediately, which is the one this test waits on.
	svc.StartClusterRefresh(ctx, 24*time.Hour)

	adapter := &clusterServiceAdapter{svc: svc}
	var stewards []fleet.StewardData
	require.Eventually(t, func() bool {
		stewards = adapter.GetAllStewards()
		return len(stewards) == 2
	}, 5*time.Second, 10*time.Millisecond,
		"cluster adapter must return all stewards after the first refresh")

	byID := make(map[string]fleet.StewardData, len(stewards))
	for _, s := range stewards {
		byID[s.ID] = s
	}
	assert.Equal(t, "tenant-a", byID["c1"].TenantID)
	assert.Equal(t, "online", byID["c1"].Status)
	assert.Equal(t, "linux", byID["c1"].DNAAttributes["os"])
	assert.Len(t, byID["c1"].DNAFragments, 2,
		"DNAFragments must be forwarded by the cluster adapter")
	assert.Equal(t, "tenant-b", byID["c2"].TenantID)
	assert.Equal(t, "offline", byID["c2"].Status)
}
