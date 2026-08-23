// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/service"
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
