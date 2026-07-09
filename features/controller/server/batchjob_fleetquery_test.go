// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	common "github.com/cfgis/cfgms/api/proto/common"
	controllerFleet "github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newFleetQueryTestService builds a real ControllerService with three registered
// stewards spanning two tenants and distinct DNA attributes, exercising the same
// registry path the production server uses.
func newFleetQueryTestService(t *testing.T) *service.ControllerService {
	t.Helper()
	svc := service.NewControllerService(logging.NewNoopLogger())

	require.NoError(t, svc.RegisterSteward("s-linux", "tenant-a", "addr-1", "online"))
	require.True(t, svc.SetStewardDNA("s-linux", &common.DNA{
		Id:         "s-linux",
		Attributes: map[string]string{"os": "linux", "arch": "amd64", "hostname": "web-01"},
	}))

	require.NoError(t, svc.RegisterSteward("s-windows", "tenant-a", "addr-2", "online"))
	require.True(t, svc.SetStewardDNA("s-windows", &common.DNA{
		Id:         "s-windows",
		Attributes: map[string]string{"os": "windows", "arch": "amd64", "hostname": "dc-01"},
	}))

	// Different tenant, also linux — used to prove tenant scoping excludes it.
	require.NoError(t, svc.RegisterSteward("s-other", "tenant-b", "addr-3", "online"))
	require.True(t, svc.SetStewardDNA("s-other", &common.DNA{
		Id:         "s-other",
		Attributes: map[string]string{"os": "linux", "arch": "arm64", "hostname": "edge-01"},
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
