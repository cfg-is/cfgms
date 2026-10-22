// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package clusterregistry

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

func newDeclaredTestStore(t *testing.T) cfgconfig.ConfigStore {
	t.Helper()
	return newFlatFileConfigStore(t)
}

func declare(t *testing.T, cs cfgconfig.ConfigStore, tenant, cluster string, members ...string) {
	t.Helper()
	data, err := json.Marshal(ClusterMembersDocument{Members: members})
	require.NoError(t, err)
	require.NoError(t, cs.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: tenant, Namespace: ClusterMembersNamespace, Name: cluster},
		Data:   data,
		Format: cfgconfig.ConfigFormatJSON,
		Source: "test",
	}))
}

func tenantLookup(m map[string]string) StewardTenantLookup {
	return func(id string) (string, bool) { t, ok := m[id]; return t, ok }
}

func TestDeclaredMembership_DeclaredUndeclaredAndCrossTenant(t *testing.T) {
	cs := newDeclaredTestStore(t)
	declare(t, cs, "tenant-a", "hv-1", "steward-declared", "steward-foreign")
	declare(t, cs, "tenant-a", "hv-2", "steward-declared")

	// steward-claimer only carries a DNA claim; it is not declared anywhere.
	claim := []*commonpb.Fragment{{FragmentId: "cluster:hv-1"}}
	require.Equal(t, []string{"hv-1"}, ClustersFromFragments(claim))

	d := NewDeclaredMembership(cs, tenantLookup(map[string]string{
		"steward-declared": "tenant-a",
		"steward-claimer":  "tenant-a",
		"steward-foreign":  "tenant-b", // declared in tenant-a, lives in tenant-b
	}))

	assert.True(t, d.IsClusterMember("steward-declared", "hv-1"))
	assert.Equal(t, []string{"hv-1", "hv-2"}, d.MemberClusters("steward-declared"))

	assert.False(t, d.IsClusterMember("steward-claimer", "hv-1"))
	assert.Empty(t, d.MemberClusters("steward-claimer"))

	assert.False(t, d.IsClusterMember("steward-foreign", "hv-1"))
	assert.Empty(t, d.MemberClusters("steward-foreign"))

	assert.False(t, d.IsClusterMember("steward-unknown", "hv-1"))
	assert.Empty(t, d.MemberClusters("steward-unknown"))
	assert.False(t, d.IsClusterMember("steward-declared", "hv-missing"))
}

// failingConfigStore wraps a real store and fails reads with a non-not-found error.
type failingConfigStore struct{ cfgconfig.ConfigStore }

func (failingConfigStore) GetConfig(context.Context, *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return nil, errors.New("backend unavailable")
}

func (failingConfigStore) ListConfigs(context.Context, *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	return nil, errors.New("backend unavailable")
}

func TestDeclaredMembership_StoreFaultNeverGrantsMembership(t *testing.T) {
	cs := newDeclaredTestStore(t)
	declare(t, cs, "tenant-a", "hv-1", "steward-1")
	lookup := tenantLookup(map[string]string{"steward-1": "tenant-a"})

	// Sanity: the healthy store grants membership.
	require.True(t, NewDeclaredMembership(cs, lookup).IsClusterMember("steward-1", "hv-1"))

	d := NewDeclaredMembership(failingConfigStore{cs}, lookup)
	assert.False(t, d.IsClusterMember("steward-1", "hv-1"))
	assert.Empty(t, d.MemberClusters("steward-1"))
}

func TestDeclaredMembership_MalformedDocumentIsNotMembership(t *testing.T) {
	cs := newDeclaredTestStore(t)
	require.NoError(t, cs.StoreConfig(context.Background(), &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: "tenant-a", Namespace: ClusterMembersNamespace, Name: "hv-1"},
		Data:   []byte("{not json"),
		Format: cfgconfig.ConfigFormatJSON,
		Source: "test",
	}))
	d := NewDeclaredMembership(cs, tenantLookup(map[string]string{"s": "tenant-a"}))
	assert.False(t, d.IsClusterMember("s", "hv-1"))
	assert.Empty(t, d.MemberClusters("s"))
}
