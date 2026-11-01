// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleet

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time assertion: MemoryQuery implements FleetQuery.
var _ FleetQuery = (*MemoryQuery)(nil)

// TestFleetQuery_InterfaceContract verifies that MemoryQuery satisfies the FleetQuery contract.
func TestFleetQuery_InterfaceContract(t *testing.T) {
	provider := &staticProvider{
		stewards: []StewardData{
			testSteward("s1", "tenant-a", "online", map[string]string{"os": "linux", "hostname": "host1", "arch": "amd64"}),
			testSteward("s2", "tenant-a", "offline", map[string]string{"os": "windows", "hostname": "host2", "arch": "amd64"}),
			testSteward("s3", "tenant-b", "online", map[string]string{"os": "linux", "hostname": "host3", "arch": "arm64"}),
		},
	}

	var q FleetQuery = NewMemoryQuery(provider)

	t.Run("Search returns results", func(t *testing.T) {
		results, err := q.Search(context.Background(), Filter{OS: "linux"})
		require.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("Count returns count", func(t *testing.T) {
		count, err := q.Count(context.Background(), Filter{Status: "online"})
		require.NoError(t, err)
		assert.Equal(t, 2, count)
	})

	t.Run("Empty filter returns all", func(t *testing.T) {
		results, err := q.Search(context.Background(), Filter{})
		require.NoError(t, err)
		assert.Len(t, results, 3)
	})

	t.Run("Combined filter is AND", func(t *testing.T) {
		results, err := q.Search(context.Background(), Filter{
			TenantID: "tenant-a",
			OS:       "linux",
			Status:   "online",
		})
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "s1", results[0].ID)
	})
}

// TestFleetQuery_DeviceIDFilter verifies that Filter.DeviceID matches only the exact device.
func TestFleetQuery_DeviceIDFilter(t *testing.T) {
	q := newQuery(
		testSteward("device-001", "t", "online", nil),
		testSteward("device-002", "t", "online", nil),
	)

	results, err := q.Search(context.Background(), Filter{DeviceID: "device-001"})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "device-001", results[0].ID)
}

// TestFleetQuery_GlobNameFilter is a required test: Search returns only stewards whose
// hostnames match the web-* glob when Filter.Name is "web-*".
func TestFleetQuery_GlobNameFilter(t *testing.T) {
	q := newQuery(
		testSteward("web-01", "t", "online", map[string]string{"hostname": "web-01"}),
		testSteward("api-01", "t", "online", map[string]string{"hostname": "api-01"}),
	)

	results, err := q.Search(context.Background(), Filter{Name: "web-*"})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "web-01", results[0].ID)
}

// TestFleetQuery_TagFilter is a required test: tag filter matches stewards that have
// the tag anywhere in their comma-separated tags DNA attribute.
func TestFleetQuery_TagFilter(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"tags": "production,web,db"}),
		testSteward("s2", "t", "online", map[string]string{"tags": "staging,web"}),
		testSteward("s3", "t", "online", map[string]string{"tags": "production"}),
	)

	results, err := q.Search(context.Background(), Filter{Tags: []string{"production"}})
	require.NoError(t, err)
	require.Len(t, results, 2)
	ids := []string{results[0].ID, results[1].ID}
	assert.Contains(t, ids, "s1")
	assert.Contains(t, ids, "s3")
}
