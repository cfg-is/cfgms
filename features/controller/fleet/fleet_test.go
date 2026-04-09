// SPDX-License-Identifier: Apache-2.0
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
