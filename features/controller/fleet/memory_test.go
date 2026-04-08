// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// staticProvider is a test StewardProvider backed by a fixed slice.
type staticProvider struct {
	stewards []StewardData
}

func (p *staticProvider) GetAllStewards() []StewardData {
	return p.stewards
}

func testSteward(id, tenant, status string, attrs map[string]string) StewardData {
	return StewardData{
		ID:            id,
		TenantID:      tenant,
		Status:        status,
		LastHeartbeat: time.Now(),
		DNAAttributes: attrs,
	}
}

func newQuery(stewards ...StewardData) *MemoryQuery {
	return NewMemoryQuery(&staticProvider{stewards: stewards})
}

func TestMemoryQuery_EmptyFilter_ReturnsAll(t *testing.T) {
	q := newQuery(
		testSteward("s1", "tenant-a", "online", map[string]string{"os": "linux", "hostname": "host1", "arch": "amd64"}),
		testSteward("s2", "tenant-b", "offline", map[string]string{"os": "windows", "hostname": "host2", "arch": "amd64"}),
	)

	results, err := q.Search(context.Background(), Filter{})
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestMemoryQuery_FilterByTenantID(t *testing.T) {
	q := newQuery(
		testSteward("s1", "tenant-a", "online", map[string]string{"hostname": "host1"}),
		testSteward("s2", "tenant-b", "online", map[string]string{"hostname": "host2"}),
		testSteward("s3", "tenant-a", "online", map[string]string{"hostname": "host3"}),
	)

	results, err := q.Search(context.Background(), Filter{TenantID: "tenant-a"})
	require.NoError(t, err)
	assert.Len(t, results, 2)
	for _, r := range results {
		assert.Equal(t, "tenant-a", r.TenantID)
	}
}

func TestMemoryQuery_FilterByOS(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"os": "linux"}),
		testSteward("s2", "t", "online", map[string]string{"os": "windows"}),
		testSteward("s3", "t", "online", map[string]string{"os": "linux"}),
	)

	results, err := q.Search(context.Background(), Filter{OS: "linux"})
	require.NoError(t, err)
	assert.Len(t, results, 2)
	for _, r := range results {
		assert.Equal(t, "linux", r.OS)
	}
}

func TestMemoryQuery_FilterByPlatform(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"platform": "ubuntu"}),
		testSteward("s2", "t", "online", map[string]string{"platform": "rhel"}),
	)

	results, err := q.Search(context.Background(), Filter{Platform: "ubuntu"})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "s1", results[0].ID)
}

func TestMemoryQuery_FilterByArchitecture(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"arch": "amd64"}),
		testSteward("s2", "t", "online", map[string]string{"arch": "arm64"}),
		testSteward("s3", "t", "online", map[string]string{"arch": "amd64"}),
	)

	results, err := q.Search(context.Background(), Filter{Architecture: "arm64"})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "s2", results[0].ID)
}

func TestMemoryQuery_FilterByStatus(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", nil),
		testSteward("s2", "t", "offline", nil),
		testSteward("s3", "t", "online", nil),
	)

	results, err := q.Search(context.Background(), Filter{Status: "online"})
	require.NoError(t, err)
	assert.Len(t, results, 2)
	for _, r := range results {
		assert.Equal(t, "online", r.Status)
	}
}

func TestMemoryQuery_FilterByStatus_Any(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", nil),
		testSteward("s2", "t", "offline", nil),
	)

	results, err := q.Search(context.Background(), Filter{Status: "any"})
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestMemoryQuery_FilterByHostname_SubstringMatch(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"hostname": "web-server-01"}),
		testSteward("s2", "t", "online", map[string]string{"hostname": "db-server-01"}),
		testSteward("s3", "t", "online", map[string]string{"hostname": "web-server-02"}),
	)

	results, err := q.Search(context.Background(), Filter{Hostname: "web-server"})
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestMemoryQuery_FilterByTags_SingleTag(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"tags": "production,web"}),
		testSteward("s2", "t", "online", map[string]string{"tags": "staging"}),
		testSteward("s3", "t", "online", map[string]string{"tags": "production,db"}),
	)

	results, err := q.Search(context.Background(), Filter{Tags: []string{"production"}})
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestMemoryQuery_FilterByTags_MultipleTagsAND(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"tags": "production,web"}),
		testSteward("s2", "t", "online", map[string]string{"tags": "production"}),
		testSteward("s3", "t", "online", map[string]string{"tags": "web"}),
	)

	// Both production AND web must be present
	results, err := q.Search(context.Background(), Filter{Tags: []string{"production", "web"}})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "s1", results[0].ID)
}

func TestMemoryQuery_FilterByTags_NoTagAttribute(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"os": "linux"}), // no tags key
	)

	results, err := q.Search(context.Background(), Filter{Tags: []string{"production"}})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestMemoryQuery_FilterByDNAAttributes_ExactMatch(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"env": "prod", "region": "us-east-1"}),
		testSteward("s2", "t", "online", map[string]string{"env": "staging", "region": "us-east-1"}),
		testSteward("s3", "t", "online", map[string]string{"env": "prod", "region": "eu-west-1"}),
	)

	results, err := q.Search(context.Background(), Filter{
		DNAAttributes: map[string]string{"env": "prod", "region": "us-east-1"},
	})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "s1", results[0].ID)
}

func TestMemoryQuery_CombinedFilters_AND(t *testing.T) {
	q := newQuery(
		testSteward("s1", "tenant-a", "online", map[string]string{"os": "linux", "arch": "amd64", "hostname": "web-01"}),
		testSteward("s2", "tenant-a", "online", map[string]string{"os": "windows", "arch": "amd64", "hostname": "win-01"}),
		testSteward("s3", "tenant-b", "online", map[string]string{"os": "linux", "arch": "amd64", "hostname": "web-02"}),
		testSteward("s4", "tenant-a", "offline", map[string]string{"os": "linux", "arch": "amd64", "hostname": "web-03"}),
	)

	// tenant-a + linux + online
	results, err := q.Search(context.Background(), Filter{
		TenantID: "tenant-a",
		OS:       "linux",
		Status:   "online",
	})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "s1", results[0].ID)
}

func TestMemoryQuery_NoMatch_ReturnsEmptySlice(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"os": "linux"}),
	)

	results, err := q.Search(context.Background(), Filter{OS: "windows"})
	require.NoError(t, err)
	assert.NotNil(t, results)
	assert.Empty(t, results)
}

func TestMemoryQuery_EmptyProvider_ReturnsEmptySlice(t *testing.T) {
	q := newQuery() // no stewards

	results, err := q.Search(context.Background(), Filter{})
	require.NoError(t, err)
	assert.NotNil(t, results)
	assert.Empty(t, results)
}

func TestMemoryQuery_Count(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"os": "linux"}),
		testSteward("s2", "t", "online", map[string]string{"os": "windows"}),
		testSteward("s3", "t", "offline", map[string]string{"os": "linux"}),
	)

	count, err := q.Count(context.Background(), Filter{OS: "linux"})
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestMemoryQuery_Count_EmptyFilter(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", nil),
		testSteward("s2", "t", "online", nil),
	)

	count, err := q.Count(context.Background(), Filter{})
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestMemoryQuery_StewardResult_Fields(t *testing.T) {
	now := time.Now()
	provider := &staticProvider{
		stewards: []StewardData{
			{
				ID:            "abc-123",
				TenantID:      "tenant-x",
				Status:        "online",
				LastHeartbeat: now,
				DNAAttributes: map[string]string{
					"hostname": "my-host",
					"os":       "linux",
					"arch":     "arm64",
					"custom":   "value",
				},
			},
		},
	}
	q := NewMemoryQuery(provider)

	results, err := q.Search(context.Background(), Filter{})
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "abc-123", r.ID)
	assert.Equal(t, "tenant-x", r.TenantID)
	assert.Equal(t, "my-host", r.Hostname)
	assert.Equal(t, "linux", r.OS)
	assert.Equal(t, "arm64", r.Architecture)
	assert.Equal(t, "online", r.Status)
	assert.WithinDuration(t, now, r.LastHeartbeat, time.Second)
	assert.Equal(t, "value", r.DNAAttributes["custom"])
}

func TestMemoryQuery_TenantScoping_IsolatesData(t *testing.T) {
	q := newQuery(
		testSteward("s1", "msp-a/client-1", "online", map[string]string{"hostname": "host1"}),
		testSteward("s2", "msp-a/client-2", "online", map[string]string{"hostname": "host2"}),
		testSteward("s3", "msp-b/client-1", "online", map[string]string{"hostname": "host3"}),
	)

	results, err := q.Search(context.Background(), Filter{TenantID: "msp-a/client-1"})
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "s1", results[0].ID)
}

func TestMemoryQuery_Tags_WhitespaceStripped(t *testing.T) {
	q := newQuery(
		testSteward("s1", "t", "online", map[string]string{"tags": "production, web, db"}),
	)

	results, err := q.Search(context.Background(), Filter{Tags: []string{"web"}})
	require.NoError(t, err)
	assert.Len(t, results, 1)
}
