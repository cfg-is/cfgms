// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package engine

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/cache"
	"github.com/cfgis/cfgms/pkg/dna/drift"
)

const testRoot = "root"

// seededProvider is an in-memory DataProvider holding per-tenant rows. It honours the
// tenant and device selectors the way the live provider does and records every call.
type seededProvider struct {
	mu        sync.Mutex
	dna       map[string][]storage.DNARecord // tenant -> rows
	events    map[string][]drift.DriftEvent
	dnaErr    error
	driftErr  error
	dnaQ      []interfaces.DataQuery
	driftQ    []interfaces.DataQuery
	trendQ    []interfaces.DataQuery
	statsReqs [][]string
}

func newSeededProvider() *seededProvider {
	return &seededProvider{dna: map[string][]storage.DNARecord{}, events: map[string][]drift.DriftEvent{}}
}

func (p *seededProvider) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.dnaQ) + len(p.driftQ) + len(p.trendQ) + len(p.statsReqs)
}

func (p *seededProvider) seedDNA(tenant string, n int, devicePrefix string) {
	for i := 0; i < n; i++ {
		p.dna[tenant] = append(p.dna[tenant], storage.DNARecord{DeviceID: fmt.Sprintf("%s%d", devicePrefix, i), TenantID: tenant})
	}
}

func (p *seededProvider) GetDNAData(_ context.Context, q interfaces.DataQuery) ([]storage.DNARecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dnaQ = append(p.dnaQ, q)
	if p.dnaErr != nil {
		return nil, p.dnaErr
	}
	var out []storage.DNARecord
	for _, t := range q.TenantIDs {
		for _, r := range p.dna[t] {
			if len(q.DeviceIDs) == 0 || containsString(q.DeviceIDs, r.DeviceID) {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func (p *seededProvider) GetDriftEvents(_ context.Context, q interfaces.DataQuery) ([]drift.DriftEvent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.driftQ = append(p.driftQ, q)
	if p.driftErr != nil {
		return nil, p.driftErr
	}
	var out []drift.DriftEvent
	for _, t := range q.TenantIDs {
		out = append(out, p.events[t]...)
	}
	return out, nil
}

func (p *seededProvider) GetDeviceStats(_ context.Context, ids []string, _ interfaces.TimeRange) (map[string]interfaces.DeviceStats, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.statsReqs = append(p.statsReqs, append([]string(nil), ids...))
	out := map[string]interfaces.DeviceStats{}
	for _, id := range ids {
		out[id] = interfaces.DeviceStats{DeviceID: id, ComplianceScore: 0.9, RiskLevel: interfaces.RiskLevelLow}
	}
	return out, nil
}

func (p *seededProvider) GetTrendData(_ context.Context, _ string, q interfaces.DataQuery) ([]interfaces.TrendPoint, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.trendQ = append(p.trendQ, q)
	return []interfaces.TrendPoint{{Timestamp: time.Unix(1, 0), Value: 1}}, nil
}

// deviceMap is a real DeviceTenantResolver over a device-to-tenant map.
type deviceMap map[string]string

func (m deviceMap) TenantForDevice(id string) (string, bool) {
	t, ok := m[id]
	return t, ok
}

// treeAncestry is a real ancestry function over a child-to-parent map.
func treeAncestry(parents map[string]string) TenantAncestryFunc {
	return func(_ context.Context, ancestor, descendant string) (bool, error) {
		for cur := parents[descendant]; cur != ""; cur = parents[cur] {
			if cur == ancestor {
				return true, nil
			}
		}
		return false, nil
	}
}

var testTree = map[string]string{"msp-a": testRoot, "msp-b": testRoot, "a": "msp-a", "b": "msp-b", "a-child": "a"}

var testDevices = deviceMap{"a-dev-1": "a", "a-dev-2": "a", "b-dev-1": "b", "b-dev-2": "b", "child-dev": "a-child"}

func newTestBuilder(t *testing.T, p interfaces.DataProvider, cfg interfaces.CustomReportConfig) *CustomReportBuilder {
	t.Helper()
	pc := cache.NewCache(cache.CacheConfig{Name: "test-pages", MaxRuntimeItems: 1000, DefaultTTL: time.Hour})
	t.Cleanup(pc.Close)
	b, err := NewCustomReportBuilder(p, cfg, pc, testDevices, treeAncestry(testTree), testRoot)
	require.NoError(t, err)
	return b
}

func req(tenant string, sources ...string) interfaces.CustomReportRequest {
	return interfaces.CustomReportRequest{
		Name: "r", TenantID: tenant, Format: interfaces.FormatJSON,
		Query: interfaces.CustomQuery{DataSources: sources, Filters: map[string]interface{}{}},
	}
}

func TestCustomBuilder_BuildQuery_WithFiltersAndAggregations(t *testing.T) {
	b := newTestBuilder(t, newSeededProvider(), interfaces.CustomReportConfig{})
	cfg := interfaces.DefaultCustomReportConfig()

	q := interfaces.CustomQuery{
		DataSources:  []string{"dna", "drift"},
		Filters:      map[string]interface{}{"status": "active", "n": 3},
		Aggregations: []interfaces.QueryAggregation{{Field: "x", Operation: "count"}},
	}
	pq, err := b.BuildQuery(q)
	require.NoError(t, err)
	assert.Equal(t, "medium", pq.Complexity)
	assert.Equal(t, 2*cfg.DefaultTimeout, pq.Timeout)
	assert.Positive(t, pq.EstimatedRows)

	pq2, err := b.BuildQuery(q)
	require.NoError(t, err)
	assert.Equal(t, pq.CacheKey, pq2.CacheKey, "cache key must be deterministic")

	low, err := b.BuildQuery(interfaces.CustomQuery{DataSources: []string{"dna"}})
	require.NoError(t, err)
	assert.Equal(t, "low", low.Complexity)

	high := interfaces.CustomQuery{
		DataSources:  []string{"dna", "drift", "device_stats", "trends"},
		Filters:      map[string]interface{}{"a": "1", "b": "2"},
		Aggregations: []interfaces.QueryAggregation{{Field: "x", Operation: "sum"}},
	}
	hp, err := b.BuildQuery(high)
	require.NoError(t, err)
	assert.Equal(t, "high", hp.Complexity)
	assert.LessOrEqual(t, hp.Timeout, cfg.MaxTimeout)

	t.Run("limits", func(t *testing.T) {
		_, err := b.BuildQuery(interfaces.CustomQuery{DataSources: []string{"dna", "drift", "dna", "drift", "dna", "drift"}})
		assert.ErrorIs(t, err, interfaces.ErrInvalidQuery)

		filters := map[string]interface{}{}
		for i := 0; i <= cfg.MaxFilters; i++ {
			filters[fmt.Sprint("f", i)] = "v"
		}
		_, err = b.BuildQuery(interfaces.CustomQuery{DataSources: []string{"dna"}, Filters: filters})
		assert.ErrorIs(t, err, interfaces.ErrInvalidQuery)

		aggs := make([]interfaces.QueryAggregation, cfg.MaxAggregations+1)
		for i := range aggs {
			aggs[i] = interfaces.QueryAggregation{Field: "f", Operation: "sum"}
		}
		_, err = b.BuildQuery(interfaces.CustomQuery{DataSources: []string{"dna"}, Aggregations: aggs})
		assert.ErrorIs(t, err, interfaces.ErrInvalidQuery)
	})

	t.Run("unsupported data source", func(t *testing.T) {
		_, err := b.BuildQuery(interfaces.CustomQuery{DataSources: []string{"audit"}})
		assert.ErrorIs(t, err, interfaces.ErrDataSourceNotSupported)
	})

	t.Run("non-scalar filter", func(t *testing.T) {
		_, err := b.BuildQuery(interfaces.CustomQuery{DataSources: []string{"dna"}, Filters: map[string]interface{}{"x": []string{"a"}}})
		assert.ErrorIs(t, err, interfaces.ErrInvalidQuery)
	})

	t.Run("tenant changes cache key", func(t *testing.T) {
		ka, err := b.BuildQueryForTenant("a", q, nil)
		require.NoError(t, err)
		kb, err := b.BuildQueryForTenant("b", q, nil)
		require.NoError(t, err)
		assert.NotEqual(t, ka.CacheKey, kb.CacheKey)
		_, err = b.BuildQueryForTenant("", q, nil)
		assert.Error(t, err)
	})
}

func TestCustomBuilder_ValidateParameters(t *testing.T) {
	b := newTestBuilder(t, newSeededProvider(), interfaces.CustomReportConfig{})
	lo, hi := 1.0, 10.0
	minLen := 2
	tmpl := &interfaces.CustomReportTemplate{Parameters: []interfaces.CustomParameter{
		{Name: "count", Type: "number", Required: true, MinValue: &lo, MaxValue: &hi},
		{Name: "label", Type: "string", Pattern: "^[a-z]+$", MinLength: &minLen},
		{Name: "level", Type: "string", Options: []string{"low", "high"}},
		{Name: "on", Type: "boolean"},
		{Name: "since", Type: "date"},
		{Name: "tags", Type: "array"},
	}}

	t.Run("ValidateParameters_RequiredMissing", func(t *testing.T) {
		err := b.ValidateParameters(tmpl, map[string]interface{}{})
		require.ErrorIs(t, err, interfaces.ErrParameterValidationFailed)
		assert.Contains(t, err.Error(), "count")
	})
	t.Run("ValidateParameters_TypeMismatch", func(t *testing.T) {
		for name, params := range map[string]map[string]interface{}{
			"count": {"count": "five"},
			"label": {"count": 5, "label": 7},
			"on":    {"count": 5, "on": "yes"},
			"since": {"count": 5, "since": "not-a-date"},
			"tags":  {"count": 5, "tags": "x"},
		} {
			err := b.ValidateParameters(tmpl, params)
			require.ErrorIs(t, err, interfaces.ErrParameterValidationFailed, name)
			assert.Contains(t, err.Error(), name)
		}
	})
	t.Run("ValidateParameters_OutOfRange", func(t *testing.T) {
		assert.ErrorIs(t, b.ValidateParameters(tmpl, map[string]interface{}{"count": 0}), interfaces.ErrParameterValidationFailed)
		assert.ErrorIs(t, b.ValidateParameters(tmpl, map[string]interface{}{"count": 11.5}), interfaces.ErrParameterValidationFailed)
		assert.ErrorIs(t, b.ValidateParameters(tmpl, map[string]interface{}{"count": 5, "label": "A1"}), interfaces.ErrParameterValidationFailed)
		assert.ErrorIs(t, b.ValidateParameters(tmpl, map[string]interface{}{"count": 5, "label": "a"}), interfaces.ErrParameterValidationFailed)
		assert.ErrorIs(t, b.ValidateParameters(tmpl, map[string]interface{}{"count": 5, "level": "mid"}), interfaces.ErrParameterValidationFailed)
	})
	t.Run("ValidateParameters_ValidRange", func(t *testing.T) {
		assert.NoError(t, b.ValidateParameters(tmpl, map[string]interface{}{
			"count": 5, "label": "abc", "level": "low", "on": true, "since": "2026-01-02", "tags": []string{"x"},
		}))
		assert.NoError(t, b.ValidateParameters(tmpl, map[string]interface{}{"count": 1.0}))
		assert.NoError(t, b.ValidateParameters(tmpl, map[string]interface{}{"count": 10}))
	})
	t.Run("nil template", func(t *testing.T) {
		assert.ErrorIs(t, b.ValidateParameters(nil, nil), interfaces.ErrParameterValidationFailed)
	})
}

func TestCustomBuilder_GenerateReport_LargeDataset_UsePagination(t *testing.T) {
	p := newSeededProvider()
	p.seedDNA("a", 25, "a-d")
	cfg := interfaces.DefaultCustomReportConfig()
	cfg.StreamThreshold = 20
	cfg.DefaultPageSize = 10
	b := newTestBuilder(t, p, cfg)

	rep, err := b.GenerateReport(context.Background(), req("a", "dna"))
	require.NoError(t, err)
	assert.True(t, rep.IsStreamed)
	assert.Len(t, rep.StreamToken, 64)
	assert.Equal(t, 3, rep.TotalPages)
	assert.Nil(t, rep.Data)
	assert.Equal(t, 25, rep.DataPoints)
	assert.Equal(t, 25, rep.Summary.DevicesAnalyzed)

	small := newSeededProvider()
	small.seedDNA("a", 3, "a-d")
	rep, err = newTestBuilder(t, small, cfg).CreateCustomReport(context.Background(), req("a", "dna"))
	require.NoError(t, err)
	assert.False(t, rep.IsStreamed)
	data, ok := rep.Data.(*interfaces.ReportData)
	require.True(t, ok)
	assert.Len(t, data.DNARecords, 3)
}

func TestCustomBuilder_GetReportData_WithPagination(t *testing.T) {
	p := newSeededProvider()
	p.seedDNA("a", 25, "a-d")
	cfg := interfaces.DefaultCustomReportConfig()
	cfg.StreamThreshold = 20
	cfg.DefaultPageSize = 10
	b := newTestBuilder(t, p, cfg)
	rep, err := b.GenerateReport(context.Background(), req("a", "dna"))
	require.NoError(t, err)

	for page, wantMore := range map[int]bool{1: true, 2: true, 3: false} {
		body, more, err := b.GetReportData(context.Background(), interfaces.PaginationRequest{TenantID: "a", StreamToken: rep.StreamToken, Page: page})
		require.NoError(t, err)
		assert.Equal(t, wantMore, more, "page %d", page)
		assert.NotEmpty(t, body)
	}
	before := p.calls()
	_, _, err = b.GetReportData(context.Background(), interfaces.PaginationRequest{TenantID: "a", StreamToken: rep.StreamToken, Page: 1})
	require.NoError(t, err)
	assert.Equal(t, before, p.calls(), "a repeated page is served from the page cache")

	_, _, err = b.GetReportData(context.Background(), interfaces.PaginationRequest{TenantID: "a", StreamToken: rep.StreamToken, Page: 0})
	assert.ErrorIs(t, err, interfaces.ErrInvalidQuery)

	// Caller-supplied pages whose row offsets would overflow int are refused, not sliced.
	for _, page := range []int{math.MaxInt, math.MaxInt/10 + 2, (math.MaxInt-10)/10 + 2} {
		_, _, err = b.GetReportData(context.Background(), interfaces.PaginationRequest{TenantID: "a", StreamToken: rep.StreamToken, Page: page})
		assert.ErrorIs(t, err, interfaces.ErrInvalidQuery, "page %d", page)
	}
	// The largest non-overflowing page is past the data: empty, no more pages, no panic.
	maxPage := (math.MaxInt-10)/10 + 1
	body, more, err := b.GetReportData(context.Background(), interfaces.PaginationRequest{TenantID: "a", StreamToken: rep.StreamToken, Page: maxPage})
	require.NoError(t, err)
	assert.False(t, more)
	assert.NotEmpty(t, body)

	for _, tok := range []string{"", "nope", string(make([]byte, 64)), fmt.Sprintf("%064d", 0)} {
		_, _, err = b.GetReportData(context.Background(), interfaces.PaginationRequest{TenantID: "a", StreamToken: tok, Page: 1})
		assert.ErrorIs(t, err, interfaces.ErrStreamTokenInvalid)
	}
}

func TestCustomBuilder_TenantScoping(t *testing.T) {
	ctx := context.Background()

	t.Run("empty and root tenant refused before any provider call", func(t *testing.T) {
		p := newSeededProvider()
		b := newTestBuilder(t, p, interfaces.CustomReportConfig{})
		_, err := b.GenerateReport(ctx, req("", "dna", "drift", "device_stats", "trends"))
		assert.Error(t, err)
		_, err = b.GenerateReport(ctx, req(testRoot, "dna"))
		assert.Error(t, err)
		_, _, err = b.GetReportData(ctx, interfaces.PaginationRequest{StreamToken: fmt.Sprintf("%064d", 1), Page: 1})
		assert.Error(t, err)
		assert.Zero(t, p.calls())
	})

	t.Run("every query carries the request tenant", func(t *testing.T) {
		p := newSeededProvider()
		p.seedDNA("a", 2, "a-dev-")
		p.seedDNA("b", 2, "b-dev-")
		b := newTestBuilder(t, p, interfaces.CustomReportConfig{})
		_, err := b.GenerateReport(ctx, req("a", "dna", "drift", "device_stats", "trends"))
		require.NoError(t, err)
		all := append(append(append([]interfaces.DataQuery{}, p.dnaQ...), p.driftQ...), p.trendQ...)
		require.NotEmpty(t, all)
		for _, q := range all {
			assert.Equal(t, []string{"a"}, q.TenantIDs)
		}
		// device_stats naming no devices: only IDs from the tenant's DNA rows.
		require.Len(t, p.statsReqs, 1)
		assert.ElementsMatch(t, []string{"a-dev-0", "a-dev-1"}, p.statsReqs[0])
	})

	t.Run("stream token is bound to its tenant", func(t *testing.T) {
		p := newSeededProvider()
		p.seedDNA("a", 25, "a-dev-")
		cfg := interfaces.DefaultCustomReportConfig()
		cfg.StreamThreshold = 5
		b := newTestBuilder(t, p, cfg)
		rep, err := b.GenerateReport(ctx, req("a", "dna"))
		require.NoError(t, err)
		require.True(t, rep.IsStreamed)
		_, _, err = b.GetReportData(ctx, interfaces.PaginationRequest{TenantID: "b", StreamToken: rep.StreamToken, Page: 1})
		assert.ErrorIs(t, err, interfaces.ErrStreamTokenInvalid)
		_, _, err = b.GetReportData(ctx, interfaces.PaginationRequest{TenantID: "a", StreamToken: rep.StreamToken, Page: 1})
		assert.NoError(t, err)
		_, _, err = b.GetReportData(ctx, interfaces.PaginationRequest{TenantID: "b", StreamToken: rep.StreamToken, Page: 1})
		assert.ErrorIs(t, err, interfaces.ErrStreamTokenInvalid, "a page cached for A is not served to B")
	})

	t.Run("page queries carry the tenant", func(t *testing.T) {
		p := newSeededProvider()
		p.seedDNA("a", 25, "a-dev-")
		cfg := interfaces.DefaultCustomReportConfig()
		cfg.StreamThreshold = 5
		b := newTestBuilder(t, p, cfg)
		rep, err := b.GenerateReport(ctx, req("a", "dna"))
		require.NoError(t, err)
		_, _, err = b.GetReportData(ctx, interfaces.PaginationRequest{TenantID: "a", StreamToken: rep.StreamToken, Page: 2})
		require.NoError(t, err)
		for _, q := range p.dnaQ {
			assert.Equal(t, []string{"a"}, q.TenantIDs)
		}
	})
}

func TestCustomBuilder_DeviceScope(t *testing.T) {
	ctx := context.Background()
	newReq := func(tenant string, filters, user map[string]interface{}) interfaces.CustomReportRequest {
		r := req(tenant, "dna", "device_stats")
		r.Query.Filters = filters
		r.UserParams = user
		return r
	}

	cases := map[string]interfaces.CustomReportRequest{
		"filter device_id":          newReq("b", map[string]interface{}{"device_id": "a-dev-1"}, nil),
		"user device_ids []string":  newReq("b", nil, map[string]interface{}{"device_ids": []string{"a-dev-1"}}),
		"user device_ids comma str": newReq("b", nil, map[string]interface{}{"device_ids": " b-dev-1 , a-dev-1 ,"}),
	}
	for name, r := range cases {
		t.Run("cross tenant "+name, func(t *testing.T) {
			p := newSeededProvider()
			p.seedDNA("a", 2, "a-dev-")
			b := newTestBuilder(t, p, interfaces.CustomReportConfig{})
			_, err := b.GenerateReport(ctx, r)
			require.ErrorIs(t, err, errCustomDeviceOutsideTenant)
			assert.Zero(t, p.calls())
			assert.NotContains(t, err.Error(), "a-dev-1")
		})
	}

	t.Run("unknown and foreign devices fail identically", func(t *testing.T) {
		b := newTestBuilder(t, newSeededProvider(), interfaces.CustomReportConfig{})
		_, e1 := b.GenerateReport(ctx, newReq("b", map[string]interface{}{"device_id": "nobody"}, nil))
		_, e2 := b.GenerateReport(ctx, newReq("b", map[string]interface{}{"device_id": "a-dev-1"}, nil))
		require.Error(t, e1)
		assert.Equal(t, e1.Error(), e2.Error())
	})

	t.Run("no resolver fails closed", func(t *testing.T) {
		p := newSeededProvider()
		pc := cache.NewCache(cache.CacheConfig{Name: "t", MaxRuntimeItems: 10, DefaultTTL: time.Hour})
		defer pc.Close()
		b, err := NewCustomReportBuilder(p, interfaces.CustomReportConfig{}, pc, nil, nil, testRoot)
		require.NoError(t, err)
		_, err = b.GenerateReport(ctx, newReq("a", map[string]interface{}{"device_id": "a-dev-1"}, nil))
		assert.ErrorIs(t, err, errCustomDeviceScopeUnverifiable)
		assert.Zero(t, p.calls())
		_, err = b.GenerateReport(ctx, req("a", "dna"))
		assert.NoError(t, err, "a request naming no devices needs no resolver")
	})

	t.Run("ancestry error denies; descendant device and parent tenant allowed", func(t *testing.T) {
		p := newSeededProvider()
		pc := cache.NewCache(cache.CacheConfig{Name: "t", MaxRuntimeItems: 10, DefaultTTL: time.Hour})
		defer pc.Close()
		failing := func(context.Context, string, string) (bool, error) { return false, errors.New("lookup failed") }
		b, err := NewCustomReportBuilder(p, interfaces.CustomReportConfig{}, pc, testDevices, failing, testRoot)
		require.NoError(t, err)
		_, err = b.GenerateReport(ctx, newReq("a", map[string]interface{}{"device_id": "child-dev"}, nil))
		assert.ErrorIs(t, err, errCustomDeviceOutsideTenant)
		assert.Zero(t, p.calls())

		ok := newTestBuilder(t, p, interfaces.CustomReportConfig{})
		_, err = ok.GenerateReport(ctx, newReq("a", map[string]interface{}{"device_id": "child-dev"}, nil))
		assert.NoError(t, err)
	})

	t.Run("device_ids parsing", func(t *testing.T) {
		for name, v := range map[string]interface{}{
			"[]string":      []string{"d1", "d2"},
			"[]interface{}": []interface{}{"d1", "d2"},
			"comma string":  " d1 , ,d2,",
		} {
			p := newSeededProvider()
			owner := deviceMap{"d1": "a", "d2": "a"}
			pc := cache.NewCache(cache.CacheConfig{Name: "t", MaxRuntimeItems: 10, DefaultTTL: time.Hour})
			b, err := NewCustomReportBuilder(p, interfaces.CustomReportConfig{}, pc, owner, treeAncestry(testTree), testRoot)
			require.NoError(t, err)
			_, err = b.GenerateReport(ctx, newReq("a", map[string]interface{}{"device_ids": v}, nil))
			require.NoError(t, err, name)
			require.NotEmpty(t, p.dnaQ)
			assert.Equal(t, []string{"d1", "d2"}, p.dnaQ[0].DeviceIDs, name)
			assert.Equal(t, []string{"a"}, p.dnaQ[0].TenantIDs)
			assert.NotContains(t, p.dnaQ[0].Filters, "device_ids")
			pc.Close()
		}

		b := newTestBuilder(t, newSeededProvider(), interfaces.CustomReportConfig{})
		for name, v := range map[string]interface{}{"int": 42, "mixed": []interface{}{"d1", 3}} {
			_, err := b.GenerateReport(ctx, newReq("a", map[string]interface{}{"device_ids": v}, nil))
			assert.ErrorIs(t, err, interfaces.ErrInvalidQuery, name)
			_, err = b.GenerateReport(ctx, newReq("a", nil, map[string]interface{}{"device_ids": v}))
			assert.ErrorIs(t, err, interfaces.ErrInvalidQuery, name)
		}
		_, err := b.GenerateReport(ctx, newReq("a", map[string]interface{}{"device_id": 7}, nil))
		assert.ErrorIs(t, err, interfaces.ErrInvalidQuery)

		p := newSeededProvider()
		b = newTestBuilder(t, p, interfaces.CustomReportConfig{})
		_, err = b.GenerateReport(ctx, newReq("a",
			map[string]interface{}{"device_id": "a-dev-1", "device_ids": "a-dev-1"},
			map[string]interface{}{"device_id": "a-dev-1"}))
		require.NoError(t, err)
		assert.Equal(t, []string{"a-dev-1"}, p.dnaQ[0].DeviceIDs)
		require.Len(t, p.statsReqs, 1)
		assert.Equal(t, []string{"a-dev-1"}, p.statsReqs[0])

		_, err = b.GenerateReport(ctx, newReq("a", map[string]interface{}{"device_ids": " , "}, nil))
		require.NoError(t, err)
		assert.Empty(t, p.dnaQ[len(p.dnaQ)-1].DeviceIDs, "an empty list names no devices")
	})

	t.Run("user param devices change the cache key", func(t *testing.T) {
		b := newTestBuilder(t, newSeededProvider(), interfaces.CustomReportConfig{})
		q := interfaces.CustomQuery{DataSources: []string{"dna"}}
		k1, err := b.BuildQueryForTenant("a", q, nil)
		require.NoError(t, err)
		k2, err := b.BuildQueryForTenant("a", q, []string{"a-dev-1"})
		require.NoError(t, err)
		assert.NotEqual(t, k1.CacheKey, k2.CacheKey)
	})
}

func TestCustomBuilder_ProviderErrorsReturned(t *testing.T) {
	boom := errors.New("provider boom")

	p := newSeededProvider()
	p.dnaErr = boom
	_, err := newTestBuilder(t, p, interfaces.CustomReportConfig{}).GenerateReport(context.Background(), req("a", "dna"))
	assert.ErrorIs(t, err, boom)

	p = newSeededProvider()
	p.driftErr = boom
	_, err = newTestBuilder(t, p, interfaces.CustomReportConfig{}).GenerateReport(context.Background(), req("a", "drift"))
	assert.ErrorIs(t, err, boom)
}

func TestNewCustomReportBuilder_RequiredArguments(t *testing.T) {
	pc := cache.NewCache(cache.CacheConfig{Name: "t", MaxRuntimeItems: 10, DefaultTTL: time.Hour})
	defer pc.Close()
	_, err := NewCustomReportBuilder(nil, interfaces.CustomReportConfig{}, pc, nil, nil, testRoot)
	assert.Error(t, err)
	_, err = NewCustomReportBuilder(newSeededProvider(), interfaces.CustomReportConfig{}, nil, nil, nil, testRoot)
	assert.Error(t, err)
	_, err = NewCustomReportBuilder(newSeededProvider(), interfaces.CustomReportConfig{}, pc, nil, nil, "")
	assert.Error(t, err)
}

func TestWindow_RejectsInvalidBounds(t *testing.T) {
	in := []int{1, 2, 3}
	assert.Nil(t, window(in, -1, 2))
	assert.Nil(t, window(in, 1, -5))
	assert.Nil(t, window(in, 2, 1))
	assert.Nil(t, window(in, 3, 4))
	assert.Equal(t, []int{2, 3}, window(in, 1, 10))
}
