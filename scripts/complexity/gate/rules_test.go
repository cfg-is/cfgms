// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package gate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

func rec(id, file string, cc int) metrics.FuncRecord {
	return metrics.FuncRecord{Identity: id, File: file, Line: 7, CC: cc, N1: 3, N2: 4, TotalN1: 5, TotalN2: 6,
		Volume: 10, Difficulty: 2, Effort: 20}
}

func meas(aggr metrics.Totals, recs ...metrics.FuncRecord) metrics.Measurement {
	return metrics.Measurement{Aggregate: aggr, Functions: recs}
}

func totals(h, x int, p95 float64) metrics.Totals {
	return metrics.Totals{Hotspots: h, AggregateExcess: x, P95Effort: p95}
}

func TestRule1_Cases(t *testing.T) {
	base := meas(totals(5, 20, 100))
	tests := []struct {
		name   string
		cur    metrics.Totals
		metric string
	}{
		{"extra hotspot", totals(6, 20, 100), "hotspots"},
		{"extra excess equal hotspots", totals(5, 21, 100), "aggregate_excess"},
		{"higher p95 effort", totals(5, 20, 100.5), "p95_effort"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cur := meas(tc.cur)
			f := Rule1Aggregate(base, cur)
			require.Len(t, f, 1)
			assert.Equal(t, tc.metric, f[0].Metric)
			assert.Contains(t, f[0].String(), "rule 1: "+tc.metric)
			assert.Empty(t, Rule2HotspotGrowth(base, cur))
			assert.Empty(t, Rule3ChangedFunction(base, cur, []string{"a.go"}))
		})
	}
	t.Run("equal and lower pass", func(t *testing.T) {
		assert.Empty(t, Rule1Aggregate(base, meas(totals(5, 20, 100))))
		assert.Empty(t, Rule1Aggregate(base, meas(totals(4, 10, 50))))
	})
	t.Run("each metric its own finding", func(t *testing.T) {
		assert.Len(t, Rule1Aggregate(base, meas(totals(6, 21, 101))), 3)
	})
}

func TestRule2_Cases(t *testing.T) {
	tests := []struct {
		name      string
		base, cur int
		fires     bool
	}{
		{"15 to 16", 15, 16, true},
		{"15 to 15", 15, 15, false},
		{"15 to 14", 15, 14, false},
		{"non-hotspot 8 to 9", 8, 9, false},
		{"threshold 10 to 11", 10, 11, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := meas(metrics.Totals{}, rec("p.F", "a.go", tc.base))
			cur := meas(metrics.Totals{}, rec("p.F", "a.go", tc.cur))
			f := Rule2HotspotGrowth(base, cur)
			if tc.fires {
				require.Len(t, f, 1)
				assert.Equal(t, "a.go:7: rule 2: p.F CC 15 -> 16", f[0].String())
			} else {
				assert.Empty(t, f)
			}
			assert.Empty(t, Rule1Aggregate(base, cur))
			assert.Empty(t, Rule3ChangedFunction(base, cur, nil))
		})
	}
	t.Run("deleted or renamed hotspot fires nothing", func(t *testing.T) {
		base := meas(metrics.Totals{}, rec("p.F", "a.go", 30))
		assert.Empty(t, Rule2HotspotGrowth(base, meas(metrics.Totals{}, rec("p.G", "a.go", 40))))
		assert.Empty(t, Rule2HotspotGrowth(base, meas(metrics.Totals{})))
	})
}

func TestRule3_Cases(t *testing.T) {
	touched := []string{"a.go"}
	empty := meas(metrics.Totals{})
	with := func(r metrics.FuncRecord) metrics.Measurement { return meas(metrics.Totals{}, r) }

	t.Run("new CC 11 fails", func(t *testing.T) {
		f := Rule3ChangedFunction(empty, with(rec("p.N", "a.go", 11)), touched)
		require.Len(t, f, 1)
		assert.Equal(t, "a.go:7: rule 3: p.N CC 0 -> 11", f[0].String())
		assert.Empty(t, Rule1Aggregate(empty, with(rec("p.N", "a.go", 11))))
		assert.Empty(t, Rule2HotspotGrowth(empty, with(rec("p.N", "a.go", 11))))
	})
	t.Run("new CC 10 passes", func(t *testing.T) {
		assert.Empty(t, Rule3ChangedFunction(empty, with(rec("p.N", "a.go", 10)), touched))
	})
	t.Run("hotspot reduction 40 to 39 passes", func(t *testing.T) {
		assert.Empty(t, Rule3ChangedFunction(with(rec("p.F", "a.go", 40)), with(rec("p.F", "a.go", 39)), touched))
	})
	t.Run("hotspot growth 40 to 41 fails", func(t *testing.T) {
		assert.Len(t, Rule3ChangedFunction(with(rec("p.F", "a.go", 40)), with(rec("p.F", "a.go", 41)), touched), 1)
	})
	t.Run("halstead differs, CC equal and low passes", func(t *testing.T) {
		cur := rec("p.F", "a.go", 5)
		cur.Effort = 99
		assert.Empty(t, Rule3ChangedFunction(with(rec("p.F", "a.go", 5)), with(cur), touched))
	})
	t.Run("halstead-only change on a hotspot is changed and fails", func(t *testing.T) {
		cur := rec("p.F", "a.go", 40)
		cur.TotalN1++
		assert.Len(t, Rule3ChangedFunction(with(rec("p.F", "a.go", 40)), with(cur), touched), 1)
	})
	t.Run("identical to previous CC 40 in touched file passes", func(t *testing.T) {
		assert.Empty(t, Rule3ChangedFunction(with(rec("p.F", "a.go", 40)), with(rec("p.F", "a.go", 40)), touched))
	})
	t.Run("untouched file not subject", func(t *testing.T) {
		assert.Empty(t, Rule3ChangedFunction(empty, with(rec("p.N", "b.go", 50)), touched))
	})
	t.Run("backslash touched path matches", func(t *testing.T) {
		got := Rule3ChangedFunction(empty, with(rec("p.N", "pkg/x/a.go", 50)), []string{"pkg\\x\\a.go"})
		assert.Len(t, got, 1)
		got = Rule3ChangedFunction(empty, with(rec("p.N", "pkg\\x\\a.go", 50)), []string{"pkg/x/a.go"})
		assert.Len(t, got, 1)
	})
}
