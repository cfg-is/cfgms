// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package gate

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

func TestEvaluate_CombinesRules(t *testing.T) {
	base := meas(totals(1, 5, 100), rec("p.F", "a.go", 15))
	cur := meas(totals(2, 7, 100), rec("p.F", "a.go", 16), rec("p.N", "a.go", 11))
	prev := meas(metrics.Totals{}, rec("p.F", "a.go", 15))
	res := Evaluate(base, prev, cur, []string{"a.go"})
	rules := map[int]int{}
	for _, f := range res.Findings {
		rules[f.Rule]++
	}
	assert.Equal(t, map[int]int{1: 2, 2: 1, 3: 2}, rules)
}

func TestEvaluate_WarnOnlyAndNeutralMetrics(t *testing.T) {
	base := meas(metrics.Totals{Functions: 10, MeanCC: 2, P95Volume: 50})
	cur := meas(metrics.Totals{Functions: 10, MeanCC: 2.5, P95Volume: 60})
	res := Evaluate(base, meas(metrics.Totals{}), cur, nil)
	assert.Empty(t, res.Findings)
	assert.Equal(t, []string{"mean_cc 2 -> 2.5", "p95_volume 50 -> 60"}, res.Warnings)

	// A function-count change alone affects nothing.
	cur = meas(metrics.Totals{Functions: 99, MeanCC: 2, P95Volume: 50})
	res = Evaluate(base, meas(metrics.Totals{}), cur, nil)
	assert.Empty(t, res.Findings)
	assert.Empty(t, res.Warnings)
}

func TestNearestRankHandComputed(t *testing.T) {
	ten := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	assert.Equal(t, 10.0, metrics.NearestRank(ten, 0.95)) // ceil(9.5)-1 = 9
	twenty := make([]float64, 20)
	for i := range twenty {
		twenty[i] = float64((i + 1) * 10)
	}
	assert.Equal(t, 190.0, metrics.NearestRank(twenty, 0.95)) // ceil(19)-1 = 18
	assert.Equal(t, 100.0, metrics.NearestRank(twenty, 0.5))  // ceil(10)-1 = 9
}
