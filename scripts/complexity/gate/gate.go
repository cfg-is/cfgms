// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package gate

import (
	"fmt"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

// Result is the outcome of evaluating all rules.
type Result struct {
	Findings []Finding // any finding fails the gate
	Warnings []string  // reported, never fail the gate
}

// Evaluate runs rules 1 and 2 against the ratchet baseline and rule 3 against
// previous (the merge-base tree). Mean CC and P95 volume increases warn;
// function-count changes are neutral and ignored.
func Evaluate(baseline, previous, current metrics.Measurement, touched []string) Result {
	var r Result
	r.Findings = append(r.Findings, Rule1Aggregate(baseline, current)...)
	r.Findings = append(r.Findings, Rule2HotspotGrowth(baseline, current)...)
	r.Findings = append(r.Findings, Rule3ChangedFunction(previous, current, touched)...)
	b, c := baseline.Aggregate, current.Aggregate
	if c.MeanCC > b.MeanCC {
		r.Warnings = append(r.Warnings, fmt.Sprintf("mean_cc %s -> %s", num(b.MeanCC), num(c.MeanCC)))
	}
	if c.P95Volume > b.P95Volume {
		r.Warnings = append(r.Warnings, fmt.Sprintf("p95_volume %s -> %s", num(b.P95Volume), num(c.P95Volume)))
	}
	return r
}
