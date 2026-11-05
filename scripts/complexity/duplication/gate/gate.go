// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package gate

import "github.com/cfgis/cfgms/scripts/complexity/duplication/detector"

// Result is the outcome of evaluating all rules.
type Result struct {
	Findings []Finding // any finding fails the gate
}

// Evaluate runs all duplication rules against previous, the merge-base tree
// measured by the same detector and threshold as current. InvalidAnnotations
// are ignored: a copy with an invalid annotation is an unannotated run and the
// rules apply to it like any other copy.
func Evaluate(previous, current detector.Result, touched []string) Result {
	var r Result
	r.Findings = append(r.Findings, Rule1Aggregate(previous, current)...)
	r.Findings = append(r.Findings, Rule2NewClone(previous, current, touched)...)
	r.Findings = append(r.Findings, Rule3Growth(previous, current, touched)...)
	return r
}
