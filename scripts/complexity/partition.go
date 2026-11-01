// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cfgis/cfgms/scripts/complexity/analyzer"
	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

// Violation kinds reported by CheckPartition.
const (
	KindUnclassified = "unclassified"
	KindClaimedTwice = "claimed-twice"
	KindForeign      = "foreign"
	KindSumMismatch  = "sum-mismatch"
)

// Violation is one partition defect.
type Violation struct {
	Kind     string
	Identity string
	Detail   string
}

func (v Violation) String() string {
	if v.Identity == "" {
		return fmt.Sprintf("%s: %s", v.Kind, v.Detail)
	}
	return fmt.Sprintf("%s: %s (%s)", v.Kind, v.Identity, v.Detail)
}

// CheckPartition verifies that bySegment is an exact partition of aggregate:
// every function in exactly one segment, no function in a segment that is not
// in the aggregate, and matching function counts and excess sums.
func CheckPartition(aggregate []analyzer.Function, bySegment map[string][]analyzer.Function) []Violation {
	agg := make(map[string]analyzer.Function, len(aggregate))
	for _, fn := range aggregate {
		agg[fn.Identity] = fn
	}
	owners := map[string][]string{}
	names := make([]string, 0, len(bySegment))
	for name := range bySegment {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []Violation
	count, excess := 0, 0
	for _, name := range names {
		for _, fn := range bySegment[name] {
			count++
			excess += metrics.Excess(fn.CC)
			owners[fn.Identity] = append(owners[fn.Identity], name)
			if _, ok := agg[fn.Identity]; !ok {
				out = append(out, Violation{KindForeign, fn.Identity,
					fmt.Sprintf("in segment %s but absent from the aggregate", name)})
			}
		}
	}
	for _, fn := range aggregate {
		switch segs := owners[fn.Identity]; len(segs) {
		case 0:
			out = append(out, Violation{KindUnclassified, fn.Identity,
				fmt.Sprintf("in no segment; package %s", fn.Package)})
		case 1:
		default:
			out = append(out, Violation{KindClaimedTwice, fn.Identity,
				"claimed by segments " + strings.Join(segs, " and ")})
		}
	}
	aggExcess := 0
	for _, fn := range aggregate {
		aggExcess += metrics.Excess(fn.CC)
	}
	if count != len(aggregate) || excess != aggExcess {
		out = append(out, Violation{Kind: KindSumMismatch, Detail: fmt.Sprintf(
			"segments sum to %d functions and excess %d; aggregate has %d and %d",
			count, excess, len(aggregate), aggExcess)})
	}
	return out
}
