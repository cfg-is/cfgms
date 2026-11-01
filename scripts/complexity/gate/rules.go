// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package gate holds the complexity no-worsening rules as pure functions over
// metric-file Measurements. It performs no IO and runs no git commands.
package gate

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

// Finding is one gate failure.
type Finding struct {
	Rule     int    // 1, 2 or 3
	Metric   string // rule 1: the aggregate metric that worsened
	Identity string // rules 2 and 3: the function
	File     string
	Line     int
	Base     float64
	Cur      float64
}

// String renders the finding as `<file>:<line>: rule N: ...`.
func (f Finding) String() string {
	if f.Rule == 1 {
		return fmt.Sprintf("aggregate: rule 1: %s %s -> %s", f.Metric, num(f.Base), num(f.Cur))
	}
	return fmt.Sprintf("%s:%d: rule %d: %s CC %s -> %s", f.File, f.Line, f.Rule, f.Identity, num(f.Base), num(f.Cur))
}

// slash normalises a path to forward slashes. filepath.ToSlash alone is a
// no-op on Linux, so backslashes are replaced explicitly as well.
func slash(p string) string { return strings.ReplaceAll(filepath.ToSlash(p), "\\", "/") }

func num(v float64) string { return fmt.Sprintf("%g", v) }

// Rule1Aggregate fails for each of hotspot count, aggregate excess and P95
// Halstead effort that is higher in current than in the ratchet baseline.
func Rule1Aggregate(baseline, current metrics.Measurement) []Finding {
	b, c := baseline.Aggregate, current.Aggregate
	var out []Finding
	add := func(metric string, base, cur float64) {
		if cur > base {
			out = append(out, Finding{Rule: 1, Metric: metric, Base: base, Cur: cur})
		}
	}
	add("hotspots", float64(b.Hotspots), float64(c.Hotspots))
	add("aggregate_excess", float64(b.AggregateExcess), float64(c.AggregateExcess))
	add("p95_effort", b.P95Effort, c.P95Effort)
	return out
}

// Rule2HotspotGrowth fails for every identity present in both measurements
// whose baseline CC is above the hotspot threshold and whose current CC is
// higher. Deleted or renamed hotspots fire nothing.
func Rule2HotspotGrowth(baseline, current metrics.Measurement) []Finding {
	cur := index(current.Functions)
	var out []Finding
	for _, b := range baseline.Functions {
		c, ok := cur[b.Identity]
		if !ok || b.CC <= metrics.HotspotThreshold || c.CC <= b.CC {
			continue
		}
		out = append(out, Finding{Rule: 2, Identity: c.Identity, File: c.File, Line: c.Line,
			Base: float64(b.CC), Cur: float64(c.CC)})
	}
	sortFindings(out)
	return out
}

// Rule3ChangedFunction fails for every function in a touched file whose
// metrics differ from previous (a new identity counts as different) and whose
// CC is above the threshold, unless it reduces an existing hotspot judged
// against previous.
func Rule3ChangedFunction(previous, current metrics.Measurement, touched []string) []Finding {
	touchedSet := make(map[string]bool, len(touched))
	for _, t := range touched {
		touchedSet[slash(t)] = true
	}
	prev := index(previous.Functions)
	var out []Finding
	for _, c := range current.Functions {
		if !touchedSet[slash(c.File)] {
			continue
		}
		p, existed := prev[c.Identity]
		if existed && sameMetrics(p, c) {
			continue
		}
		if c.CC <= metrics.HotspotThreshold {
			continue
		}
		if existed && p.CC > metrics.HotspotThreshold && c.CC < p.CC {
			continue
		}
		base := float64(0)
		if existed {
			base = float64(p.CC)
		}
		out = append(out, Finding{Rule: 3, Identity: c.Identity, File: c.File, Line: c.Line,
			Base: base, Cur: float64(c.CC)})
	}
	sortFindings(out)
	return out
}

func sameMetrics(a, b metrics.FuncRecord) bool {
	return a.CC == b.CC && a.N1 == b.N1 && a.N2 == b.N2 && a.TotalN1 == b.TotalN1 &&
		a.TotalN2 == b.TotalN2 && a.Volume == b.Volume && a.Difficulty == b.Difficulty && a.Effort == b.Effort
}

func index(recs []metrics.FuncRecord) map[string]metrics.FuncRecord {
	m := make(map[string]metrics.FuncRecord, len(recs))
	for _, r := range recs {
		m[r.Identity] = r
	}
	return m
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool {
		if f[i].File != f[j].File {
			return f[i].File < f[j].File
		}
		if f[i].Line != f[j].Line {
			return f[i].Line < f[j].Line
		}
		return f[i].Identity < f[j].Identity
	})
}
