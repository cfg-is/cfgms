// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package metrics is the complexity metric-file model shared by the report
// command and the gate: the Measurement type, its full and compact writers,
// the reader, and the nearest-rank percentile.
package metrics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
)

const (
	// SchemaVersion is the metric-file schema version.
	SchemaVersion = 1
	// HotspotThreshold is the cyclomatic complexity above which a function is
	// a hotspot.
	HotspotThreshold = 10

	// Status values of a Measurement.
	StatusPass  = "pass"
	StatusFail  = "fail"
	StatusError = "error"

	// Form values of a Measurement: every function, or hotspots only.
	FormFull     = "full"
	FormHotspots = "hotspots"
)

// FuncRecord is one measured function in a metric file. Keys are short and
// stable so a file stays compact and diffs line by line.
type FuncRecord struct {
	Identity   string  `json:"id"`
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Segment    string  `json:"seg"`
	CC         int     `json:"cc"`
	N1         int     `json:"n1"` // distinct operators
	N2         int     `json:"n2"` // distinct operands
	TotalN1    int     `json:"N1"` // total operators
	TotalN2    int     `json:"N2"` // total operands
	Volume     float64 `json:"vol"`
	Difficulty float64 `json:"diff"`
	Effort     float64 `json:"eff"`
}

// Totals summarises a set of functions.
type Totals struct {
	Functions       int     `json:"functions"`
	Hotspots        int     `json:"hotspots"`
	AggregateExcess int     `json:"aggregate_excess"`
	MeanCC          float64 `json:"mean_cc"`
	P95Volume       float64 `json:"p95_volume"`
	P95Effort       float64 `json:"p95_effort"`
	Over20          int     `json:"over20"`
	Over30          int     `json:"over30"`
	Over50          int     `json:"over50"`
}

// Measurement is the metric-file model.
type Measurement struct {
	SchemaVersion    int               `json:"schema_version"`
	BaseCommit       string            `json:"base_commit"`
	AnalyzerVersion  string            `json:"analyzer_version"`
	ManifestSHA256   string            `json:"manifest_sha256"`
	HotspotThreshold int               `json:"hotspot_threshold"`
	Status           string            `json:"status"`
	Form             string            `json:"form"`
	Violations       []string          `json:"violations"`
	Aggregate        Totals            `json:"aggregate"`
	Segments         map[string]Totals `json:"segments"`
	Functions        []FuncRecord      `json:"functions,omitempty"`
}

// NearestRank returns the element of an ascending-sorted series at index
// ceil(p*n)-1. It returns 0 for an empty series.
func NearestRank(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(n))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	return sorted[idx]
}

// Excess is the amount a function's complexity exceeds the hotspot threshold.
func Excess(cc int) int {
	if cc > HotspotThreshold {
		return cc - HotspotThreshold
	}
	return 0
}

// Summarize computes the Totals of a set of functions.
func Summarize(recs []FuncRecord) Totals {
	var t Totals
	t.Functions = len(recs)
	if len(recs) == 0 {
		return t
	}
	vols := make([]float64, 0, len(recs))
	effs := make([]float64, 0, len(recs))
	sum := 0
	for _, r := range recs {
		sum += r.CC
		if r.CC > HotspotThreshold {
			t.Hotspots++
		}
		t.AggregateExcess += Excess(r.CC)
		if r.CC > 20 {
			t.Over20++
		}
		if r.CC > 30 {
			t.Over30++
		}
		if r.CC > 50 {
			t.Over50++
		}
		vols = append(vols, r.Volume)
		effs = append(effs, r.Effort)
	}
	sort.Float64s(vols)
	sort.Float64s(effs)
	t.MeanCC = Round(float64(sum) / float64(len(recs)))
	t.P95Volume = NearestRank(vols, 0.95)
	t.P95Effort = NearestRank(effs, 0.95)
	return t
}

// Round rounds to three decimals so metric files are stable and diff cleanly.
func Round(v float64) float64 { return math.Round(v*1000) / 1000 }

// HotspotsOnly returns the records with CC above the hotspot threshold.
func HotspotsOnly(recs []FuncRecord) []FuncRecord {
	var out []FuncRecord
	for _, r := range recs {
		if r.CC > HotspotThreshold {
			out = append(out, r)
		}
	}
	return out
}

// Write writes m as JSON with one function object per line. The functions
// written are exactly m.Functions; the caller picks full or hotspot-only.
func Write(w io.Writer, m Measurement) error {
	if m.Violations == nil {
		m.Violations = []string{}
	}
	if m.Segments == nil {
		m.Segments = map[string]Totals{}
	}
	fns := m.Functions
	m.Functions = nil
	head, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	head = bytes.TrimSuffix(head, []byte("\n}"))
	var buf bytes.Buffer
	buf.Write(head)
	buf.WriteString(",\n  \"functions\": [")
	for i, f := range fns {
		line, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString("\n    ")
		buf.Write(line)
	}
	if len(fns) > 0 {
		buf.WriteString("\n  ")
	}
	buf.WriteString("]\n}\n")
	_, err = w.Write(buf.Bytes())
	return err
}

// ReadAny parses a metric file without checking its schema version, so a
// baseline written under another schema can be reported as stale.
func ReadAny(r io.Reader) (Measurement, error) {
	var m Measurement
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Measurement{}, fmt.Errorf("parse metric file: %w", err)
	}
	return m, nil
}

// Read parses a metric file, full or hotspot-only, and checks its schema
// version.
func Read(r io.Reader) (Measurement, error) {
	m, err := ReadAny(r)
	if err != nil {
		return Measurement{}, err
	}
	if m.SchemaVersion != SchemaVersion {
		return Measurement{}, fmt.Errorf("metric file schema_version %d, want %d", m.SchemaVersion, SchemaVersion)
	}
	return m, nil
}
