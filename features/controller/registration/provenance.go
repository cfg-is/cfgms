// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package registration provides provenance matching for the registration-refresh flow (ADR-010).
package registration

import "encoding/json"

// DNAFieldKeys are volatile device-state fields excluded from provenance scoring.
// These change on every boot or OS update and carry no re-entry identity signal.
var DNAFieldKeys = map[string]bool{
	"os_version":        true,
	"kernel_version":    true,
	"uptime_seconds":    true,
	"load_avg":          true,
	"memory_free":       true,
	"disk_free":         true,
	"running_processes": true,
}

// ProvenanceMatchThreshold is the minimum score (0.0–1.0) for auto-accept.
// Scores below this threshold demote auto_accept → require_approval (demote-only).
const ProvenanceMatchThreshold = 0.60

// ProvenanceResult holds the outcome of a FuzzyMatch comparison.
type ProvenanceResult struct {
	Score         float64 // 0.0–1.0; 1.0 means every comparable field matched
	MatchedFields int
	TotalFields   int
}

// ProvenanceMatcher compares stored and incoming device-identity provenance signals.
// It is stateless; the zero value is ready for use.
type ProvenanceMatcher struct{}

// FuzzyMatch compares a stored provenance JSON string against an incoming signal map.
// DNA fields (see DNAFieldKeys) are excluded from scoring. Scoring is based only on
// fields present in the stored snapshot — extra incoming fields are ignored.
// Returns a zero ProvenanceResult when storedJSON is empty, unparseable, or contains
// no non-DNA fields.
func (ProvenanceMatcher) FuzzyMatch(storedJSON string, incoming map[string]string) ProvenanceResult {
	if storedJSON == "" {
		return ProvenanceResult{}
	}
	var stored map[string]string
	if err := json.Unmarshal([]byte(storedJSON), &stored); err != nil {
		return ProvenanceResult{}
	}

	matched := 0
	total := 0
	for k, sv := range stored {
		if DNAFieldKeys[k] {
			continue
		}
		total++
		if iv, ok := incoming[k]; ok && iv == sv {
			matched++
		}
	}

	if total == 0 {
		return ProvenanceResult{}
	}
	return ProvenanceResult{
		Score:         float64(matched) / float64(total),
		MatchedFields: matched,
		TotalFields:   total,
	}
}
