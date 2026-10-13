// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package registration provides provenance matching for the registration-refresh flow (ADR-010).
package registration

import (
	"encoding/json"
	"sort"
	"strings"
)

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

// NormalizeProvenance returns the canonical form of a host-attribute map: DNA
// fields, empty keys and empty values are dropped and surrounding whitespace is
// trimmed. Every writer of a provenance baseline and every admission-time
// comparison passes attributes through it, so an unchanged host presents the
// same set whichever path (connect, refresh claim, refresh complete) carried it.
// It returns nil when nothing usable remains.
func NormalizeProvenance(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" || DNAFieldKeys[k] {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ProvenanceKeyDiff reports which non-DNA keys of the stored baseline matched
// the incoming attributes and which did not. Key names only; never values.
func ProvenanceKeyDiff(storedJSON string, incoming map[string]string) (matched, divergent []string) {
	var stored map[string]string
	if err := json.Unmarshal([]byte(storedJSON), &stored); err != nil {
		return nil, nil
	}
	for k, sv := range stored {
		if DNAFieldKeys[k] {
			continue
		}
		if iv, ok := incoming[k]; ok && iv == sv {
			matched = append(matched, k)
		} else {
			divergent = append(divergent, k)
		}
	}
	sort.Strings(matched)
	sort.Strings(divergent)
	return matched, divergent
}

// NormalizeStoredProvenance returns storedJSON in canonical form (see
// NormalizeProvenance) so a baseline written before normalisation compares the
// same way as a fresh one. Unparseable or empty input is returned unchanged.
func NormalizeStoredProvenance(storedJSON string) string {
	var stored map[string]string
	if err := json.Unmarshal([]byte(storedJSON), &stored); err != nil {
		return storedJSON
	}
	norm := NormalizeProvenance(stored)
	if norm == nil {
		return storedJSON
	}
	raw, err := json.Marshal(norm)
	if err != nil {
		return storedJSON
	}
	return string(raw)
}

// EphemeralProvenanceKeys are host attributes that change when the same
// machine is recreated (a container or VM rebuilt from the same image gets new
// NIC MACs and a new identity-file creation date). ADR-011 §7: they corroborate
// but never decide — they count only when the baseline holds no stable key.
var EphemeralProvenanceKeys = map[string]bool{
	"nic_macs":     true,
	"install_date": true,
}

// setOverlapKeys are comma-joined set attributes that match when the baseline
// and the incoming report share at least one member.
var setOverlapKeys = map[string]bool{"nic_macs": true}

// admissionKeyScored reports whether key counts toward the admission score.
// install_date is skipped while the baseline holds a stable key; nic_macs is
// always scored (by set overlap) so a clone with different NICs diverges.
func admissionKeyScored(key string, hasStable bool) bool {
	if DNAFieldKeys[key] {
		return false
	}
	return !(hasStable && EphemeralProvenanceKeys[key] && !setOverlapKeys[key])
}

func sharesMember(a, b string) bool {
	seen := map[string]bool{}
	for _, m := range strings.Split(a, ",") {
		if m = strings.TrimSpace(m); m != "" {
			seen[strings.ToLower(m)] = true
		}
	}
	for _, m := range strings.Split(b, ",") {
		if seen[strings.ToLower(strings.TrimSpace(m))] && strings.TrimSpace(m) != "" {
			return true
		}
	}
	return false
}

// ScoreAdmission scores incoming host attributes against a stored baseline for
// ControlChannel admission. Differences from FuzzyMatch:
//   - install_date is not scored while the baseline has any stable key;
//   - nic_macs is scored by set overlap: any MAC present in both matches;
//   - a baseline key that is absent or empty in incoming is not comparable and
//     counts neither as matched nor as divergent.
//
// A changed stable key (machine_id, disk_serials) still diverges. matched and
// divergent hold key names only. A zero result means nothing was comparable.
func (ProvenanceMatcher) ScoreAdmission(storedJSON string, incoming map[string]string) (res ProvenanceResult, matched, divergent []string) {
	var stored map[string]string
	if storedJSON == "" || json.Unmarshal([]byte(storedJSON), &stored) != nil {
		return ProvenanceResult{}, nil, nil
	}
	hasStable := false
	for k := range stored {
		if !DNAFieldKeys[k] && !EphemeralProvenanceKeys[k] {
			hasStable = true
			break
		}
	}
	for k, sv := range stored {
		if !admissionKeyScored(k, hasStable) {
			continue
		}
		iv, ok := incoming[k]
		if !ok || iv == "" {
			continue
		}
		if iv == sv || (setOverlapKeys[k] && sharesMember(sv, iv)) {
			matched = append(matched, k)
		} else {
			divergent = append(divergent, k)
		}
	}
	sort.Strings(matched)
	sort.Strings(divergent)
	total := len(matched) + len(divergent)
	if total == 0 {
		return ProvenanceResult{}, nil, nil
	}
	return ProvenanceResult{
		Score:         float64(len(matched)) / float64(total),
		MatchedFields: len(matched),
		TotalFields:   total,
	}, matched, divergent
}
