// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package resolution

import (
	"strings"

	modules "github.com/cfgis/cfgms/features/modules"
)

// ResolveObserveModules returns the names of modules that should observe on the
// steward given the baseline DNA attribute map.
//
// Matching rules (ADR-024 §5, Amendment 2):
//   - A manifest with AlwaysPull true always appears in the result, regardless
//     of the DNA contents (including an empty map) — per-cycle universal pull.
//   - A manifest with nil or empty ObserveWhen and AlwaysPull false never
//     appears in the result. Absence of both fields means "never auto-pull for
//     DNA" (ADR-024 §2).
//   - When ObserveWhen is non-empty, predicates are OR'd: any one match
//     activates that module. equals requires exact string equality; contains
//     requires strings.Contains on the fact value.
//
// This is a pure function — no I/O, no RPC. The wiring to an actual call site
// (steward observation loop RPC) is handled by a separate sibling story.
func ResolveObserveModules(dna map[string]string, manifests []*modules.ModuleMetadata) []string {
	if len(manifests) == 0 {
		return nil
	}

	var result []string
	for _, m := range manifests {
		if m.AlwaysPull {
			result = append(result, m.Name)
			continue
		}
		if len(m.ObserveWhen) == 0 {
			continue
		}
		if matchesAnyPredicate(dna, m.ObserveWhen) {
			result = append(result, m.Name)
		}
	}
	return result
}

// matchesAnyPredicate returns true if at least one predicate in the list matches
// the given DNA map (OR semantics across predicates).
func matchesAnyPredicate(dna map[string]string, predicates []modules.ObservePredicate) bool {
	for _, p := range predicates {
		value, ok := dna[p.Fact]
		if !ok {
			continue
		}
		if p.Equals != "" && value == p.Equals {
			return true
		}
		if p.Contains != "" && strings.Contains(value, p.Contains) {
			return true
		}
	}
	return false
}
