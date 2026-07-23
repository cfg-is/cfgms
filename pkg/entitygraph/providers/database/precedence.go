// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// resolveSourceClass derives the source class from a source identity string.
// Sources are conventionally "<class>:<name>" (e.g. "enforcing-module:hyperv");
// the prefix before the first ':' is matched against the known source classes.
// Unrecognized sources default to the observer class per ADR-022 §4.
func resolveSourceClass(source string) types.SourceClass {
	prefix := source
	if i := strings.Index(source, ":"); i >= 0 {
		prefix = source[:i]
	}
	switch types.SourceClass(prefix) {
	case types.SourceClassEnforcingModule,
		types.SourceClassManagingIntegration,
		types.SourceClassObserver,
		types.SourceClassOperatorAssertion,
		types.SourceClassCorrelatorInference:
		return types.SourceClass(prefix)
	default:
		return types.SourceClassObserver
	}
}

// sourceClassRank returns the precedence rank of a source class: lower rank is
// higher precedence. Unknown classes rank after all known classes.
func sourceClassRank(sc types.SourceClass) int {
	for i, c := range types.DefaultPrecedenceOrder {
		if c == sc {
			return i
		}
	}
	return len(types.DefaultPrecedenceOrder)
}

// sourceEntry is one source's assertion about an entity, used for precedence
// resolution and attribute merging.
type sourceEntry struct {
	source      string
	sourceClass string
	observedAt  time.Time
	payloadHash string
	payload     map[string]interface{}
}

// entryRank returns the precedence rank of an entry, preferring its recorded
// sourceClass and falling back to deriving it from the source identity.
func entryRank(e sourceEntry) int {
	sc := types.SourceClass(e.sourceClass)
	if sc == "" {
		sc = resolveSourceClass(e.source)
	}
	return sourceClassRank(sc)
}

// betterSource reports whether a should win over b. Precedence is decided first
// by source-class rank, then by most-recent observation, and finally by payload
// hash for a stable, deterministic tie-break.
func betterSource(a, b sourceEntry) bool {
	ra, rb := entryRank(a), entryRank(b)
	if ra != rb {
		return ra < rb
	}
	if !a.observedAt.Equal(b.observedAt) {
		return a.observedAt.After(b.observedAt)
	}
	return a.payloadHash < b.payloadHash
}

// winningSourceIdx returns the index of the highest-precedence entry, or -1 for
// an empty slice.
func winningSourceIdx(sources []sourceEntry) int {
	if len(sources) == 0 {
		return -1
	}
	best := 0
	for i := 1; i < len(sources); i++ {
		if betterSource(sources[i], sources[best]) {
			best = i
		}
	}
	return best
}

// mergeAttributes merges attribute payloads across sources. For each attribute
// key the value from the highest-precedence source that supplies it wins; lower
// precedence sources fill only keys the winners do not provide.
func mergeAttributes(sources []sourceEntry) map[string]interface{} {
	merged := map[string]interface{}{}
	if len(sources) == 0 {
		return merged
	}

	order := make([]int, len(sources))
	for i := range order {
		order[i] = i
	}
	// Best-first ordering.
	sort.SliceStable(order, func(a, b int) bool {
		return betterSource(sources[order[a]], sources[order[b]])
	})

	// Apply worst-first so the best source's values overwrite lower ones.
	for i := len(order) - 1; i >= 0; i-- {
		for k, v := range sources[order[i]].payload {
			merged[k] = v
		}
	}
	return merged
}
