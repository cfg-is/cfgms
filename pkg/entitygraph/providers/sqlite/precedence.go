// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sqlite

import (
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// resolveSourceClass extracts the source class from a source identity string.
// The class is the segment before the first ':' (e.g. "enforcing-module:hyperv"
// → "enforcing-module"). Unrecognised prefixes fall back to the observer class,
// which sits mid-precedence and never wins over an enforcing module.
func resolveSourceClass(source string) types.SourceClass {
	prefix := source
	if idx := strings.IndexByte(source, ':'); idx >= 0 {
		prefix = source[:idx]
	}
	sc := types.SourceClass(prefix)
	for _, known := range types.DefaultPrecedenceOrder {
		if known == sc {
			return sc
		}
	}
	return types.SourceClassObserver
}

// sourceClassRank returns the precedence rank of a source class: the index in
// DefaultPrecedenceOrder, where a lower rank means higher precedence. Unknown
// classes rank last (lowest precedence).
func sourceClassRank(sc types.SourceClass) int {
	for i, known := range types.DefaultPrecedenceOrder {
		if known == sc {
			return i
		}
	}
	return len(types.DefaultPrecedenceOrder)
}

// sourceEntry is one current-state source contributing to an entity's merged
// view. It carries the decoded payload plus the metadata needed for precedence
// and tie-breaking.
type sourceEntry struct {
	source      string
	sourceClass string
	observedAt  time.Time
	payloadHash string
	payload     map[string]interface{}
}

// winningSourceIdx returns the index of the highest-precedence source: lowest
// class rank wins, ties broken by newest observedAt. Returns -1 for an empty
// slice.
func winningSourceIdx(sources []sourceEntry) int {
	if len(sources) == 0 {
		return -1
	}
	best := 0
	bestRank := sourceClassRank(types.SourceClass(sources[0].sourceClass))
	for i := 1; i < len(sources); i++ {
		r := sourceClassRank(types.SourceClass(sources[i].sourceClass))
		switch {
		case r < bestRank:
			best, bestRank = i, r
		case r == bestRank && sources[i].observedAt.After(sources[best].observedAt):
			best = i
		}
	}
	return best
}

// mergeAttributes merges the payloads of all sources into a single attribute
// map, applying source precedence: lower-precedence values are written first
// and higher-precedence values override them per key. Within one class the
// newer observation overrides the older.
func mergeAttributes(sources []sourceEntry) map[string]interface{} {
	ordered := make([]sourceEntry, len(sources))
	copy(ordered, sources)

	// Sort so that the winning source is applied last: higher rank (lower
	// precedence) first, and within equal rank, older observations first.
	sort.SliceStable(ordered, func(i, j int) bool {
		ri := sourceClassRank(types.SourceClass(ordered[i].sourceClass))
		rj := sourceClassRank(types.SourceClass(ordered[j].sourceClass))
		if ri != rj {
			return ri > rj
		}
		return ordered[i].observedAt.Before(ordered[j].observedAt)
	})

	merged := make(map[string]interface{})
	for _, s := range ordered {
		for k, v := range s.payload {
			merged[k] = v
		}
	}
	return merged
}
