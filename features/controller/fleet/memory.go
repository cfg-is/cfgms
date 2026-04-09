// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package fleet

import (
	"context"
	"strings"
)

// MemoryQuery implements FleetQuery by scanning all stewards from a StewardProvider.
// An in-memory scan over 50k stewards completes in <100ms — good enough for v1.
// Future optimization: index by OS/tenant for O(1) lookup.
type MemoryQuery struct {
	provider StewardProvider
}

// NewMemoryQuery creates a MemoryQuery backed by the given StewardProvider.
func NewMemoryQuery(provider StewardProvider) *MemoryQuery {
	return &MemoryQuery{provider: provider}
}

// Search returns all stewards matching the filter. Fields are AND-combined.
// An empty filter returns all stewards.
func (q *MemoryQuery) Search(_ context.Context, filter Filter) ([]StewardResult, error) {
	all := q.provider.GetAllStewards()
	results := make([]StewardResult, 0, len(all))
	for _, s := range all {
		if matchesFilter(s, filter) {
			results = append(results, toStewardResult(s))
		}
	}
	return results, nil
}

// Count returns the number of stewards matching the filter.
func (q *MemoryQuery) Count(_ context.Context, filter Filter) (int, error) {
	all := q.provider.GetAllStewards()
	count := 0
	for _, s := range all {
		if matchesFilter(s, filter) {
			count++
		}
	}
	return count, nil
}

// matchesFilter returns true if s satisfies all non-empty filter fields.
func matchesFilter(s StewardData, f Filter) bool {
	attrs := s.DNAAttributes
	if attrs == nil {
		attrs = map[string]string{}
	}

	if f.TenantID != "" && s.TenantID != f.TenantID {
		return false
	}
	if f.OS != "" && attrs["os"] != f.OS {
		return false
	}
	if f.Platform != "" && attrs["platform"] != f.Platform {
		return false
	}
	if f.Architecture != "" && attrs["arch"] != f.Architecture {
		return false
	}
	if f.Status != "" && f.Status != "any" && s.Status != f.Status {
		return false
	}
	if f.Hostname != "" && !strings.Contains(attrs["hostname"], f.Hostname) {
		return false
	}
	for _, tag := range f.Tags {
		if !stewardHasTag(attrs, tag) {
			return false
		}
	}
	for k, v := range f.DNAAttributes {
		if attrs[k] != v {
			return false
		}
	}
	return true
}

// stewardHasTag reports whether the given tag appears in the steward's DNA["tags"] list.
// Tags are stored as a comma-separated string, e.g. "production, web, db".
func stewardHasTag(attrs map[string]string, tag string) bool {
	raw, ok := attrs["tags"]
	if !ok || raw == "" {
		return false
	}
	for _, t := range strings.Split(raw, ",") {
		if strings.TrimSpace(t) == tag {
			return true
		}
	}
	return false
}

// toStewardResult converts StewardData to StewardResult.
func toStewardResult(s StewardData) StewardResult {
	attrs := s.DNAAttributes
	if attrs == nil {
		attrs = map[string]string{}
	}
	return StewardResult{
		ID:            s.ID,
		TenantID:      s.TenantID,
		Hostname:      attrs["hostname"],
		OS:            attrs["os"],
		Architecture:  attrs["arch"],
		Status:        s.Status,
		LastHeartbeat: s.LastHeartbeat,
		DNAAttributes: attrs,
	}
}
