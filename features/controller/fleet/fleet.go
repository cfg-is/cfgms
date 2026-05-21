// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package fleet

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// StewardData is the minimal steward information needed for fleet queries.
// StewardProvider implementations translate from their internal representation to this struct.
type StewardData struct {
	ID            string
	TenantID      string
	Status        string
	LastHeartbeat time.Time
	DNAAttributes map[string]string // Flattened DNA attributes (hostname, os, arch, platform, tags, ...)
}

// StewardProvider is the source of steward data for fleet queries.
type StewardProvider interface {
	GetAllStewards() []StewardData
}

// Filter defines criteria for filtering stewards. All fields are optional.
// Multiple non-empty fields are AND-combined.
type Filter struct {
	TenantID      string            // Scope to this tenant (exact match)
	OS            string            // Match DNA["os"] (exact)
	Platform      string            // Match DNA["platform"] (exact)
	Architecture  string            // Match DNA["arch"] (exact)
	Tags          []string          // All tags must be present (DNA["tags"] is comma-separated)
	DNAAttributes map[string]string // All key-value pairs must match exactly
	Status        string            // "online", "offline", or "any"/empty (any status)
	Hostname      string            // Substring match on DNA["hostname"] (kept for backward compat)
	Name          string            // Glob match on DNA["hostname"] via path.Match (use name: selector key)
}

// ParseTargetSelector parses a space-separated key:value selector string into a Filter.
// Supported keys: name, os, platform, arch, tag, dna.<k>.
// Glob matching (path.Match) applies to name: and tag: values; all other keys are exact match.
// An empty selector is an error. Use the literal "all" to match all stewards.
func ParseTargetSelector(s string) (Filter, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Filter{}, fmt.Errorf("target selector must not be empty; use \"all\" to match all stewards")
	}
	if s == "all" {
		return Filter{}, nil
	}

	var f Filter
	for _, token := range strings.Fields(s) {
		idx := strings.Index(token, ":")
		if idx < 0 {
			return Filter{}, fmt.Errorf("invalid selector token %q: expected key:value format", token)
		}
		key := token[:idx]
		value := token[idx+1:]

		switch {
		case key == "name":
			f.Name = value
		case key == "os":
			f.OS = value
		case key == "platform":
			f.Platform = value
		case key == "arch":
			f.Architecture = value
		case key == "tag":
			f.Tags = append(f.Tags, value)
		case strings.HasPrefix(key, "dna."):
			dnaKey := strings.TrimPrefix(key, "dna.")
			if f.DNAAttributes == nil {
				f.DNAAttributes = make(map[string]string)
			}
			f.DNAAttributes[dnaKey] = value
		default:
			return Filter{}, fmt.Errorf("unrecognised selector key %q", key)
		}
	}
	return f, nil
}

// StewardResult is a device record returned by a fleet query.
// Contains enough information for targeting decisions without a full DNA dump.
type StewardResult struct {
	ID            string
	TenantID      string
	Hostname      string
	OS            string
	Architecture  string
	Status        string
	LastHeartbeat time.Time
	DNAAttributes map[string]string
}

// FleetQuery is the single query path for all device filtering.
// REST API, workflow dispatch, and future Web UI all use this interface.
// No duplicate filtering logic elsewhere.
type FleetQuery interface {
	Search(ctx context.Context, filter Filter) ([]StewardResult, error)
	Count(ctx context.Context, filter Filter) (int, error)
}
