// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package fleet

import (
	"context"
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
	Hostname      string            // Substring match on DNA["hostname"]
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
