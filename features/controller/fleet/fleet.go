// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package fleet provides fleet-wide device query and filtering for the CFGMS controller.
//
// The FleetQuery interface is the single query path used by both the REST API
// (GET /api/v1/stewards?os=windows&tag=prod) and workflow script dispatch targeting.
// This ensures consistent filter semantics across all device-selection code paths.
package fleet

import "strings"

// Filter defines criteria for selecting devices from the fleet.
// Field names match the REST API query parameters for consistency:
//
//	GET /api/v1/stewards?os=windows&tag=prod&group=servers
//
// An empty Filter matches all devices.
type Filter struct {
	// OS filters by operating system (e.g., "windows", "linux", "darwin").
	// Matches the ?os= REST API query parameter and DNA attribute "os".
	OS string `yaml:"os,omitempty" json:"os,omitempty"`

	// Tags filters devices that have ALL listed tags.
	// Matches the ?tag= REST API query parameter.
	Tags []string `yaml:"tags,omitempty" json:"tags,omitempty"`

	// Groups filters devices belonging to ALL listed groups.
	// Matches the ?group= REST API query parameter.
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`

	// DNAQuery filters by arbitrary DNA attributes (key=value pairs).
	// All entries must match (AND semantics).
	DNAQuery map[string]string `yaml:"dna_query,omitempty" json:"dna_query,omitempty"`
}

// IsEmpty reports whether the filter has no criteria set,
// which means it would match every device in the fleet.
func (f Filter) IsEmpty() bool {
	return f.OS == "" && len(f.Tags) == 0 && len(f.Groups) == 0 && len(f.DNAQuery) == 0
}

// FleetQuery resolves a Filter into a set of matching device IDs.
// Implementations must re-evaluate the filter on each call — results must
// reflect current fleet state, not a cached snapshot. This guarantees that
// recurring scheduled workflows always target the current device population.
type FleetQuery interface {
	// Search returns the IDs of all devices that match the given filter.
	// An empty filter returns all known device IDs.
	// Returns an empty slice (not an error) when no devices match.
	Search(filter Filter) ([]string, error)
}

// Device represents a single device entry in the fleet registry.
type Device struct {
	// ID is the unique device identifier.
	ID string

	// OS is the operating system ("windows", "linux", "darwin").
	OS string

	// Tags are labels assigned to the device.
	Tags []string

	// Groups are group memberships for the device.
	Groups []string

	// Attributes holds arbitrary DNA key-value properties.
	Attributes map[string]string
}

// DeviceSource provides a snapshot of the current fleet for querying.
// The controller service implements this via its steward registry.
type DeviceSource interface {
	// ListDevices returns all currently known devices with their metadata.
	ListDevices() []Device
}

// StewardFleetQuery implements FleetQuery against a DeviceSource.
// It evaluates the filter on each Search call so that recurring workflows
// always see the current fleet state.
type StewardFleetQuery struct {
	source DeviceSource
}

// NewStewardFleetQuery creates a FleetQuery backed by the given DeviceSource.
func NewStewardFleetQuery(source DeviceSource) *StewardFleetQuery {
	return &StewardFleetQuery{source: source}
}

// Search returns all device IDs that match the filter.
// The filter is evaluated against the live DeviceSource on every call.
func (q *StewardFleetQuery) Search(filter Filter) ([]string, error) {
	devices := q.source.ListDevices()
	matches := make([]string, 0, len(devices))

	for _, d := range devices {
		if matchesFilter(d, filter) {
			matches = append(matches, d.ID)
		}
	}
	return matches, nil
}

// matchesFilter returns true when d satisfies all criteria in f.
// All criteria use AND semantics: every non-empty criterion must match.
func matchesFilter(d Device, f Filter) bool {
	// OS filter
	if f.OS != "" && !strings.EqualFold(d.OS, f.OS) {
		return false
	}

	// Tags filter — device must have ALL requested tags
	if len(f.Tags) > 0 {
		deviceTagSet := sliceToSet(d.Tags)
		for _, tag := range f.Tags {
			if !deviceTagSet[tag] {
				return false
			}
		}
	}

	// Groups filter — device must belong to ALL requested groups
	if len(f.Groups) > 0 {
		deviceGroupSet := sliceToSet(d.Groups)
		for _, group := range f.Groups {
			if !deviceGroupSet[group] {
				return false
			}
		}
	}

	// DNAQuery filter — all key=value pairs must match device attributes
	for key, value := range f.DNAQuery {
		if d.Attributes[key] != value {
			return false
		}
	}

	return true
}

// sliceToSet converts a string slice to a set (map[string]bool) for O(1) lookup.
func sliceToSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
}
