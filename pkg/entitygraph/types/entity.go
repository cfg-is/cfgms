// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import "time"

// Entity is a node in the entity graph: a typed asset known to CFGMS.
// Current state is a projection over accumulated observations (ADR-022 §4).
type Entity struct {
	EID          EID
	Kind         string
	Attributes   map[string]interface{}
	OwningTenant string
}

// Freshness captures how current a piece of knowledge is (ADR-022 §4).
type Freshness struct {
	// ObservedAt is when the source observed this value.
	ObservedAt time.Time
	// RecordedAt is when the controller ingested this value.
	RecordedAt time.Time
	// Stale reports whether the observation is past its declared cadence.
	Stale bool
}

// EntityView is the read-projected view returned by GetEntity.
// It includes the current state, provenance summary, freshness, and an
// optional collapsed same-as group view (ADR-022 §3/§9).
type EntityView struct {
	Entity    *Entity
	Sources   []Observation
	Freshness Freshness

	// CollapseGroup, when non-nil, is the merged view of the same-as group
	// after the tenant-cut and source-precedence rules are applied (§3).
	CollapseGroup *CollapseGroupView
}

// CollapseGroupView is the merged entity view across a same-as group (ADR-022 §3).
type CollapseGroupView struct {
	Members   []EID
	Merged    map[string]interface{} // attribute key → winning value
	Conflicts map[string][]AttributeConflict
}

// AttributeConflict holds the competing values for one attribute in a collapse group.
type AttributeConflict struct {
	Source string
	Value  interface{}
}

// DesiredStateView is the return type for GetDesiredState (ADR-022 §6/§9).
type DesiredStateView struct {
	EID            EID
	State          map[string]interface{}
	ConfigRevision string
	ObservedAt     time.Time
}
