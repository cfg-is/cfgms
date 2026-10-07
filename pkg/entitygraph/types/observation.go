// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package types

import "time"

// ObservationKind classifies the intent of an observation (ADR-022 §4).
type ObservationKind string

const (
	ObservationKindState    ObservationKind = "state"
	ObservationKindPresence ObservationKind = "presence"
	ObservationKindAbsence  ObservationKind = "absence"

	// ObservationKindDriftDiff is written by the steward drift reporter for
	// each entity where actual state diverges from desired state (ADR-022 §6).
	// Drift-diff observations project to eg_drift_projection, not entity_current.
	ObservationKindDriftDiff ObservationKind = "drift-diff"

	// ObservationKindLifecycle is written by UpdateDriftLifecycle to record
	// workflow annotations (acknowledge/resolve/ignore) on drift records.
	// Tagged by actor rather than a source provenance class; appears distinctly
	// in GetHistory alongside state and drift-diff observations.
	ObservationKindLifecycle ObservationKind = "lifecycle"

	// ObservationKindDesiredState is written by the ConfigStore internal writer
	// (ADR-022 §6) when a config revision is pushed to a set of entities. Each
	// entity receives one desired-state observation per push; GetDesiredState
	// reads the most-recent such observation from the log. Desired-state
	// observations project into eg_entity_current for content-hash dedup but are
	// excluded from entity-state views and the entity index so they do not
	// contaminate the merged attribute set.
	ObservationKindDesiredState ObservationKind = "desired-state"

	// ObservationKindApplyOutcome is written by handleConfigAppliedEvent when a
	// steward ships its per-resource apply results via the event bus (ADR-022 §6,
	// Issue #3375). The observation payload carries status, error, module_name,
	// config_version, and the timestamp of the resource execution. Apply-outcome
	// observations are host-scoped only; the controller resolves
	// host:<peerHostAuthority>/<resourceID> from the mTLS-verified peer identity
	// and the bare resource ID the steward ships. GetTimeline surfaces these as
	// "apply-outcome" events alongside state-change events.
	ObservationKindApplyOutcome ObservationKind = "apply-outcome"
)

// Confidence is the producer-declared confidence level for an observation.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Observation is the single write primitive for entities, attributes, and edges
// alike (ADR-022 §4). Subject is either an EID or an edge identity string.
type Observation struct {
	Source     string          // source identity (e.g. "enforcing-module:hyperv")
	ObservedAt time.Time       // when true in the world, per the source
	RecordedAt time.Time       // when the controller ingested this observation
	Subject    string          // eid.String() or edge identity
	Kind       ObservationKind // state | presence | absence
	Confidence Confidence
	Payload    map[string]interface{} // typed, optional
}

// EdgeScopePattern is the edge-addressed variant of a claim scope pattern.
type EdgeScopePattern struct {
	EdgeType  string
	AnchorEID EID
	Direction TraversalDirection
}

// EntityScopePattern is the entity-addressed variant of a claim scope pattern.
type EntityScopePattern struct {
	EntityType      string
	AuthorityPrefix string
}

// ClaimScopePattern is a discriminated union of the two pattern kinds.
// Exactly one of Edge or Entity must be non-nil.
type ClaimScopePattern struct {
	Edge   *EdgeScopePattern
	Entity *EntityScopePattern
}

// ClaimScope declares the scope of a snapshot-style collector's assertion set
// per ADR-022 §4. An enumeration under a claim scope implicitly retracts any
// prior assertion by the same source inside that scope.
type ClaimScope struct {
	Source  string
	Pattern ClaimScopePattern
	AsOf    time.Time
}
