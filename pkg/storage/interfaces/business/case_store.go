// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package business defines the CaseStore interface for cockpit investigation cases.
package business

import (
	"context"
	"errors"
	"time"
)

// ErrCaseNotFound indicates no case record exists for the given ID.
var ErrCaseNotFound = errors.New("case not found")

// ErrPinNotFound indicates no pin exists for the given case and pin ID.
var ErrPinNotFound = errors.New("pin not found")

// CaseStatus represents the lifecycle state of a case (MVP: open/closed only;
// additional workflow states are cockpit-epic follow-on work per ADR-022 §8).
type CaseStatus string

const (
	CaseStatusOpen   CaseStatus = "open"
	CaseStatusClosed CaseStatus = "closed"
)

// TicketFieldSource identifies the provenance of a ticket field value.
type TicketFieldSource string

const (
	TicketFieldSourceEmail    TicketFieldSource = "email"
	TicketFieldSourceCallerID TicketFieldSource = "caller-id"
	TicketFieldSourcePSA      TicketFieldSource = "psa"
	TicketFieldSourceOperator TicketFieldSource = "operator"
	TicketFieldSourceInferred TicketFieldSource = "inferred"
)

// TicketField is a single provenanced ticket field: value, source, and filled/missing state.
// Per-field provenance is load-bearing in the cockpit UI (ADR-022 §8).
type TicketField struct {
	Value  string
	Source TicketFieldSource
	Filled bool
}

// Ticket is the structured intake record attached to a Case. Each field carries
// its own source and filled/missing state (ADR-022 §8).
type Ticket struct {
	Title    TicketField
	Client   TicketField
	Contact  TicketField
	Priority TicketField
	Category TicketField
}

// PinRefKind discriminates the five graph reference shapes a Pin can hold.
// Story 5 (pin REST) and Story 7 (evidence canvas) branch on this value.
type PinRefKind string

const (
	PinRefKindEID                PinRefKind = "eid"
	PinRefKindEdgeIdentity       PinRefKind = "edge-identity"
	PinRefKindObservationVersion PinRefKind = "observation-version"
	PinRefKindDriftRecord        PinRefKind = "drift-record"
	PinRefKindSubjectTimeRange   PinRefKind = "subject-time-range"
)

// PinRef is a discriminated graph reference. Only the fields relevant to Kind
// are populated; all others are zero values (ADR-022 §8).
type PinRef struct {
	Kind PinRefKind

	// EID is the entity-graph identifier. Populated when Kind == PinRefKindEID.
	EID string

	// EdgeIdentity is populated when Kind == PinRefKindEdgeIdentity.
	EdgeIdentity string

	// ObservationVersion is populated when Kind == PinRefKindObservationVersion.
	ObservationVersion string

	// DriftRecord is populated when Kind == PinRefKindDriftRecord.
	DriftRecord string

	// Subject is the entity ID anchor. TimeRangeStart and TimeRangeEnd are the
	// inclusive bounds. All three are populated when Kind == PinRefKindSubjectTimeRange;
	// a time-range is always anchored to a subject (ADR-022 §8).
	Subject        string
	TimeRangeStart time.Time
	TimeRangeEnd   time.Time
}

// Pin is a typed graph reference attached to a Case, with annotation and authorship.
type Pin struct {
	ID         string
	CaseID     string
	Ref        PinRef
	Annotation string
	Author     string
	PinnedAt   time.Time
}

// ContentKind distinguishes the three content entry types a Case holds (ADR-022 §8).
type ContentKind string

const (
	ContentKindFinding         ContentKind = "finding"
	ContentKindTranscriptEntry ContentKind = "transcript-entry"
	ContentKindNote            ContentKind = "note"
)

// ContentEntry is a typed case content entry: finding, transcript-entry, or note.
type ContentEntry struct {
	ID        string
	CaseID    string
	Kind      ContentKind
	Body      string
	Author    string
	CreatedAt time.Time
}

// Case is the investigation workspace: a per-field-provenanced ticket, graph-reference
// pins, and typed content entries, all anchored to a tenant (ADR-022 §8). The case's
// tenant is its visibility ceiling.
type Case struct {
	ID        string
	TenantID  string
	Status    CaseStatus
	Ticket    Ticket
	Pins      []*Pin
	Content   []*ContentEntry
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CaseStore persists cockpit investigation cases per ADR-022 §8. It is a standard
// business store (not a central provider) consumed by the cases feature only,
// matching the tenant_crossing_store precedent.
//
// GetCase returns the full aggregate (ticket + pins + content) in one call; there
// is no separate "get pins" read method — the convenience methods AddPin/RemovePin/
// ListPins exist for the REST layer's own convenience, but the canonical read path
// for a UI consumer is GetCase.
type CaseStore interface {
	CreateCase(ctx context.Context, c *Case) error
	GetCase(ctx context.Context, id string) (*Case, error)
	// ListCases returns cases within tenantID's subtree: tenantID itself plus any
	// descendant tenant (tenantID exact match or prefixed with tenantID+"/").
	ListCases(ctx context.Context, tenantID string) ([]*Case, error)
	UpdateCase(ctx context.Context, c *Case) error
	AddPin(ctx context.Context, caseID string, pin *Pin) error
	RemovePin(ctx context.Context, caseID, pinID string) error
	ListPins(ctx context.Context, caseID string) ([]*Pin, error)
	AddContent(ctx context.Context, caseID string, entry *ContentEntry) error
	ListContent(ctx context.Context, caseID string) ([]*ContentEntry, error)

	Initialize(ctx context.Context) error
	Close() error
}
