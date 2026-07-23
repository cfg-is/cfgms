// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package interfaces defines the EntityGraph pluggable central provider for CFGMS.
//
// The entity graph is the product-wide accumulation point for everything CFGMS
// knows about a deployment: typed entities, typed relationships, their state,
// provenance, and history (ADR-022).
package interfaces

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// ErrNotImplemented is returned by stub implementations that satisfy the
// interface at compile time but are not backed by real storage.
var ErrNotImplemented = errors.New("entitygraph: not implemented")

// EIDRef is an alias for types.EID so callers can import only this package.
type EIDRef = types.EID

// --- Request / Response types ---

// GetEntityOpts carries the optional collapse-group and temporal parameters for
// GetEntity (ADR-022 §9 table; §5 scopes collapse to GetEntity + temporal reads).
type GetEntityOpts struct {
	// AsOf, when non-nil, projects state as of this timestamp.
	AsOf *time.Time

	// CollapseGroup, when true, returns the merged same-as group view (§3).
	// The provider applies the tenant-cut before merging.
	CollapseGroup bool

	// TenantFilter is the mandatory caller-tenant-subtree filter (§7).
	TenantFilter string
}

// EntityFilter selects entities for QueryEntities.
type EntityFilter struct {
	Kind         string
	TenantFilter string
	AsOf         *time.Time
	TextQuery    string
	Attributes   map[string]interface{}
}

// PageToken is a cursor for paginated queries.
type PageToken struct {
	Token    string
	PageSize int
}

// EntityPage is the paginated result of QueryEntities.
type EntityPage struct {
	Entities  []*types.EntityView
	NextToken string
}

// EdgeFilter selects edges for GetEdges.
type EdgeFilter struct {
	// At least one of FromEID or ToEID must be set.
	FromEID      *EIDRef
	ToEID        *EIDRef
	Types        []string
	Source       string
	TenantFilter string
}

// EdgeView wraps an Edge with freshness metadata.
type EdgeView struct {
	Edge      *types.Edge
	Freshness types.Freshness
}

// TimeRange is an inclusive time interval for history and diff operations.
type TimeRange struct {
	From time.Time
	To   time.Time
}

// ObservationRecord is a historical observation entry returned by GetHistory.
type ObservationRecord struct {
	Observation types.Observation
	Version     int64
}

// StateDiff is the result of a two-point diff between entity states (ADR-022 §5).
type StateDiff struct {
	Subject EIDRef
	T1      time.Time
	T2      time.Time
	Changes []AttributeChange
}

// AttributeChange records one attribute's before/after in a StateDiff.
type AttributeChange struct {
	Attribute string
	Before    interface{}
	After     interface{}
	Source    string
}

// TimelineEvent is one entry in a merged change-event stream (ADR-022 §5).
type TimelineEvent struct {
	Subject    EIDRef
	OccurredAt time.Time
	Kind       string // "state-change" | "drift-detected" | "apply-outcome"
	Detail     map[string]interface{}
}

// DriftState holds the persisted desired-vs-actual delta for one entity (ADR-022 §6).
type DriftState struct {
	EID             EIDRef
	DetectedAt      time.Time
	Fields          []DriftField
	ConfigRevision  string
	LifecycleStatus string // "detected" | "acknowledged" | "resolved" | "ignored"
}

// DriftField is one attribute in a DriftState comparison.
type DriftField struct {
	Attribute string
	Desired   interface{}
	Actual    interface{}
	Matching  bool
}

// DriftFilter selects entities for ListDrifted.
type DriftFilter struct {
	TenantFilter    string
	LifecycleStatus string
	Kind            string
}

// WatchFilter selects the subjects for a Watch subscription.
type WatchFilter struct {
	TenantFilter string
	Kinds        []string
	EIDs         []EIDRef
}

// WatchEvent is one event delivered by the Watch cursor feed (ADR-022 §9).
type WatchEvent struct {
	Subject   EIDRef
	EventKind string // "entity-updated" | "edge-updated" | "drift-updated"
	Version   int64
	At        time.Time
}

// IdentityClaims carries device/object identity claims for ResolveIdentity (ADR-022 §9).
// This covers device claims only — not PSA/CRM contacts.
type IdentityClaims struct {
	Hostname            string
	MACAddrs            []string
	MachineSID          string
	DirectoryObjectGUID string
	SerialNumber        string
	CloudObjectID       string
}

// ObservationBatch groups observations under one source identity (ADR-022 §4/§9).
type ObservationBatch struct {
	// Source is the identity of the reporting collector.
	Source string

	// Observations is the batch of observations to ingest.
	Observations []types.Observation

	// ClaimScopes, when non-empty, declares snapshot scopes that trigger
	// implicit retraction of prior assertions outside this batch.
	ClaimScopes []types.ClaimScope
}

// DriftLifecycleUpdate carries a single drift lifecycle transition (ADR-022 §6/§9).
type DriftLifecycleUpdate struct {
	EID        EIDRef
	Transition string // "acknowledge" | "resolve" | "ignore"
	Actor      string // identity of the technician or automation
	At         time.Time
	Note       string
}

// --- Provider Interface ---

// EntityGraphProvider is the pluggable central provider contract for the entity
// graph (ADR-022 §9/§10). All read operations accept the mandatory tenant filter
// embedded in their opts/filter arguments. GetEntity is the only read that takes
// the collapse-group opts; GetDesiredState and GetDriftState take no opts.
//
// Implementations must be safe for concurrent use.
type EntityGraphProvider interface {
	// Identification.
	Name() string
	Description() string
	Available() (bool, error)

	// --- Read operations (ADR-022 §9 table) ---

	// GetEntity returns the current entity state, provenance, and freshness.
	// opts carries the mandatory tenant filter, optional as-of timestamp, and
	// collapse-group flag.
	GetEntity(ctx context.Context, eid EIDRef, opts GetEntityOpts) (*types.EntityView, error)

	// GetDesiredState returns the desired state and originating config revision.
	// Takes no opts parameter per ADR-022 §9.
	GetDesiredState(ctx context.Context, eid EIDRef) (*types.DesiredStateView, error)

	// GetDriftState returns the persisted drift-diff for a managed entity.
	// Takes no opts parameter per ADR-022 §9.
	GetDriftState(ctx context.Context, eid EIDRef) (*DriftState, error)

	// QueryEntities returns entities matching the filter, paged.
	QueryEntities(ctx context.Context, filter EntityFilter, page PageToken) (*EntityPage, error)

	// GetEdges returns edges matching the filter.
	GetEdges(ctx context.Context, filter EdgeFilter) ([]*EdgeView, error)

	// GetNeighborhood returns a depth-bounded connected subgraph starting at eid.
	// depth must be ≤3 per the access contract.
	GetNeighborhood(ctx context.Context, eid EIDRef, edgeTypes []string, direction types.TraversalDirection, depth int) (*types.Neighborhood, error)

	// GetHistory returns the versioned observation log for a subject over a time range.
	GetHistory(ctx context.Context, eid EIDRef, r TimeRange) ([]*ObservationRecord, error)

	// Diff returns the attribute delta between two points in time for a subject.
	Diff(ctx context.Context, eid EIDRef, r TimeRange) (*StateDiff, error)

	// GetTimeline returns a merged change-event stream for the given subjects.
	GetTimeline(ctx context.Context, eids []EIDRef, r TimeRange) ([]*TimelineEvent, error)

	// ListDrifted returns entities with active drift matching the filter.
	ListDrifted(ctx context.Context, filter DriftFilter) ([]*DriftState, error)

	// Watch returns a durable, cursor-replayable change feed.
	// cursor is the last-seen cursor position; empty starts from now.
	// The returned channel is closed when the context is cancelled.
	Watch(ctx context.Context, filter WatchFilter, cursor string) (<-chan WatchEvent, error)

	// ResolveIdentity returns the best-known EIDs for the given device/object
	// identity claims. Not a PSA/CRM contact lookup.
	ResolveIdentity(ctx context.Context, claims IdentityClaims) ([]EIDRef, error)

	// --- Write contract (collectors only, ADR-022 §9) ---

	// ReportObservations ingests a batch of observations from one source.
	ReportObservations(ctx context.Context, batch ObservationBatch) error

	// UpdateDriftLifecycle records a workflow annotation on a drift record.
	UpdateDriftLifecycle(ctx context.Context, update DriftLifecycleUpdate) error

	// RebuildProjections rebuilds all derived projection tables (entity index,
	// edge, and drift projections) from the observation log and current-state
	// tables. Used after a projection-logic change or schema migration so that
	// derived views reflect the full accumulated observation history (ADR-022 §6).
	RebuildProjections(ctx context.Context) error
}

// --- Provider Registry ---

var (
	egRegistry = &entityGraphRegistry{providers: make(map[string]EntityGraphProvider)}
)

type entityGraphRegistry struct {
	mu        sync.RWMutex
	providers map[string]EntityGraphProvider
}

// RegisterEntityGraphProvider registers an EntityGraphProvider.
// Returns an error if a provider with the same name is already registered.
// Call from init() functions in provider packages.
func RegisterEntityGraphProvider(p EntityGraphProvider) error {
	if p == nil {
		return fmt.Errorf("entitygraph: cannot register nil provider")
	}
	name := p.Name()
	if name == "" {
		return fmt.Errorf("entitygraph: provider name must not be empty")
	}

	egRegistry.mu.Lock()
	defer egRegistry.mu.Unlock()

	if _, exists := egRegistry.providers[name]; exists {
		return fmt.Errorf("entitygraph: provider %q already registered", name)
	}
	egRegistry.providers[name] = p
	return nil
}

// GetEntityGraphProvider retrieves a registered provider by name.
// Returns an error if no provider with that name is registered.
func GetEntityGraphProvider(name string) (EntityGraphProvider, error) {
	egRegistry.mu.RLock()
	defer egRegistry.mu.RUnlock()

	p, ok := egRegistry.providers[name]
	if !ok {
		return nil, fmt.Errorf("entitygraph: provider %q not registered", name)
	}
	return p, nil
}

// ListEntityGraphProviders returns all registered provider names.
func ListEntityGraphProviders() []string {
	egRegistry.mu.RLock()
	defer egRegistry.mu.RUnlock()

	names := make([]string, 0, len(egRegistry.providers))
	for name := range egRegistry.providers {
		names = append(names, name)
	}
	return names
}

// UnregisterEntityGraphProvider removes a provider from the registry.
// Primarily for testing; returns true if the provider was found and removed.
func UnregisterEntityGraphProvider(name string) bool {
	egRegistry.mu.Lock()
	defer egRegistry.mu.Unlock()

	if _, ok := egRegistry.providers[name]; ok {
		delete(egRegistry.providers, name)
		return true
	}
	return false
}
