// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package tenantsync implements the TenantStore → tenant-tree entity-graph
// internal writer (ADR-022 §7, Issue #3370). It mirrors the CFGMS tenant
// hierarchy as tenant:* entities connected by contains edges, making tenancy
// traversable via GetNeighborhood alongside every other structural relationship.
//
// # Source identity
//
// Every observation written by this package carries Source = "tenantstore".
// The source is distinct from operator:*, config:*, and module authorities so
// the mirror's observations are clearly attributable and retractable as a unit.
//
// # EID form
//
// Each tenant is identified as cfgms:tenant/<tenantID>. "cfgms" is the
// registered authority type for CFGMS-internal entities (eid.go), and "tenant"
// is a seeded entity kind with AuthorityClasses: []string{"cfgms"}
// (taxonomy.go). No taxonomy change is required.
//
// The tenant ID is carried in the EID's local_id, never in the authority name.
// CFGMS tenant IDs are path-based by design (root/msp-a/client-1), and NewEID
// rejects an authority name containing '/' while permitting it in a local_id —
// so a hierarchical tenant ID is representable only in this form.
//
// # Quarantine, not abort
//
// A tenant row that cannot be represented (an empty ID, or an ID containing the
// reserved edge-subject delimiter "|") is skipped with a sanitized warning; the
// rest of the snapshot is written normally. A single malformed row — a
// ParentID is persisted verbatim by the tenant API — must never wedge the
// fleet-wide mirror, because aborting the batch would also stop claim-scope
// retraction and leave deleted tenants in the graph indefinitely. A skipped
// tenant is absent from the snapshot and is therefore retracted by the entity
// claim scope like any other removed tenant.
//
// # Re-sync and retraction
//
// Every Ingest call is a full-tree snapshot. Two claim-scope mechanisms ensure
// stale observations are retracted on re-sync:
//
//  1. EntityScopePattern{AuthorityPrefix: "cfgms:tenant/"} — retracts any
//     mirrored tenant entity observation whose EID is absent from the current
//     snapshot (deleted tenants are removed from the entity index on the next
//     Ingest call).
//
//  2. Per-tenant EdgeScopePattern{EdgeType: "contains", AnchorEID: <tenantEID>,
//     Direction: TraversalOutbound} — for every tenant still present in the
//     snapshot, any outbound contains edge that was asserted in a prior sync but
//     is absent from the current snapshot is retracted. This handles the case
//     where a child tenant is deleted while its parent still exists.
//
// When a parent tenant is removed, its entity is retracted by the entity scope.
// Its formerly-emitted child edges are not retracted in the same cycle (the
// parent's per-tenant edge scope is omitted from the new batch); they are
// cleaned up by the retention GC tombstone sweep.
//
// # Authorization note
//
// ADR-022 §7 is explicit: authorization never uses graph traversal. The owning-
// tenant attribute on each entity remains the sole access-control axis. This
// package does not set owning_tenant on tenant entities — they are structural
// nodes for graph traversal only.
package tenantsync

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// source is the fixed source identity for all observations emitted by this writer.
const source = "tenantstore"

// tenantAuthority is the authority name shared by every mirrored tenant. The
// tenant ID itself is the local_id, which — unlike an authority name — may
// contain '/' and so can carry a path-based tenant ID.
const tenantAuthority = "tenant"

// authorityPrefix scopes entity retraction to this writer's own EID space.
const authorityPrefix = "cfgms:" + tenantAuthority + "/"

// edgeSubjectSep is the delimiter used in edge-subject strings. EID strings
// containing this character would produce non-injective edge subjects, so
// tenant IDs containing it are quarantined rather than mirrored.
const edgeSubjectSep = "|"

// Writer is the TenantStore → tenant-tree entity-graph internal writer.
type Writer struct {
	provider interfaces.EntityGraphProvider
	logger   logging.Logger
}

// New returns a Writer backed by provider. provider must not be nil.
func New(provider interfaces.EntityGraphProvider) (*Writer, error) {
	if provider == nil {
		return nil, fmt.Errorf("tenantsync/writer: provider must not be nil")
	}
	return &Writer{provider: provider, logger: logging.NewLogger("info")}, nil
}

// WithLogger replaces the writer's logger, which receives one warning per
// quarantined tenant row. A nil logger is ignored.
func (w *Writer) WithLogger(logger logging.Logger) *Writer {
	if logger != nil {
		w.logger = logger
	}
	return w
}

// tenantEID builds the mirrored EID for a tenant ID. The ID is placed in the
// local_id so that path-based IDs (root/msp-a/client-1) are representable.
//
// IDs containing edgeSubjectSep are rejected: they would make the edge subject
// "contains|<parent>|<child>" ambiguous to parse.
func tenantEID(tenantID string) (types.EID, error) {
	if tenantID == "" {
		return types.EID{}, fmt.Errorf("tenant id must not be empty")
	}
	if strings.Contains(tenantID, edgeSubjectSep) {
		return types.EID{}, fmt.Errorf("tenant id contains reserved delimiter %q", edgeSubjectSep)
	}
	return types.NewEID("cfgms", tenantAuthority, tenantID)
}

// Ingest reads the complete tenant tree from store and writes it into the
// entity graph as cfgms:tenant/<tenantID> entities and contains edges.
//
// Each call is a full-tree snapshot. Claim scopes ensure that deleted tenants
// and their edges are retracted on the following sync.
//
// If store.ListTenants returns an error the call propagates the error and writes
// nothing, preventing accidental retraction of all mirrored tenants. A single
// unrepresentable tenant row, by contrast, is quarantined (skipped and warned
// about) so it cannot wedge the fleet-wide snapshot.
func (w *Writer) Ingest(ctx context.Context, store business.TenantStore) error {
	tenants, err := store.ListTenants(ctx, nil)
	if err != nil {
		return fmt.Errorf("tenantsync/writer: list tenants: %w", err)
	}

	now := time.Now().UTC()

	var obs []types.Observation
	// claimScopes is seeded with the entity scope and extended below with
	// per-tenant edge scopes.
	claimScopes := []types.ClaimScope{
		{
			Source: source,
			Pattern: types.ClaimScopePattern{
				Entity: &types.EntityScopePattern{
					AuthorityPrefix: authorityPrefix,
				},
			},
			AsOf: now,
		},
	}

	for _, t := range tenants {
		eid, err := tenantEID(t.ID)
		if err != nil {
			// Quarantine the row: skipping one tenant keeps the rest of the
			// snapshot — and its claim-scope retraction — intact.
			w.logger.WarnCtx(ctx, "tenantsync: skipping tenant with unrepresentable id",
				"tenant_id", logging.SanitizeLogValue(t.ID),
				"error", logging.SanitizeLogValue(err.Error()))
			continue
		}

		obs = append(obs, types.Observation{
			Source:     source,
			ObservedAt: now,
			RecordedAt: now,
			Subject:    eid.String(),
			Kind:       types.ObservationKindState,
			Confidence: types.ConfidenceHigh,
			Payload: map[string]interface{}{
				"entity_kind":   "tenant",
				"tenant_name":   t.Name,
				"tenant_status": string(t.Status),
			},
		})

		// Outbound-contains edge scope for this tenant. Even when the tenant
		// currently has no children, this scope is included so that a previously
		// asserted child edge is retracted when the child is removed.
		claimScopes = append(claimScopes, types.ClaimScope{
			Source: source,
			Pattern: types.ClaimScopePattern{
				Edge: &types.EdgeScopePattern{
					EdgeType:  "contains",
					AnchorEID: eid,
					Direction: types.TraversalOutbound,
				},
			},
			AsOf: now,
		})

		if t.ParentID == "" {
			continue
		}

		parentEID, err := tenantEID(t.ParentID)
		if err != nil {
			// The tenant itself is still mirrored; only the edge to its
			// unrepresentable parent is dropped.
			w.logger.WarnCtx(ctx, "tenantsync: skipping contains edge with unrepresentable parent id",
				"tenant_id", logging.SanitizeLogValue(t.ID),
				"parent_id", logging.SanitizeLogValue(t.ParentID),
				"error", logging.SanitizeLogValue(err.Error()))
			continue
		}

		edgeSubject := "contains" + edgeSubjectSep + parentEID.String() + edgeSubjectSep + eid.String()
		obs = append(obs, types.Observation{
			Source:     source,
			ObservedAt: now,
			RecordedAt: now,
			Subject:    edgeSubject,
			Kind:       types.ObservationKindState,
			Confidence: types.ConfidenceHigh,
			Payload:    map[string]interface{}{},
		})
	}

	return w.provider.ReportObservations(ctx, interfaces.ObservationBatch{
		Source:       source,
		Observations: obs,
		ClaimScopes:  claimScopes,
	})
}
