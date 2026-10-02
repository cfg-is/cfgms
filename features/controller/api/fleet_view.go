// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/cfgis/cfgms/pkg/ctxkeys"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// The fleet list used to be answered entirely from ControllerService's
// in-process steward map. That map is populated only by the registrations and
// reconnections THIS node handled, so in a cluster a steward actively
// heartbeating through one node was invisible on every other node — including
// the elected leader — while its row sat in the shared backend the whole time
// (measured live, story #3096, runbook §6 finding F4).
//
// The two sources are authoritative for different things, so the fix composes
// them rather than replacing one with the other:
//
//   - the durable StewardStore is authoritative for EXISTENCE, identity and
//     last-known status across the cluster;
//   - the local in-process map is authoritative for LIVE state on this node —
//     DNA, metrics and the heartbeat this node is actually receiving.
//
// A steward attached to a peer node therefore appears in the list with its
// durable facts and without fabricated liveness, which is exactly the
// distinction an operator needs.

// fleetRecords returns the cluster-wide steward set for a caller, keyed by
// steward ID, drawn from the durable store and filtered to the caller's tenant
// subtree.
//
// Tenant scoping uses the same isWithinTenantScope rule as handleGetSteward, so
// a scoped caller sees only its own subtree. That scoping is NEW to the
// unfiltered list path: it was previously safe to omit only because the
// in-process map was node-local, and reading the shared store without it would
// hand a tenant-scoped caller the entire cluster's fleet.
//
// Returns ok=false when no durable store is wired, which is the OSS
// composite-backend case; callers then fall back to the node-local view rather
// than reporting an empty fleet.
func (s *Server) fleetRecords(ctx context.Context, callerTenant string) (map[string]*business.StewardRecord, bool) {
	store := s.stewardStore
	if store == nil {
		return nil, false
	}
	records, err := store.ListStewards(ctx)
	if err != nil {
		// Degrade to the node-local view rather than serving an empty fleet: a
		// partial answer that says so is more useful to an operator than a
		// confident lie, and this path also runs on every dashboard poll.
		s.logger.Error("Failed to list stewards from durable store; falling back to node-local view",
			"error", logging.SanitizeLogValue(err.Error()))
		return nil, false
	}
	out := make(map[string]*business.StewardRecord, len(records))
	for _, rec := range records {
		if rec == nil || !isWithinTenantScope(callerTenant, rec.TenantID) {
			continue
		}
		out[rec.ID] = rec
	}
	return out, true
}

// durableStewardRecord fetches one steward from the durable store, or nil when
// there is no store, no such record, or the lookup fails. Used as the
// cluster-wide fallback when a steward is not attached to this node.
func (s *Server) durableStewardRecord(ctx context.Context, stewardID string) *business.StewardRecord {
	store := s.stewardStore
	if store == nil {
		return nil
	}
	rec, err := store.GetSteward(ctx, stewardID)
	if err != nil {
		// ErrStewardNotFound is the ordinary "no such steward" answer and is not
		// worth logging on a lookup path; anything else is a real store problem.
		if !errors.Is(err, business.ErrStewardNotFound) {
			s.logger.Error("Durable steward lookup failed",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
		}
		return nil
	}
	return rec
}

// writeStewardFromDurableRecord answers GET /stewards/{id} for a steward that
// exists in the shared backend but is not attached to this node.
//
// It reports connection_state "disconnected" and zero active sessions, which is
// accurate rather than pessimistic: the connection registry is per-node, so this
// node genuinely has no session with it. What it must NOT do is 404, which is
// what made a steward attached to a peer look non-existent (Issue #3480).
func (s *Server) writeStewardFromDurableRecord(w http.ResponseWriter, r *http.Request, rec *business.StewardRecord) {
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if !isWithinTenantScope(callerTenant, rec.TenantID) {
		// 404 rather than 403: never disclose existence across tenants.
		s.logger.Info("Cross-tenant steward get refused (durable record)",
			"steward_tenant", logging.SanitizeLogValue(rec.TenantID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	s.writeSuccessResponse(w, StewardInfo{
		ID:              rec.ID,
		TenantID:        rec.TenantID,
		Version:         rec.Version,
		Status:          string(rec.Status),
		LastSeen:        rec.LastSeen,
		Hidden:          rec.Hidden,
		ConnectionState: "disconnected",
		ActiveSessions:  0,
	})
}
