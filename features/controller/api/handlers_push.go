// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/push"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	configstorewriter "github.com/cfgis/cfgms/pkg/entitygraph/writers/configstore"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// egConfigstoreIngestor is the narrow interface the config-push handler needs
// to record desired-state observations into the entity graph after a push is
// accepted. *configstorewriter.Writer satisfies it.
type egConfigstoreIngestor interface {
	Ingest(ctx context.Context, rev configstorewriter.ConfigRevision, eids []egtypes.EID) error
}

// leaderStatus is the minimal interface the config-push handler needs from the
// HA manager. *ha.Manager satisfies it automatically; test doubles use stubLeaderStatus.
//
// HasLeadership(), not IsLeader() (Issue #3389): config push is side-effecting —
// past this gate, handleConfigPush resolves the selector, queries the fleet, writes
// desired state to the entity graph, and fans out to stewards via commandPublisher,
// with no Raft commit anywhere in that path. IsLeader()/IsRaftLeader() only guarantee
// replicated-log write-safety, which never covered these effects — the lease-backed
// HasLeadership() is the correct admission primitive here (ADR-029 Decision 3).
type leaderStatus interface {
	HasLeadership() bool
}

// configPushRequest is the JSON body for POST /api/v1/config/push.
// Selector selects which stewards receive the push; it is required and must not
// be empty — use "all" to target every steward in the configuration's tenant.
// The StewardConfiguration fields (config_id, version, tenant_id, …) are promoted
// to the top-level JSON object by Go's embedded-struct encoding.
type configPushRequest struct {
	Selector string `json:"selector"`
	push.StewardConfiguration
}

// handleConfigPush implements POST /api/v1/config/push.
//
// Validates the request, resolves the target selector scoped to cfg.TenantID
// (never the caller's tenant), records an audit event, triggers a fire-and-forget
// fan-out to matched stewards via commandPublisher, and returns 202 Accepted.
func (s *Server) handleConfigPush(w http.ResponseWriter, r *http.Request) {
	// Reject callers without lease-backed authority immediately — only a node that
	// currently holds the lease accepts config pushes (Issue #3389). During a normal
	// leader handover this returns 503 for up to a lease duration; that is the accepted
	// tradeoff recorded in epic #3386's design, not a regression. The message
	// deliberately does not name or imply which other node holds leadership.
	if checker := s.pushLeaderStatus; checker != nil && !checker.HasLeadership() {
		s.respondError(w, http.StatusServiceUnavailable, "not the leader")
		return
	}

	// Require an authenticated principal.
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.respondError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Decode and validate request body.
	var req configPushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Warn("Failed to decode config push body", "error", logging.SanitizeLogValue(err.Error()))
		s.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cfg := req.StewardConfiguration

	if cfg.ConfigID == "" || cfg.Version == "" || cfg.TenantID == "" {
		s.logger.Warn("Config push request missing required fields",
			"config_id", logging.SanitizeLogValue(cfg.ConfigID),
			"version", logging.SanitizeLogValue(cfg.Version),
			"tenant_id", logging.SanitizeLogValue(cfg.TenantID),
		)
		s.respondError(w, http.StatusBadRequest, "config_id, version, and tenant_id are required")
		return
	}

	// Authorize caller: tenant-scoped callers may only push configs labelled with
	// their own tenant. Admin callers (TenantID == "") may push any cfg.TenantID,
	// but the fan-out is still scoped to that specific tenant — never left empty.
	if principal.TenantID != "" && principal.TenantID != cfg.TenantID {
		s.respondError(w, http.StatusForbidden, "caller may only push configs for their own tenant")
		return
	}

	// Require an explicit, non-empty selector — no implicit "all" default.
	if req.Selector == "" {
		s.respondError(w, http.StatusBadRequest, "selector is required: use 'all' to match all stewards")
		return
	}
	// Strip newlines so CodeQL's go/log-injection taint cannot reach log calls.
	safeSelector := strings.ReplaceAll(strings.ReplaceAll(req.Selector, "\n", ""), "\r", "")

	filter, parsedTenantPath, err := selector.Parse(req.Selector)
	if err != nil {
		s.logger.Info("Invalid selector expression", "selector", safeSelector, "error", logging.SanitizeLogValue(err.Error()))
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Scope to cfg.TenantID subtree. An explicit selector prefix must be within
	// that subtree; absent prefix defaults to cfg.TenantID and all descendants.
	if parsedTenantPath != "" {
		if parsedTenantPath != cfg.TenantID && !strings.HasPrefix(parsedTenantPath, cfg.TenantID+"/") {
			s.logger.Info("Selector tenant outside config tenant subtree",
				"parsed_tenant", logging.SanitizeLogValue(parsedTenantPath),
				"config_tenant", logging.SanitizeLogValue(cfg.TenantID))
			s.respondError(w, http.StatusForbidden, "selector tenant outside config tenant subtree")
			return
		}
		filter.TenantSubtree = parsedTenantPath
	} else {
		filter.TenantSubtree = cfg.TenantID
	}

	results, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Fleet query failed during config push", "error", logging.SanitizeLogValue(err.Error()), "selector", safeSelector)
		s.respondError(w, http.StatusInternalServerError, "fleet query failed")
		return
	}

	// Build matched-ID set, then filter GetAllStewards() to those IDs.
	// This bridges fleet.StewardResult → *service.StewardInfo for Fanout
	// without any new interface methods.
	matchedIDs := make(map[string]struct{}, len(results))
	for _, res := range results {
		matchedIDs[res.ID] = struct{}{}
	}
	targeted := make([]*service.StewardInfo, 0, len(matchedIDs))
	for _, st := range s.controllerService.GetAllStewards() {
		if _, hit := matchedIDs[st.ID]; hit {
			targeted = append(targeted, st)
		}
	}

	pushID := fmt.Sprintf("push-%d", time.Now().UnixNano())
	queuedAt := time.Now().UTC()

	// Write desired-state observations for every targeted steward into the
	// entity graph so that GetDesiredState reflects the new config revision
	// before the fan-out completes (ADR-022 §6). Best-effort: a failure here
	// does not block the push — the fan-out and audit are more critical.
	if s.egConfigstoreWriter != nil {
		eids := make([]egtypes.EID, 0, len(targeted))
		for _, st := range targeted {
			if eid, eidErr := egtypes.NewEID("cfgms", "controller", st.ID); eidErr == nil {
				eids = append(eids, eid)
			}
		}
		egRev := configstorewriter.ConfigRevision{
			ConfigID: cfg.ConfigID,
			Revision: cfg.Version,
			TenantID: cfg.TenantID,
			DesiredState: map[string]interface{}{
				"policies": cfg.Policies,
				"modules":  cfg.Modules,
			},
		}
		if err := s.egConfigstoreWriter.Ingest(r.Context(), egRev, eids); err != nil {
			s.logger.Warn("Failed to ingest desired-state observations into entity graph",
				"push_id", pushID,
				"error", logging.SanitizeLogValue(err.Error()),
			)
		}
	}

	s.emitConfigPushAudit(r, cfg.TenantID, cfg.ConfigID, pushID)

	// Build the push record (the "config write") up front. It is persisted
	// below in the same transaction as the per-steward delivery rows it
	// requires (Issue #3757, ADR-031 Decision 2: "config write + notify
	// steward X are atomic") whenever a commandStore is configured — a
	// controller crash between the two can no longer leave a push recorded
	// with no trace that stewards were ever owed it, or delivery rows with no
	// corresponding push.
	var pushRecord *business.PushRecord
	if s.pushStore != nil {
		pushData, marshalErr := json.Marshal(&cfg)
		if marshalErr != nil {
			s.logger.Warn("Failed to marshal push payload for persistence", "error", logging.SanitizeLogValue(marshalErr.Error()), "push_id", pushID)
		} else {
			pushRecord = &business.PushRecord{
				ID:        pushID,
				ConfigID:  cfg.ConfigID,
				TenantID:  cfg.TenantID,
				Version:   cfg.Version,
				Status:    business.PushStatusInProgress,
				Data:      pushData,
				CreatedAt: queuedAt,
				UpdatedAt: queuedAt,
			}
		}
	}

	// Issue #3757 (ADR-031 Decision 2): one durable delivery/outbox row per
	// targeted steward, all in a single transaction — either every steward this
	// push targets gets a trackable pending row, or none do. This replaces the old
	// detached fire-and-forget goroutine, whose only durable trace was the
	// aggregate PushRecord above; a controller crash between that goroutine
	// starting and finishing silently dropped delivery to whichever stewards had
	// not yet been reached, with no record that they were ever owed a push.
	recordsByStewardID := make(map[string]*business.CommandRecord, len(targeted))
	var records []*business.CommandRecord
	if s.commandStore != nil && len(targeted) > 0 {
		records = make([]*business.CommandRecord, 0, len(targeted))
		for _, st := range targeted {
			rec := &business.CommandRecord{
				ID:        fmt.Sprintf("%s-%s", pushID, st.ID),
				Type:      string(controlplaneTypes.CommandSyncConfig),
				StewardID: st.ID,
				TenantID:  cfg.TenantID,
				Payload: map[string]interface{}{
					"push_id":   pushID,
					"config_id": cfg.ConfigID,
					"version":   cfg.Version,
				},
				IssuedAt:       queuedAt,
				IssuedBy:       principal.ID,
				DeliveryStatus: business.DeliveryStatusPending,
			}
			records = append(records, rec)
			recordsByStewardID[st.ID] = rec
		}
	}

	switch {
	case s.commandStore != nil:
		// The transactional-CommandStore seam: pushRecord (nil when no
		// pushStore is configured) and records (empty when no steward matched)
		// commit together, or neither commits.
		if err := s.commandStore.CreatePushAndCommandRecords(r.Context(), pushRecord, records); err != nil {
			s.logger.Error("Failed to durably record config push and its deliveries",
				"push_id", pushID, "error", logging.SanitizeLogValue(err.Error()))
			recordsByStewardID = nil
		}
	case s.pushStore != nil && pushRecord != nil:
		// No commandStore configured in this deployment, so there are no
		// delivery rows to co-commit the push record with.
		if err := s.pushStore.CreatePush(r.Context(), pushRecord); err != nil {
			s.logger.Warn("Failed to persist push record", "error", logging.SanitizeLogValue(err.Error()), "push_id", pushID)
		}
	}

	// Drain immediately via the existing node-local fan-out path (still the only
	// delivery mechanism in this story; cross-node delivery via a shared routing
	// table arrives in S10). Synchronous, not detached: even when a durable
	// delivery row exists, nothing is gained by detaching this attempt — the row
	// already guarantees the obligation survives a failed attempt or a process
	// stop, and detaching it is exactly what left per-steward outcomes
	// unobserved before. Runs whenever commandPublisher is configured,
	// independent of commandStore — deployments without a durable command store
	// still get best-effort fan-out, same as before this story.
	if s.commandPublisher != nil {
		result := push.Fanout(r.Context(), &cfg, targeted, s.commandPublisher, s.logger)
		s.logger.Info("Config push fan-out complete",
			"push_id", pushID,
			"succeeded", len(result.Succeeded),
			"failed", len(result.Failed))

		for _, stewardID := range result.Succeeded {
			rec := recordsByStewardID[stewardID]
			if rec == nil {
				continue
			}
			if err := s.commandStore.UpdateDeliveryStatus(r.Context(), rec.ID, business.DeliveryStatusDelivered, ""); err != nil {
				s.logger.Warn("Failed to record delivered status", "push_id", pushID,
					"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
				continue
			}
			rec.DeliveryStatus = business.DeliveryStatusDelivered
		}
		for stewardID, deliveryErr := range result.Failed {
			s.logger.Error("Config push fan-out delivery failed",
				"push_id", pushID,
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(deliveryErr.Error()))
			rec := recordsByStewardID[stewardID]
			if rec == nil {
				continue
			}
			// Transport attempt failed but the row itself stays pending, not
			// terminally failed: the outbox row is the guarantee under the fast
			// path (ADR-031 Decision 2/3) — it drains on the steward's next
			// reconnect rather than being abandoned after one failed attempt.
			detail := logging.SanitizeLogValue(deliveryErr.Error())
			if err := s.commandStore.UpdateDeliveryStatus(r.Context(), rec.ID, business.DeliveryStatusPending, detail); err != nil {
				s.logger.Warn("Failed to record delivery attempt failure", "push_id", pushID,
					"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
				continue
			}
			rec.DeliveryDetail = detail
		}

		if s.pushStore != nil {
			finalStatus := business.PushStatusCompleted
			if len(result.Failed) > 0 && len(result.Succeeded) == 0 {
				finalStatus = business.PushStatusFailed
			}
			if updateErr := s.pushStore.UpdatePushStatus(r.Context(), pushID, finalStatus); updateErr != nil {
				s.logger.Warn("Failed to update push record status", "error", logging.SanitizeLogValue(updateErr.Error()), "push_id", pushID)
			}
		}
	}

	deliveries := make([]*ConfigPushDelivery, 0, len(recordsByStewardID))
	for _, st := range targeted {
		rec := recordsByStewardID[st.ID]
		if rec == nil {
			continue
		}
		deliveries = append(deliveries, &ConfigPushDelivery{
			StewardID: st.ID,
			CommandID: rec.ID,
			Status:    string(rec.DeliveryStatus),
		})
	}

	s.respondJSON(w, http.StatusAccepted, ConfigPushResponse{
		PushID:     pushID,
		Status:     "accepted",
		QueuedAt:   queuedAt,
		Deliveries: deliveries,
	})
}

// handleGetConfigPush implements GET /api/v1/config/push/{id}.
//
// Retrieves a single push record by ID. Returns 404 for unknown IDs or records
// owned by a different tenant — returning 403 would disclose that the push ID
// exists (mirrors runVisibleTo in handlers_runs.go). Returns 503 when the push
// store is unavailable.
func (s *Server) handleGetConfigPush(w http.ResponseWriter, r *http.Request) {
	if s.pushStore == nil {
		s.respondError(w, http.StatusServiceUnavailable, "push store not available")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.respondError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := mux.Vars(r)["id"]

	record, err := s.pushStore.GetPush(r.Context(), id)
	if errors.Is(err, business.ErrPushNotFound) {
		s.respondError(w, http.StatusNotFound, "push not found")
		return
	}
	if err != nil {
		s.logger.Error("Failed to retrieve push record",
			"push_id", logging.SanitizeLogValue(id), "error", logging.SanitizeLogValue(err.Error()))
		s.respondError(w, http.StatusInternalServerError, "failed to retrieve push record")
		return
	}

	// Tenant isolation: return 404 (not 403) on mismatch to avoid leaking
	// cross-tenant push existence. requirePermission path-var isolation does not
	// cover push-ID path vars (middleware.go:775), so this check is explicit here.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if !isWithinTenantScope(callerTenant, record.TenantID) {
		s.respondError(w, http.StatusNotFound, "push not found")
		return
	}

	s.respondJSON(w, http.StatusOK, PushStatusResponse{
		PushID:      record.ID,
		ConfigID:    record.ConfigID,
		TenantID:    record.TenantID,
		Version:     record.Version,
		Status:      string(record.Status),
		InitiatedBy: record.InitiatedBy,
		CreatedAt:   record.CreatedAt,
		UpdatedAt:   record.UpdatedAt,
	})
}

// emitConfigPushAudit records an audit event for a config push initiation.
// It is a no-op when auditManager is nil and never blocks or fails the caller.
func (s *Server) emitConfigPushAudit(r *http.Request, tenantID, configID, pushID string) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action("config.push.initiated").
		User(audit.SystemUserID, business.AuditUserTypeSystem).
		Resource("config", logging.SanitizeLogValue(configID), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityMedium).
		Detail("push_id", pushID).
		Detail("config_id", logging.SanitizeLogValue(configID))
	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Warn("Failed to emit config push audit event", "error", err, "push_id", pushID)
	}
}
