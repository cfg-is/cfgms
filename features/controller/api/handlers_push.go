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

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/controller/fleet/selector"
	"github.com/cfgis/cfgms/features/controller/push"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/audit"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
	configstorewriter "github.com/cfgis/cfgms/pkg/entitygraph/writers/configstore"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// egConfigstoreIngestor is the narrow interface the config-push handler needs
// to record desired-state observations into the entity graph after a push is
// accepted. *configstorewriter.Writer satisfies it.
type egConfigstoreIngestor interface {
	Ingest(ctx context.Context, rev configstorewriter.ConfigRevision, eids []egtypes.EID) error
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
	// Require an authenticated principal, routed through the same assurance and
	// empty-tenant guard as handleGetJob/handleCreateJob/handlePostRunScript/
	// handlePostRunCommand (Issue #4335), rather than a separate ad hoc check: a
	// machine principal with no tenant is rejected here too.
	principal, tenantID, ok := s.authRunAccess(w, r)
	if !ok {
		return
	}

	req, ok := s.decodeConfigPushRequest(w, r)
	if !ok {
		return
	}
	cfg := req.StewardConfiguration

	if !s.authorizeConfigPushTenant(w, r, tenantID, cfg.TenantID) {
		return
	}

	filter, safeSelector, ok := s.scopeConfigPushSelector(w, r, req.Selector, cfg.TenantID)
	if !ok {
		return
	}

	targeted, ok := s.resolveConfigPushTargets(w, r, filter, safeSelector)
	if !ok {
		return
	}

	pushID := fmt.Sprintf("push-%d", time.Now().UnixNano())
	queuedAt := time.Now().UTC()

	s.ingestConfigPushDesiredState(r, &cfg, targeted, pushID)

	s.emitConfigPushAudit(r, principal, cfg.TenantID, cfg.ConfigID, pushID)

	pushRecord := s.buildConfigPushRecord(&cfg, principal, targeted, pushID, queuedAt)
	records, recordsByStewardID := s.buildConfigPushDeliveryRecords(&cfg, principal, targeted, pushID, queuedAt)
	recordsByStewardID = s.persistConfigPush(r, pushRecord, records, recordsByStewardID, pushID)

	s.fanOutConfigPush(r, &cfg, targeted, recordsByStewardID, pushID)

	s.respondJSON(w, http.StatusAccepted, ConfigPushResponse{
		PushID:     pushID,
		Status:     "accepted",
		QueuedAt:   queuedAt,
		Deliveries: configPushDeliveries(targeted, recordsByStewardID),
	})
}

// decodeConfigPushRequest decodes and validates the request body. It writes the
// rejection and returns ok=false on a malformed body or missing required fields.
func (s *Server) decodeConfigPushRequest(w http.ResponseWriter, r *http.Request) (configPushRequest, bool) {
	var req configPushRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Warn("Failed to decode config push body", "error", logging.SanitizeLogValue(err.Error()))
		s.respondError(w, http.StatusBadRequest, "invalid request body")
		return req, false
	}
	cfg := req.StewardConfiguration

	if cfg.ConfigID == "" || cfg.Version == "" || cfg.TenantID == "" {
		s.logger.Warn("Config push request missing required fields",
			"config_id", logging.SanitizeLogValue(cfg.ConfigID),
			"version", logging.SanitizeLogValue(cfg.Version),
			"tenant_id", logging.SanitizeLogValue(cfg.TenantID),
		)
		s.respondError(w, http.StatusBadRequest, "config_id, version, and tenant_id are required")
		return req, false
	}
	return req, true
}

// authorizeConfigPushTenant authorizes the caller for cfgTenantID: tenant-scoped
// callers may only push configs labelled with their own tenant. A root caller may
// push any cfg.TenantID that passes its tenant decision — a root caller subject to
// the ADR-025 boundary needs a crossing for a tenant below root (Issue #4665) — and
// the fan-out is still scoped to that specific tenant, never left empty. It writes
// the rejection and returns false when the caller is not authorized.
func (s *Server) authorizeConfigPushTenant(w http.ResponseWriter, r *http.Request, callerTenantID, cfgTenantID string) bool {
	if callerTenantID != "" && callerTenantID != cfgTenantID { //architecture:allow-root-scope -- tenant-scoped callers: exact tenant match
		s.respondError(w, http.StatusForbidden, "caller may only push configs for their own tenant")
		return false
	}
	if access := s.tenantAccessForScope(r.Context(), callerTenantScope(r), cfgTenantID, "POST /api/v1/config/push"); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, cfgTenantID) {
			s.respondError(w, http.StatusForbidden, "caller may only push configs for their own tenant")
		}
		return false
	}
	return true
}

// scopeConfigPushSelector requires a non-empty selector, parses it and scopes the
// resulting filter to the cfg tenant subtree. It returns the filter and the
// log-safe selector, or writes the rejection and returns ok=false.
func (s *Server) scopeConfigPushSelector(w http.ResponseWriter, r *http.Request, rawSelector, cfgTenantID string) (fleet.Filter, string, bool) {
	// Require an explicit, non-empty selector — no implicit "all" default.
	if rawSelector == "" {
		s.respondError(w, http.StatusBadRequest, "selector is required: use 'all' to match all stewards")
		return fleet.Filter{}, "", false
	}
	// Strip newlines so CodeQL's go/log-injection taint cannot reach log calls.
	safeSelector := logging.SanitizeLogValue(strings.ReplaceAll(strings.ReplaceAll(rawSelector, "\n", ""), "\r", ""))

	filter, parsedTenantPath, err := selector.Parse(rawSelector)
	if err != nil {
		s.logger.Info("Invalid selector expression", "selector", safeSelector, "error", logging.SanitizeLogValue(err.Error()))
		s.respondError(w, http.StatusBadRequest, err.Error())
		return filter, safeSelector, false
	}
	// Scope to cfg.TenantID subtree. An explicit selector prefix must be within
	// that subtree; absent prefix defaults to cfg.TenantID and all descendants.
	if parsedTenantPath != "" {
		if !selectorPathWithinCaller(cfgTenantID, parsedTenantPath) {
			s.logger.Info("Selector tenant outside config tenant subtree",
				"parsed_tenant", logging.SanitizeLogValue(parsedTenantPath),
				"config_tenant", logging.SanitizeLogValue(cfgTenantID))
			s.respondError(w, http.StatusForbidden, "selector tenant outside config tenant subtree")
			return filter, safeSelector, false
		}
		filter.TenantSubtree = parsedTenantPath
	} else {
		s.scopeFilterToTenantSubtree(r.Context(), &filter, cfgTenantID)
	}
	return filter, safeSelector, true
}

// resolveConfigPushTargets runs the fleet search for filter and returns the
// matched stewards as the fan-out set, or writes the failure and returns ok=false.
func (s *Server) resolveConfigPushTargets(w http.ResponseWriter, r *http.Request, filter fleet.Filter, safeSelector string) ([]*service.StewardInfo, bool) {
	results, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Fleet query failed during config push", "error", logging.SanitizeLogValue(err.Error()), "selector", safeSelector)
		s.respondError(w, http.StatusInternalServerError, "fleet query failed")
		return nil, false
	}

	// Build matched-ID set, then filter ListFleetStewards() to those IDs.
	// This bridges fleet.StewardResult → *service.StewardInfo for Fanout
	// without any new interface methods.
	matchedIDs := make(map[string]struct{}, len(results))
	for _, res := range results {
		matchedIDs[res.ID] = struct{}{}
	}
	// Unscoped read: matchedIDs above is already the authoritative, correctly
	// scoped set (filter.TenantSubtree = cfg.TenantID, never the caller's own
	// tenant — see handleConfigPush's doc comment). Passing r.Context() here
	// would additionally scope by the caller's tenant and could silently drop
	// a legitimately matched steward for a caller whose own tenant sits above
	// cfg.TenantID in the hierarchy. The read is marked system-internal
	// explicitly: a bare context.Background() carries no caller and is refused
	// (Issue #4665).
	targeted := make([]*service.StewardInfo, 0, len(matchedIDs))
	for _, st := range s.controllerService.ListFleetStewards(ctxkeys.WithSystem(r.Context())) {
		if _, hit := matchedIDs[st.ID]; hit {
			targeted = append(targeted, st)
		}
	}
	return targeted, true
}

// ingestConfigPushDesiredState writes desired-state observations for every
// targeted steward into the entity graph so that GetDesiredState reflects the new
// config revision before the fan-out completes (ADR-022 §6). Best-effort: a
// failure here does not block the push — the fan-out and audit are more critical.
func (s *Server) ingestConfigPushDesiredState(r *http.Request, cfg *push.StewardConfiguration, targeted []*service.StewardInfo, pushID string) {
	if s.egConfigstoreWriter == nil {
		return
	}
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

// buildConfigPushRecord builds the push record (the "config write") up front. It
// is persisted by persistConfigPush in the same transaction as the per-steward
// delivery rows it requires (Issue #3757, ADR-031 Decision 2: "config write +
// notify steward X are atomic") whenever a commandStore is configured — a
// controller crash between the two can no longer leave a push recorded with no
// trace that stewards were ever owed it, or delivery rows with no corresponding
// push. It returns nil when no pushStore is configured or the payload cannot be
// marshaled.
func (s *Server) buildConfigPushRecord(cfg *push.StewardConfiguration, principal *Principal, targeted []*service.StewardInfo, pushID string, queuedAt time.Time) *business.PushRecord {
	if s.pushStore == nil {
		return nil
	}
	pushData, marshalErr := json.Marshal(cfg)
	if marshalErr != nil {
		s.logger.Warn("Failed to marshal push payload for persistence", "error", logging.SanitizeLogValue(marshalErr.Error()), "push_id", pushID)
		return nil
	}
	// The authorized, tenant-scoped set: a resumed push delivers only here.
	targetIDs := make([]string, 0, len(targeted))
	for _, st := range targeted {
		targetIDs = append(targetIDs, st.ID)
	}
	return &business.PushRecord{
		ID:               pushID,
		InitiatedBy:      principal.ID,
		ConfigID:         cfg.ConfigID,
		TenantID:         cfg.TenantID,
		Version:          cfg.Version,
		Status:           business.PushStatusInProgress,
		Data:             pushData,
		TargetStewardIDs: targetIDs,
		CreatedAt:        queuedAt,
		UpdatedAt:        queuedAt,
	}
}

// buildConfigPushDeliveryRecords builds one durable delivery/outbox row per
// targeted steward (Issue #3757, ADR-031 Decision 2), written together in a
// single transaction by persistConfigPush — either every steward this push
// targets gets a trackable pending row, or none do. This replaces the old
// detached fire-and-forget goroutine, whose only durable trace was the aggregate
// PushRecord; a controller crash between that goroutine starting and finishing
// silently dropped delivery to whichever stewards had not yet been reached, with
// no record that they were ever owed a push. It returns the rows and the same
// rows keyed by steward ID; the rows are empty when no commandStore is configured
// or no steward matched.
func (s *Server) buildConfigPushDeliveryRecords(cfg *push.StewardConfiguration, principal *Principal, targeted []*service.StewardInfo, pushID string, queuedAt time.Time) ([]*business.CommandRecord, map[string]*business.CommandRecord) {
	recordsByStewardID := make(map[string]*business.CommandRecord, len(targeted))
	var records []*business.CommandRecord
	if s.commandStore == nil || len(targeted) == 0 {
		return records, recordsByStewardID
	}
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
	return records, recordsByStewardID
}

// persistConfigPush writes the push record and delivery rows. It returns the
// delivery rows keyed by steward ID, or nil when the transactional write failed so
// that no delivery is tracked against rows that were not committed.
func (s *Server) persistConfigPush(r *http.Request, pushRecord *business.PushRecord, records []*business.CommandRecord, recordsByStewardID map[string]*business.CommandRecord, pushID string) map[string]*business.CommandRecord {
	switch {
	case s.commandStore != nil:
		// The transactional-CommandStore seam: pushRecord (nil when no
		// pushStore is configured) and records (empty when no steward matched)
		// commit together, or neither commits.
		if err := s.commandStore.CreatePushAndCommandRecords(r.Context(), pushRecord, records); err != nil {
			s.logger.Error("Failed to durably record config push and its deliveries",
				"push_id", pushID, "error", logging.SanitizeLogValue(err.Error()))
			return nil
		}
	case s.pushStore != nil && pushRecord != nil:
		// No commandStore configured in this deployment, so there are no
		// delivery rows to co-commit the push record with.
		if err := s.pushStore.CreatePush(r.Context(), pushRecord); err != nil {
			s.logger.Warn("Failed to persist push record", "error", logging.SanitizeLogValue(err.Error()), "push_id", pushID)
		}
	}
	return recordsByStewardID
}

// fanOutConfigPush drains immediately via the existing node-local fan-out path
// (still the only delivery mechanism in this story; cross-node delivery via a
// shared routing table arrives in S10). Synchronous, not detached: even when a
// durable delivery row exists, nothing is gained by detaching this attempt — the
// row already guarantees the obligation survives a failed attempt or a process
// stop, and detaching it is exactly what left per-steward outcomes unobserved
// before. Runs whenever commandPublisher is configured, independent of
// commandStore — deployments without a durable command store still get
// best-effort fan-out, same as before this story.
func (s *Server) fanOutConfigPush(r *http.Request, cfg *push.StewardConfiguration, targeted []*service.StewardInfo, recordsByStewardID map[string]*business.CommandRecord, pushID string) {
	if s.commandPublisher == nil {
		return
	}
	var commandIDs map[string]string
	if recordsByStewardID != nil {
		commandIDs = make(map[string]string, len(recordsByStewardID))
		for id, rec := range recordsByStewardID {
			commandIDs[id] = rec.ID
		}
	}
	result := push.FanoutWithCommandIDs(r.Context(), cfg, targeted, s.commandPublisher, commandIDs, s.logger)
	s.logger.Info("Config push fan-out complete",
		"push_id", pushID,
		"succeeded", len(result.Succeeded),
		"failed", len(result.Failed))

	s.recordConfigPushDeliveryOutcomes(r, result, recordsByStewardID, pushID)

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

// recordConfigPushDeliveryOutcomes writes each steward's fan-out outcome onto its
// delivery row.
func (s *Server) recordConfigPushDeliveryOutcomes(r *http.Request, result push.FanoutResult, recordsByStewardID map[string]*business.CommandRecord, pushID string) {
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
}

// configPushDeliveries builds the response's per-steward delivery references, in
// fan-out order, for stewards that have a durable delivery row.
func configPushDeliveries(targeted []*service.StewardInfo, recordsByStewardID map[string]*business.CommandRecord) []*ConfigPushDelivery {
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
	return deliveries
}

// handleGetConfigPush implements GET /api/v1/config/push/{id}.
//
// Retrieves a single push record by ID. Returns 404 for unknown IDs or records
// owned by a different tenant — returning 403 would disclose that the push ID
// exists (mirrors runAccess in handlers_runs.go). Returns 503 when the push
// store is unavailable.
func (s *Server) handleGetConfigPush(w http.ResponseWriter, r *http.Request) {
	if s.pushStore == nil {
		s.respondError(w, http.StatusServiceUnavailable, "push store not available")
		return
	}

	// Routed through the same assurance and empty-tenant guard as
	// handleGetJob/handleCreateJob/handlePostRunScript/handlePostRunCommand
	// (Issue #4335), rather than a separate ad hoc check.
	_, _, ok := s.authRunAccess(w, r)
	if !ok {
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
	if !s.authorizeRecordRead(w, r, record.TenantID, "GET /api/v1/config/push/{id}", func() {
		s.respondError(w, http.StatusNotFound, "push not found")
	}) {
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

// auditWriteTimeout bounds an audit write made with a context detached from
// request cancellation.
const auditWriteTimeout = 5 * time.Second

// detachedAuditContext returns a context that keeps reqCtx's values (tenant,
// principal, trace) but is not cancelled when the request is, so an audit
// record for an action that already took effect is not lost to a client abort.
// The write is bounded by auditWriteTimeout; callers must call the cancel func.
func detachedAuditContext(reqCtx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(reqCtx), auditWriteTimeout)
}

// emitConfigPushAudit records an audit event for a config push initiation.
// It is a no-op when auditManager is nil and never blocks or fails the caller.
func (s *Server) emitConfigPushAudit(r *http.Request, principal *Principal, tenantID, configID, pushID string) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action("config.push.initiated").
		User(principal.ID, principalAuditUserType(principal)).
		Resource("config", logging.SanitizeLogValue(configID), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityMedium).
		Detail("push_id", pushID).
		Detail("config_id", logging.SanitizeLogValue(configID))
	auditCtx, cancel := detachedAuditContext(r.Context())
	defer cancel()
	if err := s.auditManager.RecordEvent(auditCtx, b); err != nil {
		s.logger.Warn("Failed to emit config push audit event", "error", logging.SanitizeLogValue(err.Error()), "push_id", pushID)
	}
}

// principalAuditUserType maps an authenticated principal to the audit actor type:
// API-key (machine) principals are recorded as API clients, everything else as humans.
func principalAuditUserType(p *Principal) business.AuditUserType {
	if p != nil && p.Assurance == session.AssuranceMachine {
		return business.AuditUserTypeAPI
	}
	return business.AuditUserTypeHuman
}

// emitOperatorAudit records an audit event for an action an authenticated operator
// took, naming the principal as the actor. It is a no-op when auditManager is nil
// and never blocks or fails the caller.
func (s *Server) emitOperatorAudit(
	r *http.Request,
	principal *Principal,
	tenantID string,
	eventType business.AuditEventType,
	action, resourceType, resourceID string,
	result business.AuditResult,
	severity business.AuditSeverity,
	details map[string]interface{},
) {
	if s.auditManager == nil || principal == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(eventType).
		Action(action).
		User(principal.ID, principalAuditUserType(principal)).
		Resource(resourceType, resourceID, "").
		Result(result).
		Severity(severity)
	for k, v := range details {
		b = b.Detail(k, v)
	}
	auditCtx, cancel := detachedAuditContext(r.Context())
	defer cancel()
	if err := s.auditManager.RecordEvent(auditCtx, b); err != nil {
		s.logger.Warn("Failed to emit operator audit event",
			"error", logging.SanitizeLogValue(err.Error()), "action", action)
	}
}

// auditTenantOrSystem returns tenantID, or audit.SystemTenantID when the credential
// has no tenant owner.
func auditTenantOrSystem(tenantID string) string {
	if tenantID == "" {
		return audit.SystemTenantID
	}
	return tenantID
}
