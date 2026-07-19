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
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// leaderStatus is the minimal interface the config-push handler needs from the
// HA manager. *ha.Manager satisfies it automatically; test doubles use stubLeaderStatus.
type leaderStatus interface {
	IsLeader() bool
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
	// Reject followers immediately — only the leader accepts config pushes.
	if checker := s.pushLeaderStatus; checker != nil && !checker.IsLeader() {
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
		s.logger.Warn("Failed to decode config push body", "error", err)
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
		s.logger.Error("Fleet query failed during config push", "error", err, "selector", safeSelector)
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

	s.emitConfigPushAudit(r, cfg.TenantID, cfg.ConfigID, pushID)

	// Durably record the push intent before fan-out begins so that an HA leader
	// failover can replay any push that was interrupted mid-delivery.
	if s.pushStore != nil {
		pushData, marshalErr := json.Marshal(&cfg)
		if marshalErr == nil {
			record := &business.PushRecord{
				ID:        pushID,
				ConfigID:  cfg.ConfigID,
				TenantID:  cfg.TenantID,
				Version:   cfg.Version,
				Status:    business.PushStatusInProgress,
				Data:      pushData,
				CreatedAt: queuedAt,
				UpdatedAt: queuedAt,
			}
			if err := s.pushStore.CreatePush(r.Context(), record); err != nil {
				s.logger.Warn("Failed to persist push record", "error", err, "push_id", pushID)
			}
		} else {
			s.logger.Warn("Failed to marshal push payload for persistence", "error", marshalErr, "push_id", pushID)
		}
	}

	// Fan-out CommandSyncConfig to matched stewards only. Fire-and-forget: the
	// goroutine uses context.Background so it is not cancelled when the HTTP
	// response is written. 202 is returned to the caller immediately.
	if s.commandPublisher != nil {
		cfgSnapshot := cfg
		go func() {
			result := push.Fanout(context.Background(), &cfgSnapshot, targeted, s.commandPublisher, s.logger)
			s.logger.Info("Config push fan-out complete",
				"push_id", pushID,
				"succeeded", len(result.Succeeded),
				"failed", len(result.Failed))
			for stewardID, err := range result.Failed {
				s.logger.Error("Config push fan-out delivery failed",
					"push_id", pushID,
					"steward_id", logging.SanitizeLogValue(stewardID),
					"error", err)
			}
			if s.pushStore != nil {
				finalStatus := business.PushStatusCompleted
				if len(result.Failed) > 0 && len(result.Succeeded) == 0 {
					finalStatus = business.PushStatusFailed
				}
				if updateErr := s.pushStore.UpdatePushStatus(context.Background(), pushID, finalStatus); updateErr != nil {
					s.logger.Warn("Failed to update push record status", "error", updateErr, "push_id", pushID)
				}
			}
		}()
	}

	s.respondJSON(w, http.StatusAccepted, ConfigPushResponse{
		PushID:   pushID,
		Status:   "accepted",
		QueuedAt: queuedAt,
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
			"push_id", logging.SanitizeLogValue(id), "error", err)
		s.respondError(w, http.StatusInternalServerError, "failed to retrieve push record")
		return
	}

	// Tenant isolation: return 404 (not 403) on mismatch to avoid leaking
	// cross-tenant push existence. requirePermission path-var isolation does not
	// cover push-ID path vars (middleware.go:775), so this check is explicit here.
	// Global-scope callers (GlobalScope=true, typically empty TenantID) may read any push record.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if !principal.GlobalScope && record.TenantID != callerTenant {
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
