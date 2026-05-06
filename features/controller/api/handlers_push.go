// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cfgis/cfgms/features/controller/push"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// leaderStatus is the minimal interface the config-push handler needs from the
// HA manager. *ha.Manager satisfies it automatically; test doubles use stubLeaderStatus.
type leaderStatus interface {
	IsLeader() bool
}

// handleConfigPush implements POST /api/v1/config/push.
//
// Validates the StewardConfiguration body, rejects non-leader nodes with 503,
// records an audit event, triggers a fire-and-forget fan-out to all active
// stewards via commandPublisher, and returns 202 Accepted immediately.
func (s *Server) handleConfigPush(w http.ResponseWriter, r *http.Request) {
	// Reject followers immediately — only the leader accepts config pushes.
	if checker := s.pushLeaderStatus; checker != nil && !checker.IsLeader() {
		s.respondError(w, http.StatusServiceUnavailable, "not the leader")
		return
	}

	// Decode and validate request body.
	var cfg push.StewardConfiguration
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.logger.Warn("Failed to decode config push body", "error", err)
		s.respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if cfg.ConfigID == "" || cfg.Version == "" || cfg.TenantID == "" {
		s.logger.Warn("Config push request missing required fields",
			"config_id", logging.SanitizeLogValue(cfg.ConfigID),
			"version", logging.SanitizeLogValue(cfg.Version),
			"tenant_id", logging.SanitizeLogValue(cfg.TenantID),
		)
		s.respondError(w, http.StatusBadRequest, "config_id, version, and tenant_id are required")
		return
	}

	pushID := fmt.Sprintf("push-%d", time.Now().UnixNano())
	queuedAt := time.Now().UTC()

	s.emitConfigPushAudit(r, cfg.TenantID, cfg.ConfigID, pushID)

	// Fan-out CommandSyncConfig to every active steward. Fire-and-forget: the
	// goroutine uses context.Background so it is not cancelled when the HTTP
	// response is written. 202 is returned to the caller immediately.
	if s.commandPublisher != nil {
		stewards := s.controllerService.GetAllStewards()
		cfgSnapshot := cfg
		go func() {
			result := push.Fanout(context.Background(), &cfgSnapshot, stewards, s.commandPublisher, s.logger)
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
		}()
	}

	s.respondJSON(w, http.StatusAccepted, ConfigPushResponse{
		PushID:   pushID,
		Status:   "accepted",
		QueuedAt: queuedAt,
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
