//go:build cfgms_test_endpoints

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

// Test-mode admin handlers — guarded by CFGMS_ENABLE_TEST_ENDPOINTS=true via
// authenticationMiddleware. These endpoints are used by fleet E2E tests in lieu
// of sqlite3 CLI (not present in the Alpine controller container).
//
// DO NOT rely on these endpoints in production configurations.

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// testSetStewardStatusRequest is the body for PUT /api/v1/test/stewards/{id}/status.
type testSetStewardStatusRequest struct {
	Status string `json:"status"` // e.g. "revoked", "archived", "registered"
}

// handleTestSetStewardStatus handles PUT /api/v1/test/stewards/{id}/status.
// Requires CFGMS_ENABLE_TEST_ENDPOINTS=true (enforced by authenticationMiddleware).
// Accepts the steward's UUID as {id} and updates its lifecycle status.
//
// Test-only endpoint compiled solely behind the cfgms_test_endpoints build tag and
// refused at runtime unless CFGMS_ENABLE_TEST_ENDPOINTS=true
// (test_endpoints_enabled.go); never present in a production binary, used only by
// fleet E2E tests in place of the sqlite3 CLI.
//
//architecture:allow-unscoped-tenant-read -- test-only, build-tag- and env-var-gated, never shipped in a production binary
func (s *Server) handleTestSetStewardStatus(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("CFGMS_ENABLE_TEST_ENDPOINTS") != "true" {
		http.Error(w, "test endpoints disabled", http.StatusForbidden)
		return
	}
	if s.stewardStore == nil {
		http.Error(w, "steward store unavailable", http.StatusServiceUnavailable)
		return
	}

	id := mux.Vars(r)["id"]

	var req testSetStewardStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Status == "" {
		http.Error(w, "body must be {\"status\": \"<status>\"}", http.StatusBadRequest)
		return
	}

	if err := s.stewardStore.UpdateStewardStatus(r.Context(), id, business.StewardStatus(req.Status)); err != nil {
		s.logger.Error("handleTestSetStewardStatus: failed to update status",
			"steward_id", logging.SanitizeLogValue(id), "status", logging.SanitizeLogValue(req.Status), "error", logging.SanitizeLogValue(err.Error()))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// testAuditCountResponse is the response body for GET /api/v1/test/audit/count.
type testAuditCountResponse struct {
	Count int `json:"count"`
}

// handleTestAuditCount handles GET /api/v1/test/audit/count.
// Query params: action=<action>&device_id=<device_id>
// Returns {"count": N} — the number of audit entries matching both filters.
// device_id is matched via the audit entry's user_id field (set by emitRefreshAudit).
// Flushes the audit manager before querying so in-flight entries are drained.
// Requires CFGMS_ENABLE_TEST_ENDPOINTS=true (enforced by authenticationMiddleware).
func (s *Server) handleTestAuditCount(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("CFGMS_ENABLE_TEST_ENDPOINTS") != "true" {
		http.Error(w, "test endpoints disabled", http.StatusForbidden)
		return
	}
	if s.auditStore == nil {
		http.Error(w, "audit store unavailable", http.StatusServiceUnavailable)
		return
	}

	action := r.URL.Query().Get("action")
	deviceID := r.URL.Query().Get("device_id")

	if action == "" {
		http.Error(w, "action query param required", http.StatusBadRequest)
		return
	}

	// Flush audit manager so entries queued after the scenario are persisted before query.
	if s.auditManager != nil {
		_ = s.auditManager.Flush(r.Context())
	}

	filter := &business.AuditFilter{
		Actions: []string{action},
	}
	if deviceID != "" {
		filter.UserIDs = []string{deviceID}
	}

	entries, err := s.auditStore.ListAuditEntries(r.Context(), filter)
	if err != nil {
		s.logger.Error("handleTestAuditCount: query failed", "action", logging.SanitizeLogValue(action), "device_id", logging.SanitizeLogValue(deviceID), "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(testAuditCountResponse{Count: len(entries)}); err != nil {
		s.logger.Error("handleTestAuditCount: encode failed", "error", err)
	}
}
