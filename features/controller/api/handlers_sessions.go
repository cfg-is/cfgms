// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
)

// sessionCreateRequest is the JSON body for POST /api/v1/sessions.
type sessionCreateRequest struct {
	ConnectionName string `json:"connection_name"`
}

// sessionCreateResponse is returned on successful session creation (HTTP 201).
// The token is the opaque 43-char base64url bearer credential; it is returned
// exactly once and never re-issued — the client must store it securely.
type sessionCreateResponse struct {
	SessionID      string    `json:"session_id"`
	Token          string    `json:"token"`
	IssuedAt       time.Time `json:"issued_at"`
	IdleTTLSeconds int64     `json:"idle_ttl"`
	AbsoluteExpiry time.Time `json:"absolute_expiry"`
}

// handleSessionCreate handles POST /api/v1/sessions.
// Requires an admin mTLS principal (principal.IsAdmin == true).
// Returns HTTP 201 with session metadata and a one-time bearer token.
func (s *Server) handleSessionCreate(w http.ResponseWriter, r *http.Request) {
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil || !principal.IsAdmin {
		s.writeErrorResponse(w, http.StatusForbidden, "Admin mTLS certificate required", "NOT_ADMIN")
		return
	}
	if s.sessionManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Session management not available", "SESSION_UNAVAILABLE")
		return
	}

	var req sessionCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	sess, token, err := s.sessionManager.Issue(r.Context(), principal.ID, req.ConnectionName, principal.TenantID)
	if err != nil {
		s.logger.Error("Failed to issue session",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create session", "SESSION_CREATE_ERROR")
		return
	}

	s.logger.Info("Session issued",
		"session_id", logging.SanitizeLogValue(sess.ID),
		"principal_id", logging.SanitizeLogValue(sess.PrincipalID),
		"connection_name", logging.SanitizeLogValue(sess.ConnectionName))

	resp := sessionCreateResponse{
		SessionID:      sess.ID,
		Token:          token,
		IssuedAt:       sess.IssuedAt,
		IdleTTLSeconds: int64(s.sessionCfg.IdleTimeout / time.Second),
		AbsoluteExpiry: sess.AbsoluteExpiresAt,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// sessionListItem is the allow-listed per-session payload for GET /api/v1/sessions.
// Fields are named explicitly so a future field added to session.Session cannot
// silently leak through this endpoint via a raw json.Marshal passthrough.
type sessionListItem struct {
	SessionID      string    `json:"session_id"`
	PrincipalID    string    `json:"principal_id"`
	ConnectionName string    `json:"connection_name"`
	IssuedAt       time.Time `json:"issued_at"`
	LastActivity   time.Time `json:"last_activity"`
	AbsoluteExpiry time.Time `json:"absolute_expiry"`
}

// sessionListResponse wraps the active-session listing for GET /api/v1/sessions.
type sessionListResponse struct {
	Sessions []sessionListItem `json:"sessions"`
}

// handleSessionList handles GET /api/v1/sessions.
// Requires an admin principal (principal.IsAdmin == true).
// Tenant-scoped admins see only sessions whose TenantID matches their own;
// global admins (TenantID == "") see every tenant's sessions.
func (s *Server) handleSessionList(w http.ResponseWriter, r *http.Request) {
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil || !principal.IsAdmin {
		s.writeErrorResponse(w, http.StatusForbidden, "Admin mTLS certificate required", "NOT_ADMIN")
		return
	}
	if s.sessionManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Session management not available", "SESSION_UNAVAILABLE")
		return
	}

	all, err := s.sessionManager.List(r.Context())
	if err != nil {
		s.logger.Error("Failed to list sessions",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list sessions", "SESSION_LIST_ERROR")
		return
	}

	items := make([]sessionListItem, 0, len(all))
	for _, sess := range all {
		if principal.TenantID != "" && sess.TenantID != principal.TenantID {
			continue
		}
		items = append(items, sessionListItem{
			SessionID:      sess.ID,
			PrincipalID:    sess.PrincipalID,
			ConnectionName: sess.ConnectionName,
			IssuedAt:       sess.IssuedAt,
			LastActivity:   sess.LastActivity,
			AbsoluteExpiry: sess.AbsoluteExpiresAt,
		})
	}

	s.logger.Info("Sessions listed",
		"principal_id", logging.SanitizeLogValue(principal.ID),
		"count", len(items))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sessionListResponse{Sessions: items})
}

// handleSessionRevoke handles DELETE /api/v1/sessions/{id}.
// Accepts either a valid session token or an admin mTLS cert as credentials.
// Returns HTTP 200 on success or HTTP 404 if the session does not exist.
func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil || !principal.IsAdmin {
		s.writeErrorResponse(w, http.StatusForbidden, "Admin credential required", "NOT_ADMIN")
		return
	}
	if s.sessionManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Session management not available", "SESSION_UNAVAILABLE")
		return
	}

	vars := mux.Vars(r)
	sessionID := vars["id"]
	if sessionID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Session ID required", "MISSING_ID")
		return
	}

	if err := s.sessionManager.Revoke(r.Context(), sessionID); err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Session not found", "SESSION_NOT_FOUND")
			return
		}
		s.logger.Error("Failed to revoke session",
			"session_id", logging.SanitizeLogValue(sessionID),
			"error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke session", "SESSION_REVOKE_ERROR")
		return
	}

	s.logger.Info("Session revoked",
		"session_id", logging.SanitizeLogValue(sessionID),
		"principal_id", logging.SanitizeLogValue(principal.ID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":      sessionID,
		"revoked": true,
	})
}
