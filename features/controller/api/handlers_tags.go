// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/tagstore"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// tagsRequest is the JSON body for POST and DELETE /api/v1/stewards/{id}/tags.
type tagsRequest struct {
	Tags []string `json:"tags"`
}

// tagsResponse is the JSON data envelope for tag endpoints.
type tagsResponse struct {
	Tags []string `json:"tags"`
}

// handleListStewardTags handles GET /api/v1/stewards/{id}/tags.
// Returns the current tag list for the steward.
func (s *Server) handleListStewardTags(w http.ResponseWriter, r *http.Request) {
	stewardID, ok := s.resolveStewardForTags(w, r)
	if !ok {
		return
	}

	s.mu.RLock()
	ts := s.tagStore
	s.mu.RUnlock()
	if ts == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tag store not available", "TAG_STORE_UNAVAILABLE")
		return
	}

	tags, err := ts.Get(r.Context(), stewardID)
	if err != nil {
		s.logger.Error("Failed to get tags",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read tags", "INTERNAL_ERROR")
		return
	}

	if tags == nil {
		tags = []string{}
	}
	s.writeSuccessResponse(w, tagsResponse{Tags: tags})
}

// handleAddStewardTags handles POST /api/v1/stewards/{id}/tags.
// Merges the provided tags into the steward's existing tag set (idempotent).
func (s *Server) handleAddStewardTags(w http.ResponseWriter, r *http.Request) {
	stewardID, ok := s.resolveStewardForTags(w, r)
	if !ok {
		return
	}

	s.mu.RLock()
	ts := s.tagStore
	s.mu.RUnlock()
	if ts == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tag store not available", "TAG_STORE_UNAVAILABLE")
		return
	}

	var req tagsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_BODY")
		return
	}

	current, err := ts.Get(r.Context(), stewardID)
	if err != nil {
		s.logger.Error("Failed to read current tags",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read tags", "INTERNAL_ERROR")
		return
	}

	merged := mergeTags(current, req.Tags)
	if err := ts.Set(r.Context(), stewardID, merged); err != nil {
		if errors.Is(err, tagstore.ErrInvalidTag) {
			s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_TAG")
			return
		}
		s.logger.Error("Failed to set tags",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to set tags", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Tags added",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"count", len(merged))
	s.writeSuccessResponse(w, tagsResponse{Tags: merged})
}

// handleDeleteStewardTags handles DELETE /api/v1/stewards/{id}/tags.
// Removes the provided tags from the steward's tag set (idempotent).
func (s *Server) handleDeleteStewardTags(w http.ResponseWriter, r *http.Request) {
	stewardID, ok := s.resolveStewardForTags(w, r)
	if !ok {
		return
	}

	s.mu.RLock()
	ts := s.tagStore
	s.mu.RUnlock()
	if ts == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tag store not available", "TAG_STORE_UNAVAILABLE")
		return
	}

	var req tagsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_BODY")
		return
	}

	current, err := ts.Get(r.Context(), stewardID)
	if err != nil {
		s.logger.Error("Failed to read current tags",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read tags", "INTERNAL_ERROR")
		return
	}

	remaining := removeTags(current, req.Tags)
	if err := ts.Set(r.Context(), stewardID, remaining); err != nil {
		s.logger.Error("Failed to set tags after removal",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to set tags", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Tags removed",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"removed", len(req.Tags),
		"remaining", len(remaining))
	s.writeSuccessResponse(w, tagsResponse{Tags: remaining})
}

// resolveStewardForTags validates the steward ID, looks up the steward, and enforces
// tenant scoping. On any error it writes the response and returns false.
func (s *Server) resolveStewardForTags(w http.ResponseWriter, r *http.Request) (string, bool) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return "", false
	}

	stewardInfo, exists := s.controllerService.GetStewardInfo(stewardID)
	if !exists {
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return "", false
	}

	// Enforce tenant scoping: a scoped caller may only operate on stewards in its
	// own subtree. mTLS admin principals (empty TenantID) have global access.
	// Returns 403 (not 404) to match the handleConfigPush cross-tenant guard pattern
	// and the explicit requirement in issue #2545 AC.
	callerTenantID := s.callerTenantID(r)
	if callerTenantID != "" {
		inSubtree := stewardInfo.TenantID == callerTenantID ||
			strings.HasPrefix(stewardInfo.TenantID, callerTenantID+"/")
		if !inSubtree {
			s.writeErrorResponse(w, http.StatusForbidden,
				"caller may only manage tags for stewards in its own tenant subtree",
				"FORBIDDEN")
			return "", false
		}
	}

	return stewardID, true
}

// callerTenantID returns the authenticated caller's tenant ID.
// mTLS admin certs have global scope (empty TenantID); API-key callers have a tenant scope.
func (s *Server) callerTenantID(r *http.Request) string {
	if p := s.extractAdminPrincipal(r); p != nil {
		return p.TenantID
	}
	tid, _ := r.Context().Value(ctxkeys.TenantID).(string)
	return tid
}

// mergeTags returns the sorted union of current and incoming, deduplicated.
func mergeTags(current, incoming []string) []string {
	seen := make(map[string]struct{}, len(current)+len(incoming))
	for _, t := range current {
		seen[t] = struct{}{}
	}
	for _, t := range incoming {
		seen[t] = struct{}{}
	}
	merged := make([]string, 0, len(seen))
	for t := range seen {
		merged = append(merged, t)
	}
	sort.Strings(merged)
	return merged
}

// removeTags returns a copy of current with all tags in toRemove filtered out.
func removeTags(current, toRemove []string) []string {
	remove := make(map[string]struct{}, len(toRemove))
	for _, t := range toRemove {
		remove[t] = struct{}{}
	}
	result := make([]string, 0, len(current))
	for _, t := range current {
		if _, skip := remove[t]; !skip {
			result = append(result, t)
		}
	}
	return result
}
