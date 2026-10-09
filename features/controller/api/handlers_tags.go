// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/tagstore"
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
			"error", logging.SanitizeLogValue(err.Error()))
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

	incoming := req.Tags
	var changed bool
	merged, err := ts.Update(r.Context(), stewardID, func(current []string) ([]string, error) {
		next := mergeTags(current, incoming)
		changed = !sameTagSet(current, next)
		return next, nil
	})
	if err != nil {
		if errors.Is(err, tagstore.ErrInvalidTag) {
			s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_TAG")
			return
		}
		s.logger.Error("Failed to set tags",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to set tags", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Tags added",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"count", len(merged))
	if changed {
		s.syncStewardAfterTagChange(r, stewardID)
	}
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

	toRemove := req.Tags
	var changed bool
	remaining, err := ts.Update(r.Context(), stewardID, func(current []string) ([]string, error) {
		next := removeTags(current, toRemove)
		changed = !sameTagSet(current, next)
		return next, nil
	})
	if err != nil {
		s.logger.Error("Failed to set tags after removal",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to set tags", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Tags removed",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"removed", len(toRemove),
		"remaining", len(remaining))
	if changed {
		s.syncStewardAfterTagChange(r, stewardID)
	}
	s.writeSuccessResponse(w, tagsResponse{Tags: remaining})
}

// syncStewardAfterTagChange pushes the steward's new effective configuration after
// its tag set changed (role fragments are selected by tag).
func (s *Server) syncStewardAfterTagChange(r *http.Request, stewardID string) {
	tenantID, _ := s.stewardOwnerTenant(r.Context(), stewardID)
	var issuedBy string
	if principal, ok := r.Context().Value(principalContextKey).(*Principal); ok && principal != nil {
		issuedBy = principal.ID
	}
	s.syncStewardConfig(r.Context(), stewardID, tenantID, issuedBy)
}

// sameTagSet reports whether a and b hold the same tags, ignoring order and duplicates.
func sameTagSet(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, t := range a {
		set[t] = struct{}{}
	}
	other := make(map[string]struct{}, len(b))
	for _, t := range b {
		other[t] = struct{}{}
		if _, ok := set[t]; !ok {
			return false
		}
	}
	return len(set) == len(other)
}

// resolveStewardForTags validates the steward ID, looks up the steward, and enforces
// tenant scoping via ctxkeys.TenantScope (Issue #4335). On any error it writes the
// response and returns false. Out-of-scope and not-found both return 404
// STEWARD_NOT_FOUND (authorizeStewardScope) so a cross-tenant caller cannot use the
// response code as an existence oracle for steward IDs — replaces the prior 403
// FORBIDDEN on cross-tenant, which let the two responses be told apart.
func (s *Server) resolveStewardForTags(w http.ResponseWriter, r *http.Request) (string, bool) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if !identifierRegex.MatchString(stewardID) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid steward ID format", "INVALID_STEWARD_ID")
		return "", false
	}

	if !s.authorizeStewardScope(w, r, stewardID, "/api/v1/stewards/{id}/tags") {
		return "", false
	}

	return stewardID, true
}

// callerTenantID returns the caller's tenant restriction (callerTenantFilter):
// "" only for an explicitly root-scoped caller, the caller's tenant otherwise
// (Issue #4665).
func (s *Server) callerTenantID(r *http.Request) string {
	return callerTenantFilter(r.Context())
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
