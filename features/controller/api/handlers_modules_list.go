// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"net/http"

	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/pkg/logging"
)

// moduleListEntry is a single module cache entry in the GET /api/v1/modules
// response, carrying its approval status (unlike moduleApprovalEntry, this
// endpoint is not pending-only, so status is meaningful here).
type moduleListEntry struct {
	Publisher   string `json:"publisher"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	ContentHash string `json:"content_hash"`
	Status      string `json:"status"`
}

// moduleListResponse is returned by GET /api/v1/modules.
type moduleListResponse struct {
	Modules []moduleListEntry `json:"modules"`
	Total   int               `json:"total"`
}

// moduleStatusFilterValues are the only accepted ?status= query values,
// matching cache.ApprovalStatus 1:1.
var moduleStatusFilterValues = map[string]cache.ApprovalStatus{
	string(cache.ApprovalStatusPending):  cache.ApprovalStatusPending,
	string(cache.ApprovalStatusApproved): cache.ApprovalStatusApproved,
	string(cache.ApprovalStatusRejected): cache.ApprovalStatusRejected,
}

// handleListModules handles GET /api/v1/modules.
// Returns every module bundle in the cache regardless of approval status —
// the read-only catalog view backing `cfg module list`. Distinct in purpose
// from GET /api/v1/modules/approvals, which is the pending-only human review
// queue feeding the web UI's useModuleQueue.ts and must keep that shape.
func (s *Server) handleListModules(w http.ResponseWriter, r *http.Request) {
	if s.moduleCacheLister == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Module cache not configured", "SERVICE_UNAVAILABLE")
		return
	}

	var statusFilter cache.ApprovalStatus
	filterRaw := r.URL.Query().Get("status")
	if filterRaw != "" {
		status, ok := moduleStatusFilterValues[filterRaw]
		if !ok {
			s.writeErrorResponse(w, http.StatusBadRequest, "invalid status filter: must be pending, approved, or rejected", "INVALID_STATUS")
			return
		}
		statusFilter = status
	}

	entries, err := s.moduleCacheLister.List()
	if err != nil {
		s.logger.Error("Failed to list module cache", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list module cache", "INTERNAL_ERROR")
		return
	}

	modules := make([]moduleListEntry, 0, len(entries))
	for _, e := range entries {
		if filterRaw != "" && e.Status != statusFilter {
			continue
		}
		modules = append(modules, moduleListEntry{
			Publisher:   e.Addr.Publisher,
			Name:        e.Addr.Name,
			Version:     e.Addr.Version,
			ContentHash: e.Addr.ContentHash,
			Status:      string(e.Status),
		})
	}

	s.writeSuccessResponse(w, moduleListResponse{Modules: modules, Total: len(modules)})
}
