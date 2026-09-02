// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// moduleApprovalEntry is a single pending bundle entry in the list response.
type moduleApprovalEntry struct {
	// Address is the composite key used in approve/reject paths.
	Address     string `json:"address"`
	Publisher   string `json:"publisher"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	ContentHash string `json:"content_hash"`
}

// moduleApprovalListResponse is returned by GET /api/v1/modules/approvals.
type moduleApprovalListResponse struct {
	Pending []moduleApprovalEntry `json:"pending"`
}

// handleListModuleApprovals handles GET /api/v1/modules/approvals.
// Returns all module bundles currently awaiting human review.
func (s *Server) handleListModuleApprovals(w http.ResponseWriter, r *http.Request) {
	if s.moduleCacheLister == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Module cache not configured", "SERVICE_UNAVAILABLE")
		return
	}

	entries, err := s.moduleCacheLister.List()
	if err != nil {
		s.logger.Error("Failed to list module cache", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list module cache", "INTERNAL_ERROR")
		return
	}

	pending := make([]moduleApprovalEntry, 0)
	for _, e := range entries {
		if e.Status != cache.ApprovalStatusPending {
			continue
		}
		pending = append(pending, moduleApprovalEntry{
			Address:     formatModuleAddress(e.Addr),
			Publisher:   e.Addr.Publisher,
			Name:        e.Addr.Name,
			Version:     e.Addr.Version,
			ContentHash: e.Addr.ContentHash,
		})
	}

	s.writeSuccessResponse(w, moduleApprovalListResponse{Pending: pending})
}

// handleApproveModuleBundle handles POST /api/v1/modules/approvals/{address}/approve.
// Approves a queued module bundle, authorizing it for deployment to managed endpoints.
func (s *Server) handleApproveModuleBundle(w http.ResponseWriter, r *http.Request) {

	rawAddr := mux.Vars(r)["address"]

	addr, ok := s.resolveModuleAddress(w, rawAddr)
	if !ok {
		return
	}

	if s.moduleBundleReviewer == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Module approval not configured", "SERVICE_UNAVAILABLE")
		return
	}

	if err := s.moduleBundleReviewer.Approve(addr); err != nil {
		s.handleModuleDecisionError(w, err, "approve", logging.SanitizeLogValue(rawAddr))
		return
	}

	s.emitModuleApprovalAudit(r, addr, "module.bundle.approved")
	s.writeSuccessResponse(w, map[string]string{"status": "approved"})
}

// handleRejectModuleBundle handles POST /api/v1/modules/approvals/{address}/reject.
// Rejects a queued module bundle, blocking it from deployment.
func (s *Server) handleRejectModuleBundle(w http.ResponseWriter, r *http.Request) {

	rawAddr := mux.Vars(r)["address"]

	addr, ok := s.resolveModuleAddress(w, rawAddr)
	if !ok {
		return
	}

	if s.moduleBundleReviewer == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Module approval not configured", "SERVICE_UNAVAILABLE")
		return
	}

	if err := s.moduleBundleReviewer.RejectPending(addr); err != nil {
		s.handleModuleDecisionError(w, err, "reject", logging.SanitizeLogValue(rawAddr))
		return
	}

	s.emitModuleApprovalAudit(r, addr, "module.bundle.rejected")
	s.writeSuccessResponse(w, map[string]string{"status": "rejected"})
}

// resolveModuleAddress parses the {address} path parameter.
// Writes an error response and returns false if the param is malformed.
func (s *Server) resolveModuleAddress(w http.ResponseWriter, rawAddr string) (bundle.ContentAddress, bool) {
	addr, err := parseModuleAddress(rawAddr)
	if err != nil {
		s.logger.Debug("Malformed module address", "address", logging.SanitizeLogValue(rawAddr), "error", err)
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid module address format", "INVALID_ADDRESS")
		return bundle.ContentAddress{}, false
	}
	return addr, true
}

// handleModuleDecisionError maps approve/reject workflow errors to HTTP responses.
func (s *Server) handleModuleDecisionError(w http.ResponseWriter, err error, action, safeAddr string) {
	switch {
	case errors.Is(err, approval.ErrNotQueued):
		s.logger.Info("Module bundle not in pending state",
			"action", action, "address", safeAddr, "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusConflict, "Module bundle is not pending review", "NOT_PENDING")
	case errors.Is(err, cache.ErrBundleNotFound):
		s.logger.Info("Module bundle not found", "action", action, "address", safeAddr)
		s.writeErrorResponse(w, http.StatusNotFound, "Module bundle not found", "BUNDLE_NOT_FOUND")
	default:
		s.logger.Error("Module bundle decision failed",
			"action", action, "address", safeAddr, "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to record decision", "INTERNAL_ERROR")
	}
}

// emitModuleApprovalAudit records a module bundle human-decision audit event.
// No-op when auditManager is nil.
func (s *Server) emitModuleApprovalAudit(r *http.Request, addr bundle.ContentAddress, action string) {
	if s.auditManager == nil {
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	callerID := ""
	if principal != nil {
		callerID = principal.ID
	}

	resourceID := addr.Publisher + "/" + addr.Name + "@" + addr.Version

	b := audit.NewEventBuilder().
		Tenant("root").
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(callerID, business.AuditUserTypeHuman).
		Resource("module_bundle", resourceID, addr.ContentHash).
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Request(s.getRequestID(r), r.Method, r.URL.Path, extractSourceIP(r, s.trustedProxies), r.Header.Get("User-Agent")).
		Detail("publisher", logging.SanitizeLogValue(addr.Publisher)).
		Detail("name", logging.SanitizeLogValue(addr.Name)).
		Detail("version", logging.SanitizeLogValue(addr.Version)).
		Detail("content_hash", logging.SanitizeLogValue(addr.ContentHash))

	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Warn("Failed to emit module approval audit event",
			"error", err, "action", action, "resource", logging.SanitizeLogValue(resourceID))
	}
}

// formatModuleAddress encodes a ContentAddress as the URL-safe composite address string.
// Format: publisher:name:version:safehash
// where safehash has / replaced with _, + replaced with -, and = stripped.
// This matches the hashToDir transformation used by the module cache for filesystem paths.
func formatModuleAddress(addr bundle.ContentAddress) string {
	safeHash := strings.NewReplacer("/", "_", "+", "-", "=", "").Replace(addr.ContentHash)
	return addr.Publisher + ":" + addr.Name + ":" + addr.Version + ":" + safeHash
}

// parseModuleAddress decodes a composite address string back to a ContentAddress.
// Returns an error if the format is invalid.
func parseModuleAddress(param string) (bundle.ContentAddress, error) {
	parts := strings.SplitN(param, ":", 4)
	if len(parts) != 4 {
		return bundle.ContentAddress{}, errors.New("address must be publisher:name:version:hash")
	}
	for i, p := range parts {
		if p == "" {
			return bundle.ContentAddress{}, fmt.Errorf("address component %d must not be empty", i)
		}
	}
	// Reverse the URL-safe hash encoding: _→/, -→+, restore base64 padding.
	rawHash := strings.NewReplacer("_", "/", "-", "+").Replace(parts[3])
	if r := len(rawHash) % 4; r != 0 {
		rawHash += strings.Repeat("=", 4-r)
	}
	return bundle.ContentAddress{
		Publisher:   parts[0],
		Name:        parts[1],
		Version:     parts[2],
		ContentHash: rawHash,
	}, nil
}
