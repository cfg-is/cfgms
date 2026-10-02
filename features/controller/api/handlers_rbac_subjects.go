// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// isEscalationError reports whether err originated from the escalation prevention
// manager. Used to surface escalation rejections as 403 rather than 500.
func isEscalationError(err error) bool {
	return strings.Contains(err.Error(), "escalation protection")
}

// subjectInCallerScope looks up subjectID and confirms that its tenant is within
// callerTenant's subtree. On failure it writes the HTTP error response and returns
// ("", false). On success it returns the subject's tenant and true.
// An empty callerTenant (unscoped mTLS admin) bypasses the scope check.
func (s *Server) subjectInCallerScope(w http.ResponseWriter, r *http.Request, subjectID, callerTenant string) (string, bool) {
	subjectResp, err := s.rbacService.GetSubject(r.Context(), &controller.GetSubjectRequest{
		SubjectId: subjectID,
	})
	if err != nil || subjectResp == nil || subjectResp.Subject == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Subject not found", "SUBJECT_NOT_FOUND")
		return "", false
	}

	subjectTenant := subjectResp.Subject.TenantId
	if callerTenant != "" && !isWithinTenantScope(callerTenant, subjectTenant) {
		s.logger.Warn("Blocked cross-tenant subject operation",
			"subject_id", logging.SanitizeLogValue(subjectID),
			"subject_tenant", logging.SanitizeLogValue(subjectTenant),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		// 404: do not confirm the subject's existence to out-of-scope callers.
		s.writeErrorResponse(w, http.StatusNotFound, "Subject not found", "SUBJECT_NOT_FOUND")
		return "", false
	}

	return subjectTenant, true
}

// handleGetSubjectRoles handles GET /api/v1/rbac/subjects/{id}/roles
func (s *Server) handleGetSubjectRoles(w http.ResponseWriter, r *http.Request) {
	if s.rbacService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "RBAC service not available", "SERVICE_UNAVAILABLE")
		return
	}

	vars := mux.Vars(r)
	subjectID := vars["id"]
	if subjectID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Subject ID is required", "MISSING_SUBJECT_ID")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	subjectTenant, ok := s.subjectInCallerScope(w, r, subjectID, callerTenant)
	if !ok {
		return
	}

	resp, err := s.rbacService.GetSubjectRoles(r.Context(), &controller.GetSubjectRolesRequest{
		SubjectId: subjectID,
		TenantId:  subjectTenant,
	})
	if err != nil {
		s.logger.Error("Failed to get subject roles",
			"subject_id", logging.SanitizeLogValue(subjectID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get subject roles", "INTERNAL_ERROR")
		return
	}

	var roles []RoleInfo
	for _, role := range resp.Roles {
		roles = append(roles, RoleInfo{
			ID:          role.Id,
			Name:        role.Name,
			Description: role.Description,
			Permissions: role.PermissionIds,
			TenantID:    role.TenantId,
		})
	}

	s.writeSuccessResponse(w, roles)
}

// handleAssignSubjectRole handles POST /api/v1/rbac/subjects/{id}/roles
func (s *Server) handleAssignSubjectRole(w http.ResponseWriter, r *http.Request) {
	if s.rbacService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "RBAC service not available", "SERVICE_UNAVAILABLE")
		return
	}

	vars := mux.Vars(r)
	subjectID := vars["id"]
	if subjectID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Subject ID is required", "MISSING_SUBJECT_ID")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	subjectTenant, ok := s.subjectInCallerScope(w, r, subjectID, callerTenant)
	if !ok {
		return
	}

	var req RoleAssignmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	if req.RoleID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "role_id is required", "MISSING_ROLE_ID")
		return
	}

	// The role being granted must itself be in the caller's scope. Nothing below this
	// handler enforces that: the assignment's tenant is derived from the subject, so the
	// escalation manager's cross-tenant check compares the subject's tenant against
	// itself, and the store validates only that the role exists. Without this guard a
	// caller scoped to one subtree could grant a subject a system role (system.admin's
	// TenantId is "", and system roles bypass the store's tenant filter when effective
	// permissions are resolved) and escalate beyond that subtree. Same guard as role
	// CRUD: 403 for system roles, 404 for roles outside the caller's subtree.
	if _, inScope := s.loadRoleForWrite(w, r, req.RoleID, callerTenant, "assigned"); !inScope {
		return
	}

	// M-AUTH-2: Inject justification from X-Justification header when present.
	ctx := r.Context()
	if justification := r.Header.Get("X-Justification"); justification != "" {
		ctx = rbac.WithSensitiveOperationJustification(ctx, justification)
	}

	assignment := &common.RoleAssignment{
		SubjectId: subjectID,
		RoleId:    req.RoleID,
		TenantId:  subjectTenant,
	}

	_, err := s.rbacService.AssignRole(ctx, &controller.AssignRoleRequest{
		Assignment: assignment,
	})
	if err != nil {
		if errors.Is(err, rbac.ErrJustificationRequired) {
			s.writeErrorResponse(w, http.StatusForbidden, "Justification required for this sensitive operation", "JUSTIFICATION_REQUIRED")
			return
		}
		if isEscalationError(err) {
			s.logger.Warn("Role assignment blocked by escalation prevention",
				"subject_id", logging.SanitizeLogValue(subjectID),
				"role_id", logging.SanitizeLogValue(req.RoleID))
			s.writeErrorResponse(w, http.StatusForbidden, "Role assignment blocked by privilege escalation prevention", "ESCALATION_BLOCKED")
			return
		}
		s.logger.Error("Failed to assign role",
			"subject_id", logging.SanitizeLogValue(subjectID),
			"role_id", logging.SanitizeLogValue(req.RoleID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to assign role", "INTERNAL_ERROR")
		return
	}

	s.writeResponse(w, http.StatusCreated, map[string]interface{}{
		"subject_id": subjectID,
		"role_id":    req.RoleID,
		"tenant_id":  subjectTenant,
		"assigned":   true,
	})
}

// handleRevokeSubjectRole handles DELETE /api/v1/rbac/subjects/{id}/roles/{role_id}
func (s *Server) handleRevokeSubjectRole(w http.ResponseWriter, r *http.Request) {
	if s.rbacService == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "RBAC service not available", "SERVICE_UNAVAILABLE")
		return
	}

	vars := mux.Vars(r)
	subjectID := vars["id"]
	roleID := vars["role_id"]

	if subjectID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Subject ID is required", "MISSING_SUBJECT_ID")
		return
	}
	if roleID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Role ID is required", "MISSING_ROLE_ID")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	// tenantID for the revoke call is derived from the subject's tenant (from GetSubject),
	// never from a client-supplied body field (issue #3128 implementation note).
	subjectTenant, ok := s.subjectInCallerScope(w, r, subjectID, callerTenant)
	if !ok {
		return
	}

	// M-AUTH-2: Inject justification from X-Justification header when present.
	ctx := r.Context()
	if justification := r.Header.Get("X-Justification"); justification != "" {
		ctx = rbac.WithSensitiveOperationJustification(ctx, justification)
	}

	_, err := s.rbacService.RevokeRole(ctx, &controller.RevokeRoleRequest{
		SubjectId: subjectID,
		RoleId:    roleID,
		TenantId:  subjectTenant,
	})
	if err != nil {
		if errors.Is(err, rbac.ErrJustificationRequired) {
			s.writeErrorResponse(w, http.StatusForbidden, "Justification required for this sensitive operation", "JUSTIFICATION_REQUIRED")
			return
		}
		s.logger.Error("Failed to revoke role",
			"subject_id", logging.SanitizeLogValue(subjectID),
			"role_id", logging.SanitizeLogValue(roleID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke role", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, map[string]interface{}{
		"subject_id": subjectID,
		"role_id":    roleID,
		"revoked":    true,
	})
}
