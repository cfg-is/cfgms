// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6141: the route that sets the software-authenticator account flag
// (ADR-021 Amendment 10).
//
// The flag is the account half of the software-authenticator policy (Issue #6140);
// the tenant list in controller.cfg is the other half and has no API writer. Setting
// the flag is a tap-gated human act held by root scope: it widens what the account
// may enrol. Clearing it only narrows, so a tenant administrator who may manage the
// account's tenant may clear it. Neither ordinary account write path can set it.

package api

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const softwareAuthenticatorFlagAuditAction = "account.software_authenticator_flag_changed"

// SoftwareAuthenticatorFlagResponse is the PUT /accounts/{username}/software-authenticator
// result. The flag only takes effect for a tenant listed in controller.cfg.
type SoftwareAuthenticatorFlagResponse struct {
	Username                   string `json:"username"`
	TenantID                   string `json:"tenant_id"`
	AllowSoftwareAuthenticator bool   `json:"allow_software_authenticator"`
}

// handlePutSoftwareAuthenticatorFlag handles PUT /api/v1/accounts/{username}/software-authenticator
// with body {"enabled": bool}.
//
// Like the unattended rollout setting, the change is audited before it is made: if
// the audit event cannot be recorded the flag is left as it was. Setting the value
// the account already has goes through the same permission, tap and audit.
func (s *Server) handlePutSoftwareAuthenticatorFlag(w http.ResponseWriter, r *http.Request) {
	principal, acct, enabled, ok := s.resolveSoftwareAuthenticatorFlagRequest(w, r)
	if !ok {
		return
	}
	if enabled && !s.authorizeSoftwareAuthenticatorEnable(w, r, acct) {
		return
	}
	s.applySoftwareAuthenticatorFlag(w, r, principal, acct, enabled)
}

// resolveSoftwareAuthenticatorFlagRequest validates the request, loads the target
// account and applies the tenant-scope decision of account:update: a caller outside
// the account's tenant gets 404, not 403, so the route does not disclose that the
// account exists. It writes the response and returns false when the request cannot
// proceed.
func (s *Server) resolveSoftwareAuthenticatorFlagRequest(w http.ResponseWriter, r *http.Request) (principal *Principal, acct *account, enabled, ok bool) {
	username := mux.Vars(r)["username"]
	if err := validateUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return nil, nil, false, false
	}
	principal, _ = r.Context().Value(principalContextKey).(*Principal)
	if principal == nil || principal.ID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return nil, nil, false, false
	}
	// The body is the same strict {"enabled": bool} shape as the rollout setting.
	enabled, ok = s.decodeUnattendedRolloutRequest(w, r)
	if !ok {
		return nil, nil, false, false
	}
	acct, err := s.getAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up account", "error", logging.SanitizeLogValue(err.Error()),
			"username", logging.SanitizeLogValue(username))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up account", "STORE_ERROR")
		return nil, nil, false, false
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		return nil, nil, false, false
	}
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if access := s.tenantAccessForScope(r.Context(), scope, acct.TenantID, "PUT /api/v1/accounts/{username}/software-authenticator"); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, acct.TenantID) {
			s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		}
		return nil, nil, false, false
	}
	return principal, acct, enabled, true
}

// authorizeSoftwareAuthenticatorEnable applies the extra rules for setting the flag:
// a root-scope caller, and an account that is not one of the refused root shapes. It
// writes the response and returns false when the flag may not be set.
func (s *Server) authorizeSoftwareAuthenticatorEnable(w http.ResponseWriter, r *http.Request, acct *account) bool {
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if !scope.IsRoot() { //architecture:allow-root-scope -- narrows: only root may enable; the tenant decision for this account (including a boundary-subject root caller's crossing) was made by tenantAccessForScope in resolveSoftwareAuthenticatorFlagRequest
		s.writeErrorResponse(w, http.StatusForbidden,
			"Only a root-scope administrator may enable a software authenticator", "ROOT_SCOPE_REQUIRED")
		return false
	}
	if status, code, msg := s.softwareAuthenticatorFlagRefusal(r.Context(), acct); status != 0 {
		s.writeErrorResponse(w, status, msg, code)
		return false
	}
	return true
}

// applySoftwareAuthenticatorFlag records the audit event, then writes the flag through
// the compare-and-swap path so a concurrent credential change is not clobbered. With
// no audit event nothing is written.
func (s *Server) applySoftwareAuthenticatorFlag(w http.ResponseWriter, r *http.Request, principal *Principal, acct *account, enabled bool) {
	if s.auditManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Audit trail not available", "SERVICE_UNAVAILABLE")
		return
	}
	if err := s.recordSoftwareAuthenticatorFlagAudit(r, principal, acct, enabled, business.AuditResultSuccess); err != nil {
		s.logger.Error("Software authenticator flag change refused: audit event not recorded",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Audit trail unavailable; flag not changed", "AUDIT_UNAVAILABLE")
		return
	}

	updated := *acct
	updated.AllowSoftwareAuthenticator = enabled
	newVersion, swapped, persistErr := s.persistAccountCAS(r.Context(), &updated, principal.ID)
	if persistErr != nil || !swapped {
		s.failSoftwareAuthenticatorFlagWrite(w, r, principal, acct, enabled, persistErr)
		return
	}
	updated.Version = newVersion
	s.cacheAccount(&updated)

	s.logger.Info("Software authenticator flag changed",
		"username", logging.SanitizeLogValue(updated.Username),
		"tenant_id", logging.SanitizeLogValue(updated.TenantID),
		"principal_id", logging.SanitizeLogValue(principal.ID))
	s.writeSuccessResponse(w, SoftwareAuthenticatorFlagResponse{
		Username:                   updated.Username,
		TenantID:                   s.accountPrincipalTenant(r.Context(), &updated),
		AllowSoftwareAuthenticator: updated.AllowSoftwareAuthenticator,
	})
}

// failSoftwareAuthenticatorFlagWrite answers a write that did not land: a store error
// is 500, a lost compare-and-swap (nil persistErr) is 409. The success event is already
// recorded, so a failure event corrects it.
func (s *Server) failSoftwareAuthenticatorFlagWrite(w http.ResponseWriter, r *http.Request, principal *Principal, acct *account, enabled bool, persistErr error) {
	status, code, msg := http.StatusConflict, "ACCOUNT_MODIFIED", "Account was concurrently modified; retry the update"
	if persistErr != nil {
		s.logger.Error("Failed to persist software authenticator flag",
			"error", logging.SanitizeLogValue(persistErr.Error()),
			"username", logging.SanitizeLogValue(acct.Username))
		status, code, msg = http.StatusInternalServerError, "STORE_ERROR", "Failed to update account"
	}
	if aerr := s.recordSoftwareAuthenticatorFlagAudit(r, principal, acct, enabled, business.AuditResultFailure); aerr != nil {
		s.logger.Warn("Failed to record software authenticator flag failure audit",
			"error", logging.SanitizeLogValue(aerr.Error()))
	}
	s.writeErrorResponse(w, status, msg, code)
}

// softwareAuthenticatorFlagRefusal decides whether the flag may be set on acct. A
// non-zero status means refuse with that status. It applies the root-shape rules of
// softwareAuthenticatorPermitted (software_authenticator_policy.go) — a RootScope
// account, an empty TenantID or a root-tenant account is refused with 400, and an
// unresolvable root tenant fails closed with 503 — but not its tenant-list test: the
// flag may be set ahead of the tenant being listed, and has no effect until it is.
func (s *Server) softwareAuthenticatorFlagRefusal(ctx context.Context, acct *account) (status int, code, msg string) {
	if acct.RootScope || acct.TenantID == "" {
		return http.StatusBadRequest, errCodeSoftwareAuthenticatorNotAllowed,
			"A software authenticator cannot be allowed for a root-scope account"
	}
	root := s.rootTenantID(ctx)
	if root == "" {
		return http.StatusServiceUnavailable, "SOFTWARE_AUTHENTICATOR_POLICY_UNAVAILABLE",
			"Software authenticator policy cannot be evaluated"
	}
	if acct.TenantID == root {
		return http.StatusBadRequest, errCodeSoftwareAuthenticatorNotAllowed,
			"A software authenticator cannot be allowed for an account in the root tenant"
	}
	return 0, "", ""
}

// recordSoftwareAuthenticatorFlagAudit records one account.software_authenticator_flag_changed
// event naming the account, its tenant, the old and new value and the acting
// principal. It returns the error: the caller must not change the flag without it.
func (s *Server) recordSoftwareAuthenticatorFlagAudit(r *http.Request, principal *Principal, acct *account, next bool, result business.AuditResult) error {
	tenantID := acct.TenantID
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(softwareAuthenticatorFlagAuditAction).
		User(principal.ID, principalAuditUserType(principal)).
		Resource("account", logging.SanitizeLogValue(acct.Username), "").
		Result(result).
		Severity(business.AuditSeverityHigh).
		Detail("account", acct.Username).
		Detail("account_id", acct.ID).
		Detail("tenant", acct.TenantID).
		Detail("principal", principal.ID).
		Detail("previous", acct.AllowSoftwareAuthenticator).
		Detail("new", next)
	auditCtx, cancel := detachedAuditContext(r.Context())
	defer cancel()
	return s.auditManager.RecordEvent(auditCtx, b)
}
