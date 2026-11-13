// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6225: the permission set of a root-scope agent account (ADR-021 Amendment 11).
//
// A root-scope account that carries the AllowSoftwareAuthenticator flag does not
// receive ImplicitAdmin. Its principal is marked RootAgent and holds exactly the
// permissions in rootAgentPermissions; every other permission is refused, including
// every key of knownPermissions and of permissionAssurance. The restriction keys on
// the account flag (acct.RootScope && acct.AllowSoftwareAuthenticator), not on which
// credential signed in, on the root-agent setting in controller.cfg or on the
// eligibility predicate, so a human credential added later or the setting being
// switched off cannot return the account to full admin. Clearing the flag, which needs
// another root caller and a presence tap, is the only way back.
//
// Adding to the set is a deliberate, reviewed change to this one named map.

package api

import (
	"context"
	"net/http"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// errCodeRootAgentLimited answers a root agent request that an account-write handler
// refuses although the principal holds the route's permission.
const errCodeRootAgentLimited = "ROOT_AGENT_LIMITED"

// Reasons recorded on a refused root agent request.
const (
	reasonRootAgentPermissionNotAllowed = "root_agent_permission_not_allowed"
)

// rootAgentPermissions is the exact allowlist of a RootAgent principal (16 entries).
// Only webauthn:assert-presence and webauthn:elevate are outside knownPermissions (they
// are in permissionAssurance); a RootAgent principal reaches them here, where an
// ordinary account can reach them only through ImplicitAdmin.
//
// operator-payload:sign and workflow:publish must stay members:
// accountHoldsOperatorPayloadSigning and accountHoldsWorkflowPublish answer true for
// any root-scope account, and agree with hasPermission only because of these two entries.
var rootAgentPermissions = map[string]bool{
	"webauthn:assert-presence": true,
	"webauthn:elevate":         true,
	"tenant:create":            true,
	"tenant:list":              true,
	"tenant:read":              true,
	"account:create":           true,
	"steward:list":             true,
	"steward:read":             true,
	"steward:read-scripts":     true,
	"steward:execute-scripts":  true,
	"operator-payload:sign":    true,
	"workflow:publish":         true,
	"workflow:read":            true,
	"workflow:list":            true,
	"module:approve":           true,
	"module:list-approvals":    true,
}

// rootAgentPermitted reports whether a RootAgent principal holds permissionID.
// Anything not named in rootAgentPermissions is refused.
func rootAgentPermitted(permissionID string) bool {
	return rootAgentPermissions[permissionID]
}

// rootAgentSession reports whether a session for acct is limited to
// rootAgentPermissions: a root-scope account carrying the software-authenticator flag.
func rootAgentSession(acct *account) bool {
	return acct != nil && acct.RootScope && acct.AllowSoftwareAuthenticator
}

// rootAgentRefusalDetails builds the audit details of a refused root agent request: the
// software-authenticator marker, root_scope: true and the reason. The marker describes
// the credential that opened the session when the session record identifies it;
// otherwise it states whether the account holds a CFGMS software credential.
func rootAgentRefusalDetails(ctx context.Context, acct *account, reason string) map[string]interface{} {
	var details map[string]interface{}
	if ref, ok := ctx.Value(authSessionContextKey).(authSessionRef); ok {
		if sess, err := ref.manager.GetByID(ctx, ref.id); err == nil && sess != nil {
			details = softwareAuthenticatorAuditDetails(acct, sess.LoginCredentialID)
		}
	}
	if details == nil {
		details = map[string]interface{}{auditKeySoftwareAuthenticator: acct.hasSoftwareCredential()}
	}
	details[auditKeyRootScope] = true
	details[auditKeyReason] = reason
	return details
}

// auditRootAgentRefusal records a request refused to a RootAgent principal, in the same
// shape as the credential-use events (softwareAuthenticatorAuditDetails). permissionID,
// when non-empty, names the refused permission. The refusal stands even when the audit
// trail cannot take the event.
func (s *Server) auditRootAgentRefusal(r *http.Request, principal *Principal, reason, permissionID string) {
	if s.auditManager == nil || principal == nil {
		return
	}
	ctx := r.Context()
	acct, err := s.getAccountByID(ctx, principal.ID)
	if err != nil || acct == nil {
		s.logger.Warn("Root agent refusal not audited: account unavailable",
			"principal_id", logging.SanitizeLogValue(principal.ID))
		return
	}
	details := rootAgentRefusalDetails(ctx, acct, reason)
	details["method"] = r.Method
	details["request_path"] = redactCredentialPath(r.URL.Path)
	if permissionID != "" {
		details["permission_id"] = permissionID
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventAuthorization).
		Action("authorization.root_agent_denied").
		User(acct.ID, business.AuditUserTypeHuman).
		Resource("account", logging.SanitizeLogValue(acct.Username), "").
		Result(business.AuditResultDenied).
		Severity(business.AuditSeverityHigh).
		Details(details)
	auditCtx, cancel := detachedAuditContext(ctx)
	defer cancel()
	if err := s.auditManager.RecordEvent(auditCtx, b); err != nil {
		s.logger.Warn("Failed to emit root agent refusal audit event",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
