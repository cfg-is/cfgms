// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6140: software-authenticator policy at registration (ADR-021 Amendment 10).
//
// A CFGMS software authenticator (pkg/softauthn) is accepted for an account only
// when both hold: the account's tenant is listed in
// webauthn.allow_software_authenticators.tenants in controller.cfg, and the
// account carries the AllowSoftwareAuthenticator flag. It is never accepted for a
// root-scope account, an account with an empty TenantID, or an account in the root
// tenant, and it is refused when the root tenant cannot be resolved.
//
// The tenant list is exact-match (a listed tenant does not cover its children) and
// has no API writer. The AAGUID that selects this policy is self-asserted under
// attestation "none", so a credential with any other AAGUID is registered on the
// ordinary path and receives no different trust, assurance or exemption.

package api

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const errCodeSoftwareAuthenticatorNotAllowed = "SOFTWARE_AUTHENTICATOR_NOT_ALLOWED"

// errRootTenantUnresolved reports that the deployment's root tenant could not be
// determined, so the policy cannot rule out that the account sits in it.
var errRootTenantUnresolved = errors.New("root tenant cannot be resolved")

// SetSoftwareAuthenticatorTenants installs the controller.cfg tenant list
// (webauthn.allow_software_authenticators.tenants). Call after New() and before
// Start(). A nil or empty list turns software-authenticator registration off. The
// list is matched exactly; the IDs are copied.
func (s *Server) SetSoftwareAuthenticatorTenants(tenants []string) {
	set := make(map[string]struct{}, len(tenants))
	for _, id := range tenants {
		if id != "" {
			set[id] = struct{}{}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.softwareAuthenticatorTenants = set
}

// SoftwareAuthenticatorTenantListed reports whether tenantID is in the configured
// list, by exact match. It says nothing about the account flag or the root rules;
// softwareAuthenticatorPermitted is the decision.
func (s *Server) SoftwareAuthenticatorTenantListed(tenantID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.softwareAuthenticatorTenants[tenantID]
	return ok
}

// softwareAuthenticatorPermitted reports whether acct may hold a CFGMS software
// authenticator. It fails closed: it returns (false, errRootTenantUnresolved) when
// the root tenant cannot be resolved, and (false, nil) for every refused shape.
func (s *Server) softwareAuthenticatorPermitted(ctx context.Context, acct *account) (bool, error) {
	if acct == nil || acct.RootScope || acct.TenantID == "" {
		return false, nil
	}
	root := s.rootTenantID(ctx)
	if root == "" {
		return false, errRootTenantUnresolved
	}
	if acct.TenantID == root {
		return false, nil
	}
	return s.SoftwareAuthenticatorTenantListed(acct.TenantID) && acct.AllowSoftwareAuthenticator, nil
}

// enforceSoftwareAuthenticatorPolicy applies the policy to a just-verified
// registration. It returns true when registration may proceed. A credential whose
// AAGUID is not softauthn.AAGUID is not subject to the policy and is never treated
// differently for that reason. On refusal it audits the denial, writes the response
// (403, or 503 when the root tenant cannot be resolved) and returns false; the
// caller must not persist anything.
func (s *Server) enforceSoftwareAuthenticatorPolicy(w http.ResponseWriter, r *http.Request, acct *account, cred *WebAuthnCredential) bool {
	if !cred.isSoftwareAuthenticator() {
		return true
	}
	permitted, err := s.softwareAuthenticatorPermitted(r.Context(), acct)
	if permitted {
		return true
	}
	reason := "policy"
	if err != nil {
		reason = "root_tenant_unresolved"
	}
	s.auditSoftwareAuthenticatorRefused(r.Context(), acct, cred, reason)
	if err != nil {
		s.logger.Error("Software authenticator registration refused: root tenant unresolved",
			"account_id", logging.SanitizeLogValue(acct.ID))
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Software authenticator policy cannot be evaluated", "SOFTWARE_AUTHENTICATOR_POLICY_UNAVAILABLE")
		return false
	}
	s.logger.Warn("Software authenticator registration refused",
		"account_id", logging.SanitizeLogValue(acct.ID),
		"tenant_id", logging.SanitizeLogValue(acct.TenantID))
	s.writeErrorResponse(w, http.StatusForbidden,
		"A software authenticator is not permitted for this account", errCodeSoftwareAuthenticatorNotAllowed)
	return false
}

// auditSoftwareAuthenticatorRefused records a denied registration naming the
// account, its tenant and the AAGUID.
func (s *Server) auditSoftwareAuthenticatorRefused(ctx context.Context, acct *account, cred *WebAuthnCredential, reason string) {
	if s.auditManager == nil {
		return
	}
	tenantID := acct.TenantID
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action("account.passkey_registration_denied").
		User(acct.ID, business.AuditUserTypeHuman).
		Resource("account", logging.SanitizeLogValue(acct.Username), "").
		Result(business.AuditResultDenied).
		Severity(business.AuditSeverityHigh).
		Details(map[string]interface{}{
			"account_id": acct.ID,
			"tenant_id":  acct.TenantID,
			"aaguid":     hex.EncodeToString(cred.AAGUID),
			"reason":     reason,
		})
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit software authenticator refusal audit event",
			"account_id", logging.SanitizeLogValue(acct.ID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
