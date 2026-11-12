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

// softwareCredentialsUsable reports whether acct's CFGMS software-authenticator
// credentials may be used right now (Issue #6143, ADR-021 Amendment 10 use-time half).
// An account that holds no software credential is always true and pays no policy
// lookup, so rootTenantID stays off its hot path. Otherwise the answer is
// softwareAuthenticatorPermitted, which fails closed: an unresolved root tenant
// returns (false, errRootTenantUnresolved).
func (s *Server) softwareCredentialsUsable(ctx context.Context, acct *account) (bool, error) {
	if acct == nil || !acct.hasSoftwareCredential() {
		return true, nil
	}
	return s.softwareAuthenticatorPermitted(ctx, acct)
}

// permittedAccountView returns the account as ceremony and session code may read its
// credentials: while softwareAuthenticatorPermitted is true (or the account holds no
// software credential) it is acct itself; otherwise it is a COPY with every software
// credential removed, so a credential the policy no longer permits cannot log in,
// elevate, give presence, sign, publish, be accepted by VerifyAssertion, or be listed
// in a roster. Credentials with any other AAGUID pass through untouched and gain
// nothing. acct is never modified and the stored credential is never deleted: it
// works again when the policy is turned back on.
//
// It fails closed. When the root tenant cannot be resolved the returned view still
// has the software credentials removed and the error is errRootTenantUnresolved
// (callers read the view and may ignore the error; it is logged here once).
//
// The view is for READ-ONLY use. A write that loads and stores the account (sign-count
// compare-and-swap, registration, revoke, relabel, enrollment) must use the FULL record
// so a write never drops a credential; that is why the filtering is not done in the
// account-load layer.
//
// Sites that read acct.Credentials in non-test code, and how each is treated:
//
// Filtered through this helper:
//   - handlers_passkey_login.go passkeyLoginUserResolver (user handed to
//     FinishDiscoverableLogin)
//   - handlers_webauthn.go handlePresenceBegin / handlePresenceFinish (user and the
//     NO_CREDENTIALS check)
//   - handlers_webauthn_elevate.go handleStepUpBegin / handleStepUpFinish (user and
//     the NO_CREDENTIALS check)
//   - handlers_operator_payload_sign.go sign begin / finish (user and the
//     NO_CREDENTIALS check)
//   - handlers_workflow_publish.go publish begin (user, NO_CREDENTIALS),
//     verifyPublishAssertion (VerifyAssertion) and the publicationSigner built by
//     VerifyWorkflowPublication (stored publication re-verification)
//   - operator_envelope_verify.go verifyActionWebAuthn (run-command proof)
//   - handlers_revocation_manifest.go steward roster build
//   - middleware.go webSessionRefusal / cliLoginSessionRefused (through
//     softwareCredentialsUsable), webSessionPrincipal and the principal refresh
//     AuthenticatorCount (auth_reauthorize.go)
//
// Deliberately the FULL set:
//   - handlers_webauthn.go registration begin/finish, enrollment begin/finish,
//     credential list, relabel and revoke (exclusions must hold every existing ID;
//     admins must still see and revoke software credentials), and
//     checkEnrollmentPreconditions (a software-only account whose policy is off is
//     still "already enrolled", so the zero-credential bootstrap stays closed)
//   - handlers_passkey_login.go recordAssertionSignCount and
//     operator_ceremony_core.go withAdvancedSignCount/persistAdvancedSignCount
//     (persist paths on the fresh record)
//   - handlers_accounts.go (storage encode/decode, reset, enrollment-link minting)
//   - webauthn_types.go hasSoftwareCredential (the predicate itself)
func (s *Server) permittedAccountView(ctx context.Context, acct *account) (*account, error) {
	usable, err := s.softwareCredentialsUsable(ctx, acct)
	if usable {
		return acct, nil
	}
	if err != nil {
		s.logger.Warn("Software authenticator credentials ignored: root tenant unresolved",
			"account_id", logging.SanitizeLogValue(acct.ID))
	}
	view := *acct
	view.Credentials = make([]WebAuthnCredential, 0, len(acct.Credentials))
	for _, c := range acct.Credentials {
		if !c.isSoftwareAuthenticator() {
			view.Credentials = append(view.Credentials, c)
		}
	}
	return &view, err
}

// usableCredentialCount is the number of registered credentials that count toward
// the account's authenticator count: every credential, minus the CFGMS software
// authenticators when softwareCredentialsPermitted is false (Issue #6143). A
// software-only account whose policy is off therefore reports 0 and is held to the
// zero-authenticator confinement (fail closed); the stored credentials are untouched.
func (a *account) usableCredentialCount(softwareCredentialsPermitted bool) int {
	if softwareCredentialsPermitted {
		return len(a.Credentials)
	}
	n := 0
	for _, c := range a.Credentials {
		if !c.isSoftwareAuthenticator() {
			n++
		}
	}
	return n
}
