// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6140: software-authenticator policy at registration (ADR-021 Amendment 10).
//
// A CFGMS software authenticator (pkg/softauthn) is accepted for an account only
// on one of two paths, and both need the account's AllowSoftwareAuthenticator flag:
//
//   - Tenant path: the account's tenant is listed in
//     webauthn.allow_software_authenticators.tenants in controller.cfg. It is never
//     accepted for an account with an empty TenantID and no root scope, or an account
//     in the root tenant, and it is refused when the root tenant cannot be resolved.
//   - Root agent path (Issue #6225, ADR-021 Amendment 11): the account is root-scope,
//     webauthn.allow_software_authenticators.root_agent_accounts is on, the account is
//     not cfgms-admin, holds no bound admin certificate and every credential it holds
//     is a CFGMS software credential (rootAgentRefusalReason).
//
// The tenant list and the root-agent setting are exact and have no API writer. The AAGUID that selects this policy is self-asserted under
// attestation "none", so a credential with any other AAGUID is registered on the
// ordinary path and receives no different trust, assurance or exemption.

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const errCodeSoftwareAuthenticatorNotAllowed = "SOFTWARE_AUTHENTICATOR_NOT_ALLOWED"

// systemAdminAccountName is the reserved name of the system admin account. It repeats
// systemAdminUsername in features/controller/initialization/admin_bundle.go, which api
// cannot import (import cycle); a rename there must be made here too. The account is
// never a root agent account.
const systemAdminAccountName = "cfgms-admin"

// Refusal reasons recorded on a refused software-authenticator registration (the
// "reason" audit detail). reasonPolicy is every refusal that is not a root-agent rule.
const (
	reasonPolicy                   = "policy"
	reasonRootTenantUnresolved     = "root_tenant_unresolved"
	reasonRootAgentSettingOff      = "root_agent_setting_off"
	reasonRootAgentFlagUnset       = "root_agent_flag_unset"
	reasonRootAgentSystemAdmin     = "root_agent_system_admin"
	reasonRootAgentCertBound       = "root_agent_cert_bound"
	reasonRootAgentHumanCredential = "root_agent_non_software_credential"
)

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

// SetSoftwareAuthenticatorRootAgentAccounts installs the controller.cfg root-agent
// setting (webauthn.allow_software_authenticators.root_agent_accounts, Issue #6225).
// Call after New() and before Start(). False, the default, refuses every root-scope
// account.
func (s *Server) SetSoftwareAuthenticatorRootAgentAccounts(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.softwareAuthenticatorRootAgents = enabled
}

// SoftwareAuthenticatorRootAgentAccounts reports the root-agent setting. It says
// nothing about any account; softwareAuthenticatorPermitted is the decision.
func (s *Server) SoftwareAuthenticatorRootAgentAccounts() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.softwareAuthenticatorRootAgents
}

// rootAgentRefusalReason names the first root-agent condition acct fails, or "" when
// acct is eligible. The root-agent setting is not part of it (the caller owns that
// test). The conditions: the flag is set, the account is not cfgms-admin, it holds no
// bound admin certificate and every credential it holds is a CFGMS software
// credential. A zero-credential account passes the last one.
func rootAgentRefusalReason(acct *account) string {
	switch {
	case !acct.AllowSoftwareAuthenticator:
		return reasonRootAgentFlagUnset
	case acct.Username == systemAdminAccountName:
		return reasonRootAgentSystemAdmin
	case len(acct.CertBindings) > 0:
		return reasonRootAgentCertBound
	}
	for i := range acct.Credentials {
		if !acct.Credentials[i].isSoftwareAuthenticator() {
			return reasonRootAgentHumanCredential
		}
	}
	return ""
}

// softwareAuthenticatorPermitted reports whether acct may hold a CFGMS software
// authenticator. It fails closed: it returns (false, errRootTenantUnresolved) when
// the root tenant cannot be resolved, and (false, nil) for every refused shape. A
// root-scope account is judged by the root agent rules (rootAgentRefusalReason plus
// the controller.cfg setting) and needs no root tenant; every other account by the
// tenant list.
func (s *Server) softwareAuthenticatorPermitted(ctx context.Context, acct *account) (bool, error) {
	permitted, _, err := s.softwareAuthenticatorDecision(ctx, acct)
	return permitted, err
}

// softwareAuthenticatorDecision is softwareAuthenticatorPermitted plus the reason for
// a refusal, for the registration audit event.
func (s *Server) softwareAuthenticatorDecision(ctx context.Context, acct *account) (permitted bool, reason string, err error) {
	if acct == nil {
		return false, reasonPolicy, nil
	}
	if acct.RootScope {
		if !s.SoftwareAuthenticatorRootAgentAccounts() {
			return false, reasonRootAgentSettingOff, nil
		}
		if reason := rootAgentRefusalReason(acct); reason != "" {
			return false, reason, nil
		}
		return true, "", nil
	}
	if acct.TenantID == "" {
		return false, reasonPolicy, nil
	}
	root := s.rootTenantID(ctx)
	if root == "" {
		return false, reasonRootTenantUnresolved, errRootTenantUnresolved
	}
	if acct.TenantID == root {
		return false, reasonPolicy, nil
	}
	if s.SoftwareAuthenticatorTenantListed(acct.TenantID) && acct.AllowSoftwareAuthenticator {
		return true, "", nil
	}
	return false, reasonPolicy, nil
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
	permitted, reason, err := s.softwareAuthenticatorDecision(r.Context(), acct)
	if permitted {
		return true
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
// account, its tenant, the AAGUID and the reason. A root-scope account's event also
// carries root_scope: true, which tells it from tenant use (Issue #6225).
func (s *Server) auditSoftwareAuthenticatorRefused(ctx context.Context, acct *account, cred *WebAuthnCredential, reason string) {
	if s.auditManager == nil {
		return
	}
	tenantID := acct.TenantID
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	details := map[string]interface{}{
		"account_id": acct.ID,
		"tenant_id":  acct.TenantID,
		"aaguid":     hex.EncodeToString(cred.AAGUID),
		"reason":     reason,
	}
	if acct.RootScope {
		details[auditKeyRootScope] = true
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action("account.passkey_registration_denied").
		User(acct.ID, business.AuditUserTypeHuman).
		Resource("account", logging.SanitizeLogValue(acct.Username), "").
		Result(business.AuditResultDenied).
		Severity(business.AuditSeverityHigh).
		Details(details)
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

// Audit actions for a presence ceremony's credential use (Issue #6144).
const (
	presenceAuditActionSuccess = "web.presence.success"
	presenceAuditActionFailure = "web.presence.failure"
)

// Audit actions for a step-up elevation's credential use (Issue #6144).
const (
	stepUpAuditActionSuccess = "web.stepup.success"
	stepUpAuditActionFailure = "web.stepup.failure"
)

// Audit detail keys written for every audited use of a credential (Issue #6144).
const (
	auditKeySoftwareAuthenticator = "software_authenticator"
	auditKeyAAGUID                = "aaguid"
	auditKeyCredentialID          = "credential_id"
	auditKeyReason                = "reason"
	auditKeyRootScope             = "root_scope" // true on an event for a root-scope account (Issue #6225)

	// auditReasonSoftwareAuthenticatorPolicy is the reason on a use the policy refused.
	auditReasonSoftwareAuthenticatorPolicy = "software_authenticator_policy"
)

// softwareAuthenticatorAuditDetails is the one place that turns "this credential was
// used on this account" into audit detail fields (Issue #6144): software_authenticator
// (true when the recorded AAGUID is softauthn.AAGUID, false for every other
// credential), aaguid (hex) and credential_id (base64url, the form the credential
// list and the registration events use), plus root_scope: true for a root-scope
// account (Issue #6225), so a root agent's use is told from tenant use. It returns nil when the credential is not
// one of acct's, so an event never claims a marker for a credential it cannot
// identify. acct must be the full record, not permittedAccountView's copy: a
// credential the policy has stopped permitting is still on the full record, which is
// what lets a refused use be attributed.
//
// The marker reflects a self-asserted AAGUID: it labels the credential and is not
// proof of what produced it.
func softwareAuthenticatorAuditDetails(acct *account, credentialID []byte) map[string]interface{} {
	if acct == nil || len(credentialID) == 0 {
		return nil
	}
	for i := range acct.Credentials {
		c := &acct.Credentials[i]
		if !bytes.Equal(c.ID, credentialID) {
			continue
		}
		details := map[string]interface{}{
			auditKeySoftwareAuthenticator: c.isSoftwareAuthenticator(),
			auditKeyAAGUID:                hex.EncodeToString(c.AAGUID),
			auditKeyCredentialID:          base64.RawURLEncoding.EncodeToString(c.ID),
		}
		if acct.RootScope {
			details[auditKeyRootScope] = true
		}
		return details
	}
	return nil
}

// softwareAuthenticatorFailedUse classifies a use of credentialID on acct that did not
// succeed. It returns business.AuditResultDenied with the policy reason when the
// credential is a CFGMS software authenticator the policy does not permit right now
// (the library never saw it, so a bad signature cannot be told from a refusal),
// business.AuditResultFailure otherwise. details are softwareAuthenticatorAuditDetails
// plus the reason on a refusal (nil when the credential is not identifiable) and
// software reports whether the credential is a software authenticator.
func (s *Server) softwareAuthenticatorFailedUse(ctx context.Context, acct *account, credentialID []byte) (result business.AuditResult, details map[string]interface{}, software bool) {
	details = softwareAuthenticatorAuditDetails(acct, credentialID)
	software, _ = details[auditKeySoftwareAuthenticator].(bool)
	if !software {
		return business.AuditResultFailure, details, false
	}
	if usable, _ := s.softwareCredentialsUsable(ctx, acct); !usable {
		details[auditKeyReason] = auditReasonSoftwareAuthenticatorPolicy
		return business.AuditResultDenied, details, true
	}
	return business.AuditResultFailure, details, true
}

// emitCredentialUseAudit records one use of a credential by acct under action: the
// outcome plus the softwareAuthenticatorAuditDetails fields. It is the event for the
// ceremonies that have no audit event of their own (presence, step-up elevation, and a
// publish assertion that did not verify). details, when non-nil, replaces the default
// softwareAuthenticatorAuditDetails (a failed use passes the ones that carry the reason).
func (s *Server) emitCredentialUseAudit(ctx context.Context, acct *account, credentialID []byte, action string, result business.AuditResult, details map[string]interface{}) {
	if s.auditManager == nil || acct == nil {
		return
	}
	tenantID := acct.TenantID
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	severity := business.AuditSeverityHigh
	if result == business.AuditResultSuccess {
		severity = business.AuditSeverityLow
	}
	if details == nil {
		details = softwareAuthenticatorAuditDetails(acct, credentialID)
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventAuthentication).
		Action(action).
		User(acct.ID, business.AuditUserTypeHuman).
		Resource("account", logging.SanitizeLogValue(acct.Username), "").
		Result(result).
		Severity(severity).
		Details(details)
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit credential use audit event",
			"action", action,
			"account_id", logging.SanitizeLogValue(acct.ID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// auditCredentialUseSuccess records a verified use of credentialID by acct under action,
// whatever kind of credential it is.
func (s *Server) auditCredentialUseSuccess(ctx context.Context, acct *account, credentialID []byte, action string) {
	s.emitCredentialUseAudit(ctx, acct, credentialID, action, business.AuditResultSuccess, nil)
}

// auditSoftwareAuthenticatorFailure records a failed or policy-refused use of a CFGMS
// software authenticator under action. A use of any other credential is not recorded:
// the ceremonies that had no failure event keep none for hardware credentials, so
// what they record for those does not change.
func (s *Server) auditSoftwareAuthenticatorFailure(ctx context.Context, acct *account, credentialID []byte, action string) {
	result, details, software := s.softwareAuthenticatorFailedUse(ctx, acct, credentialID)
	if software {
		s.emitCredentialUseAudit(ctx, acct, credentialID, action, result, details)
	}
}

// finishLoginWithCredentialID is webauthn.FinishLogin (parse the assertion, then
// ValidateLogin) that also returns the credential ID the assertion named, so a failed
// verification can still be attributed to the credential. The ID is nil when the body
// did not parse.
func finishLoginWithCredentialID(wa *webauthn.WebAuthn, user webauthn.User, data webauthn.SessionData, r *http.Request) (*webauthn.Credential, []byte, error) {
	parsed, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		return nil, nil, err
	}
	credential, err := wa.ValidateLogin(user, data, parsed)
	return credential, parsed.RawID, err
}
