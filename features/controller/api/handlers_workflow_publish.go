// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
//
// ADR-036 section 4: publish one stored workflow version with a passkey tap.
//
//	POST /api/v1/workflows/{id}/versions/{version}/publish/begin
//	     Loads the exact stored version, builds the operatorpayload workflow envelope
//	     (tenant, name, version and the canonical content hash, with a fresh nonce and
//	     expiry) and issues a WebAuthn challenge equal to its ChallengeHash.
//
//	POST /api/v1/workflows/{id}/versions/{version}/publish/finish
//	     Reloads the version, rebuilds the envelope from the CURRENT canonical hash and
//	     refuses unless it equals the one the ceremony issued, verifies the assertion
//	     through VerifyAssertion (the account's registered credential key is the only
//	     trust anchor), and stores a workflow.Publication on that exact version.
//
// The controller holds no workflow-signing key: it stores the authenticator's assertion
// and re-verifies it with VerifyWorkflowPublication whenever a published version is used.
package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// workflowPublishAuditAction is the audit action recorded for a completed publish.
const workflowPublishAuditAction = "workflow.publish"

// workflowPublishSessionKey keys a publish ceremony apart from a payload-sign ceremony
// of the same web session, so neither can consume or replace the other.
func workflowPublishSessionKey(sessID string) string { return "workflow-publish:" + sessID }

// WorkflowPublishBeginResponse is the JSON response from publish/begin.
type WorkflowPublishBeginResponse struct {
	Assertion   *protocol.CredentialAssertion `json:"assertion"`
	Name        string                        `json:"name"`
	Version     string                        `json:"version"`
	ContentHash string                        `json:"content_hash"` // canonical hash of the version being published
}

// WorkflowPublishFinishResponse is the JSON response from publish/finish. It carries no
// ceremony state.
type WorkflowPublishFinishResponse struct {
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	ContentHash     string    `json:"content_hash"`
	SignerAccountID string    `json:"signer_account_id"`
	SignedAt        time.Time `json:"signed_at"`
}

// publishTarget is the stored workflow version a publish request addresses.
type publishTarget struct {
	store   *workflow.WorkflowStore
	version workflow.SemanticVersion
	vw      *workflow.VersionedWorkflow
}

// loadPublishTarget resolves the tenant store for the caller and loads the exact stored
// version named in the URL. It writes the response and returns false when the request
// is refused; a version outside the caller's tenant is simply not found.
func (s *Server) loadPublishTarget(w http.ResponseWriter, r *http.Request) (*publishTarget, bool) {
	s.mu.RLock()
	h := s.workflowHandler
	s.mu.RUnlock()
	if h == nil || h.engine == nil || h.configStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "workflow engine not available", "WORKFLOW_UNAVAILABLE")
		return nil, false
	}
	vars := mux.Vars(r)
	name := vars["id"]
	sv, err := workflow.ParseSemanticVersion(vars["version"])
	if name == "" || err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "a workflow name and semantic version are required", "INVALID_VERSION")
		return nil, false
	}
	store, ok := h.workflowStoreForRequest(w, r)
	if !ok {
		return nil, false
	}
	vw, err := store.GetWorkflow(r.Context(), name, *sv)
	if err != nil || vw == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "workflow version not found", "NOT_FOUND")
		return nil, false
	}
	return &publishTarget{store: store, version: *sv, vw: vw}, true
}

// accountHoldsWorkflowPublish reports whether acct may publish in tenantID right now: it
// is enabled and either root-scoped or holds workflow:publish with tenantID inside its
// own tenant's subtree. It is deliberately not accountHoldsOperatorPayloadSigning, which
// answers for a different permission.
func (s *Server) accountHoldsWorkflowPublish(ctx context.Context, acct *account, tenantID string) bool {
	if acct == nil || acct.Disabled {
		return false
	}
	if acct.RootScope {
		return true
	}
	for _, p := range acct.Permissions {
		if p == workflow.PublishPermission {
			return s.tenantSubtreeContains(ctx, acct.TenantID, tenantID)
		}
	}
	return false
}

// publicationSigner adapts a live account to workflow.PublicationSigner.
type publicationSigner struct {
	s    *Server
	acct *account
}

func (p publicationSigner) Enabled() bool { return !p.acct.Disabled }

func (p publicationSigner) VerifyAssertion(envelope operatorpayload.Envelope, pub *workflow.Publication) error {
	proof, err := proofFromPublication(pub)
	if err != nil {
		return err
	}
	_, err = p.s.VerifyAssertion(p.acct, envelope, proof)
	return err
}

// proofFromPublication decodes the stored assertion fields.
func proofFromPublication(pub *workflow.Publication) (*OperatorWebAuthnProof, error) {
	dec := base64.RawURLEncoding.DecodeString
	var proof OperatorWebAuthnProof
	var err error
	if proof.CredentialID, err = dec(pub.CredentialID); err != nil {
		return nil, errors.New("stored credential id is malformed")
	}
	if proof.AuthenticatorData, err = dec(pub.AuthenticatorData); err != nil {
		return nil, errors.New("stored authenticator data is malformed")
	}
	if proof.ClientDataJSON, err = dec(pub.ClientDataJSON); err != nil {
		return nil, errors.New("stored client data is malformed")
	}
	if proof.Signature, err = dec(pub.Signature); err != nil {
		return nil, errors.New("stored signature is malformed")
	}
	return &proof, nil
}

// VerifyWorkflowPublication re-verifies the stored Publication of vw, a version stored in
// tenantID. It reads the signer account live on every call and caches nothing.
func (s *Server) VerifyWorkflowPublication(ctx context.Context, tenantID string, vw *workflow.VersionedWorkflow) error {
	return workflow.VerifyPublication(ctx, tenantID, vw,
		func(ctx context.Context, accountID string) (workflow.PublicationSigner, error) {
			acct, err := s.getAccountByID(ctx, accountID)
			if err != nil || acct == nil {
				return nil, err
			}
			return publicationSigner{s: s, acct: acct}, nil
		},
		func(ctx context.Context, accountID, permissionID, tenantID string) bool {
			if permissionID != workflow.PublishPermission {
				return false
			}
			acct, err := s.getAccountByID(ctx, accountID)
			return err == nil && s.accountHoldsWorkflowPublish(ctx, acct, tenantID)
		})
}

// ceremonyAccount loads the calling account for a publish ceremony call. It writes the
// response and returns false when the request cannot proceed.
func (s *Server) ceremonyAccount(w http.ResponseWriter, r *http.Request) (*Principal, string, *account, bool) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return nil, "", nil, false
	}
	sessID, _ := r.Context().Value(webSessionIDContextKey).(string)
	if sessID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Publishing requires a cookie-authenticated web session", "SESSION_REQUIRED")
		return nil, "", nil, false
	}
	acct, err := s.getAccountByID(r.Context(), principal.ID)
	if err != nil {
		s.logger.Error("Workflow publish: failed to load account",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to load account", "STORE_ERROR")
		return nil, "", nil, false
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Account not found", "ACCOUNT_NOT_FOUND")
		return nil, "", nil, false
	}
	return principal, sessID, acct, true
}

// handleWorkflowPublishBegin handles POST /api/v1/workflows/{id}/versions/{version}/publish/begin.
func (s *Server) handleWorkflowPublishBegin(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}
	principal, sessID, acct, ok := s.ceremonyAccount(w, r)
	if !ok {
		return
	}
	if len(acct.Credentials) == 0 {
		s.writeErrorResponse(w, http.StatusConflict,
			"No WebAuthn credentials registered — enroll a passkey first", "NO_CREDENTIALS")
		return
	}
	target, ok := s.loadPublishTarget(w, r)
	if !ok {
		return
	}
	tenantID := target.store.TenantID()
	// A publication the signer could not later pass VerifyPublication with is refused now.
	if !s.accountHoldsWorkflowPublish(r.Context(), acct, tenantID) {
		s.writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions", "FORBIDDEN")
		return
	}

	envelope, contentHash, hash, ok := s.newPublishChallenge(w, tenantID, target.vw)
	if !ok {
		return
	}

	assertion, sessionData, err := wa.BeginLogin(buildWebauthnUser(acct),
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithChallenge(hash[:]))
	if err != nil {
		s.logger.Error("Workflow publish begin: BeginLogin failed",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to begin publish ceremony", "WEBAUTHN_BEGIN_ERROR")
		return
	}
	if out := s.putPayloadSignSession(r.Context(), workflowPublishSessionKey(sessID), &operatorPayloadSignSession{
		data:      *sessionData,
		expires:   time.Now().Add(webAuthnSessionTTL),
		accountID: principal.ID,
		envelope:  envelope,
		hash:      hash,
	}); out != ceremonyOK {
		s.writeCeremonyUnavailable(w)
		return
	}

	s.writeResponse(w, http.StatusOK, WorkflowPublishBeginResponse{
		Assertion:   assertion,
		Name:        target.vw.Name,
		Version:     target.version.String(),
		ContentHash: contentHash,
	})
}

// newPublishChallenge builds the publish envelope for vw in tenantID with a fresh nonce
// and ceremony expiry, and its WebAuthn challenge hash. It writes the response and
// returns false when the envelope cannot be built.
func (s *Server) newPublishChallenge(w http.ResponseWriter, tenantID string, vw *workflow.VersionedWorkflow) (operatorpayload.Envelope, string, [32]byte, bool) {
	nonce, err := generateOperatorPayloadSignNonce()
	if err != nil {
		s.logger.Error("Workflow publish begin: nonce generation failed",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate nonce", "NONCE_ERROR")
		return operatorpayload.Envelope{}, "", [32]byte{}, false
	}
	// Whole seconds in UTC, so the expiry survives storage and rebuilds the same bytes.
	expiresAt := time.Now().Add(operatorpayload.WorkflowEnvelopeMaxTTL).UTC().Truncate(time.Second)
	envelope, contentHash, err := workflow.PublicationEnvelope(tenantID, vw, nonce, expiresAt)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Workflow version cannot be published", "INVALID_ENVELOPE")
		return operatorpayload.Envelope{}, "", [32]byte{}, false
	}
	hash, err := operatorpayload.ChallengeHash(envelope)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Workflow version cannot be published", "INVALID_ENVELOPE")
		return operatorpayload.Envelope{}, "", [32]byte{}, false
	}
	return envelope, contentHash, hash, true
}

// takePublishSession consumes the publish ceremony session of sessID. The session is
// single use: it is consumed whatever the outcome. It writes the response and returns
// false when there is no live session issued to principalID.
func (s *Server) takePublishSession(w http.ResponseWriter, r *http.Request, sessID, principalID string) (*operatorPayloadSignSession, bool) {
	pending, out := s.takePayloadSignSession(r.Context(), workflowPublishSessionKey(sessID))
	if out == ceremonyUnavailable {
		s.writeCeremonyUnavailable(w)
		return nil, false
	}
	if out != ceremonyOK || (pending.accountID != "" && pending.accountID != principalID) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"No active publish session — call begin first", "NO_ACTIVE_PUBLISH_SESSION")
		return nil, false
	}
	if time.Now().After(pending.expires) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Publish session expired — restart with begin", "SESSION_EXPIRED")
		return nil, false
	}
	return pending, true
}

// publishThrottled reports whether failed attempts on the web session or client IP have
// tripped the sign throttle, writing the response when they have.
func (s *Server) publishThrottled(w http.ResponseWriter, sessID, ipKey string) bool {
	blocked, _ := s.checkSignThrottle(signSessionThrottleKey(sessID))
	if !blocked && ipKey != "" {
		blocked, _ = s.checkSignThrottle(signIPThrottleKey(ipKey))
	}
	if blocked {
		s.writeErrorResponse(w, http.StatusTooManyRequests, "Too many failed attempts — try again later", "THROTTLED")
	}
	return blocked
}

// rebuildPublishEnvelope reloads the version's CURRENT canonical hash into the envelope
// the ceremony issued and refuses unless its challenge equals the issued one: an edit
// between begin and finish changes the hash, so the signed challenge no longer matches.
func rebuildPublishEnvelope(tenantID string, vw *workflow.VersionedWorkflow, pending *operatorPayloadSignSession) (operatorpayload.Envelope, string, int, string, string) {
	envelope, contentHash, err := workflow.PublicationEnvelope(tenantID, vw, pending.envelope.Nonce, pending.envelope.ExpiresAt)
	if err != nil {
		return operatorpayload.Envelope{}, "", http.StatusConflict, "Workflow version cannot be published", "INVALID_ENVELOPE"
	}
	rebuilt, err := operatorpayload.ChallengeHash(envelope)
	if err != nil || rebuilt != pending.hash {
		return operatorpayload.Envelope{}, "", http.StatusConflict, "Workflow version changed since the publish ceremony began — restart with begin", "VERSION_CHANGED"
	}
	return envelope, contentHash, 0, "", ""
}

// publishAssertion is a verified publish assertion and the credential that made it.
type publishAssertion struct {
	proof      *OperatorWebAuthnProof
	credential *WebAuthnCredential
	newCount   uint32
}

// verifyPublishAssertion reads the assertion from the request body and verifies it over
// envelope under acct's registered credential, refusing a non-advancing sign count. It
// writes the response (counting a throttle failure through fail where the attempt is a
// failed verification) and returns false when the assertion does not verify.
func (s *Server) verifyPublishAssertion(w http.ResponseWriter, r *http.Request, acct *account, principalID string, envelope operatorpayload.Envelope, fail func(int, string, string)) (*publishAssertion, bool) {
	body, err := readAllAndClose(r)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to read request body", "INVALID_BODY")
		return nil, false
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		fail(http.StatusBadRequest, "WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return nil, false
	}
	raw := parsed.Raw.AssertionResponse
	proof := &OperatorWebAuthnProof{
		AuthenticatorData: []byte(raw.AuthenticatorData),
		ClientDataJSON:    []byte(raw.ClientDataJSON),
		Signature:         []byte(raw.Signature),
		CredentialID:      parsed.RawID,
	}
	credential, err := s.VerifyAssertion(acct, envelope, proof)
	if err != nil {
		s.logger.Warn("Workflow publish finish: assertion verification failed",
			"principal_id", logging.SanitizeLogValue(principalID),
			"error", logging.SanitizeLogValue(err.Error()))
		fail(http.StatusBadRequest, "WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return nil, false
	}
	newCount := parsed.Response.AuthenticatorData.Counter
	if !signCountAdvances(credential.SignCount, newCount) {
		s.logger.Warn("Workflow publish finish: sign count not advancing — potential authenticator clone",
			"principal_id", logging.SanitizeLogValue(principalID))
		fail(http.StatusBadRequest, "WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return nil, false
	}
	return &publishAssertion{proof: proof, credential: credential, newCount: newCount}, true
}

// storePublication stores published over target's version and audits it. An unaudited
// publish must not stand, so an audit failure puts the version back as it was. It
// writes the response and returns false on failure.
func (s *Server) storePublication(w http.ResponseWriter, r *http.Request, target *publishTarget, tenantID, principalID string, published *workflow.VersionedWorkflow) bool {
	if err := target.store.StoreWorkflow(r.Context(), published); err != nil {
		s.logger.Error("Workflow publish finish: failed to store publication",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store publication", "STORE_ERROR")
		return false
	}
	if err := s.auditWorkflowPublish(r.Context(), tenantID, principalID, published); err != nil {
		s.logger.Error("Workflow publish finish: audit failed, withdrawing publication",
			"error", logging.SanitizeLogValue(err.Error()))
		if rbErr := target.store.StoreWorkflow(r.Context(), target.vw); rbErr != nil {
			s.logger.Error("Workflow publish finish: failed to withdraw publication",
				"error", logging.SanitizeLogValue(rbErr.Error()))
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to audit publication", "AUDIT_ERROR")
		return false
	}
	return true
}

// handleWorkflowPublishFinish handles POST /api/v1/workflows/{id}/versions/{version}/publish/finish.
func (s *Server) handleWorkflowPublishFinish(w http.ResponseWriter, r *http.Request) {
	if s.getWebAuthn() == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}
	principal, sessID, acct, ok := s.ceremonyAccount(w, r)
	if !ok {
		return
	}
	pending, ok := s.takePublishSession(w, r, sessID, principal.ID)
	if !ok {
		return
	}
	ipKey := s.clientIPKey(r)
	if s.publishThrottled(w, sessID, ipKey) {
		return
	}
	fail := func(status int, msg, code string) {
		s.recordSignFailures(sessID, ipKey)
		s.writeErrorResponse(w, status, msg, code)
	}

	target, ok := s.loadPublishTarget(w, r)
	if !ok {
		return
	}
	tenantID := target.store.TenantID()
	envelope, contentHash, status, msg, code := rebuildPublishEnvelope(tenantID, target.vw, pending)
	if status != 0 {
		fail(status, msg, code)
		return
	}
	verified, ok := s.verifyPublishAssertion(w, r, acct, principal.ID, envelope, fail)
	if !ok {
		return
	}
	if !s.accountHoldsWorkflowPublish(r.Context(), acct, tenantID) {
		s.writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions", "FORBIDDEN")
		return
	}
	s.persistAdvancedSignCount(r.Context(), acct, verified.credential.ID, verified.newCount, principal.ID, "Workflow publish finish")

	b64 := base64.RawURLEncoding.EncodeToString
	signedAt := time.Now().UTC()
	published := *target.vw
	published.Publication = &workflow.Publication{
		ContentHash:       contentHash,
		Nonce:             pending.envelope.Nonce,
		ExpiresAt:         pending.envelope.ExpiresAt,
		CredentialID:      b64(verified.credential.ID),
		AuthenticatorData: b64(verified.proof.AuthenticatorData),
		ClientDataJSON:    b64(verified.proof.ClientDataJSON),
		Signature:         b64(verified.proof.Signature),
		SignerAccountID:   acct.ID,
		SignedAt:          signedAt,
	}
	if !s.storePublication(w, r, target, tenantID, principal.ID, &published) {
		return
	}

	s.writeResponse(w, http.StatusOK, WorkflowPublishFinishResponse{
		Name:            published.Name,
		Version:         target.version.String(),
		ContentHash:     contentHash,
		SignerAccountID: acct.ID,
		SignedAt:        signedAt,
	})
}

// auditWorkflowPublish records workflow.publish naming the workflow, version, content
// hash and signer. A failure is returned: an unaudited publish fails.
func (s *Server) auditWorkflowPublish(ctx context.Context, tenantID, signerID string, vw *workflow.VersionedWorkflow) error {
	if s.auditManager == nil {
		return errors.New("audit manager unavailable")
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventDataModification).
		Action(workflowPublishAuditAction).
		User(signerID, business.AuditUserTypeHuman).
		Resource("workflow", vw.Name, vw.Name).
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Details(map[string]interface{}{
			"name":          vw.Name,
			"version":       vw.SemanticVersion.String(),
			"hash":          vw.Publication.ContentHash,
			"signer":        signerID,
			"credential_id": vw.Publication.CredentialID,
		})
	return s.auditManager.RecordEvent(ctx, b)
}
