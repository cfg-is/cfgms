// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3725 (Epic #3711): revocation and containment for enrolment-issued
// credentials. Minting (#3717-#3719) and un-minting ship together — this story gives
// an administrator the tooling to contain a bad enrolment: revoke every certificate
// already issued from one enrolment token and block that token's still-pending/approved
// requests from ever producing one, cancel a request that was approved but never
// collected, and find — and, as a separate explicit action, revoke — enrolment-issued
// certificates that exist with no account binding.
//
// Cancelling a request is a state transition, not a certificate revocation: approval
// (#3718) signs nothing, and collect (#3719) is what mints the certificate, so an
// "approved" request has no certificate to revoke yet. Cancel and revoke-by-token both
// reuse credentialRequestStatusDenied for that transition (no new status value) and
// both persist via CompareAndSwapSecret (Issue #3775) — the same primitive
// claimCredentialRequestForCollection uses — so an in-flight collect can never race a
// containment action for the same request.
package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Sentinel errors returned by cancelApprovedCredentialRequest. Callers switch on these
// to translate the state-machine outcome to a distinct HTTP response per current status,
// exactly as the Issue #3725 AC requires (pending / already-collected / already-denied
// must each refuse with a distinguishable error).
var (
	errCredentialRequestNotFound            = errors.New("credential request not found")
	errCredentialRequestPendingNotApproved  = errors.New("credential request is pending, not yet approved")
	errCredentialRequestAlreadyDeniedCancel = errors.New("credential request is already denied")
)

// ---- response types -----------------------------------------------------------------

// credentialRequestContainmentOutcome is the per-request result of a revoke-by-token
// pass. Outcome is one of "contained", "already_contained" or "error" — the batch
// action reports one outcome per affected request rather than failing the whole
// operation on the first error (Issue #3725 AC).
type credentialRequestContainmentOutcome struct {
	RequestID string `json:"request_id"`
	Outcome   string `json:"outcome"`
	Detail    string `json:"detail,omitempty"`
}

// RevokeByEnrolmentTokenResponse is returned by POST .../enrolment-tokens/{id}/revoke-issued-credentials.
type RevokeByEnrolmentTokenResponse struct {
	TokenID string                                `json:"token_id"`
	Results []credentialRequestContainmentOutcome `json:"results"`
}

// OrphanedCredentialInfo describes a collected enrolment-flow certificate with no
// matching account binding — the on-demand equivalent of sweepOrphanedCollectedCertificates'
// predicate (Issue #3725 implementation note). Never carries the CSR or the collect secret.
type OrphanedCredentialInfo struct {
	RequestID   string `json:"request_id"`
	TenantID    string `json:"tenant_id"`
	Serial      string `json:"serial"`
	AccountID   string `json:"account_id"`
	CollectedAt string `json:"collected_at"`
}

// ---- state-machine helpers ------------------------------------------------------------

// cancelApprovedCredentialRequest performs the approved->denied compare-and-set for the
// standalone cancel action via CompareAndSwapSecret, keyed on the version just read —
// the same primitive claimCredentialRequestForCollection uses for the approved->collected
// transition, so a cancel and an in-flight collect for the same request can never both
// win against "approved" (Issue #3775).
//
// Returns a distinct sentinel per non-approved current status so the handler can refuse
// with a distinguishable error (Issue #3725 AC): pending isn't approved yet (use deny),
// collected already has a live certificate (use revoke-by-token or revoke-orphaned, not
// cancel), denied is already terminal.
func (s *Server) cancelApprovedCredentialRequest(ctx context.Context, id, actingPrincipalID string) (*pendingCredentialRequest, error) {
	fresh, err := s.getPendingCredentialRequestByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if fresh == nil {
		return nil, errCredentialRequestNotFound
	}
	switch fresh.Status {
	case credentialRequestStatusApproved:
		// falls through to the transition below
	case credentialRequestStatusCollected:
		return nil, errCredentialRequestAlreadyCollected
	case credentialRequestStatusDenied:
		return nil, errCredentialRequestAlreadyDeniedCancel
	default:
		// pending, or any future status — cancel only applies to "approved".
		return nil, errCredentialRequestPendingNotApproved
	}

	now := time.Now().UTC()
	fresh.Status = credentialRequestStatusDenied
	fresh.DeniedAt = &now
	fresh.DeniedBy = actingPrincipalID
	newVersion, ok, err := s.persistPendingCredentialRequestCAS(ctx, fresh)
	if err != nil {
		return nil, err
	}
	if !ok {
		// Lost the race: a concurrent collect or containment action already
		// transitioned this request away from "approved" between the read above
		// and this compare-and-set. Re-read to report the accurate sentinel
		// rather than a generic conflict.
		latest, latestErr := s.getPendingCredentialRequestByID(ctx, id)
		if latestErr != nil {
			return nil, latestErr
		}
		if latest == nil {
			return nil, errCredentialRequestNotFound
		}
		switch latest.Status {
		case credentialRequestStatusCollected:
			return nil, errCredentialRequestAlreadyCollected
		case credentialRequestStatusDenied:
			return nil, errCredentialRequestAlreadyDeniedCancel
		default:
			return nil, errCredentialRequestPendingNotApproved
		}
	}
	fresh.Version = newVersion
	return fresh, nil
}

// blockCredentialRequestFromEverCollecting transitions req from "pending" or "approved"
// to "denied" via CompareAndSwapSecret keyed on the version just read, so an in-flight
// collect claim (or any other concurrent transition) on the same request can never race
// this containment action (Issue #3775). Unlike cancelApprovedCredentialRequest it
// accepts "pending" as well — revoke-by-token must block every request that could still
// someday produce a certificate, not only ones an administrator already approved.
//
// blocked is false (with a nil error) when the request has already left the
// pending/approved window (denied, collected, or gone) — that is itself containment,
// not a failure, and the caller reports it as such.
func (s *Server) blockCredentialRequestFromEverCollecting(ctx context.Context, id, actingPrincipalID string) (blocked bool, err error) {
	fresh, err := s.getPendingCredentialRequestByID(ctx, id)
	if err != nil {
		return false, err
	}
	if fresh == nil {
		return false, nil
	}
	if fresh.Status != credentialRequestStatusPending && fresh.Status != credentialRequestStatusApproved {
		return false, nil
	}

	now := time.Now().UTC()
	fresh.Status = credentialRequestStatusDenied
	fresh.DeniedAt = &now
	fresh.DeniedBy = actingPrincipalID
	_, ok, err := s.persistPendingCredentialRequestCAS(ctx, fresh)
	if err != nil {
		return false, err
	}
	if !ok {
		// Lost the race: a concurrent transition already moved this request out of
		// pending/approved between the read above and this compare-and-set.
		return false, nil
	}

	s.emitCredentialRequestAudit(ctx, "credential_request.denied", fresh.TenantID, actingPrincipalID,
		business.AuditUserTypeHuman, "credential_request", fresh.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{"reason": "enrolment-token containment"})
	return true, nil
}

// revokeCollectedCredentialRequest revokes req's issued certificate then removes its
// account binding — revoke first, so a partial failure leaves a revoked-but-still-bound
// certificate rather than a live unbound one (Issue #3725 [REQUIRED TEST], mirroring
// handleRevokeCertBinding's fail-closed ordering).
func (s *Server) revokeCollectedCredentialRequest(ctx context.Context, req *pendingCredentialRequest, actingPrincipalID string) credentialRequestContainmentOutcome {
	if req.CollectedSerial == "" {
		return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "already_contained"}
	}
	if s.certManager == nil {
		return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "error", Detail: "certificate manager not available"}
	}

	if err := s.certManager.Revoke(req.CollectedSerial); err != nil {
		s.logger.Error("Revoke-by-token: failed to revoke collected certificate",
			"request_id", logging.SanitizeLogValue(req.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "error", Detail: "failed to revoke certificate"}
	}

	if req.BoundAccountID == "" {
		s.emitCredentialRequestAudit(ctx, "credential_request.collected_certificate_revoked", req.TenantID, actingPrincipalID,
			business.AuditUserTypeHuman, "credential_request", req.ID,
			business.AuditResultSuccess, business.AuditSeverityHigh,
			map[string]interface{}{"serial": req.CollectedSerial})
		return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "contained"}
	}

	acct, err := s.getAccountByID(ctx, req.BoundAccountID)
	if err != nil {
		s.logger.Error("Revoke-by-token: certificate revoked but account lookup failed; binding state unknown",
			"request_id", logging.SanitizeLogValue(req.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "error", Detail: "certificate revoked but account lookup failed; binding may still be present"}
	}
	if acct != nil {
		if err := s.removeCertBindingFromAccount(ctx, acct.Username, req.CollectedSerial, actingPrincipalID); err != nil {
			s.logger.Error("Revoke-by-token: certificate revoked but binding removal failed",
				"request_id", logging.SanitizeLogValue(req.ID),
				"error", logging.SanitizeLogValue(err.Error()))
			return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "error", Detail: "certificate revoked but binding removal failed"}
		}
	}

	s.emitCredentialRequestAudit(ctx, "credential_request.collected_certificate_revoked", req.TenantID, actingPrincipalID,
		business.AuditUserTypeHuman, "credential_request", req.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{"serial": req.CollectedSerial, "account_id": req.BoundAccountID})
	return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "contained"}
}

// containOneCredentialRequest routes req to the correct containment action for its
// current status and returns the per-request outcome revoke-by-token reports.
func (s *Server) containOneCredentialRequest(ctx context.Context, req *pendingCredentialRequest, actingPrincipalID string) credentialRequestContainmentOutcome {
	switch req.Status {
	case credentialRequestStatusDenied:
		return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "already_contained"}

	case credentialRequestStatusPending, credentialRequestStatusApproved:
		blocked, err := s.blockCredentialRequestFromEverCollecting(ctx, req.ID, actingPrincipalID)
		if err != nil {
			s.logger.Error("Revoke-by-token: failed to block credential request from collecting",
				"request_id", logging.SanitizeLogValue(req.ID),
				"error", logging.SanitizeLogValue(err.Error()))
			return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "error", Detail: "failed to block request from collecting"}
		}
		if !blocked {
			// The request's status changed between listing and the block attempt
			// (e.g. a concurrent collect just claimed it). Report this honestly as
			// an error rather than a false "already_contained" — a re-run of
			// revoke-by-token will pick up whatever it became.
			return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "error", Detail: "request state changed concurrently; re-run revoke-by-token"}
		}
		return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "contained"}

	case credentialRequestStatusCollected:
		return s.revokeCollectedCredentialRequest(ctx, req, actingPrincipalID)

	default:
		return credentialRequestContainmentOutcome{RequestID: req.ID, Outcome: "error", Detail: "unrecognized request status"}
	}
}

// findCredentialRequestsByEnrolmentToken lists every pendingCredentialRequest lodged
// against tokenID, mirroring the "id" filter shape getPendingCredentialRequestByID uses
// (Issue #3725 scope-decision note).
func (s *Server) findCredentialRequestsByEnrolmentToken(ctx context.Context, tokenID string) ([]*pendingCredentialRequest, error) {
	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags: []string{"credential_request"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: credentialRequestSecretType,
			"enrolment_token_id":            tokenID,
		},
		IncludeExpired: true,
	})
	if err != nil {
		return nil, err
	}
	result := make([]*pendingCredentialRequest, 0, len(metas))
	for _, m := range metas {
		result = append(result, pendingCredentialRequestFromMetadata(m))
	}
	return result, nil
}

// getCollectedCredentialRequestBySerial looks up the "collected" request that carries
// serial as its CollectedSerial — the lookup direction handleRevokeOrphanedCredential
// needs (admin-supplied serial -> request record).
func (s *Server) getCollectedCredentialRequestBySerial(ctx context.Context, serial string) (*pendingCredentialRequest, error) {
	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags: []string{"credential_request"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: credentialRequestSecretType,
			"status":                        credentialRequestStatusCollected,
			"collected_serial":              serial,
		},
		IncludeExpired: true,
	})
	if err != nil {
		return nil, err
	}
	if len(metas) == 0 {
		return nil, nil
	}
	return pendingCredentialRequestFromMetadata(metas[0]), nil
}

// ---- handlers -------------------------------------------------------------------------

// handleRevokeCredentialsByEnrolmentToken handles
// POST /api/v1/enrolment-tokens/{id}/revoke-issued-credentials. Revokes every certificate
// already issued from the token and blocks every still-pending/approved request under it
// from ever producing one, reporting a per-request outcome (Issue #3725 AC).
func (s *Server) handleRevokeCredentialsByEnrolmentToken(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "id is required", "MISSING_ID")
		return
	}

	tok, err := s.getEnrolmentTokenByID(r.Context(), id)
	if err != nil {
		s.logger.Error("Failed to look up enrolment token for revoke-by-token", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up enrolment token", "STORE_ERROR")
		return
	}
	if tok == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Enrolment token not found", "TOKEN_NOT_FOUND")
		return
	}
	callerTenant := s.callerTenantID(r)
	if !isWithinTenantScope(callerTenant, tok.TenantID) {
		s.writeErrorResponse(w, http.StatusNotFound, "Enrolment token not found", "TOKEN_NOT_FOUND")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingID := ""
	if principal != nil {
		actingID = principal.ID
	}

	reqs, err := s.findCredentialRequestsByEnrolmentToken(r.Context(), tok.ID)
	if err != nil {
		s.logger.Error("Failed to list credential requests for revoke-by-token", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list credential requests", "STORE_ERROR")
		return
	}

	results := make([]credentialRequestContainmentOutcome, 0, len(reqs))
	for _, req := range reqs {
		results = append(results, s.containOneCredentialRequest(r.Context(), req, actingID))
	}

	s.logger.Info("Revoked credentials issued from enrolment token",
		"token_id", logging.SanitizeLogValue(tok.ID),
		"request_count", len(results))
	s.emitCredentialRequestAudit(r.Context(), "enrolment_token.credentials_revoked", tok.TenantID, actingID,
		business.AuditUserTypeHuman, "enrolment_token", tok.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{"result_count": len(results)})

	s.writeSuccessResponse(w, RevokeByEnrolmentTokenResponse{TokenID: tok.ID, Results: results})
}

// handleCancelCredentialRequest handles POST /api/v1/credential-requests/{id}/cancel.
// Cancels a request that is "approved" but not yet "collected" — a state transition,
// not a certificate revocation, since collect (not approval) mints the certificate
// (Issue #3725 AC).
func (s *Server) handleCancelCredentialRequest(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "id is required", "MISSING_ID")
		return
	}

	// Tenant-scope and existence checks happen against a plain read first (mirroring
	// handleDenyCredentialRequest / handleApproveCredentialRequest) so a caller outside
	// the request's tenant subtree gets the same 404 whether or not the request exists.
	// cancelApprovedCredentialRequest re-reads the record under the lock for the actual
	// compare-and-set.
	reqRecord, err := s.getPendingCredentialRequestByID(r.Context(), id)
	if err != nil {
		s.logger.Error("Failed to look up credential request for cancel", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up credential request", "STORE_ERROR")
		return
	}
	if reqRecord == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Credential request not found", "REQUEST_NOT_FOUND")
		return
	}
	callerTenant := s.callerTenantID(r)
	if !isWithinTenantScope(callerTenant, reqRecord.TenantID) {
		s.writeErrorResponse(w, http.StatusNotFound, "Credential request not found", "REQUEST_NOT_FOUND")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingID := ""
	if principal != nil {
		actingID = principal.ID
	}

	cancelled, err := s.cancelApprovedCredentialRequest(r.Context(), id, actingID)
	if err != nil {
		switch {
		case errors.Is(err, errCredentialRequestNotFound):
			s.writeErrorResponse(w, http.StatusNotFound, "Credential request not found", "REQUEST_NOT_FOUND")
		case errors.Is(err, errCredentialRequestPendingNotApproved):
			s.writeErrorResponse(w, http.StatusConflict,
				"Credential request is pending, not yet approved; deny it instead", "REQUEST_NOT_APPROVED")
		case errors.Is(err, errCredentialRequestAlreadyCollected):
			s.writeErrorResponse(w, http.StatusConflict,
				"Credential request has already been collected; revoke the issued certificate instead", "REQUEST_ALREADY_COLLECTED")
		case errors.Is(err, errCredentialRequestAlreadyDeniedCancel):
			s.writeErrorResponse(w, http.StatusConflict, "Credential request is already denied", "REQUEST_ALREADY_DENIED")
		default:
			s.logger.Error("Failed to cancel credential request", "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to cancel credential request", "STORE_ERROR")
		}
		return
	}

	s.logger.Info("Credential request cancelled", "request_id", logging.SanitizeLogValue(cancelled.ID))
	s.emitCredentialRequestAudit(r.Context(), "credential_request.cancelled", cancelled.TenantID, actingID,
		business.AuditUserTypeHuman, "credential_request", cancelled.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh, nil)

	s.writeSuccessResponse(w, map[string]interface{}{"id": cancelled.ID, "status": cancelled.Status})
}

// handleListOrphanedCredentials handles GET /api/v1/credential-requests/orphaned. Lists
// "collected" enrolment-flow certificates whose bound account no longer carries a
// matching CertBinding — the exact window sweepOrphanedCollectedCertificates closes on
// its own interval, surfaced on demand (Issue #3725 implementation note).
func (s *Server) handleListOrphanedCredentials(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}
	if s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate manager not available", "SERVICE_UNAVAILABLE")
		return
	}

	metas, err := s.secretStore.ListSecrets(r.Context(), &secretsif.SecretFilter{
		Tags: []string{"credential_request"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: credentialRequestSecretType,
			"status":                        credentialRequestStatusCollected,
		},
	})
	if err != nil {
		s.logger.Error("Failed to list collected credential requests", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list collected credential requests", "STORE_ERROR")
		return
	}

	callerTenant := s.callerTenantID(r)
	result := make([]OrphanedCredentialInfo, 0)
	for _, m := range metas {
		req := pendingCredentialRequestFromMetadata(m)
		if !isWithinTenantScope(callerTenant, req.TenantID) {
			continue
		}
		if req.CollectedSerial == "" || req.BoundAccountID == "" {
			continue
		}
		revoked, err := s.certManager.IsRevoked(req.CollectedSerial)
		if err != nil {
			s.logger.Error("Revocation check failed while listing orphaned credentials; skipping entry",
				"cert_serial", logging.SanitizeLogValue(req.CollectedSerial),
				"error", logging.SanitizeLogValue(err.Error()))
			continue
		}
		if revoked {
			continue
		}
		acct, err := s.getAccountByID(r.Context(), req.BoundAccountID)
		if err != nil {
			s.logger.Error("Failed to look up bound account while listing orphaned credentials",
				"error", logging.SanitizeLogValue(err.Error()))
			continue
		}
		bound := false
		if acct != nil {
			for _, b := range acct.CertBindings {
				if b.Serial == req.CollectedSerial {
					bound = true
					break
				}
			}
		}
		if bound {
			continue
		}
		collectedAt := ""
		if req.CollectedAt != nil {
			collectedAt = req.CollectedAt.UTC().Format(time.RFC3339)
		}
		result = append(result, OrphanedCredentialInfo{
			RequestID:   req.ID,
			TenantID:    req.TenantID,
			Serial:      req.CollectedSerial,
			AccountID:   req.BoundAccountID,
			CollectedAt: collectedAt,
		})
	}
	s.writeSuccessResponse(w, result)
}

// handleRevokeOrphanedCredential handles
// POST /api/v1/credential-requests/orphaned/{serial}/revoke. Revoking a listed orphan is
// a separate explicit action from listing (Issue #3725 AC) — it re-verifies the serial is
// actually orphaned (no account binding) before revoking, so this endpoint cannot be used
// as a side channel to revoke a live, properly bound credential.
func (s *Server) handleRevokeOrphanedCredential(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Secret store not available", "SERVICE_UNAVAILABLE")
		return
	}
	if s.certManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Certificate manager not available", "SERVICE_UNAVAILABLE")
		return
	}

	serial := mux.Vars(r)["serial"]
	if serial == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "serial is required", "MISSING_SERIAL")
		return
	}

	req, err := s.getCollectedCredentialRequestBySerial(r.Context(), serial)
	if err != nil {
		s.logger.Error("Failed to look up collected credential request for orphan revoke",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up credential request", "STORE_ERROR")
		return
	}
	if req == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "No collected credential request found for this serial", "REQUEST_NOT_FOUND")
		return
	}
	callerTenant := s.callerTenantID(r)
	if !isWithinTenantScope(callerTenant, req.TenantID) {
		s.writeErrorResponse(w, http.StatusNotFound, "No collected credential request found for this serial", "REQUEST_NOT_FOUND")
		return
	}

	alreadyRevoked, err := s.certManager.IsRevoked(serial)
	if err != nil {
		s.logger.Error("Revocation check failed for orphan revoke",
			"cert_serial", logging.SanitizeLogValue(serial),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to check revocation status", "STORE_ERROR")
		return
	}
	if alreadyRevoked {
		s.writeErrorResponse(w, http.StatusConflict, "Certificate is already revoked", "ALREADY_REVOKED")
		return
	}

	orphaned := true
	if req.BoundAccountID != "" {
		acct, err := s.getAccountByID(r.Context(), req.BoundAccountID)
		if err != nil {
			s.logger.Error("Failed to look up bound account for orphan revoke", "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up bound account", "STORE_ERROR")
			return
		}
		if acct != nil {
			for _, b := range acct.CertBindings {
				if b.Serial == serial {
					orphaned = false
					break
				}
			}
		}
	}
	if !orphaned {
		s.writeErrorResponse(w, http.StatusConflict,
			"Certificate is bound to an account; it is not orphaned", "NOT_ORPHANED")
		return
	}

	if err := s.certManager.Revoke(serial); err != nil {
		s.logger.Error("Failed to revoke orphaned certificate", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke certificate", "REVOKE_FAILED")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingID := ""
	if principal != nil {
		actingID = principal.ID
	}
	s.logger.Info("Orphaned enrolment-flow certificate revoked",
		"request_id", logging.SanitizeLogValue(req.ID),
		"serial", logging.SanitizeLogValue(serial))
	s.emitCredentialRequestAudit(r.Context(), "credential_request.orphaned_certificate_revoked", req.TenantID, actingID,
		business.AuditUserTypeHuman, "credential_request", req.ID,
		business.AuditResultSuccess, business.AuditSeverityHigh,
		map[string]interface{}{"serial": serial})

	s.writeSuccessResponse(w, map[string]interface{}{
		"request_id": req.ID,
		"serial":     serial,
		"revoked":    true,
	})
}
