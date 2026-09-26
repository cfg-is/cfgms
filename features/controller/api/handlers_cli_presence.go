// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #4287: the CLI presence relay. ADR-021 Amendment 4 named a controller-served
// presence relay as the fix for CLI-driven WebAuthn presence assertion — cfg does not
// run the ceremony itself and does not serve a page (the rejected loopback-listener
// shape); it opens a page served by the controller, at the controller's own rp_id
// origin, where the admin sees the exact pending action and touches their key.
//
// Shape mirrors handlers_cli_login.go (Issue #3721): lodge a request, a browser
// confirms it, the CLI polls and collects — but every step here is authenticated
// (the CLI already holds an AssuranceStrong-eligible credential by the time a
// RequireUserPresence-gated route challenges it), unlike cli-login's anonymous
// bootstrap lodge/collect. Lodge and collect are therefore mounted on the
// authenticated api subrouter, gated by inline principal checks rather than
// requirePermission — this story does not add a new permissionAssurance entry.
//
// The action binding itself (method, path, body hash, permission) is minted onto the
// presenceTokenRecord by handlePresenceFinish (handlers_webauthn.go), not here: this
// file's job is to durably record what the CLI lodged, and to hand the resulting token
// to the CLI's own collect poll once the browser-side ceremony completes. The pending
// record is the trust anchor — the browser never supplies (or can alter) the bound
// method/path/body hash/permission itself, since those values are read back from this
// record, never from browser-supplied request parameters (see handlePresenceFinish).
//
// Consent display is the bound values, and nothing else. ADR-021 Amendment 7 Decision 1
// puts the binding in place because malware holding the CLI credential could otherwise
// swap a different pending action into the same gesture. That adversary also authors
// every field of the lodge body, so a free-form "description" string rendered as the
// consent text would let it re-open the substitution it closes: lodge the evil
// method/path, describe it as a benign one, and the admin's gesture authorizes the evil
// action from the controller's own trusted origin. GetCliPresenceResponse therefore
// carries the four enforced values — Permission, Method, Path, BodyHash — and the relay
// page renders exactly those (CliPresence.tsx). There is no caller-supplied display
// text: lodge accepts none, so nothing an attacker writes can ever reach the page.
// Method and Path are additionally validated at lodge time (closed method set,
// bounded printable-ASCII path) so that the values the page must render are themselves
// non-deceptive and bounded in the durable store.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	// cliPresenceRequestSecretType and cliPresenceRequestKeyPrefix namespace this
	// record kind in the central secret store (M-AUTH-1), mirroring
	// cliLoginRequestSecretType.
	cliPresenceRequestSecretType = "cli_presence_request"
	cliPresenceRequestKeyPrefix  = "cli-presence-request-"

	// cliPresenceRequestTenantID is the fixed storage partition for every
	// pendingCliPresenceRequest record, mirroring cliLoginRequestTenantID — storage
	// plumbing only, never read back into an authorization decision.
	cliPresenceRequestTenantID = "system"

	// cliPresenceRequestTTL bounds the lifetime of a lodged presence request — the
	// operator is expected to complete the browser ceremony within a few minutes of
	// the CLI command failing with a step-up challenge.
	cliPresenceRequestTTL = 10 * time.Minute

	// cliPresenceRequestStatus* is the status vocabulary for a
	// pendingCliPresenceRequest. Collected is terminal.
	cliPresenceRequestStatusPending   = "pending"
	cliPresenceRequestStatusApproved  = "approved"
	cliPresenceRequestStatusCollected = "collected"

	// cliPresenceSweepInterval controls how often the background sweep reaps expired
	// presence requests, mirroring cliLoginSweepInterval.
	cliPresenceSweepInterval = time.Minute

	// cliPresenceLodgeActor is the audit UserID for the sweep, which runs with no
	// authenticated principal. Lodge and collect always carry a real principal (both
	// are authenticated routes), unlike cli-login's anonymous bootstrap actor.
	cliPresenceSweepActor = "cli-presence-expiry-sweep"

	// cliPresenceMaxPathLen bounds the lodged request path. Every real
	// RequireUserPresence-gated route is far shorter than this; the cap exists because
	// Path is both persisted to the durable store on an authenticated 20/min budget and
	// rendered as consent text, so it must not be attacker-unbounded.
	cliPresenceMaxPathLen = 512
)

// cliPresenceAllowedMethods is the closed set of HTTP methods a presence-gated action
// can use — the set requirePermission can ever compare r.Method against.
var cliPresenceAllowedMethods = map[string]struct{}{
	http.MethodGet:    {},
	http.MethodPost:   {},
	http.MethodPut:    {},
	http.MethodPatch:  {},
	http.MethodDelete: {},
}

// isDisplaySafeActionPath reports whether p is a bounded, absolute request path made
// only of printable ASCII (0x21–0x7E).
//
// Both halves matter. requirePermission compares the bound path against r.URL.Path, so
// a path that cannot appear there is never useful; and the relay page renders this
// value as the consent text an admin authorizes with a security-key gesture, so it must
// not be able to carry control characters, spaces, or bidi-override codepoints that
// would make the rendered action read as a different one. Rejecting every byte above
// 0x7E rejects all multi-byte UTF-8 — including U+202E and the rest of the bidi
// controls — since every continuation byte is >= 0x80.
func isDisplaySafeActionPath(p string) bool {
	if p == "" || len(p) > cliPresenceMaxPathLen || p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return false
		}
	}
	return true
}

// errCliPresenceRequestAlreadyCollected signals a lost compare-and-set at collect
// time, mirroring errCliLoginRequestAlreadyCollected.
var errCliPresenceRequestAlreadyCollected = errors.New("cli presence request already collected")

// pendingCliPresenceRequest is the durable record for a lodged CLI presence-relay
// request. Persisted through the central secret store, mirroring pendingCliLoginRequest.
//
// LodgedByPrincipalID is the authenticated principal that lodged the request — the
// account the browser-side ceremony must match (Desired State 3 [REQUIRED TEST]).
// Method/Path/BodyHash/PermissionID are the action binding (Desired State 2): read
// verbatim by handlePresenceFinish onto the minted presenceTokenRecord, never
// re-derived from anything the browser supplies. They are also the only values the
// confirmation page displays — this record holds no free-form display text, by design
// (see this file's package comment).
type pendingCliPresenceRequest struct {
	ID     string
	Status string

	LodgedByPrincipalID string

	Method       string
	Path         string
	BodyHash     string
	PermissionID string

	UserCode string

	CreatedAt time.Time
	ExpiresAt time.Time

	ApprovedAt *time.Time
	ApprovedBy string

	// PresenceToken is the raw minted token, held only between the ceremony finishing
	// (handlePresenceFinish) and the CLI's single collect — mirrors
	// pendingCliLoginRequest.SessionToken exactly, including being cleared before the
	// collected transition is persisted.
	PresenceToken string
	CollectedAt   *time.Time

	// Version is CompareAndSwapSecret's expectedVersion, mirroring
	// pendingCliLoginRequest.Version (Issue #3775 CAS pattern).
	Version int
}

func cliPresenceRequestStoreKey(id string) string { return cliPresenceRequestKeyPrefix + id }

// persistCliPresenceRequest writes req through the central secret store.
func (s *Server) persistCliPresenceRequest(ctx context.Context, req *pendingCliPresenceRequest) error {
	return s.secretStore.StoreSecret(ctx, buildCliPresenceRequestSecretRequest(req))
}

// persistCliPresenceRequestCAS writes req through CompareAndSwapSecret, keyed on
// req.Version, mirroring persistCliLoginRequestCAS.
func (s *Server) persistCliPresenceRequestCAS(ctx context.Context, req *pendingCliPresenceRequest) (newVersion int, ok bool, err error) {
	secretReq := buildCliPresenceRequestSecretRequest(req)
	return s.secretStore.CompareAndSwapSecret(ctx, cliPresenceRequestTenantID+"/"+secretReq.Key, req.Version, secretReq)
}

func buildCliPresenceRequestSecretRequest(req *pendingCliPresenceRequest) *secretsif.SecretRequest {
	meta := map[string]string{
		secretsif.MetadataKeySecretType: cliPresenceRequestSecretType,
		"id":                            req.ID,
		"status":                        req.Status,
		"lodged_by":                     req.LodgedByPrincipalID,
		"method":                        req.Method,
		"path":                          req.Path,
		"body_hash":                     req.BodyHash,
		"permission_id":                 req.PermissionID,
		"user_code":                     req.UserCode,
		"created_at":                    req.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at":                    req.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if req.ApprovedAt != nil {
		meta["approved_at"] = req.ApprovedAt.UTC().Format(time.RFC3339)
		meta["approved_by"] = req.ApprovedBy
	}
	if req.PresenceToken != "" {
		meta["presence_token"] = req.PresenceToken
	}
	if req.CollectedAt != nil {
		meta["collected_at"] = req.CollectedAt.UTC().Format(time.RFC3339)
	}
	ttl := time.Until(req.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Second // already past expiry; persist briefly so the sweep can find and remove it
	}
	return &secretsif.SecretRequest{
		Key:         cliPresenceRequestStoreKey(req.ID),
		Value:       "",
		TenantID:    cliPresenceRequestTenantID,
		Description: "pending cli presence request",
		Tags:        []string{cliPresenceRequestSecretType},
		TTL:         ttl,
		Metadata:    meta,
	}
}

func cliPresenceRequestFromMetadata(m *secretsif.SecretMetadata) *pendingCliPresenceRequest {
	req := &pendingCliPresenceRequest{
		ID:                  m.Metadata["id"],
		Status:              m.Metadata["status"],
		LodgedByPrincipalID: m.Metadata["lodged_by"],
		Method:              m.Metadata["method"],
		Path:                m.Metadata["path"],
		BodyHash:            m.Metadata["body_hash"],
		PermissionID:        m.Metadata["permission_id"],
		UserCode:            m.Metadata["user_code"],
		ApprovedBy:          m.Metadata["approved_by"],
		PresenceToken:       m.Metadata["presence_token"],
		Version:             m.Version,
	}
	if ts := m.Metadata["created_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.CreatedAt = t
		}
	}
	if ts := m.Metadata["expires_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.ExpiresAt = t
		}
	}
	if ts := m.Metadata["approved_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.ApprovedAt = &t
		}
	}
	if ts := m.Metadata["collected_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.CollectedAt = &t
		}
	}
	return req
}

// getCliPresenceRequestByID looks up a presence-relay request by its server-generated ID.
func (s *Server) getCliPresenceRequestByID(ctx context.Context, id string) (*pendingCliPresenceRequest, error) {
	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags: []string{cliPresenceRequestSecretType},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: cliPresenceRequestSecretType,
			"id":                            id,
		},
		IncludeExpired: true,
	})
	if err != nil {
		return nil, err
	}
	if len(metas) == 0 {
		return nil, nil
	}
	return cliPresenceRequestFromMetadata(metas[0]), nil
}

// ---- audit ----------------------------------------------------------------------

func (s *Server) emitCliPresenceAudit(
	ctx context.Context,
	action, principalID string,
	userType business.AuditUserType,
	resourceID string,
	result business.AuditResult,
	severity business.AuditSeverity,
) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(principalID, userType).
		Resource(cliPresenceRequestSecretType, resourceID, "").
		Result(result).
		Severity(severity)
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit cli-presence audit event",
			"error", logging.SanitizeLogValue(err.Error()), "action", action)
	}
}

// ---- handlers ---------------------------------------------------------------------

// LodgeCliPresenceRequestBody is the POST /api/v1/cli-presence/lodge body. Method,
// Path and BodyHash describe the exact pending action the presence proof must gate —
// the SHA-256 hex digest of the request body (an empty body hashes to a fixed,
// well-known value; the CLI always sends one). Permission is the permission ID the
// step-up challenge named (Desired State 2).
//
// These four fields are the whole body: there is deliberately no display-text field.
// The confirmation page's consent text is rendered from these bound values alone, so a
// caller cannot describe one action while binding another (see the package comment).
// A "description" key in an inbound body is ignored like any other unknown field.
type LodgeCliPresenceRequestBody struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	BodyHash   string `json:"body_sha256"`
	Permission string `json:"permission"`
}

// LodgeCliPresenceResponse is returned once, at lodge time.
type LodgeCliPresenceResponse struct {
	RequestID string `json:"request_id"`
	UserCode  string `json:"user_code"`
	ExpiresAt string `json:"expires_at"`
}

// handleLodgeCliPresenceRequest handles POST /api/v1/cli-presence/lodge. Mounted on
// the authenticated api subrouter (unlike cli-login's anonymous bootstrap lodge): a
// presence request can only ever be lodged by a principal that already cleared the
// assurance-level gate for the RequireUserPresence-gated route it is retrying — the
// presence proof is the only thing missing, not the credential itself.
//
// ADR-021 Amendment 7 Decision 2: AssuranceMachine (API-key) principals cannot lodge — automation
// stays out of the presence relay entirely.
func (s *Server) handleLodgeCliPresenceRequest(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	if principal.Assurance == session.AssuranceMachine {
		s.writeErrorResponse(w, http.StatusForbidden,
			"API-key principals cannot lodge a presence request", "MACHINE_PRINCIPAL_CANNOT_LODGE")
		return
	}
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Cli presence service not available", "SERVICE_UNAVAILABLE")
		return
	}

	var body LodgeCliPresenceRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}
	if _, methodOK := cliPresenceAllowedMethods[body.Method]; !methodOK {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"method must be a standard HTTP method", "INVALID_ACTION")
		return
	}
	if !isDisplaySafeActionPath(body.Path) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"path must be an absolute request path of printable ASCII", "INVALID_ACTION")
		return
	}
	if !isValidVerifierHash(body.BodyHash) {
		s.writeErrorResponse(w, http.StatusBadRequest, "body_sha256 must be a SHA-256 hex digest", "INVALID_BODY_HASH")
		return
	}
	req, presenceRequired := permissionAssurance[body.Permission]
	if body.Permission == "" || !presenceRequired || !req.RequireUserPresence {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"permission must name a RequireUserPresence-gated permission", "INVALID_PERMISSION")
		return
	}

	userCode, err := generateCliLoginUserCode()
	if err != nil {
		s.logger.Error("Failed to generate cli-presence user code", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to lodge presence request", "TOKEN_ERROR")
		return
	}

	now := time.Now().UTC()
	pending := &pendingCliPresenceRequest{
		ID:                  "cli-presence-" + uuid.New().String(),
		Status:              cliPresenceRequestStatusPending,
		LodgedByPrincipalID: principal.ID,
		Method:              body.Method,
		Path:                body.Path,
		BodyHash:            body.BodyHash,
		PermissionID:        body.Permission,
		UserCode:            userCode,
		CreatedAt:           now,
		ExpiresAt:           now.Add(cliPresenceRequestTTL),
	}
	if err := s.persistCliPresenceRequest(r.Context(), pending); err != nil {
		s.logger.Error("Failed to persist lodged cli-presence request", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to lodge presence request", "STORE_ERROR")
		return
	}

	s.logger.Info("Cli-presence request lodged",
		"request_id", logging.SanitizeLogValue(pending.ID),
		"permission_id", logging.SanitizeLogValue(pending.PermissionID))
	s.emitCliPresenceAudit(r.Context(), "cli_presence.lodged", principal.ID, business.AuditUserTypeHuman,
		pending.ID, business.AuditResultSuccess, business.AuditSeverityMedium)

	s.writeResponse(w, http.StatusCreated, LodgeCliPresenceResponse{
		RequestID: pending.ID,
		UserCode:  pending.UserCode,
		ExpiresAt: pending.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// GetCliPresenceResponse is returned by GET /api/v1/cli-presence/{id}. UserCode is the
// same non-secret pairing code cli-login uses — a confused-deputy guard, not a secret.
//
// Permission, Method, Path and BodyHash are the pending action in plain words (Desired
// state 1) and are the four values requirePermission enforces against the retried
// request (middleware.go's action-binding check). They are what the relay page renders,
// so what the admin authorizes with the gesture is what the token is bound to; no other
// description of the action exists anywhere in this flow.
type GetCliPresenceResponse struct {
	RequestID  string `json:"request_id"`
	Status     string `json:"status"`
	UserCode   string `json:"user_code"`
	ExpiresAt  string `json:"expires_at"`
	Permission string `json:"permission"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	BodyHash   string `json:"body_sha256"`
}

// handleGetCliPresenceRequest handles GET /api/v1/cli-presence/{id} — the relay page's
// only way to learn the bound action and user code. Scoped to the account that
// lodged the request: an unknown ID and a request lodged by a different account are
// indistinguishable (both 404), the same existence-oracle stance cli-login's collect
// takes for an unknown ID vs. a wrong verifier.
func (s *Server) handleGetCliPresenceRequest(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Cli presence service not available", "SERVICE_UNAVAILABLE")
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "id is required", "MISSING_ID")
		return
	}

	reqRecord, err := s.getCliPresenceRequestByID(r.Context(), id)
	if err != nil {
		s.logger.Error("Failed to look up cli-presence request", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up presence request", "STORE_ERROR")
		return
	}
	if reqRecord == nil || reqRecord.LodgedByPrincipalID != principal.ID {
		s.writeErrorResponse(w, http.StatusNotFound, "Presence request not found", "REQUEST_NOT_FOUND")
		return
	}

	status := reqRecord.Status
	if time.Now().UTC().After(reqRecord.ExpiresAt) {
		status = "expired"
	}
	s.writeResponse(w, http.StatusOK, GetCliPresenceResponse{
		RequestID:  reqRecord.ID,
		Status:     status,
		UserCode:   reqRecord.UserCode,
		ExpiresAt:  reqRecord.ExpiresAt.UTC().Format(time.RFC3339),
		Permission: reqRecord.PermissionID,
		Method:     reqRecord.Method,
		Path:       reqRecord.Path,
		BodyHash:   reqRecord.BodyHash,
	})
}

// CollectCliPresenceResponse is returned on every poll. PresenceToken is set only on
// the single successful collection.
type CollectCliPresenceResponse struct {
	Status        string `json:"status"`
	PresenceToken string `json:"presence_token,omitempty"`
}

// claimCliPresenceRequestForCollection performs the approved->collected
// compare-and-set, mirroring claimCliLoginRequestForCollection exactly, including why
// the token is cleared from the persisted record before it is ever handed to the CLI.
func (s *Server) claimCliPresenceRequestForCollection(ctx context.Context, id string) (*pendingCliPresenceRequest, error) {
	fresh, err := s.getCliPresenceRequestByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if fresh == nil || fresh.Status != cliPresenceRequestStatusApproved {
		return nil, errCliPresenceRequestAlreadyCollected
	}
	now := time.Now().UTC()
	token := fresh.PresenceToken
	fresh.Status = cliPresenceRequestStatusCollected
	fresh.CollectedAt = &now
	fresh.PresenceToken = ""
	_, ok, err := s.persistCliPresenceRequestCAS(ctx, fresh)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errCliPresenceRequestAlreadyCollected
	}
	fresh.PresenceToken = token
	return fresh, nil
}

// handleCollectCliPresenceRequest handles POST /api/v1/cli-presence/{id}/collect.
// Authenticated (unlike cli-login's anonymous verifier-gated collect): the CLI polls
// using the same credential it lodged with, so the account-match check below is the
// real gate, not a bearer secret. A collect attempt by a different account than the
// one that lodged the request is rejected — the browser-side ceremony's account match
// (handlePresenceFinish) closes the mint side of this; this closes the retrieval side.
func (s *Server) handleCollectCliPresenceRequest(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "id is required", "MISSING_ID")
		return
	}
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Cli presence service not available", "SERVICE_UNAVAILABLE")
		return
	}

	reqRecord, err := s.getCliPresenceRequestByID(r.Context(), id)
	if err != nil {
		s.logger.Error("Failed to look up cli-presence request for collect", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up presence request", "STORE_ERROR")
		return
	}
	if reqRecord == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Presence request not found", "REQUEST_NOT_FOUND")
		return
	}
	if reqRecord.LodgedByPrincipalID != principal.ID {
		s.writeErrorResponse(w, http.StatusForbidden,
			"Presence request was lodged by a different account", "REQUEST_ACCOUNT_MISMATCH")
		return
	}

	if reqRecord.Status == cliPresenceRequestStatusCollected {
		w.WriteHeader(http.StatusGone)
		return
	}
	if time.Now().UTC().After(reqRecord.ExpiresAt) {
		s.writeSuccessResponse(w, CollectCliPresenceResponse{Status: "expired"})
		return
	}
	switch reqRecord.Status {
	case cliPresenceRequestStatusPending:
		s.writeSuccessResponse(w, CollectCliPresenceResponse{Status: "pending"})
		return
	case cliPresenceRequestStatusApproved:
		// Fall through to the claim branch below.
	default:
		s.writeSuccessResponse(w, CollectCliPresenceResponse{Status: reqRecord.Status})
		return
	}

	claimed, err := s.claimCliPresenceRequestForCollection(r.Context(), id)
	if err != nil {
		if errors.Is(err, errCliPresenceRequestAlreadyCollected) {
			w.WriteHeader(http.StatusGone)
			return
		}
		s.logger.Error("Failed to claim cli-presence request for collection", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to collect presence request", "STORE_ERROR")
		return
	}

	s.logger.Info("Cli-presence request collected", "request_id", logging.SanitizeLogValue(claimed.ID))
	s.emitCliPresenceAudit(r.Context(), "cli_presence.collected", principal.ID, business.AuditUserTypeHuman,
		claimed.ID, business.AuditResultSuccess, business.AuditSeverityHigh)

	s.writeResponse(w, http.StatusOK, CollectCliPresenceResponse{
		Status:        claimed.Status,
		PresenceToken: claimed.PresenceToken,
	})
}

// ---- expiry sweep -----------------------------------------------------------------

// startCliPresenceRequestSweep starts the background expiry sweep goroutine, mirroring
// startCliLoginRequestSweep's stop/done channel shape.
func (s *Server) startCliPresenceRequestSweep() {
	go func() {
		defer close(s.cliPresenceSweepDone)
		ticker := time.NewTicker(cliPresenceSweepInterval)
		defer ticker.Stop()

		s.logger.Info("Started cli-presence expiry sweep", "interval", cliPresenceSweepInterval)

		for {
			select {
			case <-s.stopCliPresenceSweep:
				return
			case <-ticker.C:
				s.cliPresenceSweepLease.RunIfLeader(context.Background(), s.sweepExpiredCliPresenceRequests)
			}
		}
	}()
}

// sweepExpiredCliPresenceRequests deletes expired pending/approved presence requests.
// Unlike cli-login's sweep, there is no session to revoke here — an uncollected
// presence token still expires on its own via presenceTokenTTL (30s), so this sweep
// only needs to reap the durable request record itself.
func (s *Server) sweepExpiredCliPresenceRequests(ctx context.Context) {
	if s.secretStore == nil {
		return
	}
	now := time.Now().UTC()

	for _, status := range []string{cliPresenceRequestStatusPending, cliPresenceRequestStatusApproved} {
		metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
			Tags: []string{cliPresenceRequestSecretType},
			Metadata: map[string]string{
				secretsif.MetadataKeySecretType: cliPresenceRequestSecretType,
				"status":                        status,
			},
			IncludeExpired: true,
		})
		if err != nil {
			s.logger.Error("Cli-presence expiry sweep: failed to list requests",
				"status", status, "error", logging.SanitizeLogValue(err.Error()))
			continue
		}
		for _, m := range metas {
			req := cliPresenceRequestFromMetadata(m)
			if !req.ExpiresAt.Before(now) {
				continue
			}
			if delErr := s.secretStore.DeleteSecret(ctx, m.TenantID+"/"+m.Key); delErr != nil {
				s.logger.Warn("Cli-presence expiry sweep: failed to delete expired request",
					"error", logging.SanitizeLogValue(delErr.Error()))
				continue
			}
			s.emitCliPresenceAudit(ctx, "cli_presence.expired", cliPresenceSweepActor, business.AuditUserTypeSystem,
				req.ID, business.AuditResultSuccess, business.AuditSeverityLow)
		}
	}
}
