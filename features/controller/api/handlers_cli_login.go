// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3721 (Epic #3711): browser-authenticated CLI login. The token never travels
// from the browser to the CLI over a relay the security review rejected both shapes
// of (planning-review amendment): no loopback listener, no reuse of the WebAuthn relay
// helpers. Instead the CLI lodges a login request, opens the browser at the
// controller, and collects the minted session token from the controller over its own
// already-pinned TLS connection.
//
// The CLI generates a random verifier locally and sends only its SHA-256 hash at
// lodge time — the raw value is never transmitted until collect, and never appears in
// a URL. Approval mints the session through the existing session-creation path
// (handleSessionCreate's own Issue/IssueRootScoped branch), so the resulting session
// inherits the approving account's scope exactly — including the root-scope marker
// (ADR-025 Amendment 4, Issue #3726): browser login for a root-scoped account now
// mints a session that is itself RootScoped and therefore confined by the Decision 1
// boundary, not exempt from it (Amendment 2, superseding this story's original
// root-scope refusal).
//
// pendingCliLoginRequest carries no tenant or scope field of any kind — the approving
// principal's TenantID/RootScoped are read once, at approval, straight from the
// authenticated principal, and the minted session re-derives its own scope from the
// bound account on every request (bearer branch of authenticationMiddleware). Storing
// a tenant or scope marker on the request record would be redundant at best and a
// forgeable widening surface at worst.
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
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
	// cliLoginRequestSecretType and cliLoginRequestKeyPrefix namespace this record
	// kind in the central secret store (M-AUTH-1), mirroring credentialRequestSecretType.
	cliLoginRequestSecretType = "cli_login_request"
	cliLoginRequestKeyPrefix  = "cli-login-request-"

	// cliLoginRequestTenantID is the fixed storage partition used for every
	// pendingCliLoginRequest record — StoreSecret requires a non-empty TenantID
	// (M-AUTH-1), but a login request itself carries no tenant of its own (Amendment
	// 2 [REQUIRED TEST]). This is storage plumbing only: it is never read back into
	// pendingCliLoginRequest and never influences any authorization decision — the
	// approving principal's own TenantID, read fresh at approval, is what the minted
	// session actually carries.
	cliLoginRequestTenantID = "system"

	// cliLoginRequestTTL bounds the lifetime of a lodged login request — short-lived
	// by design, matching a device-pairing-style flow: the operator is expected to
	// complete the browser step within a few minutes of running the command.
	cliLoginRequestTTL = 10 * time.Minute

	// cliLoginRequestStatus* is the status vocabulary for a pendingCliLoginRequest.
	// Denied and Collected are both terminal — neither can move to any other status.
	cliLoginRequestStatusPending   = "pending"
	cliLoginRequestStatusApproved  = "approved"
	cliLoginRequestStatusDenied    = "denied"
	cliLoginRequestStatusCollected = "collected"

	// cliLoginUserCodeAlphabet excludes visually ambiguous characters (0/O, 1/I/L) so
	// an operator can type the code back accurately from a phone or a second screen.
	cliLoginUserCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	cliLoginUserCodeGroupLen = 4

	// cliLoginConnectionName is the fixed ConnectionName recorded on every session
	// this flow mints — this story's sessions are not tied to a caller-supplied
	// connection label the way handleSessionCreate's are.
	cliLoginConnectionName = "cli-login"

	// cliLoginSweepInterval controls how often the background sweep reaps expired
	// login requests — short, to match the request TTL itself (Issue #3721 AC:
	// "removed by a background sweep, not only lazily on read").
	cliLoginSweepInterval = time.Minute

	// cliLoginLodgeActor and cliLoginSweepActor are the audit UserID recorded when no
	// authenticated principal exists for the action — lodge is the unauthenticated
	// bootstrap path, and the sweep runs with no principal at all. audit.Manager.
	// validateEntry rejects an empty UserID, so a fixed, non-secret sentinel
	// identifies the actor as the mechanism, not any human or token.
	cliLoginLodgeActor = "cli-login-lodge"
	cliLoginSweepActor = "cli-login-expiry-sweep"
)

// errCliLoginRequestAlreadyCollected signals a lost compare-and-set: another caller,
// or this same request replayed after a restart, already transitioned this request to
// "collected". Surfaced as 410 Gone.
var errCliLoginRequestAlreadyCollected = errors.New("cli login request already collected")

// pendingCliLoginRequest is the durable record for a lodged browser-login request.
// Persisted through the central secret store, mirroring pendingCredentialRequest.
//
// Deliberately absent: any tenant, scope, or root-scope field (Amendment 2 [REQUIRED
// TEST]). The approving principal's scope is read once, at approval, directly from
// the authenticated Principal and handed straight to the session manager — never
// staged on this record, which would be a second place for that value to live and a
// forgeable widening surface if this record were ever read back into a decision.
type pendingCliLoginRequest struct {
	ID     string
	Status string

	// VerifierHash is the SHA-256 hex digest of the verifier the CLI generated
	// locally and never transmitted until collect. UserCode is the short,
	// human-comparable pairing code shown by both the CLI and the browser
	// confirmation screen — not a secret; it is a confused-deputy guard, not an
	// authentication factor, so it is stored and compared in cleartext.
	VerifierHash string
	UserCode     string

	CreatedAt time.Time
	ExpiresAt time.Time

	// ApprovedAt/ApprovedBy and DeniedAt/DeniedBy record the browser-side decision.
	// ApprovedBy is the approving principal's ID — an identifier, not a credential.
	ApprovedAt *time.Time
	ApprovedBy string
	DeniedAt   *time.Time
	DeniedBy   string

	// SessionID, SessionToken and SessionAbsoluteExpiry are written by approve, the
	// moment it mints the session through the existing session-creation path.
	// SessionToken is the raw bearer value — held here only for the window between
	// approval and collection, never logged, and returned to the CLI exactly once
	// through the collect response body (Issue #3721 [REQUIRED TEST]: the token
	// appears only there). Two mechanisms bound that window from both ends, so no
	// durable record ever outlives the session it names: an approved-but-never-
	// collected request has its session revoked and its record deleted by the expiry
	// sweep, and a collected one has this field cleared before the terminal transition
	// is persisted (claimCliLoginRequestForCollection).
	SessionID             string
	SessionToken          string
	SessionAbsoluteExpiry time.Time
	CollectedAt           *time.Time
}

// cliLoginRequestStoreKey namespaces id in the secret store.
func cliLoginRequestStoreKey(id string) string { return cliLoginRequestKeyPrefix + id }

// isValidVerifierHash reports whether s looks like a SHA-256 hex digest (64 lowercase
// or uppercase hex characters) — the shape the CLI is expected to send at lodge time.
func isValidVerifierHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// generateCliLoginUserCode returns a random, human-typeable pairing code in the form
// "XXXX-XXXX" drawn from cliLoginUserCodeAlphabet.
func generateCliLoginUserCode() (string, error) {
	alphabetLen := big.NewInt(int64(len(cliLoginUserCodeAlphabet)))
	b := make([]byte, cliLoginUserCodeGroupLen*2)
	for i := range b {
		n, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			return "", err
		}
		b[i] = cliLoginUserCodeAlphabet[n.Int64()]
	}
	return string(b[:cliLoginUserCodeGroupLen]) + "-" + string(b[cliLoginUserCodeGroupLen:]), nil
}

// verifierMatches reports whether raw, hashed, matches storedHash in constant time.
// Mirrors collectSecretMatches (handlers_credential_requests_collect.go) — the
// codebase's established constant-time-compare shape for a secret whose only durable
// form is its hash.
func verifierMatches(raw, storedHash string) bool {
	if raw == "" || storedHash == "" {
		return false
	}
	presented := hashCredentialSecret(raw)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(storedHash)) == 1
}

// ---- persistence --------------------------------------------------------------------

// persistCliLoginRequest writes req through the central secret store (M-AUTH-1),
// mirroring persistPendingCredentialRequest. created_at/expires_at are duplicated into
// metadata rather than read back from the store's own CreatedAt/ExpiresAt because
// StoreSecret always stamps CreatedAt fresh on every call, including updates.
func (s *Server) persistCliLoginRequest(ctx context.Context, req *pendingCliLoginRequest) error {
	meta := map[string]string{
		secretsif.MetadataKeySecretType: cliLoginRequestSecretType,
		"id":                            req.ID,
		"status":                        req.Status,
		"verifier_hash":                 req.VerifierHash,
		"user_code":                     req.UserCode,
		"created_at":                    req.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at":                    req.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if req.ApprovedAt != nil {
		meta["approved_at"] = req.ApprovedAt.UTC().Format(time.RFC3339)
		meta["approved_by"] = req.ApprovedBy
	}
	if req.DeniedAt != nil {
		meta["denied_at"] = req.DeniedAt.UTC().Format(time.RFC3339)
		meta["denied_by"] = req.DeniedBy
	}
	if req.SessionID != "" {
		meta["session_id"] = req.SessionID
	}
	if req.SessionToken != "" {
		meta["session_token"] = req.SessionToken
	}
	if !req.SessionAbsoluteExpiry.IsZero() {
		meta["session_absolute_expiry"] = req.SessionAbsoluteExpiry.UTC().Format(time.RFC3339)
	}
	if req.CollectedAt != nil {
		meta["collected_at"] = req.CollectedAt.UTC().Format(time.RFC3339)
	}
	ttl := time.Until(req.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Second // already past expiry; persist briefly so the sweep can find and remove it
	}
	return s.secretStore.StoreSecret(ctx, &secretsif.SecretRequest{
		Key:         cliLoginRequestStoreKey(req.ID),
		Value:       "",
		TenantID:    cliLoginRequestTenantID,
		Description: "pending cli login request",
		Tags:        []string{cliLoginRequestSecretType},
		TTL:         ttl,
		Metadata:    meta,
	})
}

// cliLoginRequestFromMetadata reconstructs a pendingCliLoginRequest from a stored record.
func cliLoginRequestFromMetadata(m *secretsif.SecretMetadata) *pendingCliLoginRequest {
	req := &pendingCliLoginRequest{
		ID:           m.Metadata["id"],
		Status:       m.Metadata["status"],
		VerifierHash: m.Metadata["verifier_hash"],
		UserCode:     m.Metadata["user_code"],
		ApprovedBy:   m.Metadata["approved_by"],
		DeniedBy:     m.Metadata["denied_by"],
		SessionID:    m.Metadata["session_id"],
		SessionToken: m.Metadata["session_token"],
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
	if ts := m.Metadata["denied_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.DeniedAt = &t
		}
	}
	if ts := m.Metadata["session_absolute_expiry"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.SessionAbsoluteExpiry = t
		}
	}
	if ts := m.Metadata["collected_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			req.CollectedAt = &t
		}
	}
	return req
}

// getCliLoginRequestByID looks up a login request by its server-generated ID.
func (s *Server) getCliLoginRequestByID(ctx context.Context, id string) (*pendingCliLoginRequest, error) {
	if s.secretStore == nil {
		return nil, nil
	}
	metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
		Tags: []string{cliLoginRequestSecretType},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: cliLoginRequestSecretType,
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
	return cliLoginRequestFromMetadata(metas[0]), nil
}

// getCliLoginRequestWithToken is getCliLoginRequestByID under a name that makes call
// sites that specifically need SessionToken (tests, the sweep's revoke path) explicit
// about why they are reading this record — both return the same fully-populated
// struct; there is no separate redacted accessor.
func (s *Server) getCliLoginRequestWithToken(ctx context.Context, id string) (*pendingCliLoginRequest, error) {
	return s.getCliLoginRequestByID(ctx, id)
}

// ---- audit ----------------------------------------------------------------------

// emitCliLoginAudit records an audit event for a lodge, approve, deny, collect or
// expiry action. No-op when auditManager is nil. Mirrors emitCredentialRequestAudit
// in shape: resource identifiers only, never the session token or the verifier
// (Issue #3721 AC).
func (s *Server) emitCliLoginAudit(
	ctx context.Context,
	action, principalID string,
	userType business.AuditUserType,
	resourceID string,
	result business.AuditResult,
	severity business.AuditSeverity,
	extras map[string]interface{},
) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(audit.SystemTenantID).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(principalID, userType).
		Resource(cliLoginRequestSecretType, resourceID, "").
		Result(result).
		Severity(severity)
	for k, v := range extras {
		b = b.Detail(k, v)
	}
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit cli-login audit event",
			"error", logging.SanitizeLogValue(err.Error()), "action", action)
	}
}

// ---- handlers ---------------------------------------------------------------------

// LodgeCliLoginRequestBody is the POST /api/v1/cli-login/lodge body. VerifierHash is
// the SHA-256 hex digest of a verifier generated and retained locally by the CLI — the
// raw value is never sent here, and never appears in any URL.
type LodgeCliLoginRequestBody struct {
	VerifierHash string `json:"verifier_hash"`
}

// LodgeCliLoginResponse is returned once, at lodge time.
type LodgeCliLoginResponse struct {
	RequestID string `json:"request_id"`
	UserCode  string `json:"user_code"`
	ExpiresAt string `json:"expires_at"`
}

// handleLodgeCliLoginRequest handles POST /api/v1/cli-login/lodge. Unauthenticated by
// API key or mTLS — this is the bootstrap path for an operator holding no prior
// credential (Issue #3721). Registered on the base router, not the authenticated api
// subrouter, mirroring handleLodgeCredentialRequest.
func (s *Server) handleLodgeCliLoginRequest(w http.ResponseWriter, r *http.Request) {
	if checker := s.registrationLeaderStatus; checker != nil && !checker.HasLeadership() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Cli login service not available", "SERVICE_UNAVAILABLE")
		return
	}

	var body LodgeCliLoginRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}
	if !isValidVerifierHash(body.VerifierHash) {
		s.writeErrorResponse(w, http.StatusBadRequest, "verifier_hash must be a SHA-256 hex digest", "INVALID_VERIFIER_HASH")
		return
	}

	userCode, err := generateCliLoginUserCode()
	if err != nil {
		s.logger.Error("Failed to generate cli-login user code", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to lodge login request", "TOKEN_ERROR")
		return
	}

	now := time.Now().UTC()
	pending := &pendingCliLoginRequest{
		ID:           "cli-login-" + uuid.New().String(),
		Status:       cliLoginRequestStatusPending,
		VerifierHash: body.VerifierHash,
		UserCode:     userCode,
		CreatedAt:    now,
		ExpiresAt:    now.Add(cliLoginRequestTTL),
	}
	if err := s.persistCliLoginRequest(r.Context(), pending); err != nil {
		s.logger.Error("Failed to persist lodged cli-login request", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to lodge login request", "STORE_ERROR")
		return
	}

	s.logger.Info("Cli-login request lodged", "request_id", logging.SanitizeLogValue(pending.ID))
	s.emitCliLoginAudit(r.Context(), "cli_login.lodged", cliLoginLodgeActor, business.AuditUserTypeSystem,
		pending.ID, business.AuditResultSuccess, business.AuditSeverityMedium, nil)

	s.writeResponse(w, http.StatusCreated, LodgeCliLoginResponse{
		RequestID: pending.ID,
		UserCode:  pending.UserCode,
		ExpiresAt: pending.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// GetCliLoginResponse is returned by GET /api/v1/cli-login/{id}. UserCode is the same
// non-secret pairing code recorded on pendingCliLoginRequest — safe to return here for
// the same reason it is safe to store and compare in cleartext (see the field comment).
// Deliberately absent: VerifierHash and SessionToken, which never leave this file except
// through the collect response body.
type GetCliLoginResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	UserCode  string `json:"user_code"`
	ExpiresAt string `json:"expires_at"`
}

// handleGetCliLoginRequest handles GET /api/v1/cli-login/{id}. This is the confirmation
// screen's (Issue #3722) only way to learn the true user code: the CLI never puts it in
// the confirmation URL (only the request ID), so the operator has nothing to compare
// against without this call. Requiring the code to be read same-origin, under the same
// AssuranceStrong gate as approve (requirePermission("cli-login", "approve")), rather
// than accepting it as a URL parameter, is deliberate: a cross-site forged approve/deny
// POST cannot supply a code its origin was never able to read. A session that has not
// completed a passkey login never reaches this body, matching the confirmation screen's
// own requirement that login happens before anything is displayed.
//
// Status mirrors handleCollectCliLoginRequest's own precedence: an expired request
// reports "expired" regardless of its stored status, computed here rather than
// persisted — the stored value is left untouched for the sweep to find and reap.
func (s *Server) handleGetCliLoginRequest(w http.ResponseWriter, r *http.Request) {
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Cli login service not available", "SERVICE_UNAVAILABLE")
		return
	}
	id := mux.Vars(r)["id"]
	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "id is required", "MISSING_ID")
		return
	}

	reqRecord, err := s.getCliLoginRequestByID(r.Context(), id)
	if err != nil {
		s.logger.Error("Failed to look up cli-login request", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up login request", "STORE_ERROR")
		return
	}
	if reqRecord == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Login request not found", "REQUEST_NOT_FOUND")
		return
	}

	status := reqRecord.Status
	if time.Now().UTC().After(reqRecord.ExpiresAt) {
		status = "expired"
	}
	s.writeResponse(w, http.StatusOK, GetCliLoginResponse{
		RequestID: reqRecord.ID,
		Status:    status,
		UserCode:  reqRecord.UserCode,
		ExpiresAt: reqRecord.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// ApproveCliLoginRequestBody is the POST /api/v1/cli-login/{id}/approve body. UserCode
// is the pairing code the operator sees on both screens — required on every call,
// including a denial, so only the browser session actually showing the matching code
// can resolve the request either way. Deny defaults to false (approve).
type ApproveCliLoginRequestBody struct {
	UserCode string `json:"user_code"`
	Deny     bool   `json:"deny,omitempty"`
}

// ApproveCliLoginResponse is returned on a successful approval or denial. It never
// carries the minted session token (Issue #3721 [REQUIRED TEST]) — only the collect
// response, fetched by the CLI over its own connection, ever does.
type ApproveCliLoginResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

// handleApproveCliLoginRequest handles POST /api/v1/cli-login/{id}/approve.
// Authorization is enforced at the router level via requirePermission("cli-login",
// "approve"), which requires AssuranceStrong (permissionAssurance) — a session that
// has not completed a passkey login never reaches this body. Approval mints the
// session through the same Issue/IssueRootScoped branch handleSessionCreate uses, so
// the resulting session inherits the approving principal's scope exactly, including
// the root-scope marker for a root-scoped principal (ADR-025 Amendment 4).
func (s *Server) handleApproveCliLoginRequest(w http.ResponseWriter, r *http.Request) {
	if checker := s.registrationLeaderStatus; checker != nil && !checker.HasLeadership() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Cli login service not available", "SERVICE_UNAVAILABLE")
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "id is required", "MISSING_ID")
		return
	}
	var body ApproveCliLoginRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	reqRecord, err := s.getCliLoginRequestByID(r.Context(), id)
	if err != nil {
		s.logger.Error("Failed to look up cli-login request", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up login request", "STORE_ERROR")
		return
	}
	if reqRecord == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Login request not found", "REQUEST_NOT_FOUND")
		return
	}
	if reqRecord.Status != cliLoginRequestStatusPending {
		s.writeErrorResponse(w, http.StatusConflict, "Login request is not pending", "REQUEST_NOT_PENDING")
		return
	}
	// Constant-time comparison is not needed here — the user code is a confused-deputy
	// guard the operator reads and re-types, not a secret — but the code must match
	// exactly before this request moves out of pending, whether approving or denying.
	if !strings.EqualFold(body.UserCode, reqRecord.UserCode) {
		s.writeErrorResponse(w, http.StatusConflict, "User code does not match", "USER_CODE_MISMATCH")
		return
	}

	now := time.Now().UTC()
	if body.Deny {
		reqRecord.Status = cliLoginRequestStatusDenied
		reqRecord.DeniedAt = &now
		reqRecord.DeniedBy = principal.ID
		if err := s.persistCliLoginRequest(r.Context(), reqRecord); err != nil {
			s.logger.Error("Failed to persist cli-login denial", "error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to deny login request", "STORE_ERROR")
			return
		}
		s.logger.Info("Cli-login request denied", "request_id", logging.SanitizeLogValue(reqRecord.ID))
		s.emitCliLoginAudit(r.Context(), "cli_login.denied", principal.ID, business.AuditUserTypeHuman,
			reqRecord.ID, business.AuditResultSuccess, business.AuditSeverityMedium, nil)
		s.writeResponse(w, http.StatusOK, ApproveCliLoginResponse{RequestID: reqRecord.ID, Status: reqRecord.Status})
		return
	}

	if s.sessionManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Session management not available", "SESSION_UNAVAILABLE")
		return
	}
	// Scope inheritance mirrors handleSessionCreate exactly (ADR-025 Amendment 1
	// A1.3 / Amendment 4): read from the authenticated principal, never inferred from
	// an empty TenantID, never staged on the request record in between.
	var (
		sess  *session.Session
		token string
	)
	if principal.RootScoped {
		sess, token, err = s.sessionManager.IssueRootScoped(r.Context(), principal.ID, cliLoginConnectionName)
	} else {
		sess, token, err = s.sessionManager.Issue(r.Context(), principal.ID, cliLoginConnectionName, principal.TenantID)
	}
	if err != nil {
		s.logger.Error("Failed to issue session for cli-login approval",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to approve login request", "SESSION_CREATE_ERROR")
		return
	}

	reqRecord.Status = cliLoginRequestStatusApproved
	reqRecord.ApprovedAt = &now
	reqRecord.ApprovedBy = principal.ID
	reqRecord.SessionID = sess.ID
	reqRecord.SessionToken = token
	reqRecord.SessionAbsoluteExpiry = sess.AbsoluteExpiresAt
	if err := s.persistCliLoginRequest(r.Context(), reqRecord); err != nil {
		s.logger.Error("Failed to persist cli-login approval", "error", logging.SanitizeLogValue(err.Error()))
		// The session was already minted; leaving it live but unrecorded here would
		// strand a credential the sweep can never find. Best effort revoke before
		// reporting the failure.
		if revokeErr := s.sessionManager.Revoke(r.Context(), sess.ID); revokeErr != nil {
			s.logger.Error("Failed to revoke session after cli-login approval persist failure",
				"error", logging.SanitizeLogValue(revokeErr.Error()))
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to approve login request", "STORE_ERROR")
		return
	}

	s.logger.Info("Cli-login request approved",
		"request_id", logging.SanitizeLogValue(reqRecord.ID),
		"principal_id", logging.SanitizeLogValue(principal.ID))
	s.emitCliLoginAudit(r.Context(), "cli_login.approved", principal.ID, business.AuditUserTypeHuman,
		reqRecord.ID, business.AuditResultSuccess, business.AuditSeverityHigh, nil)

	s.writeResponse(w, http.StatusOK, ApproveCliLoginResponse{RequestID: reqRecord.ID, Status: reqRecord.Status})
}

// CollectCliLoginResponse is returned on every poll. Token and SessionID are set only
// on the single successful collection; every other response (pending/denied/expired)
// carries Status alone.
type CollectCliLoginResponse struct {
	Status         string    `json:"status"`
	Token          string    `json:"token,omitempty"`
	SessionID      string    `json:"session_id,omitempty"`
	AbsoluteExpiry time.Time `json:"absolute_expiry,omitempty"`
}

// claimCliLoginRequestForCollection performs the approved->collected compare-and-set
// under cliLoginCollectMu: re-fetch the record inside the lock, verify it is still
// "approved", and persist the transition before releasing it — mirroring
// claimCredentialRequestForCollection. This commits before the token is ever written
// to the response, so a process restart or a second caller between this commit and
// the eventual response always observes "collected" and never hands out the token twice.
//
// The committed record deliberately carries no session_token: the token is lifted into
// a local, cleared on the struct before persisting, and restored only on the in-memory
// value returned for the response body. A collected request is terminal and is never
// swept, so anything left in its metadata would remain in git-backed durable storage —
// and in that store's history — for longer than the session it names. Collection is the
// single point at which the token stops being needed at rest, so it is dropped there.
func (s *Server) claimCliLoginRequestForCollection(ctx context.Context, id string) (*pendingCliLoginRequest, error) {
	s.cliLoginCollectMu.Lock()
	defer s.cliLoginCollectMu.Unlock()

	fresh, err := s.getCliLoginRequestByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if fresh == nil || fresh.Status != cliLoginRequestStatusApproved {
		return nil, errCliLoginRequestAlreadyCollected
	}
	now := time.Now().UTC()
	token := fresh.SessionToken
	fresh.Status = cliLoginRequestStatusCollected
	fresh.CollectedAt = &now
	fresh.SessionToken = ""
	if err := s.persistCliLoginRequest(ctx, fresh); err != nil {
		return nil, err
	}
	fresh.SessionToken = token
	return fresh, nil
}

// handleCollectCliLoginRequest handles POST /api/v1/cli-login/{id}/collect.
// Unauthenticated by API key or mTLS — gated entirely on the verifier the CLI
// generated locally and presents as a bearer credential exactly once, mirroring
// handleCollectCredentialRequest. Registered on the base router, not the authenticated
// api subrouter.
func (s *Server) handleCollectCliLoginRequest(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "id is required", "MISSING_ID")
		return
	}
	if s.secretStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Cli login service not available", "SERVICE_UNAVAILABLE")
		return
	}

	rawVerifier := ""
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		rawVerifier = strings.TrimPrefix(authHeader, "Bearer ")
	}

	reqRecord, err := s.getCliLoginRequestByID(r.Context(), id)
	if err != nil {
		s.logger.Error("Failed to look up cli-login request for collect", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up login request", "STORE_ERROR")
		return
	}
	// A wrong verifier and an unknown ID are indistinguishable: this endpoint never
	// confirms a request ID exists to a caller who cannot prove they hold its
	// verifier (Issue #3721 [REQUIRED TEST]).
	if reqRecord == nil || !verifierMatches(rawVerifier, reqRecord.VerifierHash) {
		s.writeErrorResponse(w, http.StatusNotFound, "Login request not found", "REQUEST_NOT_FOUND")
		return
	}

	if reqRecord.Status == cliLoginRequestStatusCollected {
		w.WriteHeader(http.StatusGone)
		return
	}
	if time.Now().UTC().After(reqRecord.ExpiresAt) {
		s.writeSuccessResponse(w, CollectCliLoginResponse{Status: "expired"})
		return
	}
	switch reqRecord.Status {
	case cliLoginRequestStatusPending:
		s.writeSuccessResponse(w, CollectCliLoginResponse{Status: "pending"})
		return
	case cliLoginRequestStatusDenied:
		s.writeSuccessResponse(w, CollectCliLoginResponse{Status: "denied"})
		return
	case cliLoginRequestStatusApproved:
		// Fall through to the claim branch below.
	default:
		s.writeSuccessResponse(w, CollectCliLoginResponse{Status: reqRecord.Status})
		return
	}

	// Leadership is gated on the claim/mutate branch only (mirrors
	// handleCollectCredentialRequest): polling remains available on a
	// non-authoritative node, but the single-use transition is only ever performed
	// by the leader. The request stays "approved" — untouched — on a 503 here.
	if checker := s.registrationLeaderStatus; checker != nil && !checker.HasLeadership() {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}

	claimed, err := s.claimCliLoginRequestForCollection(r.Context(), id)
	if err != nil {
		if errors.Is(err, errCliLoginRequestAlreadyCollected) {
			w.WriteHeader(http.StatusGone)
			return
		}
		s.logger.Error("Failed to claim cli-login request for collection", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to collect login request", "STORE_ERROR")
		return
	}

	s.logger.Info("Cli-login request collected", "request_id", logging.SanitizeLogValue(claimed.ID))
	s.emitCliLoginAudit(r.Context(), "cli_login.collected", claimed.ApprovedBy, business.AuditUserTypeHuman,
		claimed.ID, business.AuditResultSuccess, business.AuditSeverityHigh, nil)

	s.writeResponse(w, http.StatusOK, CollectCliLoginResponse{
		Status:         claimed.Status,
		Token:          claimed.SessionToken,
		SessionID:      claimed.SessionID,
		AbsoluteExpiry: claimed.SessionAbsoluteExpiry,
	})
}

// ---- expiry sweep -----------------------------------------------------------------

// startCliLoginRequestSweep starts the background expiry sweep goroutine. Mirrors
// startCredentialRequestSweep's stop/done channel shape, using its own dedicated pair
// so the two cleanup loops stop independently.
func (s *Server) startCliLoginRequestSweep() {
	go func() {
		defer close(s.cliLoginSweepDone)
		ticker := time.NewTicker(cliLoginSweepInterval)
		defer ticker.Stop()

		s.logger.Info("Started cli-login expiry sweep", "interval", cliLoginSweepInterval)

		for {
			select {
			case <-s.stopCliLoginSweep:
				return
			case <-ticker.C:
				s.cliLoginSweepLease.RunIfLeader(context.Background(), s.sweepExpiredCliLoginRequests)
			}
		}
	}()
}

// sweepExpiredCliLoginRequests deletes expired pending and expired approved-but-
// uncollected login requests. An approved request's minted session is revoked before
// its record is deleted — an uncollected token must never remain a live credential
// once its request expires (Issue #3721 amendment).
//
// Denied and collected requests are terminal and are deliberately left in place: a
// collected session is the operator's live credential and must not be revoked by a
// sweep keyed on the request's own expiry, and a denied request never minted one.
// Neither carries a credential at rest — a denial never writes SessionToken, and
// collection clears it before committing — so their retention is not bounded here.
// The store's TTL is advisory (it filters reads only; see SOPSSecretStore.isExpired),
// so nothing else reaps these records either, and nothing needs to.
func (s *Server) sweepExpiredCliLoginRequests(ctx context.Context) {
	if s.secretStore == nil {
		return
	}
	now := time.Now().UTC()

	for _, status := range []string{cliLoginRequestStatusPending, cliLoginRequestStatusApproved} {
		metas, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
			Tags: []string{cliLoginRequestSecretType},
			Metadata: map[string]string{
				secretsif.MetadataKeySecretType: cliLoginRequestSecretType,
				"status":                        status,
			},
			IncludeExpired: true,
		})
		if err != nil {
			s.logger.Error("Cli-login expiry sweep: failed to list requests",
				"status", status, "error", logging.SanitizeLogValue(err.Error()))
			continue
		}
		for _, m := range metas {
			req := cliLoginRequestFromMetadata(m)
			if !req.ExpiresAt.Before(now) {
				continue
			}
			if req.SessionID != "" && s.sessionManager != nil {
				if revokeErr := s.sessionManager.Revoke(ctx, req.SessionID); revokeErr != nil && !errors.Is(revokeErr, session.ErrSessionNotFound) {
					s.logger.Warn("Cli-login expiry sweep: failed to revoke uncollected session",
						"error", logging.SanitizeLogValue(revokeErr.Error()))
					continue
				}
			}
			if delErr := s.secretStore.DeleteSecret(ctx, m.TenantID+"/"+m.Key); delErr != nil {
				s.logger.Warn("Cli-login expiry sweep: failed to delete expired request",
					"error", logging.SanitizeLogValue(delErr.Error()))
				continue
			}
			s.emitCliLoginAudit(ctx, "cli_login.expired", cliLoginSweepActor, business.AuditUserTypeSystem,
				req.ID, business.AuditResultSuccess, business.AuditSeverityLow, nil)
		}
	}
}
