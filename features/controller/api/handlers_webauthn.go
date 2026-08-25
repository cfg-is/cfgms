// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2782: WebAuthn passkey / FIDO2 registration endpoints.
// Issue #2783: WebAuthn credential list and revoke endpoints (cfg CLI bootstrap).
// Issue #2966: first-passkey enrollment via single-use magic link (ADR-021 Amendment 1).
// Issue #2992: backup passkey self-service UI; IDOR fix; server-side anti-lockout guard.
//
// Routes (register: webauthn:register permission, AssuranceStrong;
//
//	        list:     webauthn:list permission, no assurance requirement;
//	        revoke:   webauthn:revoke permission, AssuranceStrong):
//
//		POST /api/v1/accounts/{username}/webauthn/register/begin
//		     Returns PublicKeyCredentialCreationOptions (the WebAuthn challenge).
//		     Cookie-auth principals are self-scoped to their own account.
//
//		POST /api/v1/accounts/{username}/webauthn/register/finish
//		     Verifies the authenticator response, persists the credential.
//		     Cookie-auth principals are self-scoped to their own account.
//
//		GET  /api/v1/accounts/{username}/webauthn/credentials
//		     Lists registered credentials for the account (public metadata only).
//		     Cookie-auth principals are self-scoped to their own account.
//
//		POST /api/v1/accounts/{username}/webauthn/revoke/{credential_id}
//		     Removes a specific credential. credential_id is base64url-encoded.
//		     Cookie-auth principals are self-scoped and cannot remove their last credential.
//
// Enrollment routes (Issue #2966; no assurance requirement — token IS the credential;
// registered on the BASE router, not under the authenticated api subrouter):
//
//	POST /api/v1/web/passkey/enroll/begin
//	     Header: X-Enrollment-Token: <raw-hex-token>
//	     Verifies the token, begins WebAuthn registration ceremony self-scoped to the
//	     account the token identifies (never a caller-supplied username).
//
//	POST /api/v1/web/passkey/enroll/finish
//	     Header: X-Enrollment-Token: <raw-hex-token>
//	     Body: WebAuthn PublicKeyCredential JSON
//	     Verifies WebAuthn response, enforces zero-credential CAS precondition, appends
//	     credential, and atomically consumes the token. Token not reusable after this.
//
// Server-side verification enforces: challenge freshness (5-min TTL, server-stored),
// single-use (session deleted on every finish attempt), origin match, RP-ID match,
// and cryptographic attestation verification — all via the go-webauthn/webauthn
// library. No WebAuthn primitive is hand-rolled.
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// webAuthnPendingSession holds an in-progress WebAuthn registration ceremony state
// server-side. Stored in s.webAuthnSessions (sync.Map) keyed by username. It is
// single-use (deleted on every finish attempt, success or failure) and expires after
// webAuthnSessionTTL — preventing replay of stale begin responses.
type webAuthnPendingSession struct {
	data    webauthn.SessionData
	expires time.Time
}

// webauthnUser adapts a account to the go-webauthn/webauthn User interface.
type webauthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// buildWebauthnUser converts a account into the webauthn.User the library expects.
// Existing credentials are included so BeginRegistration can populate excludeCredentials.
func buildWebauthnUser(acct *account) *webauthnUser {
	creds := make([]webauthn.Credential, 0, len(acct.Credentials))
	for _, c := range acct.Credentials {
		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transport))
		for _, t := range c.Transport {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		creds = append(creds, webauthn.Credential{
			ID:        c.ID,
			PublicKey: c.PublicKey,
			Transport: transports,
			Flags: webauthn.CredentialFlags{
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
			},
		})
	}
	return &webauthnUser{
		id:          []byte(acct.ID),
		name:        acct.Username,
		displayName: acct.Username,
		credentials: creds,
	}
}

// resolveAccountForCredentials enforces caller-scoping for the credential
// management surface (Issue #2992). Cookie-auth principals (human web accounts,
// ADR-021 Amendment 1) may only operate on their own account — IDOR prevention.
// mTLS and API-key principals retain admin-level access via the path {username}.
//
// Returns (account, principal, true) on success, or writes an error response and
// returns (nil, nil, false).
func (s *Server) resolveAccountForCredentials(w http.ResponseWriter, r *http.Request) (*account, *Principal, bool) {
	pathUsername := mux.Vars(r)["username"]
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	isCookieAuth, _ := r.Context().Value(cookieAuthContextKey).(bool)

	if isCookieAuth && principal != nil {
		// Self-service path (human web account): resolve from session, not path.
		// Session PrincipalID is the account's UUID; getAccountByID looks it up.
		acct, err := s.getAccountByID(r.Context(), principal.ID)
		if err != nil {
			s.logger.Error("Failed to resolve web account for credential operation",
				"principal_id", logging.SanitizeLogValue(principal.ID),
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError,
				"Failed to look up web account", "STORE_ERROR")
			return nil, nil, false
		}
		if acct == nil {
			s.writeErrorResponse(w, http.StatusNotFound,
				"Web account not found", "WEB_ACCOUNT_NOT_FOUND")
			return nil, nil, false
		}
		// IDOR rejection: path username must match the session-bound account.
		if pathUsername != acct.Username {
			s.writeErrorResponse(w, http.StatusForbidden,
				"Access denied: passkey operations are scoped to your own account", "FORBIDDEN")
			return nil, nil, false
		}
		return acct, principal, true
	}

	// Admin (mTLS / API-key) path: use path username directly.
	if err := validateUsername(pathUsername); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return nil, nil, false
	}
	acct, err := s.getAccount(r.Context(), pathUsername)
	if err != nil {
		s.logger.Error("Failed to resolve web account for credential operation",
			"username", logging.SanitizeLogValue(pathUsername),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to look up web account", "STORE_ERROR")
		return nil, nil, false
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound,
			"Web account not found", "WEB_ACCOUNT_NOT_FOUND")
		return nil, nil, false
	}
	return acct, principal, true
}

// handleWebAuthnRegisterBegin handles
// POST /api/v1/accounts/{username}/webauthn/register/begin.
//
// Generates a WebAuthn challenge and returns PublicKeyCredentialCreationOptions.
// The challenge is stored server-side (never trusted from the client); the
// client MUST embed it in clientDataJSON and return it in the finish step.
//
// Cookie-auth principals are self-scoped: the target account is resolved from the
// session, not the path parameter (Issue #2992 IDOR fix).
func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	acct, _, ok := s.resolveAccountForCredentials(w, r)
	if !ok {
		return
	}
	username := acct.Username

	user := buildWebauthnUser(acct)

	creation, sessionData, err := wa.BeginRegistration(user,
		// userVerification: "required" for the initial enrollment ceremony:
		// the human-presence gesture is cheap at registration time.
		// ADR-021 Decision 3 relaxes this only for ongoing continuity checks
		// (a separate, later story), not the one-time enrollment here.
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		}),
		// Prevent re-registering an authenticator already enrolled for this account.
		webauthn.WithExclusions(webauthn.Credentials(user.credentials).CredentialDescriptors()),
	)
	if err != nil {
		s.logger.Error("WebAuthn BeginRegistration failed",
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to begin WebAuthn registration", "WEBAUTHN_BEGIN_ERROR")
		return
	}

	// Store the session server-side, single-use, time-bounded.
	// The authoritative challenge lives in sessionData.Challenge — the server's
	// copy is what FinishRegistration verifies against.
	s.webAuthnSessions.Store(username, &webAuthnPendingSession{
		data:    *sessionData,
		expires: time.Now().Add(webAuthnSessionTTL),
	})

	s.logger.Info("WebAuthn registration ceremony started",
		"username", logging.SanitizeLogValue(username))

	s.writeResponse(w, http.StatusOK, creation)
}

// handleWebAuthnRegisterFinish handles
// POST /api/v1/accounts/{username}/webauthn/register/finish.
//
// Verifies the authenticator response via the library (challenge match against
// the server-stored value, origin match, RP-ID match, attestation/signature),
// then persists the credential on the account record.
//
// Any extra fields in the request body (including a client-supplied "assurance"
// or "level" claim) are silently ignored by the library's JSON parser — the server
// never reads them. AssuranceStrong is assigned because a WebAuthn authenticator
// was cryptographically verified, never from a caller-asserted claim (ADR-021 §D1).
//
// Cookie-auth principals are self-scoped: the target account is resolved from the
// session, not the path parameter (Issue #2992 IDOR fix). An audit event is emitted
// on success.
func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	acct, principal, ok := s.resolveAccountForCredentials(w, r)
	if !ok {
		return
	}
	username := acct.Username

	actingPrincipalID := ""
	if principal != nil {
		actingPrincipalID = principal.ID
	}

	// Load and unconditionally delete the pending session (single-use enforcement).
	// A second finish attempt returns NO_ACTIVE_REGISTRATION because the session
	// is already consumed, regardless of whether the first attempt succeeded.
	rawSession, ok := s.webAuthnSessions.LoadAndDelete(username)
	if !ok {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"No active registration session — call begin first", "NO_ACTIVE_REGISTRATION")
		return
	}
	pending, ok := rawSession.(*webAuthnPendingSession)
	if !ok {
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Invalid session state", "SESSION_STATE_ERROR")
		return
	}

	// Server-side challenge freshness enforcement: reject sessions past their TTL.
	if time.Now().After(pending.expires) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Registration session expired — restart with begin", "SESSION_EXPIRED")
		return
	}

	user := buildWebauthnUser(acct)

	// Full server-side verification via the library: parses the request body,
	// verifies challenge (against the server-stored session.Challenge, not the
	// client-echoed value), origin, RP-ID, and cryptographic attestation.
	//
	// The server assigns AssuranceStrong to this credential because a WebAuthn
	// authenticator was cryptographically verified — not because the client
	// supplied any assurance claim. The future assertion handler will set
	// Principal.Assurance = session.AssuranceStrong after verifying an assertion
	// against this credential (ADR-021 Decision 1).
	credential, err := wa.FinishRegistration(user, pending.data, r)
	if err != nil {
		s.logger.Warn("WebAuthn FinishRegistration verification failed",
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest,
			"WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return
	}

	// Optional human-readable label from a query parameter (not the request body,
	// which is consumed by FinishRegistration above).
	label := logging.SanitizeLogValue(r.URL.Query().Get("label"))

	transports := make([]string, 0, len(credential.Transport))
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}
	stored := WebAuthnCredential{
		ID:             credential.ID,
		PublicKey:      credential.PublicKey,
		SignCount:      credential.Authenticator.SignCount,
		Transport:      transports,
		Label:          label,
		RegisteredAt:   time.Now().UTC(),
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
	}

	// Re-persist the account with the appended credential. The account loaded above
	// (resolveAccountForCredentials) already reflects any credentials registered
	// before this call.
	updatedAcct := *acct
	updatedAcct.Credentials = append(append([]WebAuthnCredential(nil), acct.Credentials...), stored)

	if err := s.persistAccount(r.Context(), &updatedAcct, actingPrincipalID); err != nil {
		s.logger.Error("Failed to persist WebAuthn credential",
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to persist credential", "STORE_ERROR")
		return
	}
	s.cacheAccount(&updatedAcct)

	s.logger.Info("WebAuthn credential registered",
		"username", logging.SanitizeLogValue(username),
		"label", logging.SanitizeLogValue(label))

	// Audit: record passkey addition (Issue #2992).
	s.emitPasskeyAddedAudit(r.Context(), &updatedAcct, base64.RawURLEncoding.EncodeToString(stored.ID), actingPrincipalID)

	// Response contains only the credential ID and metadata — no private-key-adjacent
	// material (the server never holds the authenticator private key).
	s.writeResponse(w, http.StatusCreated, WebAuthnRegisterFinishResponse{
		CredentialID: stored.ID,
		Label:        stored.Label,
		RegisteredAt: stored.RegisteredAt,
	})
}

// getWebAuthn returns the configured WebAuthn instance, or nil when not configured.
// Handlers return 503 when this returns nil.
func (s *Server) getWebAuthn() *webauthn.WebAuthn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.webAuthn
}

// SetWebAuthn configures the WebAuthn relying-party instance for the registration
// endpoints. Call after New() but before Start(). When nil, the registration
// endpoints return 503.
//
// The RPID must be the effective domain of the controller (e.g. "example.com");
// RPOrigins must list the fully qualified origins permitted (e.g. "https://example.com").
func (s *Server) SetWebAuthn(wa *webauthn.WebAuthn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.webAuthn = wa
}

// NewWebAuthnFromConfig creates a webauthn.WebAuthn instance from the provided values.
// Returns an error when RPID or RPOrigins are invalid.
// Intended for use during controller startup and in integration tests.
func NewWebAuthnFromConfig(rpID, rpDisplayName string, rpOrigins []string) (*webauthn.WebAuthn, error) {
	cfg := &webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     rpOrigins,
	}
	wa, err := webauthn.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("webauthn config invalid: %w", err)
	}
	return wa, nil
}

// handlePresenceBegin handles POST /api/v1/webauthn/presence/begin.
//
// Issues a WebAuthn assertion challenge scoped to the authenticated principal's
// credentials. The client must call this before performing a RequireUserPresence-
// gated action (module:approve, module:reject, publisher-trust:add).
//
// userVerification is always "required" — this is the one place where the
// authenticator gesture must be visible to the user (ADR-021 Decision 4).
// Contrast with silent continuity proofs (a separate story) which use "discouraged".
//
// Design choice: separate endpoint (not folded into the existing login/register flow)
// because presence is not a session-minting ceremony — it produces a short-lived
// single-use token rather than a session token, and its session key space is
// separate (webAuthnPresenceSessions, keyed by principalID, not username).
func (s *Server) handlePresenceBegin(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized,
			"Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	// Presence ceremonies are only meaningful for principals with registered credentials.
	acct, err := s.getAccount(r.Context(), principal.ID)
	if err != nil {
		s.logger.Error("Failed to look up web account for presence begin",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to look up web account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound,
			"Web account not found — WebAuthn credential required for presence ceremony", "WEB_ACCOUNT_NOT_FOUND")
		return
	}
	if len(acct.Credentials) == 0 {
		s.writeErrorResponse(w, http.StatusConflict,
			"No WebAuthn credentials registered — enroll a passkey first", "NO_CREDENTIALS")
		return
	}

	user := buildWebauthnUser(acct)

	// BeginLogin with userVerification=required: the authenticator MUST verify the
	// user (PIN, biometric) — "discouraged" or "preferred" are insufficient here.
	assertion, sessionData, err := wa.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.logger.Error("WebAuthn BeginLogin failed for presence ceremony",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to begin presence ceremony", "WEBAUTHN_BEGIN_ERROR")
		return
	}

	// Store server-side, single-use, time-bounded (same TTL as registration sessions).
	s.webAuthnPresenceSessions.Store(principal.ID, &webAuthnPendingSession{
		data:    *sessionData,
		expires: time.Now().Add(webAuthnSessionTTL),
	})

	s.logger.Info("WebAuthn presence ceremony started",
		"principal_id", logging.SanitizeLogValue(principal.ID))

	s.writeResponse(w, http.StatusOK, assertion)
}

// handlePresenceFinish handles POST /api/v1/webauthn/presence/finish.
//
// Verifies the authenticator assertion response and, on success, mints a short-lived
// single-use presence token (presenceTokenTTL) that the client passes in the
// X-Presence-Token header on the guarded action request. requirePermission consumes
// the token atomically (LoadAndDelete), so replay is impossible.
//
// Security properties:
//   - Challenge freshness: server-stored session data is deleted on every finish attempt
//     (LoadAndDelete), preventing replay of a stale begin response.
//   - Single-use: the presence token is consumed on first use by requirePermission.
//   - Short TTL: presenceTokenTTL (30 s) bounds the window for a hijacked session to
//     replay a presence proof — even if the session continuity is intact.
//   - Scope: the token is bound to the principal ID that ran the ceremony. requirePermission
//     rejects the token with a step-up 401 if the acting principal differs from
//     record.principalID (ADR-021 Decision 4) — presence proved by principal A can never
//     satisfy the gate for principal B's action. The gate is single-use + TTL + principal binding.
//
// Cross-reference: #2728/#2732 implementers consume permissionAssurance["module:approve"]
// and ["module:reject"] — the presence mechanism built here is what gates those routes.
func (s *Server) handlePresenceFinish(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized,
			"Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	acct, err := s.getAccount(r.Context(), principal.ID)
	if err != nil {
		s.logger.Error("Failed to look up web account for presence finish",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to look up web account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound,
			"Web account not found", "WEB_ACCOUNT_NOT_FOUND")
		return
	}

	// Load and unconditionally delete the pending session (single-use enforcement).
	rawSession, ok := s.webAuthnPresenceSessions.LoadAndDelete(principal.ID)
	if !ok {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"No active presence session — call begin first", "NO_ACTIVE_PRESENCE_SESSION")
		return
	}
	pending, ok := rawSession.(*webAuthnPendingSession)
	if !ok {
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Invalid session state", "SESSION_STATE_ERROR")
		return
	}

	if time.Now().After(pending.expires) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Presence session expired — restart with begin", "SESSION_EXPIRED")
		return
	}

	user := buildWebauthnUser(acct)

	// Full server-side assertion verification: challenge, origin, RP-ID, signature.
	// The library enforces userVerification=required (set at begin time) via SessionData.
	if _, err := wa.FinishLogin(user, pending.data, r); err != nil {
		s.logger.Warn("WebAuthn FinishLogin failed for presence ceremony",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest,
			"WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return
	}

	// Mint a 32-byte cryptographically random presence token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		s.logger.Error("Failed to generate presence token",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to generate presence token", "TOKEN_GEN_ERROR")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	tokenHash := hashPresenceToken(token)

	s.presenceTokens.Store(tokenHash, &presenceTokenRecord{
		principalID: principal.ID,
		expires:     time.Now().Add(presenceTokenTTL),
	})

	s.logger.Info("Presence token minted",
		"principal_id", logging.SanitizeLogValue(principal.ID),
		"permission_surface", "module:approve,module:reject,publisher-trust:add")

	s.writeResponse(w, http.StatusOK, WebAuthnPresenceFinishResponse{
		PresenceToken: token,
		ExpiresIn:     int(presenceTokenTTL.Seconds()),
	})
}

// handleWebAuthnListCredentials handles
// GET /api/v1/accounts/{username}/webauthn/credentials.
//
// Returns public metadata for all WebAuthn credentials registered to the account.
// The public key bytes are omitted from the response — only the credential ID,
// label, transport hints, registration timestamp, and last-used timestamp are
// returned (sufficient for display and for identifying a credential to revoke).
//
// Cookie-auth principals are self-scoped: the target account is resolved from the
// session, not the path parameter (Issue #2992 IDOR fix).
func (s *Server) handleWebAuthnListCredentials(w http.ResponseWriter, r *http.Request) {
	acct, _, ok := s.resolveAccountForCredentials(w, r)
	if !ok {
		return
	}

	infos := make([]WebAuthnCredentialInfo, 0, len(acct.Credentials))
	for _, c := range acct.Credentials {
		infos = append(infos, WebAuthnCredentialInfo{
			ID:           base64.RawURLEncoding.EncodeToString(c.ID),
			Label:        c.Label,
			Transport:    c.Transport,
			RegisteredAt: c.RegisteredAt,
			LastUsedAt:   c.LastUsedAt,
		})
	}

	s.writeResponse(w, http.StatusOK, WebAuthnListResponse{
		Username:    acct.Username,
		Credentials: infos,
	})
}

// enrollmentTokenHeader is the HTTP request header that carries the single-use
// enrollment magic-link token for first-passkey enrollment (Issue #2966).
// The raw token (hex-encoded, 160-bit) is presented here; the server computes
// SHA-256 and compares in constant time against the stored hash.
const enrollmentTokenHeader = "X-Enrollment-Token"

// handlePasskeyEnrollBegin handles POST /api/v1/web/passkey/enroll/begin.
//
// The caller presents the raw enrollment token in X-Enrollment-Token. The server:
//  1. Looks up the account by token hash (never by caller-supplied username).
//  2. Verifies the token is unexpired and not revoked.
//  3. Starts a WebAuthn registration ceremony scoped to that account.
//  4. Stores the pending session keyed by tokenHash (not username) so the finish
//     step can find it without trusting any caller-supplied identity.
//
// This route is on the BASE router (public) — the token IS the auth credential.
func (s *Server) handlePasskeyEnrollBegin(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	rawToken := r.Header.Get(enrollmentTokenHeader)
	if rawToken == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			enrollmentTokenHeader+" header is required", "MISSING_ENROLLMENT_TOKEN")
		return
	}

	// Resolve account by token — never by a caller-supplied path variable.
	// This prevents the cross-account credential injection described in the issue.
	acct, err := s.getAccountByEnrollmentToken(r.Context(), rawToken)
	if err != nil {
		s.logger.Error("Failed to look up account for enrollment begin",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to look up account", "STORE_ERROR")
		return
	}
	if acct == nil {
		// No account with this token or token does not exist.
		// Return the same error as invalid/expired to prevent account enumeration.
		s.writeErrorResponse(w, http.StatusUnauthorized,
			"Invalid or expired enrollment token", "TOKEN_INVALID")
		return
	}

	if !verifyEnrollmentToken(acct, rawToken) {
		s.writeErrorResponse(w, http.StatusUnauthorized,
			"Invalid or expired enrollment token", "TOKEN_INVALID")
		return
	}

	user := buildWebauthnUser(acct)

	creation, sessionData, err := wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(webauthn.Credentials(user.credentials).CredentialDescriptors()),
	)
	if err != nil {
		s.logger.Error("WebAuthn BeginRegistration failed for enrollment",
			"account_id", logging.SanitizeLogValue(acct.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to begin WebAuthn registration", "WEBAUTHN_BEGIN_ERROR")
		return
	}

	// Key the ceremony by tokenHash, not username. This decouples the session lookup
	// from any caller-supplied identity at finish time (self-scoping invariant).
	tokenHash := hashEnrollmentToken(rawToken)
	s.passkeyEnrollSessions.Store(tokenHash, &webAuthnPendingSession{
		data:    *sessionData,
		expires: time.Now().Add(webAuthnSessionTTL),
	})

	s.logger.Info("Passkey enrollment ceremony started",
		"account_id", logging.SanitizeLogValue(acct.ID))

	s.writeResponse(w, http.StatusOK, creation)
}

// handlePasskeyEnrollFinish handles POST /api/v1/web/passkey/enroll/finish.
//
// The caller presents X-Enrollment-Token and the WebAuthn registration response body.
// The server:
//  1. Loads and atomically deletes the pending ceremony (single-use enforcement).
//  2. Verifies the WebAuthn response cryptographically.
//  3. Reloads the account from the durable store (for CAS freshness).
//  4. Under the CAS precondition: token still valid + zero registered credentials.
//  5. Appends the credential, marks the token consumed, persists, audits.
//
// The LoadAndDelete on passkeyEnrollSessions is the primary concurrency gate: only one
// finish request per ceremony can succeed (the second gets NO_ACTIVE_ENROLLMENT). The
// store-fresh reload at step 3 guards against admin-mediated mutations between begin and
// finish (TOCTOU hardening — ADR-021 Amendment 1 security property 3).
func (s *Server) handlePasskeyEnrollFinish(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	rawToken := r.Header.Get(enrollmentTokenHeader)
	if rawToken == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			enrollmentTokenHeader+" header is required", "MISSING_ENROLLMENT_TOKEN")
		return
	}

	tokenHash := hashEnrollmentToken(rawToken)

	// LoadAndDelete is the single-use gate: only the first finish call succeeds.
	rawSession, ok := s.passkeyEnrollSessions.LoadAndDelete(tokenHash)
	if !ok {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"No active enrollment session — call begin first", "NO_ACTIVE_ENROLLMENT")
		return
	}
	pending, ok := rawSession.(*webAuthnPendingSession)
	if !ok {
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Invalid session state", "SESSION_STATE_ERROR")
		return
	}

	if time.Now().After(pending.expires) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Enrollment session expired — restart with begin", "SESSION_EXPIRED")
		return
	}

	// Resolve account by token for WebAuthn user construction.
	// We look up from cache here; CAS reload from store follows below.
	acct, err := s.getAccountByEnrollmentToken(r.Context(), rawToken)
	if err != nil {
		s.logger.Error("Failed to look up account for enrollment finish",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to look up account", "STORE_ERROR")
		return
	}
	if acct == nil || !verifyEnrollmentToken(acct, rawToken) {
		s.writeErrorResponse(w, http.StatusUnauthorized,
			"Enrollment token is no longer valid", "TOKEN_INVALID")
		return
	}

	user := buildWebauthnUser(acct)

	// Full library-level WebAuthn verification (challenge, origin, RP-ID, attestation).
	credential, err := wa.FinishRegistration(user, pending.data, r)
	if err != nil {
		s.logger.Warn("WebAuthn FinishRegistration verification failed for enrollment",
			"account_id", logging.SanitizeLogValue(acct.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest,
			"WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return
	}

	label := logging.SanitizeLogValue(r.URL.Query().Get("label"))

	transports := make([]string, 0, len(credential.Transport))
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}
	stored := WebAuthnCredential{
		ID:             credential.ID,
		PublicKey:      credential.PublicKey,
		SignCount:      credential.Authenticator.SignCount,
		Transport:      transports,
		Label:          label,
		RegisteredAt:   time.Now().UTC(),
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
	}

	// CAS reload: re-read from the durable store (not cache) to detect any
	// admin-mediated mutations that occurred between begin and finish.
	// Combined with LoadAndDelete above, this closes the TOCTOU window.
	freshAcct, freshErr := s.loadAccountFromStore(r.Context(), acct.Username, accountStorageTenant(acct.TenantID))
	if freshErr != nil {
		s.logger.Error("CAS reload failed for enrollment finish",
			"account_id", logging.SanitizeLogValue(acct.ID),
			"error", logging.SanitizeLogValue(freshErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to verify account state", "STORE_ERROR")
		return
	}
	if freshAcct == nil || !verifyEnrollmentToken(freshAcct, rawToken) {
		// Token was revoked or expired by an admin between begin and finish.
		s.writeErrorResponse(w, http.StatusGone,
			"Enrollment token is no longer valid", "TOKEN_INVALID")
		return
	}
	if len(freshAcct.Credentials) != 0 {
		// Another finish raced ahead (impossible via this path due to LoadAndDelete, but
		// guards against future code paths or direct-store mutations).
		s.writeErrorResponse(w, http.StatusConflict,
			"Account already has enrolled credentials", "ALREADY_ENROLLED")
		return
	}

	// Precondition satisfied. Build updated account: append credential, consume token.
	updatedAcct := *freshAcct
	updatedAcct.Credentials = []WebAuthnCredential{stored}
	updatedAcct.EnrollmentLinkRevoked = true

	if err := s.persistAccount(r.Context(), &updatedAcct, ""); err != nil {
		s.logger.Error("Failed to persist enrollment credential",
			"account_id", logging.SanitizeLogValue(acct.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to persist credential", "STORE_ERROR")
		return
	}
	s.cacheAccount(&updatedAcct)

	// Audit: record account, credential ID, and delivery channel.
	credIDStr := base64.RawURLEncoding.EncodeToString(stored.ID)
	s.emitEnrollmentAudit(r.Context(), &updatedAcct, credIDStr)
	s.logger.Info("First passkey enrolled via magic link",
		"account_id", logging.SanitizeLogValue(updatedAcct.ID),
		"username", logging.SanitizeLogValue(updatedAcct.Username))

	s.writeResponse(w, http.StatusCreated, WebAuthnRegisterFinishResponse{
		CredentialID: stored.ID,
		Label:        stored.Label,
		RegisteredAt: stored.RegisteredAt,
	})
}

// emitEnrollmentAudit records a first-passkey enrollment audit event.
func (s *Server) emitEnrollmentAudit(ctx context.Context, acct *account, credentialID string) {
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
		Action("account.passkey_enrolled").
		User(acct.ID, business.AuditUserTypeHuman).
		Resource("web-account", logging.SanitizeLogValue(acct.Username), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Details(map[string]interface{}{
			"credential_id":    logging.SanitizeLogValue(credentialID),
			"delivery_channel": "magic_link",
		})
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit enrollment audit event",
			"account_id", logging.SanitizeLogValue(acct.ID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// handleWebAuthnRevokeCredential handles
// POST /api/v1/accounts/{username}/webauthn/revoke/{credential_id}.
//
// Removes the named credential from the account. credential_id is the base64url-encoded
// credential ID as returned by the list endpoint. Returns 404 when the credential is not
// found on the account; returns 204 on success.
//
// Self-lockout guard (Issue #2992, ADR-021 Amendment 1): cookie-auth principals
// (human web accounts) cannot remove their last passkey — doing so would lock them out,
// because they have no mTLS cert fallback. mTLS/API-key principals are exempt: they retain
// alternative access paths (ADR-021 §7) and may revoke the last credential.
//
// Atomicity: the last-credential check and removal are a single compare-and-swap under
// s.credentialMu, with a fresh store reload inside the mutex. This prevents two concurrent
// revokes from each seeing the pre-removal count and racing to zero.
//
// Cookie-auth principals are also self-scoped: the target account is resolved from the
// session, not the path parameter (Issue #2992 IDOR fix).
func (s *Server) handleWebAuthnRevokeCredential(w http.ResponseWriter, r *http.Request) {
	// Phase 1: IDOR check and credential ID parsing (outside the CAS mutex).
	acct, principal, ok := s.resolveAccountForCredentials(w, r)
	if !ok {
		return
	}
	isCookieAuth, _ := r.Context().Value(cookieAuthContextKey).(bool)

	credIDParam := mux.Vars(r)["credential_id"]
	if credIDParam == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "credential_id is required", "INVALID_CREDENTIAL_ID")
		return
	}
	credIDBytes, err := base64.RawURLEncoding.DecodeString(credIDParam)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "credential_id must be base64url encoded", "INVALID_CREDENTIAL_ID")
		return
	}

	actingPrincipalID := ""
	if principal != nil {
		actingPrincipalID = principal.ID
	}

	// Phase 2: CAS critical section — fresh reload, last-credential check, persist.
	// A single mutex ensures that no two concurrent revokes can both see the
	// pre-removal count, both pass the last-credential guard, and both persist zero
	// credentials.
	s.credentialMu.Lock()

	freshAcct, freshErr := s.loadAccountFromStore(r.Context(), acct.Username, accountStorageTenant(acct.TenantID))
	if freshErr != nil {
		s.credentialMu.Unlock()
		s.logger.Error("Failed to reload web account for credential revocation",
			"username", logging.SanitizeLogValue(acct.Username),
			"error", logging.SanitizeLogValue(freshErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to reload account state", "STORE_ERROR")
		return
	}
	if freshAcct == nil {
		s.credentialMu.Unlock()
		s.writeErrorResponse(w, http.StatusNotFound,
			"Web account not found", "WEB_ACCOUNT_NOT_FOUND")
		return
	}

	found := false
	remaining := make([]WebAuthnCredential, 0, len(freshAcct.Credentials))
	for _, c := range freshAcct.Credentials {
		if bytes.Equal(c.ID, credIDBytes) {
			found = true
			continue
		}
		remaining = append(remaining, c)
	}
	if !found {
		s.credentialMu.Unlock()
		s.writeErrorResponse(w, http.StatusNotFound,
			"Credential not found on this account", "CREDENTIAL_NOT_FOUND")
		return
	}

	// Anti-lockout guard: cookie-auth (human web account) principals cannot remove
	// their last passkey. They have no mTLS cert fallback (ADR-021 §7 does not apply
	// to human web accounts — only to mTLS-authenticated principals). Recovery requires
	// an admin-initiated account reset.
	if isCookieAuth && len(remaining) == 0 {
		s.credentialMu.Unlock()
		s.writeErrorResponse(w, http.StatusConflict,
			"Cannot remove the last passkey — add a backup passkey first, or request an admin reset to recover account access",
			"LAST_CREDENTIAL")
		return
	}

	updatedAcct := *freshAcct
	updatedAcct.Credentials = remaining
	if persistErr := s.persistAccount(r.Context(), &updatedAcct, actingPrincipalID); persistErr != nil {
		s.credentialMu.Unlock()
		s.logger.Error("Failed to persist credential revocation",
			"username", logging.SanitizeLogValue(freshAcct.Username),
			"error", logging.SanitizeLogValue(persistErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to persist credential revocation", "STORE_ERROR")
		return
	}
	s.cacheAccount(&updatedAcct)
	s.credentialMu.Unlock()

	s.logger.Info("WebAuthn credential revoked",
		"username", logging.SanitizeLogValue(freshAcct.Username),
		"acting_principal", logging.SanitizeLogValue(actingPrincipalID))

	// Emit revoke audit (Issue #2992).
	s.emitPasskeyRevokedAudit(r.Context(), &updatedAcct, base64.RawURLEncoding.EncodeToString(credIDBytes), actingPrincipalID)

	w.WriteHeader(http.StatusNoContent)
}

// emitPasskeyAddedAudit records a passkey-added audit event (Issue #2992).
// Called after a successful additional registration (not first-enrollment — that is
// covered by emitEnrollmentAudit). actingPrincipalID is the session principal UUID,
// which may differ from acct.ID when an mTLS admin adds a credential on behalf of a user.
func (s *Server) emitPasskeyAddedAudit(ctx context.Context, acct *account, credentialID, actingPrincipalID string) {
	if s.auditManager == nil {
		return
	}
	tenantID := acct.TenantID
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	details := map[string]interface{}{
		"credential_id": logging.SanitizeLogValue(credentialID),
	}
	if actingPrincipalID != acct.ID {
		details["acting_principal"] = logging.SanitizeLogValue(actingPrincipalID)
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action("account.passkey_added").
		User(acct.ID, business.AuditUserTypeHuman).
		Resource("web-account", logging.SanitizeLogValue(acct.Username), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityMedium).
		Details(details)
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit passkey_added audit event",
			"account_id", logging.SanitizeLogValue(acct.ID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// emitPasskeyRevokedAudit records a passkey-revoked audit event (Issue #2992).
// actingPrincipalID is the session principal UUID, which may differ from acct.ID when
// an mTLS admin revokes a credential on behalf of a user.
func (s *Server) emitPasskeyRevokedAudit(ctx context.Context, acct *account, credentialID, actingPrincipalID string) {
	if s.auditManager == nil {
		return
	}
	tenantID := acct.TenantID
	if tenantID == "" {
		tenantID = audit.SystemTenantID
	}
	details := map[string]interface{}{
		"credential_id": logging.SanitizeLogValue(credentialID),
	}
	if actingPrincipalID != acct.ID {
		details["acting_principal"] = logging.SanitizeLogValue(actingPrincipalID)
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action("account.passkey_revoked").
		User(acct.ID, business.AuditUserTypeHuman).
		Resource("web-account", logging.SanitizeLogValue(acct.Username), "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Details(details)
	if err := s.auditManager.RecordEvent(ctx, b); err != nil {
		s.logger.Warn("Failed to emit passkey_revoked audit event",
			"account_id", logging.SanitizeLogValue(acct.ID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
