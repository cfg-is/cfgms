// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2782: WebAuthn passkey / FIDO2 registration endpoints.
//
// Two routes (both require webauthn:register permission, AssuranceStrong via
// permissionAssurance — credential-minting surface, consistent with session:create):
//
//	POST /api/v1/web/accounts/{username}/webauthn/register/begin
//	     Returns PublicKeyCredentialCreationOptions (the WebAuthn challenge).
//
//	POST /api/v1/web/accounts/{username}/webauthn/register/finish
//	     Verifies the authenticator response, persists the credential.
//
// Server-side verification enforces: challenge freshness (5-min TTL, server-stored),
// single-use (session deleted on every finish attempt), origin match, RP-ID match,
// and cryptographic attestation verification — all via the go-webauthn/webauthn
// library. No WebAuthn primitive is hand-rolled.
package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/logging"
)

// webAuthnPendingSession holds an in-progress WebAuthn registration ceremony state
// server-side. Stored in s.webAuthnSessions (sync.Map) keyed by username. It is
// single-use (deleted on every finish attempt, success or failure) and expires after
// webAuthnSessionTTL — preventing replay of stale begin responses.
type webAuthnPendingSession struct {
	data    webauthn.SessionData
	expires time.Time
}

// webauthnUser adapts a webAccount to the go-webauthn/webauthn User interface.
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

// buildWebauthnUser converts a webAccount into the webauthn.User the library expects.
// Existing credentials are included so BeginRegistration can populate excludeCredentials.
func buildWebauthnUser(acct *webAccount) *webauthnUser {
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

// handleWebAuthnRegisterBegin handles
// POST /api/v1/web/accounts/{username}/webauthn/register/begin.
//
// Generates a WebAuthn challenge and returns PublicKeyCredentialCreationOptions.
// The challenge is stored server-side (never trusted from the client); the
// client MUST embed it in clientDataJSON and return it in the finish step.
func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	username := mux.Vars(r)["username"]
	if err := validateWebUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}

	acct, err := s.getWebAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up web account for WebAuthn begin",
			"username", logging.SanitizeLogValue(username),
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
// POST /api/v1/web/accounts/{username}/webauthn/register/finish.
//
// Verifies the authenticator response via the library (challenge match against
// the server-stored value, origin match, RP-ID match, attestation/signature),
// then persists the credential on the account record.
//
// Any extra fields in the request body (including a client-supplied "assurance"
// or "level" claim) are silently ignored by the library's JSON parser — the server
// never reads them. AssuranceStrong is assigned because a WebAuthn authenticator
// was cryptographically verified, never from a caller-asserted claim (ADR-021 §D1).
func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	wa := s.getWebAuthn()
	if wa == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"WebAuthn not configured", "WEBAUTHN_NOT_CONFIGURED")
		return
	}

	username := mux.Vars(r)["username"]
	if err := validateWebUsername(username); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_USERNAME")
		return
	}

	acct, err := s.getWebAccount(r.Context(), username)
	if err != nil {
		s.logger.Error("Failed to look up web account for WebAuthn finish",
			"username", logging.SanitizeLogValue(username),
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
		ID:           credential.ID,
		PublicKey:    credential.PublicKey,
		SignCount:    credential.Authenticator.SignCount,
		Transport:    transports,
		Label:        label,
		RegisteredAt: time.Now().UTC(),
	}

	// Re-persist the account with the appended credential. The account loaded above
	// (getWebAccount) already reflects any credentials registered before this call.
	updatedAcct := *acct
	updatedAcct.Credentials = append(append([]WebAuthnCredential(nil), acct.Credentials...), stored)

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	actingPrincipalID := ""
	if principal != nil {
		actingPrincipalID = principal.ID
	}

	if err := s.persistWebAccount(r.Context(), &updatedAcct, actingPrincipalID); err != nil {
		s.logger.Error("Failed to persist WebAuthn credential",
			"username", logging.SanitizeLogValue(username),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to persist credential", "STORE_ERROR")
		return
	}
	s.cacheWebAccount(&updatedAcct)

	s.logger.Info("WebAuthn credential registered",
		"username", logging.SanitizeLogValue(username),
		"label", logging.SanitizeLogValue(label))

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
