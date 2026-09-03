// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #3695: WebAuthn operator-payload signing — lets a browser-only operator (no mTLS
// bundle) sign an operatorpayload.Envelope (ADR-021 Amendment 2 cross-reference).
//
// Routes (operator-payload:sign permission, AssuranceStrong minimum):
//
//	POST /api/v1/operator-payload/sign/begin
//	     Resolves Targets via the same tenant-scoped selector resolution as
//	     POST /api/v1/fleet/resolve, builds the Envelope (server fills Nonce + ExpiresAt),
//	     computes sha256(operatorpayload.CanonicalBytes(envelope)), and issues a WebAuthn
//	     assertion challenge equal to that hash — so a successful assertion is a signature
//	     over the exact envelope, not an unrelated proof-of-presence value.
//
//	POST /api/v1/operator-payload/sign/finish
//	     Verifies the authenticator assertion against the server-stored envelope/challenge,
//	     applying the same single-use-session and sign-count-advancement discipline as
//	     handleStepUpFinish (handlers_webauthn_elevate.go), and returns the signed envelope:
//	     the envelope, its hash, and the raw assertion (authenticatorData, clientDataJSON,
//	     signature, credential ID).
//
// This is a distinct operation from step-up elevation: it never changes a session's
// assurance level, and it never dispatches or executes anything — it only produces a
// signed envelope for a caller (S8, out of scope here) to submit for execution.
//
// Security properties enforced here (mirroring handlers_webauthn_elevate.go):
//   - Session bound: the pending ceremony is keyed by web session ID, never by account or
//     username, so a second concurrent browser tab cannot consume another tab's ceremony.
//   - Server-side credential resolution: the account is loaded from context principal ID —
//     never from a client-supplied username or credential hint. A forged assertion signed
//     by a WebAuthn key not registered to the authenticated caller's own account is rejected
//     because ValidateLogin only trusts credentials already stored on that account.
//   - Single-use challenge: the sign session is deleted (LoadAndDelete) at the start of
//     every finish call, preventing replay of a captured begin response.
//   - Sign-count advancement: if either the stored or response sign count is nonzero, the
//     response count must strictly exceed the stored count (W3C WebAuthn §7.2 step 21).
//   - Per-session and per-IP throttle with backoff (no hard lockout), reusing
//     elevateBackoff's schedule.
//   - Nonce generation is crypto/rand only (generateOperatorPayloadSignNonce) — never a
//     counter, timestamp, or UUID — so two begin calls for an otherwise-identical envelope
//     always produce different challenges.
package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// operatorPayloadSignNonceBytes is the raw byte length of the server-generated nonce
// (Issue #3695 AC): read from crypto/rand at the call site in
// generateOperatorPayloadSignNonce below, never a counter/timestamp/UUID. 32 bytes matches
// protocol.CreateChallenge's own randomness budget and comfortably exceeds the 16-byte AC floor.
const operatorPayloadSignNonceBytes = 32

// operatorPayloadSignExpiryTTL bounds how long a signed envelope remains valid for a
// downstream execution consumer (S8) to submit. Independent of webAuthnSessionTTL, which
// bounds the pending *ceremony* (begin→finish) instead.
const operatorPayloadSignExpiryTTL = 5 * time.Minute

// operatorPayloadSignSession holds state for an in-progress payload-signing ceremony.
// Stored in s.operatorPayloadSignSessions keyed by web session ID. Single-use: deleted via
// LoadAndDelete at the start of handleOperatorPayloadSignFinish regardless of outcome.
type operatorPayloadSignSession struct {
	data      webauthn.SessionData
	expires   time.Time
	accountID string // principal.ID at begin time; finish re-derives this from context
	envelope  operatorpayload.Envelope
	hash      [sha256.Size]byte // sha256(operatorpayload.CanonicalBytes(envelope)); == data.Challenge
}

// generateOperatorPayloadSignNonce returns a hex-encoded nonce read directly from
// crypto/rand — never a counter, timestamp, or UUID (Issue #3695 AC: asserted directly
// against this call site by TestGenerateOperatorPayloadSignNonce_SourceUsesCryptoRand).
func generateOperatorPayloadSignNonce() (string, error) {
	buf := make([]byte, operatorPayloadSignNonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// OperatorPayloadSignBeginRequest is the JSON body for POST /api/v1/operator-payload/sign/begin.
type OperatorPayloadSignBeginRequest struct {
	// Selector is a pkg/fleet/selector expression resolved server-side into the frozen
	// Envelope.Targets list — never accepted as a pre-resolved target list from the client.
	Selector string `json:"selector"`
	Content  []byte `json:"content"`
	Shell    string `json:"shell"`
}

// OperatorPayloadSignedEnvelope is the JSON view of an operatorpayload.Envelope returned to
// the caller — identical field set to what was hashed into the WebAuthn challenge.
type OperatorPayloadSignedEnvelope struct {
	Content   []byte    `json:"content"`
	Shell     string    `json:"shell"`
	Targets   []string  `json:"targets"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

func toSignedEnvelopeView(e operatorpayload.Envelope) OperatorPayloadSignedEnvelope {
	return OperatorPayloadSignedEnvelope{
		Content:   e.Content,
		Shell:     e.Shell,
		Targets:   e.Targets,
		Nonce:     e.Nonce,
		ExpiresAt: e.ExpiresAt,
	}
}

// OperatorPayloadSignBeginResponse is the JSON response from POST /api/v1/operator-payload/sign/begin.
type OperatorPayloadSignBeginResponse struct {
	Assertion    *protocol.CredentialAssertion `json:"assertion"`
	Envelope     OperatorPayloadSignedEnvelope `json:"envelope"`
	EnvelopeHash string                        `json:"envelope_hash"` // hex sha256(CanonicalBytes(envelope)); == assertion.publicKey.challenge
}

// OperatorPayloadSignFinishResponse is the JSON response from POST /api/v1/operator-payload/sign/finish.
type OperatorPayloadSignFinishResponse struct {
	Envelope     OperatorPayloadSignedEnvelope `json:"envelope"`
	EnvelopeHash string                        `json:"envelope_hash"`
	// Raw assertion fields (Issue #3695 AC) — the caller needs these to hand the signed
	// envelope to a downstream execution consumer (S8) that verifies the assertion itself.
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
	CredentialID      []byte `json:"credential_id"`
}

// handleOperatorPayloadSignBegin handles POST /api/v1/operator-payload/sign/begin.
//
// Resolves req.Selector to a frozen Targets list via the same tenant-scoped resolution as
// handleResolveSelector (resolveSelectorFilter), builds the Envelope with a server-generated
// Nonce and ExpiresAt, and issues a WebAuthn assertion challenge equal to
// sha256(operatorpayload.CanonicalBytes(envelope)) — so finishing the ceremony proves
// possession of a registered WebAuthn key AND signs this exact envelope in one step.
//
// Gated by the "operator-payload:sign" permission (requirePermission, registered by Issue
// #3687 at {Min: session.AssuranceStrong}) before this handler ever runs.
func (s *Server) handleOperatorPayloadSignBegin(w http.ResponseWriter, r *http.Request) {

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

	sessID, _ := r.Context().Value(webSessionIDContextKey).(string)
	if sessID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Operator-payload signing requires a cookie-authenticated web session", "SESSION_REQUIRED")
		return
	}

	acct, err := s.getAccount(r.Context(), principal.ID)
	if err != nil {
		s.logger.Error("Operator-payload sign begin: failed to load account",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to load account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound,
			"Account not found", "ACCOUNT_NOT_FOUND")
		return
	}
	if len(acct.Credentials) == 0 {
		s.writeErrorResponse(w, http.StatusConflict,
			"No WebAuthn credentials registered — enroll a passkey first", "NO_CREDENTIALS")
		return
	}

	var req OperatorPayloadSignBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}
	if len(req.Content) == 0 {
		s.writeErrorResponse(w, http.StatusBadRequest, "content is required", "MISSING_CONTENT")
		return
	}
	if req.Shell == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "shell is required", "MISSING_SHELL")
		return
	}

	filter, rerr := s.resolveSelectorFilter(r.Context(), req.Selector)
	if rerr != nil {
		s.writeErrorResponse(w, rerr.status, rerr.message, rerr.code)
		return
	}

	results, err := s.fleetQuery.Search(r.Context(), filter)
	if err != nil {
		s.logger.Error("Operator-payload sign begin: fleet query failed",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to resolve targets", "INTERNAL_ERROR")
		return
	}
	if len(results) == 0 {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"selector matched no stewards", "NO_TARGETS_MATCHED")
		return
	}
	targets := make([]string, 0, len(results))
	for _, res := range results {
		targets = append(targets, res.ID)
	}

	nonce, err := generateOperatorPayloadSignNonce()
	if err != nil {
		s.logger.Error("Operator-payload sign begin: nonce generation failed",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to generate nonce", "NONCE_ERROR")
		return
	}

	envelope := operatorpayload.Envelope{
		Content:   req.Content,
		Shell:     req.Shell,
		Targets:   targets,
		Nonce:     nonce,
		ExpiresAt: time.Now().Add(operatorPayloadSignExpiryTTL),
	}

	canonical, err := operatorpayload.CanonicalBytes(envelope)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_ENVELOPE")
		return
	}
	hash := sha256.Sum256(canonical)

	user := buildWebauthnUser(acct)

	assertion, sessionData, err := wa.BeginLogin(user,
		webauthn.WithUserVerification(protocol.VerificationRequired),
		webauthn.WithChallenge(hash[:]))
	if err != nil {
		s.logger.Error("Operator-payload sign begin: BeginLogin failed",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to begin sign ceremony", "WEBAUTHN_BEGIN_ERROR")
		return
	}

	s.operatorPayloadSignSessions.Store(sessID, &operatorPayloadSignSession{
		data:      *sessionData,
		expires:   time.Now().Add(webAuthnSessionTTL),
		accountID: principal.ID,
		envelope:  envelope,
		hash:      hash,
	})

	s.logger.Info("WebAuthn operator-payload sign ceremony started",
		"principal_id", logging.SanitizeLogValue(principal.ID),
		"session_id", logging.SanitizeLogValue(sessID),
		"target_count", len(targets))

	s.writeResponse(w, http.StatusOK, OperatorPayloadSignBeginResponse{
		Assertion:    assertion,
		Envelope:     toSignedEnvelopeView(envelope),
		EnvelopeHash: hex.EncodeToString(hash[:]),
	})
}

// handleOperatorPayloadSignFinish handles POST /api/v1/operator-payload/sign/finish.
//
// Verifies the authenticator assertion response against the server-stored envelope/challenge
// using the same single-use-session and sign-count-advancement discipline as
// handleStepUpFinish, then returns the signed envelope alongside the raw assertion fields.
//
// A per-session and per-IP throttle with exponential backoff guards against brute-force
// attempts, reusing elevateBackoff's schedule via s.operatorPayloadSignThrottle.
func (s *Server) handleOperatorPayloadSignFinish(w http.ResponseWriter, r *http.Request) {

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

	sessID, _ := r.Context().Value(webSessionIDContextKey).(string)
	if sessID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Operator-payload signing requires a cookie-authenticated web session", "SESSION_REQUIRED")
		return
	}

	acct, err := s.getAccount(r.Context(), principal.ID)
	if err != nil {
		s.logger.Error("Operator-payload sign finish: failed to load account",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Failed to load account", "STORE_ERROR")
		return
	}
	if acct == nil {
		s.writeErrorResponse(w, http.StatusNotFound,
			"Account not found", "ACCOUNT_NOT_FOUND")
		return
	}

	// Load and unconditionally delete the pending session (single-use enforcement).
	rawSession, ok := s.operatorPayloadSignSessions.LoadAndDelete(sessID)
	if !ok {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"No active sign session — call begin first", "NO_ACTIVE_SIGN_SESSION")
		return
	}
	pending, ok := rawSession.(*operatorPayloadSignSession)
	if !ok {
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Invalid session state", "SESSION_STATE_ERROR")
		return
	}
	if time.Now().After(pending.expires) {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"Sign session expired — restart with begin", "SESSION_EXPIRED")
		return
	}

	sourceIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	if blocked, wait := s.checkSignThrottle("session:" + sessID); blocked {
		s.logger.Warn("Operator-payload sign finish: per-session throttle active",
			"session_id", logging.SanitizeLogValue(sessID),
			"retry_after_seconds", int(wait.Seconds()))
		s.writeErrorResponse(w, http.StatusTooManyRequests,
			"Too many failed attempts — try again later", "THROTTLED")
		return
	}
	if sourceIP != "" {
		if blocked, wait := s.checkSignThrottle("ip:" + sourceIP); blocked {
			s.logger.Warn("Operator-payload sign finish: per-IP throttle active",
				"source_ip", logging.SanitizeLogValue(sourceIP),
				"retry_after_seconds", int(wait.Seconds()))
			s.writeErrorResponse(w, http.StatusTooManyRequests,
				"Too many failed attempts — try again later", "THROTTLED")
			return
		}
	}

	user := buildWebauthnUser(acct)

	body, err := readAllAndClose(r)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to read request body", "INVALID_BODY")
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		s.logger.Warn("Operator-payload sign finish: failed to parse assertion",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"session_id", logging.SanitizeLogValue(sessID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.recordSignFailure("session:" + sessID)
		if sourceIP != "" {
			s.recordSignFailure("ip:" + sourceIP)
		}
		s.writeErrorResponse(w, http.StatusBadRequest,
			"WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return
	}

	// Full server-side assertion verification: challenge (against the server-stored session
	// value, never the client-echoed field), origin, RP-ID, and ECDSA/RS256 signature. Only
	// credentials already stored on this account (server-resolved via principal.ID) are
	// trusted, so an assertion signed by a key not registered to the caller is rejected here
	// regardless of how plausible the accompanying envelope looks.
	credential, err := wa.ValidateLogin(user, pending.data, parsedResponse)
	if err != nil {
		s.logger.Warn("Operator-payload sign finish: assertion verification failed",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"session_id", logging.SanitizeLogValue(sessID),
			"source_ip", logging.SanitizeLogValue(sourceIP),
			"error", logging.SanitizeLogValue(err.Error()))
		s.recordSignFailure("session:" + sessID)
		if sourceIP != "" {
			s.recordSignFailure("ip:" + sourceIP)
		}
		s.writeErrorResponse(w, http.StatusBadRequest,
			"WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return
	}

	// Sign-count advancement check (W3C WebAuthn §7.2 step 21) — identical discipline to
	// handleStepUpFinish.
	newSignCount := credential.Authenticator.SignCount
	var storedSignCount uint32
	for _, c := range acct.Credentials {
		if string(c.ID) == string(credential.ID) {
			storedSignCount = c.SignCount
			break
		}
	}
	if (storedSignCount > 0 || newSignCount > 0) && newSignCount <= storedSignCount {
		s.logger.Warn("Operator-payload sign finish: sign count not advancing — potential authenticator clone",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"session_id", logging.SanitizeLogValue(sessID),
			"stored_count", storedSignCount,
			"response_count", newSignCount)
		s.recordSignFailure("session:" + sessID)
		if sourceIP != "" {
			s.recordSignFailure("ip:" + sourceIP)
		}
		s.writeErrorResponse(w, http.StatusBadRequest,
			"WebAuthn verification failed", "WEBAUTHN_VERIFY_ERROR")
		return
	}

	// Persist the advanced sign count. Non-fatal on failure: the cryptographic verification
	// already performed is not affected by a persistence error. Uses persistAccountCAS,
	// keyed on the version read alongside acct above, rather than a blind overwrite
	// (Issue #3761, ADR-031 Decision 1): acct.Credentials/CertBindings/etc. are copied
	// wholesale into updatedAcct, so a blind persistAccount here would silently discard
	// any unrelated field a concurrent write on a peer node — e.g. a cert bind or a
	// different credential's own sign-count advance — committed between this handler's
	// getAccount read and this persist. A lost CAS race is logged and swallowed exactly
	// like any other persist failure here; the next successful assertion advances the
	// count from whatever the winning write left in place.
	updatedAcct := *acct
	updatedAcct.Credentials = make([]WebAuthnCredential, len(acct.Credentials))
	copy(updatedAcct.Credentials, acct.Credentials)
	for i, c := range updatedAcct.Credentials {
		if string(c.ID) == string(credential.ID) {
			updatedAcct.Credentials[i].SignCount = newSignCount
			break
		}
	}
	if newVersion, ok, persistErr := s.persistAccountCAS(r.Context(), &updatedAcct, principal.ID); persistErr != nil {
		s.logger.Error("Operator-payload sign finish: failed to persist updated sign count",
			"principal_id", logging.SanitizeLogValue(principal.ID),
			"error", logging.SanitizeLogValue(persistErr.Error()))
	} else if !ok {
		s.logger.Warn("Operator-payload sign finish: sign count persist lost a concurrent-write race, not retried",
			"principal_id", logging.SanitizeLogValue(principal.ID))
	} else {
		updatedAcct.Version = newVersion
		s.cacheAccount(&updatedAcct)
	}

	s.logger.Info("WebAuthn operator-payload sign successful",
		"principal_id", logging.SanitizeLogValue(principal.ID),
		"session_id", logging.SanitizeLogValue(sessID),
		"credential_id", logging.SanitizeLogValue(string(credential.ID)),
		"source_ip", logging.SanitizeLogValue(sourceIP))

	s.writeResponse(w, http.StatusOK, OperatorPayloadSignFinishResponse{
		Envelope:          toSignedEnvelopeView(pending.envelope),
		EnvelopeHash:      hex.EncodeToString(pending.hash[:]),
		AuthenticatorData: []byte(parsedResponse.Raw.AssertionResponse.AuthenticatorData),
		ClientDataJSON:    []byte(parsedResponse.Raw.AssertionResponse.ClientDataJSON),
		Signature:         []byte(parsedResponse.Raw.AssertionResponse.Signature),
		CredentialID:      parsedResponse.RawID,
	})
}

// checkSignThrottle returns (true, retryAfter) when key is currently throttled, or
// (false, 0) when the call may proceed. Thread-safe. Mirrors checkElevateThrottle but reads
// s.operatorPayloadSignThrottle so the two ceremonies' failure counters never collide.
func (s *Server) checkSignThrottle(key string) (blocked bool, retryAfter time.Duration) {
	raw, ok := s.operatorPayloadSignThrottle.Load(key)
	if !ok {
		return false, 0
	}
	rec, ok := raw.(*elevateThrottleRecord)
	if !ok {
		return false, 0
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !rec.nextAllowed.IsZero() && time.Now().Before(rec.nextAllowed) {
		return true, time.Until(rec.nextAllowed)
	}
	return false, 0
}

// recordSignFailure increments the failure counter for key and sets the next-allowed
// timestamp via elevateBackoff. Mirrors recordElevateFailure but reads
// s.operatorPayloadSignThrottle.
//
// The failure count consulted against the backoff schedule is scaled by
// clusterBudgetDivisor (Issue #3761): this throttle's counter lives in per-process
// memory, so in ClusterMode an attacker's failed attempts can spread across nodes
// and each node's own count would undercount the fleet-wide total. Scaling the
// count up before consulting elevateBackoff makes the configured schedule apply to
// the fleet as a whole rather than to whichever single node happened to observe the
// failure — the same approximation clusterBudgetDivisor's doc comment describes for
// the source rate limiters.
func (s *Server) recordSignFailure(key string) {
	raw, _ := s.operatorPayloadSignThrottle.LoadOrStore(key, &elevateThrottleRecord{})
	rec := raw.(*elevateThrottleRecord)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.fails++
	delay := elevateBackoff(rec.fails * s.clusterBudgetDivisor())
	if delay > 0 {
		rec.nextAllowed = time.Now().Add(delay)
	}
}

// readAllAndClose reads the full request body and closes it, matching
// protocol.ParseCredentialRequestResponse's own drain-and-close contract so the raw bytes
// remain available for our own parse (protocol.ParseCredentialRequestResponseBytes) via
// wa.ValidateLogin instead of wa.FinishLogin — needed to recover the raw assertion fields
// (authenticatorData, clientDataJSON, signature) for the finish response.
func readAllAndClose(r *http.Request) ([]byte, error) {
	defer func() { _ = r.Body.Close() }()
	return io.ReadAll(r.Body)
}
