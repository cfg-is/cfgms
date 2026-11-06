// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
)

// operatorPayloadSignSession holds state for an in-progress payload-signing ceremony.
// Stored in s.operatorPayloadSignSessions keyed by web session ID. Single-use: taken via
// takePayloadSignSession (LoadAndDelete) at the start of every finish call, regardless of outcome.
type operatorPayloadSignSession struct {
	data      webauthn.SessionData
	expires   time.Time
	accountID string // principal.ID at begin time; finish re-derives this from context
	envelope  operatorpayload.Envelope
	hash      [sha256.Size]byte // operatorpayload.ChallengeHash(envelope); == data.Challenge
}

// signSessionThrottleKey and signIPThrottleKey are the throttle keys checkSignThrottle and
// recordSignFailure use for one finish call.
func signSessionThrottleKey(sessID string) string { return "session:" + sessID }

func signIPThrottleKey(ipKey string) string { return "ip:" + ipKey }

// recordSignFailures counts one failed finish against the session and, when known, the
// client IP.
func (s *Server) recordSignFailures(sessID, ipKey string) {
	s.recordSignFailure(signSessionThrottleKey(sessID))
	if ipKey != "" {
		s.recordSignFailure(signIPThrottleKey(ipKey))
	}
}

// signCountAdvances is the W3C WebAuthn §7.2 step 21 rule: when either count is nonzero the
// response count must strictly exceed the stored one. It runs at ceremony finish only.
func signCountAdvances(stored, response uint32) bool {
	return (stored == 0 && response == 0) || response > stored
}

// storedSignCount returns the sign count the account holds for credID (0 if absent).
func storedSignCount(acct *account, credID []byte) uint32 {
	for _, c := range acct.Credentials {
		if string(c.ID) == string(credID) {
			return c.SignCount
		}
	}
	return 0
}

// withAdvancedSignCount returns a copy of acct with credID's sign count set to count; acct
// itself is left untouched.
func withAdvancedSignCount(acct *account, credID []byte, count uint32) account {
	updated := *acct
	updated.Credentials = make([]WebAuthnCredential, len(acct.Credentials))
	copy(updated.Credentials, acct.Credentials)
	for i, c := range updated.Credentials {
		if string(c.ID) == string(credID) {
			updated.Credentials[i].SignCount = count
			break
		}
	}
	return updated
}

// proofComplete reports whether every field VerifyAssertion needs is present.
func proofComplete(proof *OperatorWebAuthnProof) bool {
	return proof != nil && len(proof.AuthenticatorData) > 0 && len(proof.ClientDataJSON) > 0 &&
		len(proof.Signature) > 0 && len(proof.CredentialID) > 0
}

// registeredCredential returns acct's credential whose ID matches credID (constant-time
// compare), or nil when credID is not registered to acct.
func registeredCredential(acct *account, credID []byte) *WebAuthnCredential {
	for i := range acct.Credentials {
		if subtle.ConstantTimeCompare(acct.Credentials[i].ID, credID) == 1 {
			return &acct.Credentials[i]
		}
	}
	return nil
}

// VerifyAssertion checks a WebAuthn assertion for the given ACCOUNT against the given
// ENVELOPE: signature under the account's registered credential key, challenge equal to
// operatorpayload.ChallengeHash(envelope), origin, rpIdHash, user presence and user
// verification. It returns the matching stored credential.
//
// It performs no expiry check, no caller lookup and no sign-count check. The counter rule
// runs at ceremony finish only (signCountAdvances): the credential counter moves on after
// later sign-ins, and a stored Publication must keep verifying. The account's registered
// credential key is the only key used.
func (s *Server) VerifyAssertion(acct *account, envelope operatorpayload.Envelope, proof *OperatorWebAuthnProof) (*WebAuthnCredential, error) {
	if acct == nil {
		return nil, fmt.Errorf("operator account not found")
	}
	if !proofComplete(proof) {
		return nil, fmt.Errorf("incomplete webauthn operator proof")
	}
	wa := s.getWebAuthn()
	if wa == nil || wa.Config == nil {
		return nil, fmt.Errorf("webauthn is not configured")
	}

	stored := registeredCredential(acct, proof.CredentialID)
	if stored == nil {
		return nil, fmt.Errorf("credential is not registered to the caller")
	}

	hash, err := operatorpayload.ChallengeHash(envelope)
	if err != nil {
		return nil, fmt.Errorf("invalid operator envelope: %w", err)
	}

	b64 := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id":    b64(proof.CredentialID),
		"rawId": b64(proof.CredentialID),
		"type":  "public-key",
		"response": map[string]string{
			"authenticatorData": b64(proof.AuthenticatorData),
			"clientDataJSON":    b64(proof.ClientDataJSON),
			"signature":         b64(proof.Signature),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode assertion: %w", err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, fmt.Errorf("parse webauthn assertion: %w", err)
	}

	// Cross-origin assertions are refused outright, and opaque and top origins are not
	// widened: the same posture the steward-side verifier takes.
	if err := parsed.Verify(b64(hash[:]), wa.Config.RPID, "", wa.Config.RPOrigins, nil, nil,
		protocol.TopOriginImplicitVerificationMode, false, true, true, stored.PublicKey, wa.Config.Signature); err != nil {
		return nil, fmt.Errorf("webauthn assertion verification failed: %w", err)
	}
	return stored, nil
}

// persistAdvancedSignCount stores credID's advanced sign count on acct. It is non-fatal on
// failure: the cryptographic verification already performed is not affected by a
// persistence error. It uses persistAccountCAS, keyed on the version read alongside acct,
// rather than a blind overwrite (Issue #3761, ADR-031 Decision 1): acct's credentials and
// bindings are copied wholesale, so a blind persist would discard any unrelated field a
// concurrent write on a peer node committed since acct was read. A lost CAS race is
// logged and swallowed like any other persist failure; the next successful assertion
// advances the count from whatever the winning write left in place.
func (s *Server) persistAdvancedSignCount(ctx context.Context, acct *account, credID []byte, count uint32, principalID, logPrefix string) {
	updatedAcct := withAdvancedSignCount(acct, credID, count)
	newVersion, ok, err := s.persistAccountCAS(ctx, &updatedAcct, principalID)
	switch {
	case err != nil:
		s.logger.Error(logPrefix+": failed to persist updated sign count",
			"principal_id", logging.SanitizeLogValue(principalID),
			"error", logging.SanitizeLogValue(err.Error()))
	case !ok:
		s.logger.Warn(logPrefix+": sign count persist lost a concurrent-write race, not retried",
			"principal_id", logging.SanitizeLogValue(principalID))
	default:
		updatedAcct.Version = newVersion
		s.cacheAccount(&updatedAcct)
	}
}
