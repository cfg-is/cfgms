// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #4527 (ADR-031): cluster-shared WebAuthn ceremony state and throttles.
//
// In ClusterMode a ceremony's begin and finish can land on different controller nodes,
// so the pending state cannot live in a per-process sync.Map. In ClusterMode the seven
// single-use ceremony stores go through business.NonceStore (PutNonce at begin,
// GetAndConsumeNonce at finish: an atomic cross-node get-and-delete with the TTL
// enforced by the store), and the failed-attempt throttles go through
// business.RateCounterStore. Outside ClusterMode the node-local sync.Maps remain the
// default, matching how SetRateCounterStore is already ClusterMode-only.
//
// Fail closed: in ClusterMode a nil NonceStore or any store error refuses the request
// (503); the node-local map is never used as a fallback, because a ceremony stored
// locally could not be consumed by another node and could be replayed on this one.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/operatorpayload"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Per-ceremony NonceStore key prefixes. Distinct prefixes mean an entry begun by one
// ceremony type can never be consumed by another (a login challenge cannot finish an
// elevation, a presence entry cannot finish a payload-sign ceremony).
const (
	ceremonyPrefixRegister      = "webauthn-ceremony:register:"
	ceremonyPrefixPresence      = "webauthn-ceremony:presence:"
	ceremonyPrefixPresenceToken = "webauthn-ceremony:presence-token:"
	ceremonyPrefixElevate       = "webauthn-ceremony:elevate:"
	ceremonyPrefixPayloadSign   = "webauthn-ceremony:payload-sign:"
	ceremonyPrefixLogin         = "webauthn-ceremony:login:"
	ceremonyPrefixEnroll        = "webauthn-ceremony:enroll:"
)

// RateCounterStore key prefixes for the cluster-shared throttles and the per-client
// passkey-login begin cap.
const (
	elevateThrottleKeyPrefix      = "webauthn-elevate:"
	passkeyLoginThrottleKeyPrefix = "passkey-login:"
	passkeyLoginBeginKeyPrefix    = "passkey-login-begin:"

	// webAuthnThrottleWindow is the fixed window for the shared failure counters. Equal to
	// webAuthnThrottleRecordRetention so the cluster path forgets failures on the same
	// schedule as the node-local one.
	webAuthnThrottleWindow = webAuthnThrottleRecordRetention

	// passkeyLoginBeginWindow is the window over which begin calls per client are counted.
	passkeyLoginBeginWindow = passkeyLoginCeremonyMaxAge * time.Second
)

// Wire structs. webauthn.SessionData and operatorpayload.Envelope are JSON-safe; the
// in-memory types carry unexported fields so each gets an exported-field twin.

type webAuthnPendingWire struct {
	Data    webauthn.SessionData `json:"data"`
	Expires time.Time            `json:"expires"`
	Binding string               `json:"binding"`
}

type passkeyLoginWire struct {
	Data         webauthn.SessionData `json:"data"`
	Expires      time.Time            `json:"expires"`
	AccountID    string               `json:"account_id"`
	Discoverable bool                 `json:"discoverable"`
	ClientKey    string               `json:"client_key"`
}

type presenceTokenWire struct {
	PrincipalID       string    `json:"principal_id"`
	Expires           time.Time `json:"expires"`
	BoundMethod       string    `json:"bound_method"`
	BoundPath         string    `json:"bound_path"`
	BoundBodyHash     string    `json:"bound_body_hash"`
	BoundPermissionID string    `json:"bound_permission_id"`
}

type webAuthnElevateWire struct {
	Data      webauthn.SessionData `json:"data"`
	Expires   time.Time            `json:"expires"`
	AccountID string               `json:"account_id"`
}

type operatorPayloadSignWire struct {
	Data      webauthn.SessionData     `json:"data"`
	Expires   time.Time                `json:"expires"`
	AccountID string                   `json:"account_id"`
	Envelope  operatorpayload.Envelope `json:"envelope"`
	Hash      [32]byte                 `json:"hash"`
}

func (p *webAuthnPendingSession) toWire() webAuthnPendingWire {
	return webAuthnPendingWire{Data: p.data, Expires: p.expires, Binding: p.binding}
}

func (w webAuthnPendingWire) toSession() *webAuthnPendingSession {
	return &webAuthnPendingSession{data: w.Data, expires: w.Expires, binding: w.Binding}
}

func (p *passkeyLoginSession) toWire() passkeyLoginWire {
	return passkeyLoginWire{Data: p.data, Expires: p.expires, AccountID: p.accountID,
		Discoverable: p.discoverable, ClientKey: p.clientKey}
}

func (w passkeyLoginWire) toSession() *passkeyLoginSession {
	return &passkeyLoginSession{data: w.Data, expires: w.Expires, accountID: w.AccountID,
		discoverable: w.Discoverable, clientKey: w.ClientKey}
}

func (p *presenceTokenRecord) toWire() presenceTokenWire {
	return presenceTokenWire{PrincipalID: p.principalID, Expires: p.expires,
		BoundMethod: p.boundMethod, BoundPath: p.boundPath, BoundBodyHash: p.boundBodyHash,
		BoundPermissionID: p.boundPermissionID}
}

func (w presenceTokenWire) toRecord() *presenceTokenRecord {
	return &presenceTokenRecord{principalID: w.PrincipalID, expires: w.Expires,
		boundMethod: w.BoundMethod, boundPath: w.BoundPath, boundBodyHash: w.BoundBodyHash,
		boundPermissionID: w.BoundPermissionID}
}

// ceremonyOutcome is the result of taking a ceremony from the cluster store.
type ceremonyOutcome int

const (
	ceremonyOK          ceremonyOutcome = iota
	ceremonyNotFound                    // absent, already consumed, or expired
	ceremonyUnavailable                 // store unwired or erroring: refuse, response is the caller's 503
)

// webAuthnClusterMode reports whether this node serves a cluster, in which case the
// ceremony state and throttles must be cluster-shared.
func (s *Server) webAuthnClusterMode() bool {
	return s.haManager != nil && s.haManager.GetDeploymentMode() == ha.ClusterMode
}

// ceremonyNonceStore returns the wired NonceStore under the server lock.
func (s *Server) ceremonyNonceStore() business.NonceStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nonceStore
}

// writeCeremonyUnavailable writes the fail-closed response for a ClusterMode request
// that could not reach the shared ceremony store.
func (s *Server) writeCeremonyUnavailable(w http.ResponseWriter) {
	s.writeErrorResponse(w, http.StatusServiceUnavailable,
		"WebAuthn ceremony store unavailable", "WEBAUTHN_CEREMONY_STORE_UNAVAILABLE")
}

// putClusterCeremony stores wire under prefix+id in the shared NonceStore with ttl.
// Callers must have checked webAuthnClusterMode. ceremonyUnavailable means nothing was
// stored and the request must be refused.
func (s *Server) putClusterCeremony(ctx context.Context, prefix, id string, wire any, ttl time.Duration) ceremonyOutcome {
	store := s.ceremonyNonceStore()
	if store == nil {
		s.logger.Error("WebAuthn ceremony store not wired in ClusterMode; refusing begin")
		return ceremonyUnavailable
	}
	entry, err := json.Marshal(wire)
	if err != nil {
		s.logger.Error("Failed to encode WebAuthn ceremony state",
			"error", logging.SanitizeLogValue(err.Error()))
		return ceremonyUnavailable
	}
	if err := store.PutNonce(ctx, prefix+id, entry, ttl); err != nil {
		s.logger.Error("Failed to store WebAuthn ceremony state",
			"error", logging.SanitizeLogValue(err.Error()))
		return ceremonyUnavailable
	}
	return ceremonyOK
}

// takeClusterCeremony atomically consumes prefix+id from the shared NonceStore and
// decodes it into a T. Single use cluster-wide: a second take on any node is
// ceremonyNotFound. The entry is consumed regardless of what the caller does next.
func takeClusterCeremony[T any](s *Server, ctx context.Context, prefix, id string) (*T, ceremonyOutcome) {
	store := s.ceremonyNonceStore()
	if store == nil {
		s.logger.Error("WebAuthn ceremony store not wired in ClusterMode; refusing finish")
		return nil, ceremonyUnavailable
	}
	entry, found, err := store.GetAndConsumeNonce(ctx, prefix+id)
	if err != nil {
		s.logger.Error("Failed to consume WebAuthn ceremony state",
			"error", logging.SanitizeLogValue(err.Error()))
		return nil, ceremonyUnavailable
	}
	if !found {
		return nil, ceremonyNotFound
	}
	var out T
	if err := json.Unmarshal(entry, &out); err != nil {
		// Consumed and unusable: refuse like an absent entry rather than expose detail.
		s.logger.Error("Failed to decode WebAuthn ceremony state",
			"error", logging.SanitizeLogValue(err.Error()))
		return nil, ceremonyNotFound
	}
	return &out, ceremonyOK
}

// --- per-ceremony helpers: route to the cluster store or the node-local map ---

// putPendingSession stores a registration/presence/enrol pending session.
func (s *Server) putPendingSession(ctx context.Context, local interface{ Store(k, v any) }, prefix, id string, sess *webAuthnPendingSession, ttl time.Duration) ceremonyOutcome {
	if s.webAuthnClusterMode() {
		return s.putClusterCeremony(ctx, prefix, id, sess.toWire(), ttl)
	}
	local.Store(id, sess)
	return ceremonyOK
}

// takePendingSession consumes a registration/presence/enrol pending session.
func (s *Server) takePendingSession(ctx context.Context, local interface{ LoadAndDelete(k any) (any, bool) }, prefix, id string) (*webAuthnPendingSession, ceremonyOutcome) {
	if s.webAuthnClusterMode() {
		w, out := takeClusterCeremony[webAuthnPendingWire](s, ctx, prefix, id)
		if out != ceremonyOK {
			return nil, out
		}
		return w.toSession(), ceremonyOK
	}
	raw, ok := local.LoadAndDelete(id)
	if !ok {
		return nil, ceremonyNotFound
	}
	sess, ok := raw.(*webAuthnPendingSession)
	if !ok {
		return nil, ceremonyNotFound
	}
	return sess, ceremonyOK
}

// putPresenceToken stores a minted presence token record keyed by token hash.
func (s *Server) putPresenceToken(ctx context.Context, tokenHash string, rec *presenceTokenRecord) ceremonyOutcome {
	if s.webAuthnClusterMode() {
		return s.putClusterCeremony(ctx, ceremonyPrefixPresenceToken, tokenHash, rec.toWire(), presenceTokenTTL)
	}
	s.presenceTokens.Store(tokenHash, rec)
	return ceremonyOK
}

// takePresenceToken consumes a presence token record (single use, any node).
func (s *Server) takePresenceToken(ctx context.Context, tokenHash string) (*presenceTokenRecord, ceremonyOutcome) {
	if s.webAuthnClusterMode() {
		w, out := takeClusterCeremony[presenceTokenWire](s, ctx, ceremonyPrefixPresenceToken, tokenHash)
		if out != ceremonyOK {
			return nil, out
		}
		return w.toRecord(), ceremonyOK
	}
	raw, ok := s.presenceTokens.LoadAndDelete(tokenHash)
	if !ok {
		return nil, ceremonyNotFound
	}
	rec, ok := raw.(*presenceTokenRecord)
	if !ok {
		return nil, ceremonyNotFound
	}
	return rec, ceremonyOK
}

// discardPresenceToken best-effort removes a just-minted token (persist-failure revert).
func (s *Server) discardPresenceToken(ctx context.Context, tokenHash string) {
	if s.webAuthnClusterMode() {
		if store := s.ceremonyNonceStore(); store != nil {
			_, _, _ = store.GetAndConsumeNonce(ctx, ceremonyPrefixPresenceToken+tokenHash)
		}
		return
	}
	s.presenceTokens.Delete(tokenHash)
}

// putElevateSession stores a step-up ceremony keyed by web session ID.
func (s *Server) putElevateSession(ctx context.Context, sessID string, sess *webAuthnElevateSession) ceremonyOutcome {
	if s.webAuthnClusterMode() {
		return s.putClusterCeremony(ctx, ceremonyPrefixElevate, sessID, webAuthnElevateWire{
			Data: sess.data, Expires: sess.expires, AccountID: sess.accountID}, webAuthnSessionTTL)
	}
	s.webAuthnElevateSessions.Store(sessID, sess)
	return ceremonyOK
}

// takeElevateSession consumes the step-up ceremony for sessID.
func (s *Server) takeElevateSession(ctx context.Context, sessID string) (*webAuthnElevateSession, ceremonyOutcome) {
	if s.webAuthnClusterMode() {
		w, out := takeClusterCeremony[webAuthnElevateWire](s, ctx, ceremonyPrefixElevate, sessID)
		if out != ceremonyOK {
			return nil, out
		}
		return &webAuthnElevateSession{data: w.Data, expires: w.Expires, accountID: w.AccountID}, ceremonyOK
	}
	raw, ok := s.webAuthnElevateSessions.LoadAndDelete(sessID)
	if !ok {
		return nil, ceremonyNotFound
	}
	sess, ok := raw.(*webAuthnElevateSession)
	if !ok {
		return nil, ceremonyNotFound
	}
	return sess, ceremonyOK
}

// putPayloadSignSession stores an operator-payload sign ceremony keyed by web session ID.
func (s *Server) putPayloadSignSession(ctx context.Context, sessID string, sess *operatorPayloadSignSession) ceremonyOutcome {
	if s.webAuthnClusterMode() {
		return s.putClusterCeremony(ctx, ceremonyPrefixPayloadSign, sessID, operatorPayloadSignWire{
			Data: sess.data, Expires: sess.expires, AccountID: sess.accountID,
			Envelope: sess.envelope, Hash: sess.hash}, webAuthnSessionTTL)
	}
	s.operatorPayloadSignSessions.Store(sessID, sess)
	return ceremonyOK
}

// takePayloadSignSession consumes the sign ceremony for sessID.
func (s *Server) takePayloadSignSession(ctx context.Context, sessID string) (*operatorPayloadSignSession, ceremonyOutcome) {
	if s.webAuthnClusterMode() {
		w, out := takeClusterCeremony[operatorPayloadSignWire](s, ctx, ceremonyPrefixPayloadSign, sessID)
		if out != ceremonyOK {
			return nil, out
		}
		return &operatorPayloadSignSession{data: w.Data, expires: w.Expires, accountID: w.AccountID,
			envelope: w.Envelope, hash: w.Hash}, ceremonyOK
	}
	raw, ok := s.operatorPayloadSignSessions.LoadAndDelete(sessID)
	if !ok {
		return nil, ceremonyNotFound
	}
	sess, ok := raw.(*operatorPayloadSignSession)
	if !ok {
		return nil, ceremonyNotFound
	}
	return sess, ceremonyOK
}

// --- cluster-shared throttles ---

// throttleBlocked reports whether key is throttled. In ClusterMode the shared failure
// count is consulted first; whenever it does not itself block (miss, count below the
// first backoff tier, or a Peek error) the node-local record in m is read, because
// recordThrottleFailure writes there exactly when the shared counter could not take the
// failure. Same shape as checkSignThrottle.
func (s *Server) throttleBlocked(m *sync.Map, prefix, key string) (blocked bool, retryAfter time.Duration) {
	if s.webAuthnClusterMode() && s.rateCounterStore != nil {
		count, windowRemaining, found, err := s.rateCounterStore.Peek(
			context.Background(), prefix+key, webAuthnThrottleWindow)
		if err == nil && found {
			if delay := elevateBackoff(count); delay > 0 {
				if windowRemaining < delay {
					return true, windowRemaining
				}
				return true, delay
			}
		}
	}

	raw, ok := m.Load(key)
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

// recordThrottleFailure records one failed attempt against key. In ClusterMode it goes
// to the shared counter so failures spread across nodes accumulate into one count. When
// the store declines the key at its capacity backstop the key is denied (a node-local
// record at the longest cooldown tier); any other store error falls back to the
// ordinary node-local record, as recordSignFailure does.
func (s *Server) recordThrottleFailure(m *sync.Map, prefix, key string) {
	exhausted := false
	if s.webAuthnClusterMode() && s.rateCounterStore != nil {
		_, _, err := s.rateCounterStore.Increment(context.Background(), prefix+key, webAuthnThrottleWindow)
		if err == nil {
			return
		}
		exhausted = errors.Is(err, business.ErrRateCounterCapacityExhausted)
	}

	raw, _ := m.LoadOrStore(key, &elevateThrottleRecord{})
	rec := raw.(*elevateThrottleRecord)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.fails++
	rec.lastFailure = time.Now()
	if exhausted {
		rec.fails = max(rec.fails, webAuthnThrottleDenyFails)
	}
	if delay := elevateBackoff(rec.fails); delay > 0 {
		rec.nextAllowed = time.Now().Add(delay)
	}
}

// webAuthnThrottleDenyFails is a failure count in elevateBackoff's longest tier.
const webAuthnThrottleDenyFails = 12

// reservePasskeyLoginBegin counts one begin for clientKey, and one globally, in the
// shared RateCounterStore over passkeyLoginBeginWindow. Issue #4527: in ClusterMode the
// node-local "currently pending" gauge cannot be released by a finish on another node,
// so the cap becomes "begun in the window" — a deliberate semantic change; the limits
// are unchanged. Returns the capped result, or passkeyLoginStored when within limits.
// A store error (including capacity exhaustion) refuses the begin.
func (s *Server) reservePasskeyLoginBegin(clientKey string) (passkeyLoginStoreResult, error) {
	if s.rateCounterStore == nil {
		return passkeyLoginStored, errCeremonyCounterUnavailable
	}
	ctx := context.Background()
	if clientKey != "" {
		n, _, err := s.rateCounterStore.Increment(ctx, passkeyLoginBeginKeyPrefix+"client:"+clientKey, passkeyLoginBeginWindow)
		if err != nil {
			return passkeyLoginStored, err
		}
		if int64(n) > s.passkeyLoginSessionClientCapacity() {
			return passkeyLoginStoreClientCapped, nil
		}
	}
	n, _, err := s.rateCounterStore.Increment(ctx, passkeyLoginBeginKeyPrefix+"global", passkeyLoginBeginWindow)
	if err != nil {
		return passkeyLoginStored, err
	}
	if int64(n) > s.passkeyLoginSessionCapacity() {
		return passkeyLoginStoreGlobalCapped, nil
	}
	return passkeyLoginStored, nil
}

var errCeremonyCounterUnavailable = errors.New("rate counter store not wired")
