// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #4572: bounds the in-memory WebAuthn ceremony and throttle state held on the
// API server. Pending ceremonies are only removed when the ceremony finishes, so an
// abandoned one would otherwise stay in memory for the life of the process. A periodic
// sweep reaps expired entries from every ceremony and throttle map, and pending passkey
// login ceremonies — which can be started before authentication — are hard-capped.
package api

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	// webAuthnCeremonySweepInterval is how often expired ceremony and throttle entries
	// are reaped. Every ceremony TTL is minutes long, so a one-minute cadence keeps the
	// retained-after-expiry window small without measurable cost.
	webAuthnCeremonySweepInterval = time.Minute

	// maxPendingPasskeyLoginSessions caps concurrent pending passkey login ceremonies.
	// Begin is reachable before authentication, so without a cap an unauthenticated
	// caller could grow s.passkeyLoginSessions without limit inside the 5-minute
	// ceremony TTL. 10000 is far above any legitimate concurrent-login volume for one
	// controller node while bounding the map to a few megabytes.
	maxPendingPasskeyLoginSessions = 10000

	// maxPendingPasskeyLoginSessionsPerClient caps pending passkey login ceremonies per
	// client (s.clientIPKey: trusted-proxy aware, IPv6 bucketed by /64). Checked before
	// the global cap, so one client cannot hold more than this many global slots and
	// cannot by itself fill maxPendingPasskeyLoginSessions to lock real users out. 20
	// leaves room for a shared NAT with several people signing in at once.
	maxPendingPasskeyLoginSessionsPerClient = 20

	// webAuthnThrottleRecordRetention is how long a failure-throttle record is retained
	// after its most recent failure. Sized to exceed elevateBackoff's longest cooldown
	// tier (10 minutes) so a record cannot be swept while it is still blocking, and
	// matching operatorPayloadSignThrottleWindow so a caller cannot outlast the window
	// mid-schedule to reset back to an unthrottled count.
	webAuthnThrottleRecordRetention = 15 * time.Minute
)

// passkeyLoginSessionCapacity returns the effective pending-ceremony cap. A zero
// s.passkeyLoginSessionCap (the default, and any *Server literal built in tests)
// means maxPendingPasskeyLoginSessions; tests shrink it to exercise the cap.
func (s *Server) passkeyLoginSessionCapacity() int64 {
	if s.passkeyLoginSessionCap > 0 {
		return int64(s.passkeyLoginSessionCap)
	}
	return maxPendingPasskeyLoginSessions
}

// passkeyLoginSessionClientCapacity returns the effective per-client pending cap. Zero
// s.passkeyLoginSessionClientCap means maxPendingPasskeyLoginSessionsPerClient.
func (s *Server) passkeyLoginSessionClientCapacity() int64 {
	if s.passkeyLoginSessionClientCap > 0 {
		return int64(s.passkeyLoginSessionClientCap)
	}
	return maxPendingPasskeyLoginSessionsPerClient
}

// passkeyLoginStoreResult is the outcome of storePasskeyLoginSession.
type passkeyLoginStoreResult int

const (
	passkeyLoginStored            passkeyLoginStoreResult = iota
	passkeyLoginStoreClientCapped                         // sess.clientKey is at its per-client cap
	passkeyLoginStoreGlobalCapped                         // the global pending cap is reached
	passkeyLoginStoreUnavailable                          // ClusterMode: shared store unwired or erroring; nothing stored
)

// storePasskeyLoginSession reserves a per-client slot (keyed by sess.clientKey) and
// then a global slot, and stores sess under ceremonyID. Storing nothing, it returns
// passkeyLoginStoreClientCapped or passkeyLoginStoreGlobalCapped when either cap is
// reached; a refused global reservation gives the per-client slot back.
//
// In ClusterMode (Issue #4527) the session goes to the shared NonceStore and the caps
// are counted on the shared RateCounterStore as begins per passkeyLoginBeginWindow
// rather than concurrently pending sessions: a finish on another node cannot release a
// node-local gauge. This is a deliberate semantic change, with unchanged limits. The
// store failing, or being unwired, refuses the begin (passkeyLoginStoreUnavailable).
func (s *Server) storePasskeyLoginSession(ctx context.Context, ceremonyID string, sess *passkeyLoginSession) passkeyLoginStoreResult {
	if s.webAuthnClusterMode() {
		res, err := s.reservePasskeyLoginBegin(sess.clientKey)
		if err != nil {
			s.logger.Error("Passkey login begin cap unavailable",
				"error", logging.SanitizeLogValue(err.Error()))
			return passkeyLoginStoreUnavailable
		}
		if res != passkeyLoginStored {
			return res
		}
		if s.putClusterCeremony(ctx, ceremonyPrefixLogin, ceremonyID, sess.toWire(),
			passkeyLoginCeremonyMaxAge*time.Second) != ceremonyOK {
			return passkeyLoginStoreUnavailable
		}
		return passkeyLoginStored
	}
	if sess.clientKey != "" {
		raw, _ := s.passkeyLoginPendingByClient.LoadOrStore(sess.clientKey, new(atomic.Int64))
		slot := raw.(*atomic.Int64)
		if !reservePendingSlot(slot, s.passkeyLoginSessionClientCapacity()) {
			return passkeyLoginStoreClientCapped
		}
		// The session keeps the counter it reserved on, so its release always lands on
		// that counter even if the sweep has since dropped a zeroed map entry and a
		// later begin created a fresh one for the same client.
		sess.clientSlot = slot
	}
	if !reservePendingSlot(&s.passkeyLoginPending, s.passkeyLoginSessionCapacity()) {
		if sess.clientSlot != nil {
			releasePendingSlot(sess.clientSlot)
			sess.clientSlot = nil
		}
		return passkeyLoginStoreGlobalCapped
	}
	s.passkeyLoginSessions.Store(ceremonyID, sess)
	return passkeyLoginStored
}

// takePasskeyLoginSession removes and returns the pending ceremony for ceremonyID,
// releasing its slots. Single-use: a second call for the same ID, on any node in
// ClusterMode, returns ceremonyNotFound.
func (s *Server) takePasskeyLoginSession(ctx context.Context, ceremonyID string) (*passkeyLoginSession, ceremonyOutcome) {
	if s.webAuthnClusterMode() {
		w, out := takeClusterCeremony[passkeyLoginWire](s, ctx, ceremonyPrefixLogin, ceremonyID)
		if out != ceremonyOK {
			return nil, out
		}
		return w.toSession(), ceremonyOK
	}
	raw, ok := s.passkeyLoginSessions.LoadAndDelete(ceremonyID)
	if !ok {
		return nil, ceremonyNotFound
	}
	s.releasePasskeyLoginSlots(raw)
	sess, ok := raw.(*passkeyLoginSession)
	if !ok {
		return nil, ceremonyNotFound
	}
	return sess, ceremonyOK
}

// releasePasskeyLoginSlots releases the global slot and, when one was reserved, the
// per-client slot held by a removed s.passkeyLoginSessions value.
func (s *Server) releasePasskeyLoginSlots(value any) {
	releasePendingSlot(&s.passkeyLoginPending)
	if sess, ok := value.(*passkeyLoginSession); ok && sess.clientSlot != nil {
		releasePendingSlot(sess.clientSlot)
	}
}

// reservePendingSlot increments counter unless it has already reached limit.
func reservePendingSlot(counter *atomic.Int64, limit int64) bool {
	for {
		n := counter.Load()
		if n >= limit {
			return false
		}
		if counter.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// releasePendingSlot decrements counter, never below zero. Tests inject sessions
// directly into s.passkeyLoginSessions without reserving a slot; clamping keeps their
// later removal from driving the counter negative and loosening the cap.
func releasePendingSlot(counter *atomic.Int64) {
	for {
		n := counter.Load()
		if n <= 0 {
			return
		}
		if counter.CompareAndSwap(n, n-1) {
			return
		}
	}
}

// startWebAuthnCeremonySweep starts the background sweep goroutine. Mirrors
// startCliLoginRequestSweep's stop/done channel shape with its own dedicated pair.
// Unlike that sweep it holds no cluster-singleton lease: the maps it reaps are
// per-process memory, so every node must sweep its own.
func (s *Server) startWebAuthnCeremonySweep() {
	go func() {
		defer close(s.webAuthnCeremonySweepDone)
		ticker := time.NewTicker(webAuthnCeremonySweepInterval)
		defer ticker.Stop()

		s.logger.Info("Started WebAuthn ceremony expiry sweep", "interval", webAuthnCeremonySweepInterval)

		for {
			select {
			case <-s.stopWebAuthnCeremonySweep:
				return
			case <-ticker.C:
				s.sweepExpiredWebAuthnCeremonies(time.Now())
			}
		}
	}()
}

// sweepExpiredWebAuthnCeremonies deletes every node-local ceremony, presence-token and
// throttle entry whose validity has passed as of now. In ClusterMode the state lives in
// the shared stores, which enforce their own TTL, so these maps stay empty there. Entries are removed with CompareAndDelete
// so one that a concurrent begin replaced under the same key is never reaped.
func (s *Server) sweepExpiredWebAuthnCeremonies(now time.Time) {
	sweepExpired(&s.webAuthnSessions, now, pendingSessionExpiry, nil)
	sweepExpired(&s.webAuthnPresenceSessions, now, pendingSessionExpiry, nil)
	sweepExpired(&s.passkeyEnrollSessions, now, pendingSessionExpiry, nil)
	sweepExpired(&s.presenceTokens, now, func(v any) (time.Time, bool) {
		rec, ok := v.(*presenceTokenRecord)
		if !ok {
			return time.Time{}, false
		}
		return rec.expires, true
	}, nil)
	sweepExpired(&s.webAuthnElevateSessions, now, func(v any) (time.Time, bool) {
		sess, ok := v.(*webAuthnElevateSession)
		if !ok {
			return time.Time{}, false
		}
		return sess.expires, true
	}, nil)
	sweepExpired(&s.operatorPayloadSignSessions, now, func(v any) (time.Time, bool) {
		sess, ok := v.(*operatorPayloadSignSession)
		if !ok {
			return time.Time{}, false
		}
		return sess.expires, true
	}, nil)
	sweepExpired(&s.passkeyLoginSessions, now, func(v any) (time.Time, bool) {
		sess, ok := v.(*passkeyLoginSession)
		if !ok {
			return time.Time{}, false
		}
		return sess.expires, true
	}, s.releasePasskeyLoginSlots)
	sweepZeroedClientCounters(&s.passkeyLoginPendingByClient)

	sweepExpired(&s.webAuthnElevateThrottle, now, throttleRecordExpiry, nil)
	sweepExpired(&s.operatorPayloadSignThrottle, now, throttleRecordExpiry, nil)
	sweepExpired(&s.passkeyLoginThrottle, now, throttleRecordExpiry, nil)
}

// sweepExpired deletes each entry of m whose expiry (per expiryOf) is before now,
// calling onDelete with the value of each entry actually removed. An entry whose value is not the
// expected type (ok=false) cannot be valid ceremony state and is removed as well.
func sweepExpired(m *sync.Map, now time.Time, expiryOf func(any) (time.Time, bool), onDelete func(any)) {
	m.Range(func(key, value any) bool {
		expires, ok := expiryOf(value)
		if ok && !expires.Before(now) {
			return true
		}
		if m.CompareAndDelete(key, value) && onDelete != nil {
			onDelete(value)
		}
		return true
	})
}

// sweepZeroedClientCounters drops per-client counters that no pending ceremony holds,
// so the map does not keep one entry per client ever seen. A begin racing this delete
// may reserve on the dropped counter; its session still releases onto that counter
// (see storePasskeyLoginSession), and the next begin for the client starts a fresh one.
func sweepZeroedClientCounters(m *sync.Map) {
	m.Range(func(key, value any) bool {
		if counter, ok := value.(*atomic.Int64); !ok || counter.Load() <= 0 {
			m.CompareAndDelete(key, value)
		}
		return true
	})
}

// pendingSessionExpiry reads the expiry of a *webAuthnPendingSession.
func pendingSessionExpiry(v any) (time.Time, bool) {
	sess, ok := v.(*webAuthnPendingSession)
	if !ok {
		return time.Time{}, false
	}
	return sess.expires, true
}

// throttleRecordExpiry reads when a *elevateThrottleRecord stops mattering: the later
// of webAuthnThrottleRecordRetention after its last failure and its current cooldown
// end. Removing it resets the failure count, so it must outlive any active cooldown.
func throttleRecordExpiry(v any) (time.Time, bool) {
	rec, ok := v.(*elevateThrottleRecord)
	if !ok {
		return time.Time{}, false
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	expires := rec.nextAllowed
	if !rec.lastFailure.IsZero() {
		if retained := rec.lastFailure.Add(webAuthnThrottleRecordRetention); retained.After(expires) {
			expires = retained
		}
	}
	return expires, true
}
