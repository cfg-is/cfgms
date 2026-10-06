// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #4572: tests for the in-memory WebAuthn ceremony/throttle expiry sweep and the
// pending passkey login cap. Real *Server instances via setupTestServer /
// setupPasskeySessionServer; no mocks.
package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mapLen counts the entries in m.
func mapLen(m *sync.Map) int {
	n := 0
	m.Range(func(_, _ any) bool { n++; return true })
	return n
}

// TestSweepExpiredWebAuthnCeremonies_RemovesExpiredKeepsUnexpired seeds an expired and
// an unexpired entry into every ceremony and throttle map the sweep owns, runs one sweep,
// and asserts exactly the expired entry of each map is gone.
func TestSweepExpiredWebAuthnCeremonies_RemovesExpiredKeepsUnexpired(t *testing.T) {
	server := setupTestServer(t)
	now := time.Now()
	past := now.Add(-time.Second)
	future := now.Add(time.Minute)

	type seeded struct {
		name    string
		m       *sync.Map
		expired any
		live    any
	}
	maps := []seeded{
		{"webAuthnSessions", &server.webAuthnSessions,
			&webAuthnPendingSession{expires: past}, &webAuthnPendingSession{expires: future}},
		{"webAuthnPresenceSessions", &server.webAuthnPresenceSessions,
			&webAuthnPendingSession{expires: past}, &webAuthnPendingSession{expires: future}},
		{"passkeyEnrollSessions", &server.passkeyEnrollSessions,
			&webAuthnPendingSession{expires: past}, &webAuthnPendingSession{expires: future}},
		{"presenceTokens", &server.presenceTokens,
			&presenceTokenRecord{expires: past}, &presenceTokenRecord{expires: future}},
		{"webAuthnElevateSessions", &server.webAuthnElevateSessions,
			&webAuthnElevateSession{expires: past}, &webAuthnElevateSession{expires: future}},
		{"operatorPayloadSignSessions", &server.operatorPayloadSignSessions,
			&operatorPayloadSignSession{expires: past}, &operatorPayloadSignSession{expires: future}},
		{"passkeyLoginSessions", &server.passkeyLoginSessions,
			&passkeyLoginSession{expires: past}, &passkeyLoginSession{expires: future}},
		// Throttle records expire webAuthnThrottleRecordRetention after their last failure.
		{"webAuthnElevateThrottle", &server.webAuthnElevateThrottle,
			&elevateThrottleRecord{fails: 1, lastFailure: now.Add(-webAuthnThrottleRecordRetention - time.Second)},
			&elevateThrottleRecord{fails: 1, lastFailure: now}},
		{"operatorPayloadSignThrottle", &server.operatorPayloadSignThrottle,
			&elevateThrottleRecord{fails: 1, lastFailure: now.Add(-webAuthnThrottleRecordRetention - time.Second)},
			&elevateThrottleRecord{fails: 1, lastFailure: now}},
		{"passkeyLoginThrottle", &server.passkeyLoginThrottle,
			&elevateThrottleRecord{fails: 1, lastFailure: now.Add(-webAuthnThrottleRecordRetention - time.Second)},
			&elevateThrottleRecord{fails: 1, lastFailure: now}},
	}
	for _, s := range maps {
		s.m.Store("expired", s.expired)
		s.m.Store("live", s.live)
	}

	server.sweepExpiredWebAuthnCeremonies(now)

	for _, s := range maps {
		_, expiredPresent := s.m.Load("expired")
		_, livePresent := s.m.Load("live")
		assert.False(t, expiredPresent, "%s: expired entry must be swept", s.name)
		assert.True(t, livePresent, "%s: unexpired entry must survive the sweep", s.name)
	}
}

// TestSweepExpiredWebAuthnCeremonies_ThrottleRecordOutlivesActiveCooldown pins that a
// throttle record still inside its cooldown is never swept, even when its last failure is
// older than the retention window — sweeping it would reset the failure count.
func TestSweepExpiredWebAuthnCeremonies_ThrottleRecordOutlivesActiveCooldown(t *testing.T) {
	server := setupTestServer(t)
	now := time.Now()

	server.passkeyLoginThrottle.Store("ip:203.0.113.7", &elevateThrottleRecord{
		fails:       12,
		lastFailure: now.Add(-webAuthnThrottleRecordRetention - time.Minute),
		nextAllowed: now.Add(time.Minute),
	})
	server.sweepExpiredWebAuthnCeremonies(now)
	_, present := server.passkeyLoginThrottle.Load("ip:203.0.113.7")
	assert.True(t, present, "a record still blocking must not be swept")

	server.sweepExpiredWebAuthnCeremonies(now.Add(2 * time.Minute))
	_, present = server.passkeyLoginThrottle.Load("ip:203.0.113.7")
	assert.False(t, present, "the record must be swept once its cooldown and retention have both passed")
}

// TestRecordFailure_StampsLastFailure verifies every throttle recorder stamps
// lastFailure, which the sweep's retention window is measured from.
func TestRecordFailure_StampsLastFailure(t *testing.T) {
	server := setupTestServer(t)
	before := time.Now()

	server.recordElevateFailure("ip:198.51.100.1")
	server.recordSignFailure("ip:198.51.100.1")
	server.recordPasskeyLoginFailure("ip:198.51.100.1")

	for name, m := range map[string]*sync.Map{
		"webAuthnElevateThrottle":     &server.webAuthnElevateThrottle,
		"operatorPayloadSignThrottle": &server.operatorPayloadSignThrottle,
		"passkeyLoginThrottle":        &server.passkeyLoginThrottle,
	} {
		raw, ok := m.Load("ip:198.51.100.1")
		require.True(t, ok, "%s: failure must be recorded in memory", name)
		rec := raw.(*elevateThrottleRecord)
		assert.False(t, rec.lastFailure.Before(before), "%s: lastFailure must be stamped on record", name)
	}
}

// TestPasskeyLoginBegin_CapRefusesThenRecovers drives the real begin handler against a
// shrunken cap: begins up to the cap succeed, the next is refused 503/CEREMONY_CAPACITY,
// and begin succeeds again once a pending ceremony is swept on expiry and once another
// is consumed by finish.
func TestPasskeyLoginBegin_CapRefusesThenRecovers(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)
	srv.passkeyLoginSessionCap = 3

	var ceremonyIDs []string
	for i := 0; i < 3; i++ {
		rec := doPasskeyLoginBegin(t, srv, doCSRF(t, srv), "")
		require.Equal(t, http.StatusOK, rec.Code, "begin %d under the cap: %s", i, rec.Body.String())
		id := extractCookie(rec, cookiePasskeyCeremony)
		require.NotEmpty(t, id)
		ceremonyIDs = append(ceremonyIDs, id)
	}
	assert.Equal(t, int64(3), srv.passkeyLoginPending.Load())

	rec := doPasskeyLoginBegin(t, srv, doCSRF(t, srv), "")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "CEREMONY_CAPACITY", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, extractCookie(rec, cookiePasskeyCeremony), "a refused begin must not set a ceremony cookie")
	assert.Equal(t, 3, mapLen(&srv.passkeyLoginSessions), "a refused begin must not store a ceremony")

	// Recovery via expiry: age one pending ceremony past its TTL and sweep.
	raw, ok := srv.passkeyLoginSessions.Load(ceremonyIDs[0])
	require.True(t, ok)
	aged := *raw.(*passkeyLoginSession)
	aged.expires = time.Now().Add(-time.Second)
	srv.passkeyLoginSessions.Store(ceremonyIDs[0], &aged)
	srv.sweepExpiredWebAuthnCeremonies(time.Now())
	assert.Equal(t, int64(2), srv.passkeyLoginPending.Load(), "the sweep must release the expired ceremony's slot")

	rec = doPasskeyLoginBegin(t, srv, doCSRF(t, srv), "")
	require.Equal(t, http.StatusOK, rec.Code, "begin after a sweep must succeed: %s", rec.Body.String())
	rec = doPasskeyLoginBegin(t, srv, doCSRF(t, srv), "")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "back at the cap")

	// Recovery via finish: consuming a ceremony releases its slot whatever the outcome.
	finishReq := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", bytes.NewReader([]byte(`{}`)))
	finishReq.AddCookie(&http.Cookie{Name: cookiePasskeyCeremony, Value: ceremonyIDs[1]})
	finishRec := httptest.NewRecorder()
	srv.handlePasskeyLoginFinish(finishRec, finishReq)
	require.NotEqual(t, http.StatusOK, finishRec.Code, "a junk assertion must not log in")
	assert.Equal(t, int64(2), srv.passkeyLoginPending.Load(), "finish must release the consumed ceremony's slot")

	rec = doPasskeyLoginBegin(t, srv, doCSRF(t, srv), "")
	require.Equal(t, http.StatusOK, rec.Code, "begin after a finish must succeed: %s", rec.Body.String())
}

// TestPasskeyLogin_BeginThenFinishConsumesCeremony verifies the normal begin→finish
// path: begin stores one pending ceremony, finish consumes it (single-use), and the
// pending count returns to zero.
func TestPasskeyLogin_BeginThenFinishConsumesCeremony(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)

	rec := doPasskeyLoginBegin(t, srv, doCSRF(t, srv), "")
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	ceremonyID := extractCookie(rec, cookiePasskeyCeremony)
	require.NotEmpty(t, ceremonyID)
	assert.Equal(t, int64(1), srv.passkeyLoginPending.Load())
	_, stored := srv.passkeyLoginSessions.Load(ceremonyID)
	require.True(t, stored, "begin must store the pending ceremony")

	finish := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", bytes.NewReader([]byte(`{}`)))
		req.AddCookie(&http.Cookie{Name: cookiePasskeyCeremony, Value: ceremonyID})
		r := httptest.NewRecorder()
		srv.handlePasskeyLoginFinish(r, req)
		return r
	}
	first := finish()
	assert.NotEqual(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, first.Body.Bytes()),
		"the first finish must find the ceremony begin stored")
	assert.Equal(t, int64(0), srv.passkeyLoginPending.Load())

	second := finish()
	assert.Equal(t, "NO_ACTIVE_LOGIN_SESSION", errCode(t, second.Body.Bytes()), "the ceremony is single-use")
	assert.Equal(t, int64(0), srv.passkeyLoginPending.Load(), "a replayed finish must not drive the count negative")
}

// TestStartWebAuthnCeremonySweep_RunsAndStopsOnClose covers the goroutine wrapper: New()
// starts the sweep goroutine and Close() stops it, closing webAuthnCeremonySweepDone.
func TestStartWebAuthnCeremonySweep_RunsAndStopsOnClose(t *testing.T) {
	server := setupTestServer(t)

	select {
	case <-server.webAuthnCeremonySweepDone:
		t.Fatal("the WebAuthn ceremony sweep goroutine must still be running before Close")
	default:
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, server.Close(closeCtx))

	select {
	case <-server.webAuthnCeremonySweepDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the WebAuthn ceremony sweep goroutine did not exit after Close")
	}
}

// beginPasskeyLoginFrom drives the real begin handler from remoteAddr.
func beginPasskeyLoginFrom(t *testing.T, srv *Server, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	csrfToken := doCSRF(t, srv)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/begin", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set(headerCSRFToken, csrfToken)
	req.AddCookie(&http.Cookie{Name: cookieCSRFPre, Value: csrfToken})
	rec := httptest.NewRecorder()
	srv.handlePasskeyLoginBegin(rec, req)
	return rec
}

// TestPasskeyLoginBegin_PerClientCap verifies one client at its per-client cap is
// refused 429/CEREMONY_RATE_LIMITED without consuming a global slot, a second client
// still begins, and both expiry (via the sweep) and finish free the client's slot. The
// sweep then drops the client's zeroed counter.
func TestPasskeyLoginBegin_PerClientCap(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)
	srv.passkeyLoginSessionClientCap = 2
	const clientA = "203.0.113.10:4000"
	const clientB = "198.51.100.20:4000"

	var idsA []string
	for i := 0; i < 2; i++ {
		rec := beginPasskeyLoginFrom(t, srv, clientA)
		require.Equal(t, http.StatusOK, rec.Code, "client A begin %d: %s", i, rec.Body.String())
		idsA = append(idsA, extractCookie(rec, cookiePasskeyCeremony))
	}

	rec := beginPasskeyLoginFrom(t, srv, clientA)
	require.Equal(t, http.StatusTooManyRequests, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, "CEREMONY_RATE_LIMITED", errCode(t, rec.Body.Bytes()))
	assert.Empty(t, extractCookie(rec, cookiePasskeyCeremony))
	assert.Equal(t, int64(2), srv.passkeyLoginPending.Load(), "a per-client refusal must not consume a global slot")

	rec = beginPasskeyLoginFrom(t, srv, clientB)
	require.Equal(t, http.StatusOK, rec.Code, "a second client must still begin: %s", rec.Body.String())
	idB := extractCookie(rec, cookiePasskeyCeremony)

	// Expiry frees client A's slot.
	raw, ok := srv.passkeyLoginSessions.Load(idsA[0])
	require.True(t, ok)
	aged := *raw.(*passkeyLoginSession)
	aged.expires = time.Now().Add(-time.Second)
	srv.passkeyLoginSessions.Store(idsA[0], &aged)
	srv.sweepExpiredWebAuthnCeremonies(time.Now())
	rec = beginPasskeyLoginFrom(t, srv, clientA)
	require.Equal(t, http.StatusOK, rec.Code, "client A must begin again after expiry: %s", rec.Body.String())
	idsA = append(idsA, extractCookie(rec, cookiePasskeyCeremony))
	require.Equal(t, http.StatusTooManyRequests, beginPasskeyLoginFrom(t, srv, clientA).Code, "client A back at its cap")

	// Finish frees client A's slot, whatever the outcome.
	finishFrom := func(id string) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/web/passkey/login/finish", bytes.NewReader([]byte(`{}`)))
		req.AddCookie(&http.Cookie{Name: cookiePasskeyCeremony, Value: id})
		srv.handlePasskeyLoginFinish(httptest.NewRecorder(), req)
	}
	finishFrom(idsA[1])
	rec = beginPasskeyLoginFrom(t, srv, clientA)
	require.Equal(t, http.StatusOK, rec.Code, "client A must begin again after finish: %s", rec.Body.String())
	require.NotEmpty(t, extractCookie(rec, cookiePasskeyCeremony), "the new ceremony must set its cookie")

	// Drain client B; the sweep drops its zeroed counter and keeps client A's live one.
	finishFrom(idB)
	keyB := authdefenseKeyFor(t, srv, clientB)
	keyA := authdefenseKeyFor(t, srv, clientA)
	_, present := srv.passkeyLoginPendingByClient.Load(keyB)
	require.True(t, present, "the zeroed counter is only dropped by the sweep")
	srv.sweepExpiredWebAuthnCeremonies(time.Now())
	_, present = srv.passkeyLoginPendingByClient.Load(keyB)
	assert.False(t, present, "the sweep must drop a zeroed per-client counter")
	rawA, present := srv.passkeyLoginPendingByClient.Load(keyA)
	require.True(t, present, "a counter with pending ceremonies must survive the sweep")
	assert.Equal(t, int64(2), rawA.(*atomic.Int64).Load())
	assert.Equal(t, int64(2), srv.passkeyLoginPending.Load())
}

// TestPasskeyLoginBegin_GlobalCapReturnsClientSlot verifies a begin refused by the
// global cap gives its per-client reservation back.
func TestPasskeyLoginBegin_GlobalCapReturnsClientSlot(t *testing.T) {
	srv, _ := setupPasskeySessionServer(t)
	srv.passkeyLoginSessionCap = 1
	const clientA = "203.0.113.10:4000"

	require.Equal(t, http.StatusOK, beginPasskeyLoginFrom(t, srv, "198.51.100.20:4000").Code)
	rec := beginPasskeyLoginFrom(t, srv, clientA)
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "CEREMONY_CAPACITY", errCode(t, rec.Body.Bytes()))

	raw, ok := srv.passkeyLoginPendingByClient.Load(authdefenseKeyFor(t, srv, clientA))
	require.True(t, ok)
	assert.Equal(t, int64(0), raw.(*atomic.Int64).Load(), "a global refusal must release the per-client slot")
}

// authdefenseKeyFor returns the s.clientIPKey bucket a request from remoteAddr maps to.
func authdefenseKeyFor(t *testing.T, srv *Server, remoteAddr string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = remoteAddr
	key := srv.clientIPKey(req)
	require.NotEmpty(t, key)
	return key
}
