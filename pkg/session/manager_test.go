// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/session"
)

// fakeClock is a monotonically-advanceable clock for time-injected tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestManager(t *testing.T, cfg session.Config, clock *fakeClock) (session.Manager, *session.MemStore) {
	t.Helper()
	store := session.NewMemStore(cfg, clock.Now)
	t.Cleanup(store.Close)
	mgr := session.NewManager(cfg, store, clock.Now)
	return mgr, store
}

func TestManagerIssueAndValidate(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, token, err := mgr.Issue(ctx, "alice", "my-ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if len(token) != 43 {
		t.Errorf("token length = %d, want 43 (base64url no-padding for 32 bytes)", len(token))
	}
	if sess.ID == "" || sess.PrincipalID != "alice" {
		t.Errorf("unexpected session: %+v", sess)
	}

	got, err := mgr.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("session ID mismatch: got %q, want %q", got.ID, sess.ID)
	}
}

func TestManagerRevoke(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, token, err := mgr.Issue(ctx, "bob", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := mgr.Revoke(ctx, sess.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err = mgr.Validate(ctx, token)
	if !errors.Is(err, session.ErrSessionRevoked) {
		t.Errorf("after Revoke, Validate: got %v, want ErrSessionRevoked", err)
	}
}

func TestManagerIdleTTL(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     100 * time.Millisecond,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	_, token, err := mgr.Issue(ctx, "carol", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// Advance past idle TTL without any Validate call.
	clock.advance(200 * time.Millisecond)
	_, err = mgr.Validate(ctx, token)
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Errorf("idle TTL exceeded: got %v, want ErrSessionExpired", err)
	}
}

// TestSessionAbsoluteCap verifies that a continuously-renewed session is refused
// once the absolute cap elapses, even though the idle TTL has not.
func TestSessionAbsoluteCap(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     10 * time.Minute,
		AbsoluteTimeout: 500 * time.Millisecond,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	_, token, err := mgr.Issue(ctx, "dave", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Continuously renew while advancing time, keeping idle TTL fresh.
	// Advance in 100ms increments, renewing each time, until past absolute cap.
	for i := 0; i < 7; i++ {
		clock.advance(100 * time.Millisecond)
		_, newToken, err := mgr.Renew(ctx, token)
		if err != nil {
			// If absolute cap hit during renewal, that's fine.
			if errors.Is(err, session.ErrSessionExpired) {
				return
			}
			t.Fatalf("unexpected Renew error at step %d: %v", i, err)
		}
		if newToken != "" {
			token = newToken
		}
	}

	// After > 500ms total, the session must be expired.
	_, err = mgr.Validate(ctx, token)
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Errorf("absolute cap: Validate returned %v, want ErrSessionExpired", err)
	}
}

// TestRollingTokenGraceWindow verifies:
//  1. After renewal, both prior and new tokens are accepted within GraceWindow.
//  2. Two concurrent prior-token Renew calls do not double-rotate.
//  3. Prior token is rejected after GraceWindow elapses.
func TestRollingTokenGraceWindow(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     10 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     200 * time.Millisecond,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	_, tokenA, err := mgr.Issue(ctx, "eve", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Renew with tokenA → get tokenB.
	_, tokenB, err := mgr.Renew(ctx, tokenA)
	if err != nil {
		t.Fatalf("first Renew: %v", err)
	}
	if tokenB == "" {
		t.Fatal("first Renew must return a new token")
	}

	// Within grace window, both tokenA and tokenB must be accepted.
	clock.advance(50 * time.Millisecond) // well inside 200ms grace
	if _, err := mgr.Validate(ctx, tokenA); err != nil {
		t.Errorf("prior token inside grace: Validate returned %v, want nil", err)
	}
	if _, err := mgr.Validate(ctx, tokenB); err != nil {
		t.Errorf("new token inside grace: Validate returned %v, want nil", err)
	}

	// Concurrent prior-token Renew calls must not double-rotate.
	var wg sync.WaitGroup
	tokenResults := make([]string, 2)
	errResults := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Both goroutines hold tokenA (the prev token).
			_, newTok, err := mgr.Renew(ctx, tokenA)
			tokenResults[idx] = newTok
			errResults[idx] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errResults {
		if err != nil {
			t.Errorf("concurrent Renew[%d]: unexpected error: %v", i, err)
		}
	}
	// At most one of them should have received a new token (the other sees prev slot and returns "").
	newTokenCount := 0
	for _, tok := range tokenResults {
		if tok != "" {
			newTokenCount++
		}
	}
	if newTokenCount > 1 {
		t.Errorf("double-rotation: %d concurrent prior-token Renews both returned new tokens", newTokenCount)
	}

	// After GraceWindow elapses, prior token must be rejected.
	clock.advance(300 * time.Millisecond) // past 200ms grace
	_, err = mgr.Validate(ctx, tokenA)
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Errorf("prior token after grace: got %v, want ErrSessionExpired", err)
	}
	// tokenB remains valid (it is now the current token; idle TTL was reset on first Validate).
	if _, err := mgr.Validate(ctx, tokenB); err != nil {
		t.Errorf("new token after grace elapsed: got %v (should still be valid)", err)
	}
}

// TestTokenNotStoredRaw verifies that the Store never holds the raw token value.
// The AC requires "raw-token lookup misses, hash lookup hits" as the assertion.
// Controller-level log sanitization is verified in handlers_sessions_test.go.
func TestTokenNotStoredRaw(t *testing.T) {
	cfg := session.DefaultConfig()
	clock := &fakeClock{t: time.Now()}
	store := session.NewMemStore(cfg, clock.Now)
	defer store.Close()
	mgr := session.NewManager(cfg, store, clock.Now)
	ctx := context.Background()

	sess, token, err := mgr.Issue(ctx, "frank", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Raw token must not be a valid store key.
	_, rawErr := store.Get(ctx, token)
	if !errors.Is(rawErr, session.ErrSessionNotFound) {
		t.Errorf("raw-token lookup: got %v, want ErrSessionNotFound", rawErr)
	}

	// Hash of raw token must be a valid store key.
	hash := session.HashToken(token)
	_, hashErr := store.Get(ctx, hash)
	if hashErr != nil {
		t.Errorf("hash lookup: got %v, want nil", hashErr)
	}

	// Renew and verify the new token follows the same rule.
	_, newToken, err := mgr.Renew(ctx, token)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if newToken != "" {
		_, rawErr2 := store.Get(ctx, newToken)
		if !errors.Is(rawErr2, session.ErrSessionNotFound) {
			t.Errorf("renewed raw-token lookup: got %v, want ErrSessionNotFound", rawErr2)
		}
		_, hashErr2 := store.Get(ctx, session.HashToken(newToken))
		if hashErr2 != nil {
			t.Errorf("renewed hash lookup: got %v, want nil", hashErr2)
		}
	}

	if err := mgr.Revoke(ctx, sess.ID); err != nil {
		t.Errorf("cleanup Revoke: %v", err)
	}
}

func TestValidateUnknownToken(t *testing.T) {
	cfg := session.DefaultConfig()
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	_, err := mgr.Validate(ctx, "not-a-real-token")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("unknown token: got %v, want ErrSessionNotFound", err)
	}
}

func TestRevokeUnknownSession(t *testing.T) {
	cfg := session.DefaultConfig()
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	err := mgr.Revoke(ctx, "no-such-id")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("Revoke unknown: got %v, want ErrSessionNotFound", err)
	}
}

// TestManagerList_ActiveSessionsOnly verifies that List returns only genuinely-live
// sessions — not revoked, not absolute-expired, not idle-expired — and returns copies.
func TestManagerList_ActiveSessionsOnly(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     200 * time.Millisecond,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	// Issue three sessions: one to keep active, one to revoke, one to let idle-expire.
	activeSess, activeToken, err := mgr.Issue(ctx, "alice", "ctrl-a", "tenantA")
	if err != nil {
		t.Fatalf("Issue active: %v", err)
	}
	revokedSess, _, err := mgr.Issue(ctx, "bob", "ctrl-b", "tenantA")
	if err != nil {
		t.Fatalf("Issue revoked: %v", err)
	}
	_, _, err = mgr.Issue(ctx, "carol", "ctrl-c", "tenantA")
	if err != nil {
		t.Fatalf("Issue idle: %v", err)
	}

	// Revoke bob's session.
	if err := mgr.Revoke(ctx, revokedSess.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Advance to T=100ms (inside idle TTL) and validate alice's token to refresh
	// her LastActivity. Carol's token is never validated.
	clock.advance(100 * time.Millisecond)
	if _, err := mgr.Validate(ctx, activeToken); err != nil {
		t.Fatalf("Validate alice inside idle window: %v", err)
	}

	// Advance to T=250ms: carol's LastActivity is still T=0 → idle-expired at T=200ms;
	// alice's LastActivity was reset to T=100ms → idle-expires at T=300ms → still alive.
	clock.advance(150 * time.Millisecond)

	sessions, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	// Only alice's session should be returned.
	if len(sessions) != 1 {
		t.Fatalf("List returned %d sessions, want 1 (active only); got IDs: %v",
			len(sessions), sessionIDs(sessions))
	}
	if sessions[0].ID != activeSess.ID {
		t.Errorf("List returned session %q, want %q", sessions[0].ID, activeSess.ID)
	}
}

// sessionIDs extracts session IDs for error messages.
func sessionIDs(sessions []*session.Session) []string {
	ids := make([]string, len(sessions))
	for i, s := range sessions {
		ids[i] = s.ID
	}
	return ids
}

// TestManagerList_AbsoluteExpiredExcluded verifies that a session past its absolute
// expiry is excluded from List even if the store has not yet reaped it.
func TestManagerList_AbsoluteExpiredExcluded(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     1 * time.Hour,
		AbsoluteTimeout: 100 * time.Millisecond,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	_, _, err := mgr.Issue(ctx, "dave", "ctrl-d", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Advance past absolute timeout.
	clock.advance(200 * time.Millisecond)

	sessions, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("List returned %d sessions after absolute expiry, want 0", len(sessions))
	}
}

// TestManagerList_ReturnsCopies verifies that mutating a returned *Session does not
// affect the manager's internal state (subsequent List calls return the original value).
func TestManagerList_ReturnsCopies(t *testing.T) {
	cfg := session.DefaultConfig()
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	_, _, err := mgr.Issue(ctx, "eve", "ctrl-e", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	sessions, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("List returned %d sessions, want 1", len(sessions))
	}

	originalID := sessions[0].ID
	// Mutate the returned pointer.
	sessions[0].ID = "mutated-id"
	sessions[0].PrincipalID = "mutated-principal"

	// A fresh List must still see the original values.
	sessions2, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("second List: %v", err)
	}
	if len(sessions2) != 1 {
		t.Fatalf("second List returned %d sessions, want 1", len(sessions2))
	}
	if sessions2[0].ID != originalID {
		t.Errorf("mutation leaked: ID = %q, want %q", sessions2[0].ID, originalID)
	}
}

// TestManagerList_ConcurrentWithRenew stresses List() and Renew() from parallel
// goroutines on the same set of sessions. Its purpose is to expose lock-ordering
// bugs that -race cannot: -race detects data races, not deadlocks. List() snapshots
// the sessions map under m.mu and releases it before taking any per-session ms.mu,
// while Renew() takes ms.mu then m.mu; if List instead held m.mu across ms.mu the two
// paths would form an ABBA deadlock and this test would hang. A watchdog fails the
// test rather than letting the whole suite block if that regression returns.
func TestManagerList_ConcurrentWithRenew(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     1 * time.Hour,
		AbsoluteTimeout: 24 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	const (
		numSessions = 8
		listWorkers = 8
		iterations  = 500
	)
	initialTokens := make([]string, numSessions)
	for i := 0; i < numSessions; i++ {
		_, tok, err := mgr.Issue(ctx, "user", "ctrl", "tenant")
		if err != nil {
			t.Fatalf("Issue %d: %v", i, err)
		}
		initialTokens[i] = tok
	}

	var wg sync.WaitGroup

	// One renew goroutine per session: each goroutine owns its session's rolling
	// token, so it always renews with the current token (never a grace-window token
	// that a competing renewer could have evicted). This keeps the test focused on
	// the List/Renew lock interaction rather than token-rotation bookkeeping, while
	// still driving Renew's ms.mu→m.mu ordering against List concurrently.
	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(tok string) {
			defer wg.Done()
			for n := 0; n < iterations; n++ {
				_, newTok, err := mgr.Renew(ctx, tok)
				if err != nil {
					t.Errorf("Renew: %v", err)
					return
				}
				if newTok != "" {
					tok = newTok
				}
			}
		}(initialTokens[i])
	}

	// List workers: enumerate all live sessions concurrently with the rotations,
	// exercising List's m.mu→ms.mu path against Renew's ms.mu→m.mu path.
	for w := 0; w < listWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < iterations; n++ {
				if _, err := mgr.List(ctx); err != nil {
					t.Errorf("List: %v", err)
					return
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent List/Renew workload did not complete within 10s: " +
			"likely an ABBA deadlock between List (m.mu→ms.mu) and Renew (ms.mu→m.mu)")
	}
}

// TestManagerList_EmptyWhenNoSessions verifies List returns an empty slice (not nil
// or an error) when no sessions have been issued.
func TestManagerList_EmptyWhenNoSessions(t *testing.T) {
	cfg := session.DefaultConfig()
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sessions, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List on empty manager: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}
