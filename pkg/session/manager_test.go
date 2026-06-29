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
