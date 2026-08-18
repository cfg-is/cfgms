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

// TestManagerIssueRootScoped exercises Manager.IssueRootScoped (ADR-025 Amendment 1
// A1.3). The marker gates the root<->MSP boundary in the controller API
// (authorizeTenantAccess), so it must be set on issuance, be readable through every
// lifecycle path a request can take (Validate, Renew, List), and be present on
// root-scoped sessions ONLY — never inferred from an empty TenantID.
func TestManagerIssueRootScoped(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, store := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, token, err := mgr.IssueRootScoped(ctx, "root-operator-1", "my-ctrl")
	if err != nil {
		t.Fatalf("IssueRootScoped: %v", err)
	}
	if len(token) != 43 {
		t.Errorf("token length = %d, want 43 (base64url no-padding for 32 bytes)", len(token))
	}
	if sess.ID == "" || sess.PrincipalID != "root-operator-1" || sess.ConnectionName != "my-ctrl" {
		t.Errorf("unexpected session: %+v", sess)
	}
	if !sess.RootScoped {
		t.Error("IssueRootScoped: RootScoped = false, want true")
	}
	if sess.TenantID != "" {
		t.Errorf("IssueRootScoped: TenantID = %q, want \"\" (a root-scoped session is unscoped)", sess.TenantID)
	}
	if sess.Assurance != session.AssuranceBasic {
		t.Errorf("IssueRootScoped: Assurance = %v, want AssuranceBasic (root scope is not a strong factor)", sess.Assurance)
	}

	// The marker must be persisted, not merely returned: the middleware reads it off
	// the Validate result on every request, including after a cache miss.
	stored, err := store.Get(ctx, session.HashToken(token))
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if !stored.RootScoped {
		t.Error("store record: RootScoped = false, want true")
	}

	validated, err := mgr.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if validated.ID != sess.ID {
		t.Errorf("session ID mismatch: got %q, want %q", validated.ID, sess.ID)
	}
	if !validated.RootScoped {
		t.Error("Validate: RootScoped = false, want true")
	}

	// Token rotation must not drop the marker — a renewed root-scoped session is still
	// bounded by the ADR-025 Decision 1 boundary.
	renewed, newToken, err := mgr.Renew(ctx, token)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if !renewed.RootScoped {
		t.Error("Renew: RootScoped = false, want true")
	}
	afterRenew, err := mgr.Validate(ctx, newToken)
	if err != nil {
		t.Fatalf("Validate after Renew: %v", err)
	}
	if !afterRenew.RootScoped {
		t.Error("Validate after Renew: RootScoped = false, want true")
	}

	// An ordinary unscoped session (Issue with tenantID == "") must NOT be marked:
	// this is the pre-existing superadmin shape, which keeps unrestricted access.
	ordinary, _, err := mgr.Issue(ctx, "admin-1", "my-ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if ordinary.RootScoped {
		t.Error("Issue with empty tenantID: RootScoped = true, want false — the marker must never be inferred from TenantID")
	}

	listed, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var seenRootScoped, seenOrdinary bool
	for _, s := range listed {
		switch s.ID {
		case sess.ID:
			seenRootScoped = true
			if !s.RootScoped {
				t.Error("List: root-scoped session reported RootScoped = false")
			}
		case ordinary.ID:
			seenOrdinary = true
			if s.RootScoped {
				t.Error("List: ordinary unscoped session reported RootScoped = true")
			}
		}
	}
	if !seenRootScoped || !seenOrdinary {
		t.Errorf("List: missing sessions (root-scoped seen=%v, ordinary seen=%v)", seenRootScoped, seenOrdinary)
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

// newTwoChannelManagers creates a CLI manager and a web manager over a shared MemStore.
func newTwoChannelManagers(t *testing.T, clock *fakeClock) (cliMgr session.Manager, webMgr session.Manager, store *session.MemStore) {
	t.Helper()
	cliCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "web",
	}
	store = session.NewMemStore(cliCfg, clock.Now)
	t.Cleanup(store.Close)
	cliMgr = session.NewManager(cliCfg, store, clock.Now)
	webMgr = session.NewManager(webCfg, store, clock.Now)
	return cliMgr, webMgr, store
}

// TestCrossChannelValidate_InMemoryPath verifies that presenting a CLI session token to
// the web manager is rejected (in-memory-cache path: session just issued, still in
// the issuing manager's memory, but not in the other manager's memory).
func TestCrossChannelValidate_InMemoryPath(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	cliMgr, webMgr, _ := newTwoChannelManagers(t, clock)
	ctx := context.Background()

	// Issue a CLI session — it is in the CLI manager's memory but not the web manager's.
	_, cliToken, err := cliMgr.Issue(ctx, "alice", "cli-ctrl", "")
	if err != nil {
		t.Fatalf("CLI Issue: %v", err)
	}

	// CLI token validates on CLI manager (same channel, in-memory).
	if _, err := cliMgr.Validate(ctx, cliToken); err != nil {
		t.Errorf("CLI Validate on CLI manager: %v", err)
	}

	// CLI token must be rejected by the web manager (cross-channel).
	// loadFromStore finds it in the store but channel="cli" != "web" → returns nil.
	_, err = webMgr.Validate(ctx, cliToken)
	if err == nil {
		t.Error("web manager accepted a CLI token — cross-channel validation must fail")
	}
}

// TestCrossChannelValidate_PostRestartPath verifies cross-channel rejection after a
// simulated restart: a new manager over the same store must reject sessions issued
// by the other channel (store-rehydration path, Issue #3310).
func TestCrossChannelValidate_PostRestartPath(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	cliCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "web",
	}
	store := session.NewMemStore(cliCfg, clock.Now)
	t.Cleanup(store.Close)

	// Issue a CLI session.
	cliMgr := session.NewManager(cliCfg, store, clock.Now)
	_, cliToken, err := cliMgr.Issue(context.Background(), "bob", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Simulate restart: create a fresh web manager over the same store (empty in-memory map).
	newWebMgr := session.NewManager(webCfg, store, clock.Now)

	// The web manager must reject the CLI token on the store-rehydration path.
	_, err = newWebMgr.Validate(context.Background(), cliToken)
	if err == nil {
		t.Error("new web manager accepted a CLI token after restart — cross-channel rejection must hold")
	}

	// The fresh CLI manager must accept the CLI token on the store-rehydration path.
	newCliMgr := session.NewManager(cliCfg, store, clock.Now)
	if _, err := newCliMgr.Validate(context.Background(), cliToken); err != nil {
		t.Errorf("new CLI manager rejected a CLI token after restart: %v", err)
	}
}

// TestCrossChannelList_PostRestartPath verifies that List returns only the calling
// manager's own channel's sessions on the store fallback path (Issue #3310).
func TestCrossChannelList_PostRestartPath(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	cliCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "web",
	}
	store := session.NewMemStore(cliCfg, clock.Now)
	t.Cleanup(store.Close)
	ctx := context.Background()

	// Issue one CLI session and one web session into the shared store.
	cliMgr := session.NewManager(cliCfg, store, clock.Now)
	webMgr := session.NewManager(webCfg, store, clock.Now)
	cliSess, _, err := cliMgr.Issue(ctx, "alice", "cli-ctrl", "")
	if err != nil {
		t.Fatalf("CLI Issue: %v", err)
	}
	webSess, _, err := webMgr.Issue(ctx, "bob", "web-ctrl", "")
	if err != nil {
		t.Fatalf("Web Issue: %v", err)
	}

	// Simulate restart: fresh managers with empty in-memory maps over the same store.
	freshCliMgr := session.NewManager(cliCfg, store, clock.Now)
	freshWebMgr := session.NewManager(webCfg, store, clock.Now)

	cliList, err := freshCliMgr.List(ctx)
	if err != nil {
		t.Fatalf("CLI List: %v", err)
	}
	if len(cliList) != 1 || cliList[0].ID != cliSess.ID {
		t.Errorf("CLI List got %d sessions (want 1 with ID %q): %v", len(cliList), cliSess.ID, cliList)
	}

	webList, err := freshWebMgr.List(ctx)
	if err != nil {
		t.Fatalf("Web List: %v", err)
	}
	if len(webList) != 1 || webList[0].ID != webSess.ID {
		t.Errorf("Web List got %d sessions (want 1 with ID %q): %v", len(webList), webSess.ID, webList)
	}
}

// TestCrossChannelRevoke_CacheMissBranch verifies that the web manager cannot revoke
// a CLI session by ID on the cache-miss branch (Issue #3310).
func TestCrossChannelRevoke_CacheMissBranch(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	cliMgr, webMgr, _ := newTwoChannelManagers(t, clock)
	ctx := context.Background()

	// Issue a CLI session — it is in the CLI manager's memory and the shared store.
	cliSess, cliToken, err := cliMgr.Issue(ctx, "carol", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// The web manager has not seen this session (cache miss).
	// Its Revoke must load the record, see channel="cli" != "web", and return not-found.
	err = webMgr.Revoke(ctx, cliSess.ID)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("cross-channel Revoke (cache miss): got %v, want ErrSessionNotFound", err)
	}

	// The CLI session must still be valid after the cross-channel revoke attempt.
	if _, err := cliMgr.Validate(ctx, cliToken); err != nil {
		t.Errorf("CLI session should still be valid: %v", err)
	}

	// Issuing further CLI sessions must also still work after the failed cross-channel revoke.
	_, cliToken2, err2 := cliMgr.Issue(ctx, "carol", "ctrl2", "")
	if err2 != nil {
		t.Fatalf("Issue ctrl2: %v", err2)
	}
	if _, err := cliMgr.Validate(ctx, cliToken2); err != nil {
		t.Errorf("newly issued CLI session should be valid: %v", err)
	}
}

// TestNoForeignChannelPollution verifies that presenting a foreign-channel token to a
// manager does not install that session in the manager's in-memory maps (Issue #3310).
func TestNoForeignChannelPollution(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	cliMgr, webMgr, _ := newTwoChannelManagers(t, clock)
	ctx := context.Background()

	// Issue a web session.
	webSess, webToken, err := webMgr.Issue(ctx, "dave", "web-ctrl", "")
	if err != nil {
		t.Fatalf("Web Issue: %v", err)
	}

	// Present the web token to the CLI manager — must be rejected.
	if _, err := cliMgr.Validate(ctx, webToken); err == nil {
		t.Error("CLI manager accepted a web token — cross-channel validation must fail")
	}

	// The web session must still be revocable by the web manager (not poisoned in CLI).
	if err := webMgr.Revoke(ctx, webSess.ID); err != nil {
		t.Errorf("web manager Revoke after cross-channel probe: %v", err)
	}

	// The CLI manager's List must be empty — no foreign sessions leaked into it.
	cliList, err := cliMgr.List(ctx)
	if err != nil {
		t.Fatalf("CLI List: %v", err)
	}
	for _, s := range cliList {
		if s.ID == webSess.ID {
			t.Errorf("web session %q leaked into CLI manager's List", webSess.ID)
		}
	}
}

// TestEmptyChannelRejectedByValidateAndList verifies that sessions with an empty
// channel (back-filled records predating Issue #3310) are rejected by both Validate
// and List, not grandfathered.
func TestEmptyChannelRejectedByValidateAndList(t *testing.T) {
	cliCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	clock := &fakeClock{t: time.Now()}
	store := session.NewMemStore(cliCfg, clock.Now)
	t.Cleanup(store.Close)
	ctx := context.Background()

	// Seed a session with empty channel directly into the store (simulates a back-filled record).
	tok, err := session.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	hash := session.HashToken(tok)
	now := clock.Now()
	legacySess := &session.Session{
		ID:                "legacy-no-channel",
		PrincipalID:       "legacy-user",
		ConnectionName:    "old-ctrl",
		TenantID:          "",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(1 * time.Hour),
		Assurance:         session.AssuranceBasic,
		Channel:           "", // empty = back-filled
	}
	if err := store.Set(ctx, hash, legacySess); err != nil {
		t.Fatalf("Set: %v", err)
	}

	mgr := session.NewManager(cliCfg, store, clock.Now)

	// Validate must reject the empty-channel session.
	_, err = mgr.Validate(ctx, tok)
	if err == nil {
		t.Error("Validate accepted an empty-channel session — must reject")
	}

	// List must exclude the empty-channel session (store fallback path, since in-memory is empty).
	listed, err := mgr.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, s := range listed {
		if s.ID == "legacy-no-channel" {
			t.Errorf("empty-channel session appeared in List — must be excluded")
		}
	}
}

// TestManagerGetByID_ReturnsLiveSession verifies that GetByID returns a copy of the
// live session when it exists in the in-memory cache (the happy path).
func TestManagerGetByID_ReturnsLiveSession(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, _, err := mgr.Issue(ctx, "alice", "ctrl", "tenant-a")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	got, err := mgr.GetByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("GetByID: ID = %q, want %q", got.ID, sess.ID)
	}
	if got.TenantID != "tenant-a" {
		t.Errorf("GetByID: TenantID = %q, want %q", got.TenantID, "tenant-a")
	}
}

// TestManagerGetByID_NotFound verifies that GetByID returns ErrSessionNotFound
// when no session exists for the given ID.
func TestManagerGetByID_NotFound(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	_, err := mgr.GetByID(ctx, "no-such-id")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("GetByID missing session: got %v, want ErrSessionNotFound", err)
	}
}

// TestManagerGetByID_RevokedReturnsNotFound verifies that GetByID returns
// ErrSessionNotFound (not ErrSessionRevoked) for a revoked session — the caller
// should not be able to distinguish a revoked session from an absent one.
func TestManagerGetByID_RevokedReturnsNotFound(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, _, err := mgr.Issue(ctx, "bob", "ctrl", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := mgr.Revoke(ctx, sess.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err = mgr.GetByID(ctx, sess.ID)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("GetByID revoked session: got %v, want ErrSessionNotFound", err)
	}
}

// TestManagerGetByID_StoreRehydrationPath verifies that GetByID falls back to the
// durable store (simulating post-restart behaviour where the in-memory cache is empty)
// and returns the live session.
func TestManagerGetByID_StoreRehydrationPath(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	store := session.NewMemStore(cfg, clock.Now)
	t.Cleanup(store.Close)
	ctx := context.Background()

	// Issue via original manager, then simulate restart with a fresh manager over the same store.
	origMgr := session.NewManager(cfg, store, clock.Now)
	sess, _, err := origMgr.Issue(ctx, "carol", "ctrl", "tenant-b")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	freshMgr := session.NewManager(cfg, store, clock.Now)
	got, err := freshMgr.GetByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetByID on store rehydration path: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("GetByID: ID = %q, want %q", got.ID, sess.ID)
	}
	if got.TenantID != "tenant-b" {
		t.Errorf("GetByID: TenantID = %q, want %q", got.TenantID, "tenant-b")
	}
}

// TestManagerGetByID_CrossChannelReturnsNotFound verifies that GetByID returns
// ErrSessionNotFound when the session belongs to a different channel — consistent
// with the non-disclosure posture of Revoke (Issue #3310).
func TestManagerGetByID_CrossChannelReturnsNotFound(t *testing.T) {
	cliCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "web",
	}
	store := session.NewMemStore(cliCfg, time.Now)
	t.Cleanup(store.Close)
	ctx := context.Background()

	cliMgr := session.NewManager(cliCfg, store, time.Now)
	webMgr := session.NewManager(webCfg, store, time.Now)

	cliSess, _, err := cliMgr.Issue(ctx, "alice", "cli-ctrl", "")
	if err != nil {
		t.Fatalf("Issue CLI session: %v", err)
	}

	// Web manager must not be able to see the CLI session.
	_, err = webMgr.GetByID(ctx, cliSess.ID)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("cross-channel GetByID: got %v, want ErrSessionNotFound", err)
	}
}
