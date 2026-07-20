// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session_test

// Tests for ADR-021 device-continuity behaviour (Issue #2788):
//   - IP-change-triggered downgrade (required test)
//   - Two-node simulation via shared Store (required test)
//   - Silent-proof failure falls back to AssuranceBasic (required test)

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/session"
)

// testContinuityConfig returns a Config tuned for continuity tests:
// short SilentReproofInterval so timer-based tests don't need large clock advances.
func testContinuityConfig() session.Config {
	return session.Config{
		IdleTimeout:           10 * time.Minute,
		AbsoluteTimeout:       1 * time.Hour,
		GraceWindow:           30 * time.Second,
		SilentReproofInterval: 5 * time.Minute,
	}
}

// issueAndElevate issues a session on mgr, persists an AssuranceStrong record to store
// (simulating a WebAuthn assertion handler that ran between the Issue and the next Validate),
// and returns the token and hash.
//
// Because Manager caches sessions in memory (in-process), a direct store.Set does not
// update the issuing Manager's in-memory copy — it is visible only to a fresh Manager
// or via loadFromStore on a cold-cache lookup. All continuity tests that need to start
// from AssuranceStrong therefore issue on mgrWrite and validate on mgrRead, matching
// the real-world pattern where a WebAuthn handler on one path updates the store and the
// next authenticated request arrives on a potentially-different node.
func issueAndElevate(t *testing.T, mgr session.Manager, store session.Store, clock *fakeClock,
	principalID, connName, tenantID, boundIP string) (token, hash string) {
	t.Helper()
	ctx := context.Background()

	sess, tok, err := mgr.Issue(ctx, principalID, connName, tenantID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	h := session.HashToken(tok)

	// Simulate the WebAuthn assertion handler writing AssuranceStrong to the durable store.
	sess.Assurance = session.AssuranceStrong
	sess.BoundIP = boundIP
	sess.LastProvenAt = clock.Now()
	if err := store.Set(ctx, h, sess); err != nil {
		t.Fatalf("store.Set (elevate): %v", err)
	}
	return tok, h
}

// TestIPChangeDowngradesAssurance verifies ADR-021 Decision 5:
// a source-IP change on an AssuranceStrong session immediately downgrades it to
// AssuranceBasic and clears LastProvenAt. The session must remain valid (not killed),
// and the next sensitive-action check would see AssuranceBasic → 401 step-up (not 403).
//
// [REQUIRED TEST]
func TestIPChangeDowngradesAssurance(t *testing.T) {
	cfg := testContinuityConfig()
	clock := &fakeClock{t: time.Now()}
	sharedStore := session.NewMemStore(cfg, clock.Now)
	t.Cleanup(sharedStore.Close)

	// mgrWrite issues the session; mgrRead validates (cold cache → loads from store,
	// seeing the AssuranceStrong state written by issueAndElevate).
	mgrWrite := session.NewManager(cfg, sharedStore, clock.Now)
	mgrRead := session.NewManager(cfg, sharedStore, clock.Now)
	ctx := context.Background()

	token, hash := issueAndElevate(t, mgrWrite, sharedStore, clock, "alice", "ctrl", "tenant-1", "192.0.2.1")

	// Request from the SAME IP → Assurance stays Strong.
	sameIPCtx := session.WithSourceIP(ctx, "192.0.2.1")
	got, err := mgrRead.Validate(sameIPCtx, token)
	if err != nil {
		t.Fatalf("Validate (same IP): %v", err)
	}
	if got.Assurance != session.AssuranceStrong {
		t.Errorf("same-IP Validate: Assurance = %v, want AssuranceStrong", got.Assurance)
	}

	// Request arrives from a DIFFERENT IP → Assurance must downgrade.
	newIPCtx := session.WithSourceIP(ctx, "10.0.0.1")
	got, err = mgrRead.Validate(newIPCtx, token)
	if err != nil {
		t.Fatalf("Validate (new IP): unexpected error %v", err)
	}

	// Session must remain valid (not killed — ADR Decision 5 says "never hard-lock").
	if got == nil {
		t.Fatal("Validate (new IP): session was killed (got nil), want valid session")
	}

	// Assurance must be downgraded to Basic.
	if got.Assurance != session.AssuranceBasic {
		t.Errorf("new-IP Validate: Assurance = %v, want AssuranceBasic", got.Assurance)
	}

	// LastProvenAt must be cleared.
	if !got.LastProvenAt.IsZero() {
		t.Errorf("new-IP Validate: LastProvenAt = %v, want zero", got.LastProvenAt)
	}

	// The downgrade must be visible in the store (other nodes + subsequent requests).
	stored, err := sharedStore.Get(ctx, hash)
	if err != nil {
		t.Fatalf("store.Get after downgrade: %v", err)
	}
	if stored.Assurance != session.AssuranceBasic {
		t.Errorf("store after downgrade: Assurance = %v, want AssuranceBasic", stored.Assurance)
	}
	if !stored.LastProvenAt.IsZero() {
		t.Errorf("store after downgrade: LastProvenAt = %v, want zero", stored.LastProvenAt)
	}
}

// TestTwoNodeSessionContinuity verifies that assurance state written by "node A" is
// correctly read and evaluated by "node B" (failover / rolling-restart scenario).
// Both nodes share the same Store; each has its own Manager instance (separate in-memory
// caches), simulating two independent controller processes sharing a durable store.
//
// [REQUIRED TEST]
func TestTwoNodeSessionContinuity(t *testing.T) {
	cfg := testContinuityConfig()
	clock := &fakeClock{t: time.Now()}

	// Shared store simulates the durable Postgres/SQLite store in a multi-node deployment.
	sharedStore := session.NewMemStore(cfg, clock.Now)
	t.Cleanup(sharedStore.Close)

	// Node A and Node B each have their own Manager (independent in-memory index).
	mgrA := session.NewManager(cfg, sharedStore, clock.Now)
	mgrB := session.NewManager(cfg, sharedStore, clock.Now)

	ctx := context.Background()

	// Node A issues a session and a WebAuthn assertion sets AssuranceStrong in the store.
	token, _ := issueAndElevate(t, mgrA, sharedStore, clock, "bob", "ctrl-a", "tenant-2", "198.51.100.5")

	// Node B validates the token (cold cache — never saw this session).
	// The Manager falls back to the durable store (loadFromStore).
	sameIPCtx := session.WithSourceIP(ctx, "198.51.100.5")
	gotB, err := mgrB.Validate(sameIPCtx, token)
	if err != nil {
		t.Fatalf("Node B Validate: %v", err)
	}

	// Node B must see the AssuranceStrong state set by the WebAuthn handler on Node A.
	if gotB.Assurance != session.AssuranceStrong {
		t.Errorf("Node B Validate: Assurance = %v, want AssuranceStrong", gotB.Assurance)
	}
	if gotB.LastProvenAt.IsZero() {
		t.Error("Node B Validate: LastProvenAt is zero, want non-zero (cross-node visibility)")
	}

	// Simulate the client's next request going to Node B from a new IP (failover scenario).
	// Node B must downgrade based on the BoundIP loaded from the shared store.
	newIPCtx := session.WithSourceIP(ctx, "203.0.113.99")
	gotB2, err := mgrB.Validate(newIPCtx, token)
	if err != nil {
		t.Fatalf("Node B Validate (new IP): %v", err)
	}
	if gotB2.Assurance != session.AssuranceBasic {
		t.Errorf("Node B Validate (new IP): Assurance = %v, want AssuranceBasic", gotB2.Assurance)
	}

	// The downgrade must also be visible to any reader (written to shared store by Node B).
	storedAfterDowngrade, err := sharedStore.Get(ctx, session.HashToken(token))
	if err != nil {
		t.Fatalf("shared store Get after Node-B downgrade: %v", err)
	}
	if storedAfterDowngrade.Assurance != session.AssuranceBasic {
		t.Errorf("shared store after Node-B downgrade: Assurance = %v, want AssuranceBasic",
			storedAfterDowngrade.Assurance)
	}
}

// TestSilentProofFailureFallsBackToBasic verifies that when a session holds
// AssuranceStrong but silent re-proof is impossible (CredentialID is nil — no device
// binding, so there is nothing to prove with), the session falls back to AssuranceBasic
// without returning an error. The in-flight request must not be rejected outright.
//
// [REQUIRED TEST]
func TestSilentProofFailureFallsBackToBasic(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:           10 * time.Minute,
		AbsoluteTimeout:       1 * time.Hour,
		GraceWindow:           30 * time.Second,
		SilentReproofInterval: 5 * time.Minute,
	}
	clock := &fakeClock{t: time.Now()}
	sharedStore := session.NewMemStore(cfg, clock.Now)
	t.Cleanup(sharedStore.Close)

	mgrWrite := session.NewManager(cfg, sharedStore, clock.Now)
	mgrRead := session.NewManager(cfg, sharedStore, clock.Now)
	ctx := context.Background()

	// Issue and elevate to AssuranceStrong with NO CredentialID.
	// Simulates a session where the authenticator device is no longer available.
	sess, token, err := mgrWrite.Issue(ctx, "carol", "ctrl", "tenant-3")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	hash := session.HashToken(token)
	sess.Assurance = session.AssuranceStrong
	sess.LastProvenAt = clock.Now()
	sess.CredentialID = nil // explicitly: no credential — silent proof is impossible
	if err := sharedStore.Set(ctx, hash, sess); err != nil {
		t.Fatalf("store.Set: %v", err)
	}

	// Advance past the SilentReproofInterval so a time-based re-proof is triggered.
	clock.advance(6 * time.Minute)

	// mgrRead has a cold cache → loads from store → sees AssuranceStrong with elapsed interval.
	// Validate: silent re-proof is triggered but impossible (no credential) → fall back.
	// Must NOT return an error — the request must proceed with AssuranceBasic.
	got, err := mgrRead.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate after proof interval elapsed: unexpected error %v", err)
	}
	if got == nil {
		t.Fatal("Validate: got nil session, want valid session")
	}

	// Must fall back to AssuranceBasic (not an error, not a hard rejection).
	if got.Assurance != session.AssuranceBasic {
		t.Errorf("Assurance = %v, want AssuranceBasic (graceful fallback)", got.Assurance)
	}
	// LastProvenAt must be cleared.
	if !got.LastProvenAt.IsZero() {
		t.Errorf("LastProvenAt = %v, want zero after fallback", got.LastProvenAt)
	}
}

// TestDefaultConfigSilentReproofInterval locks the SilentReproofInterval default so
// implementation stories cannot silently drift it (complements TestDefaultConfig in
// contract_test.go which locks the other three tunables).
func TestDefaultConfigSilentReproofInterval(t *testing.T) {
	cfg := session.DefaultConfig()
	if cfg.SilentReproofInterval != 5*time.Minute {
		t.Errorf("SilentReproofInterval = %v, want 5m", cfg.SilentReproofInterval)
	}
}

// TestIPChangeDowngradeNotFiredWhenBoundIPEmpty verifies that IP-change detection does
// NOT fire when BoundIP is empty (session has never been proved from an IP). Only a
// non-empty BoundIP constitutes a "bound" location to compare against.
func TestIPChangeDowngradeNotFiredWhenBoundIPEmpty(t *testing.T) {
	cfg := testContinuityConfig()
	clock := &fakeClock{t: time.Now()}
	sharedStore := session.NewMemStore(cfg, clock.Now)
	t.Cleanup(sharedStore.Close)

	mgrWrite := session.NewManager(cfg, sharedStore, clock.Now)
	mgrRead := session.NewManager(cfg, sharedStore, clock.Now)
	ctx := context.Background()

	sess, token, err := mgrWrite.Issue(ctx, "dave", "ctrl", "tenant-4")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Elevate to AssuranceStrong with an empty BoundIP — IP detection should be skipped.
	hash := session.HashToken(token)
	sess.Assurance = session.AssuranceStrong
	sess.BoundIP = "" // not yet bound to any IP
	sess.LastProvenAt = clock.Now()
	if err := sharedStore.Set(ctx, hash, sess); err != nil {
		t.Fatalf("store.Set: %v", err)
	}

	// Request from any IP must NOT downgrade because BoundIP is empty.
	someIPCtx := session.WithSourceIP(ctx, "10.255.0.1")
	got, err := mgrRead.Validate(someIPCtx, token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.Assurance != session.AssuranceStrong {
		t.Errorf("Assurance = %v, want AssuranceStrong (no BoundIP → no detection)", got.Assurance)
	}
}

// TestAssuranceLevelPersistedAcrossRenew verifies that the session's Assurance level
// is preserved through token rotation (Manager.Renew). A downgrade recorded before
// Renew must be visible on the new token as well.
func TestAssuranceLevelPersistedAcrossRenew(t *testing.T) {
	cfg := testContinuityConfig()
	clock := &fakeClock{t: time.Now()}
	sharedStore := session.NewMemStore(cfg, clock.Now)
	t.Cleanup(sharedStore.Close)

	mgrWrite := session.NewManager(cfg, sharedStore, clock.Now)
	mgrRead := session.NewManager(cfg, sharedStore, clock.Now)
	ctx := context.Background()

	// Elevate to AssuranceStrong on mgrWrite.
	token, _ := issueAndElevate(t, mgrWrite, sharedStore, clock, "eve", "ctrl", "tenant-5", "172.16.0.1")

	// Trigger IP-change downgrade via mgrRead (cold cache → loads from store).
	got, err := mgrRead.Validate(session.WithSourceIP(ctx, "172.16.0.2"), token)
	if err != nil {
		t.Fatalf("Validate (IP change): %v", err)
	}
	if got.Assurance != session.AssuranceBasic {
		t.Errorf("post-downgrade Assurance = %v, want AssuranceBasic", got.Assurance)
	}

	// Renew: new token issued; Assurance should still be AssuranceBasic on the new token.
	_, newToken, err := mgrRead.Renew(ctx, token)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if newToken == "" {
		t.Fatal("Renew: expected new token, got empty string")
	}

	gotAfterRenew, err := mgrRead.Validate(ctx, newToken)
	if err != nil {
		t.Fatalf("Validate (new token): %v", err)
	}
	if gotAfterRenew.Assurance != session.AssuranceBasic {
		t.Errorf("post-Renew Assurance = %v, want AssuranceBasic", gotAfterRenew.Assurance)
	}
}
