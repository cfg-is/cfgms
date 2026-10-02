// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/session"
)

// TestElevate_UpgradesAssuranceAndRotatesToken verifies the core elevation contract:
// after a successful Elevate call the session carries AssuranceStrong, the new token
// is validated correctly, and the old token is still accepted during the grace window.
func TestElevate_UpgradesAssuranceAndRotatesToken(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:           10 * time.Minute,
		AbsoluteTimeout:       1 * time.Hour,
		GraceWindow:           30 * time.Second,
		SilentReproofInterval: 5 * time.Minute,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, oldToken, err := mgr.Issue(ctx, "alice", "web", "tenant-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if sess.Assurance != session.AssuranceBasic {
		t.Fatalf("initial assurance = %v, want AssuranceBasic", sess.Assurance)
	}

	credID := []byte("cred-abc-123")
	srcIP := "192.0.2.10"

	elevated, newToken, err := mgr.Elevate(ctx, sess.ID, credID, srcIP)
	if err != nil {
		t.Fatalf("Elevate: %v", err)
	}
	if newToken == "" {
		t.Fatal("Elevate must return a new token")
	}
	if newToken == oldToken {
		t.Fatal("Elevate must rotate the token")
	}
	if elevated.Assurance != session.AssuranceStrong {
		t.Errorf("elevated.Assurance = %v, want AssuranceStrong", elevated.Assurance)
	}
	if elevated.BoundIP != srcIP {
		t.Errorf("elevated.BoundIP = %q, want %q", elevated.BoundIP, srcIP)
	}
	if !bytes.Equal(elevated.CredentialID, credID) {
		t.Errorf("elevated.CredentialID = %v, want %v", elevated.CredentialID, credID)
	}
	if elevated.LastProvenAt.IsZero() {
		t.Error("elevated.LastProvenAt must be set after elevation")
	}
	// Session ID must not change.
	if elevated.ID != sess.ID {
		t.Errorf("session ID changed: got %q, want %q", elevated.ID, sess.ID)
	}

	// New token validates as AssuranceStrong.
	got, err := mgr.Validate(ctx, newToken)
	if err != nil {
		t.Fatalf("Validate(newToken): %v", err)
	}
	if got.Assurance != session.AssuranceStrong {
		t.Errorf("Validate assurance = %v, want AssuranceStrong", got.Assurance)
	}
}

// TestElevate_OldTokenValidDuringGrace verifies that the pre-elevation token is still
// accepted during the grace window (so concurrent in-flight requests complete cleanly).
func TestElevate_OldTokenValidDuringGrace(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     10 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     200 * time.Millisecond,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, oldToken, err := mgr.Issue(ctx, "bob", "web", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, _, err = mgr.Elevate(ctx, sess.ID, []byte("cred"), "10.0.0.1")
	if err != nil {
		t.Fatalf("Elevate: %v", err)
	}

	// Immediately after elevation, old token should still be accepted.
	if _, err := mgr.Validate(ctx, oldToken); err != nil {
		t.Errorf("old token inside grace: Validate returned %v, want nil", err)
	}

	// After grace window elapses, old token must be rejected.
	clock.advance(300 * time.Millisecond)
	_, err = mgr.Validate(ctx, oldToken)
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Errorf("old token after grace: got %v, want ErrSessionExpired", err)
	}
}

// TestElevate_NotFound verifies that Elevate returns ErrSessionNotFound for unknown IDs.
func TestElevate_NotFound(t *testing.T) {
	cfg := session.DefaultConfig()
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	_, _, err := mgr.Elevate(ctx, "no-such-session", []byte("cred"), "10.0.0.1")
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("got %v, want ErrSessionNotFound", err)
	}
}

// TestElevate_RevokedSession verifies that Elevate refuses revoked sessions.
func TestElevate_RevokedSession(t *testing.T) {
	cfg := session.DefaultConfig()
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, _, err := mgr.Issue(ctx, "carol", "web", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := mgr.Revoke(ctx, sess.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, _, err = mgr.Elevate(ctx, sess.ID, []byte("cred"), "10.0.0.1")
	if !errors.Is(err, session.ErrSessionRevoked) {
		t.Errorf("got %v, want ErrSessionRevoked", err)
	}
}

// TestElevate_IdleExpiredSession verifies that Elevate refuses idle-expired sessions.
func TestElevate_IdleExpiredSession(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     100 * time.Millisecond,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, _, err := mgr.Issue(ctx, "dave", "web", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	clock.advance(200 * time.Millisecond)

	_, _, err = mgr.Elevate(ctx, sess.ID, []byte("cred"), "10.0.0.1")
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Errorf("got %v, want ErrSessionExpired", err)
	}
}

// TestElevate_AbsoluteExpiredSession verifies that Elevate refuses absolute-expired sessions.
func TestElevate_AbsoluteExpiredSession(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:     1 * time.Hour,
		AbsoluteTimeout: 100 * time.Millisecond,
		GraceWindow:     30 * time.Second,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, _, err := mgr.Issue(ctx, "eve", "web", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	clock.advance(200 * time.Millisecond)

	_, _, err = mgr.Elevate(ctx, sess.ID, []byte("cred"), "10.0.0.1")
	if !errors.Is(err, session.ErrSessionExpired) {
		t.Errorf("got %v, want ErrSessionExpired", err)
	}
}

// TestElevate_IPChangeDowngradesAfterElevation verifies that a subsequent Validate
// call after an IP change downgrades an elevated session back to AssuranceBasic
// (ADR-021 Decision 5 / Issue #2788).
func TestElevate_IPChangeDowngradesAfterElevation(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:           10 * time.Minute,
		AbsoluteTimeout:       1 * time.Hour,
		GraceWindow:           30 * time.Second,
		SilentReproofInterval: 5 * time.Minute,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)

	srcIP := "192.0.2.1"
	ctx := session.WithSourceIP(context.Background(), srcIP)

	sess, _, err := mgr.Issue(ctx, "frank", "web", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, newToken, err := mgr.Elevate(ctx, sess.ID, []byte("cred"), srcIP)
	if err != nil {
		t.Fatalf("Elevate: %v", err)
	}

	// Validate from same IP → still Strong.
	got, err := mgr.Validate(ctx, newToken)
	if err != nil {
		t.Fatalf("Validate same IP: %v", err)
	}
	if got.Assurance != session.AssuranceStrong {
		t.Errorf("same IP: assurance = %v, want AssuranceStrong", got.Assurance)
	}

	// Validate from different IP → downgraded to Basic.
	newIPCtx := session.WithSourceIP(context.Background(), "10.0.0.99")
	got, err = mgr.Validate(newIPCtx, newToken)
	if err != nil {
		t.Fatalf("Validate different IP: %v", err)
	}
	if got.Assurance != session.AssuranceBasic {
		t.Errorf("IP change: assurance = %v, want AssuranceBasic", got.Assurance)
	}
}

// TestElevate_SilentReproofIntervalDowngrades verifies that a session elevated with a
// SilentReproofInterval is downgraded back to AssuranceBasic once the interval elapses
// without a fresh assertion.
func TestElevate_SilentReproofIntervalDowngrades(t *testing.T) {
	cfg := session.Config{
		IdleTimeout:           30 * time.Minute,
		AbsoluteTimeout:       2 * time.Hour,
		GraceWindow:           30 * time.Second,
		SilentReproofInterval: 5 * time.Minute,
	}
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, _, err := mgr.Issue(ctx, "grace", "web", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, newToken, err := mgr.Elevate(ctx, sess.ID, []byte("cred"), "10.0.0.1")
	if err != nil {
		t.Fatalf("Elevate: %v", err)
	}

	// Within the silent reproof interval — session stays Strong.
	clock.advance(4 * time.Minute)
	got, err := mgr.Validate(ctx, newToken)
	if err != nil {
		t.Fatalf("Validate within interval: %v", err)
	}
	if got.Assurance != session.AssuranceStrong {
		t.Errorf("within interval: assurance = %v, want AssuranceStrong", got.Assurance)
	}

	// Past the silent reproof interval — downgraded to Basic.
	clock.advance(2 * time.Minute) // total 6m > 5m SilentReproofInterval
	got, err = mgr.Validate(ctx, newToken)
	if err != nil {
		t.Fatalf("Validate after interval: %v", err)
	}
	if got.Assurance != session.AssuranceBasic {
		t.Errorf("after interval: assurance = %v, want AssuranceBasic", got.Assurance)
	}
}

// TestElevate_ReturnsTokenWithCorrectLength verifies that the new token follows the
// same format rules as Issue/Renew (43 chars, base64url no-padding, 256-bit entropy).
func TestElevate_ReturnsTokenWithCorrectLength(t *testing.T) {
	cfg := session.DefaultConfig()
	clock := &fakeClock{t: time.Now()}
	mgr, _ := newTestManager(t, cfg, clock)
	ctx := context.Background()

	sess, _, err := mgr.Issue(ctx, "henry", "web", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, newToken, err := mgr.Elevate(ctx, sess.ID, []byte("cred"), "10.0.0.1")
	if err != nil {
		t.Fatalf("Elevate: %v", err)
	}
	if len(newToken) != 43 {
		t.Errorf("newToken length = %d, want 43 (base64url no-padding for 32 bytes)", len(newToken))
	}
}
