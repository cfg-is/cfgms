// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/session"
)

func TestMemStore_SetAndGet(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	defer store.Close()

	ctx := context.Background()
	token, err := session.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	hash := session.HashToken(token)
	sess := &session.Session{
		ID:                "sess-1",
		PrincipalID:       "admin",
		TenantID:          "",
		IssuedAt:          time.Now(),
		LastActivity:      time.Now(),
		AbsoluteExpiresAt: time.Now().Add(cfg.AbsoluteTimeout),
	}

	// Raw-token lookup must miss (store holds only hashes).
	_, err = store.Get(ctx, token)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("raw-token lookup: got %v, want ErrSessionNotFound", err)
	}

	if err := store.Set(ctx, hash, sess); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Hash lookup must hit.
	got, err := store.Get(ctx, hash)
	if err != nil {
		t.Fatalf("Get by hash: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("session ID mismatch: got %q, want %q", got.ID, sess.ID)
	}
}

func TestMemStore_Delete(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	defer store.Close()

	ctx := context.Background()
	token, err := session.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	hash := session.HashToken(token)
	sess := &session.Session{
		ID:                "sess-del",
		PrincipalID:       "admin",
		IssuedAt:          time.Now(),
		LastActivity:      time.Now(),
		AbsoluteExpiresAt: time.Now().Add(cfg.AbsoluteTimeout),
	}
	if err := store.Set(ctx, hash, sess); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := store.Delete(ctx, "sess-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = store.Get(ctx, hash)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("after Delete, Get: got %v, want ErrSessionNotFound", err)
	}
}

func TestMemStore_ListAll(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	defer store.Close()

	ctx := context.Background()
	sessS2 := &session.Session{
		ID:                "s2",
		IssuedAt:          time.Now(),
		LastActivity:      time.Now(),
		AbsoluteExpiresAt: time.Now().Add(cfg.AbsoluteTimeout),
	}

	// s1: one hash entry.
	t1, err := session.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken t1: %v", err)
	}
	if err := store.Set(ctx, session.HashToken(t1), &session.Session{
		ID:                "s1",
		IssuedAt:          time.Now(),
		LastActivity:      time.Now(),
		AbsoluteExpiresAt: time.Now().Add(cfg.AbsoluteTimeout),
	}); err != nil {
		t.Fatalf("Set s1: %v", err)
	}

	// s2: two hash entries — current token + prior-token grace slot, as produced by a Renew.
	t2a, err := session.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken t2a: %v", err)
	}
	t2b, err := session.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken t2b: %v", err)
	}
	if err := store.Set(ctx, session.HashToken(t2a), sessS2); err != nil {
		t.Fatalf("Set s2a: %v", err)
	}
	if err := store.Set(ctx, session.HashToken(t2b), sessS2); err != nil {
		t.Fatalf("Set s2b: %v", err)
	}

	all, err := store.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	seen := make(map[string]int)
	for _, s := range all {
		seen[s.ID]++
	}
	// s1 and s2 must each appear exactly once despite s2 having two hash entries.
	if seen["s1"] != 1 {
		t.Errorf("s1 count = %d, want 1", seen["s1"])
	}
	if seen["s2"] != 1 {
		t.Errorf("s2 count = %d, want 1 (dedup expected); got %+v", seen["s2"], all)
	}
}

func TestMemStore_NotFoundAfterExpiry(t *testing.T) {
	now := time.Now()
	cfg := session.Config{
		IdleTimeout:     50 * time.Millisecond,
		AbsoluteTimeout: 50 * time.Millisecond,
		GraceWindow:     10 * time.Millisecond,
	}
	clock := &fakeClock{t: now}
	store := session.NewMemStore(cfg, clock.Now)
	defer store.Close()

	ctx := context.Background()
	token, err := session.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	hash := session.HashToken(token)
	sess := &session.Session{
		ID:                "s-exp",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(50 * time.Millisecond),
	}
	if err := store.Set(ctx, hash, sess); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Advance clock past AbsoluteExpiresAt and trigger an explicit sweep
	// instead of sleeping — deterministic and race-free.
	clock.advance(200 * time.Millisecond)
	store.Sweep()

	all, err := store.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	for _, s := range all {
		if s.ID == "s-exp" {
			t.Error("reaper should have removed expired session from ListAll")
		}
	}
}
