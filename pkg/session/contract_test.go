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

// TestDefaultConfig locks the ADR-014 tunables so later stories cannot silently drift them.
func TestDefaultConfig(t *testing.T) {
	cfg := session.DefaultConfig()

	if cfg.IdleTimeout != 15*time.Minute {
		t.Errorf("IdleTimeout = %v, want 15m", cfg.IdleTimeout)
	}
	if cfg.AbsoluteTimeout != 8*time.Hour {
		t.Errorf("AbsoluteTimeout = %v, want 8h", cfg.AbsoluteTimeout)
	}
	if cfg.GraceWindow != 30*time.Second {
		t.Errorf("GraceWindow = %v, want 30s", cfg.GraceWindow)
	}
}

// stubManager satisfies Manager for compile-time interface verification.
type stubManager struct{}

func (s *stubManager) Issue(_ context.Context, _, _, _ string) (*session.Session, string, error) {
	return nil, "", nil
}
func (s *stubManager) Validate(_ context.Context, _ string) (*session.Session, error) {
	return nil, nil
}
func (s *stubManager) Renew(_ context.Context, _ string) (*session.Session, string, error) {
	return nil, "", nil
}
func (s *stubManager) Revoke(_ context.Context, _ string) error           { return nil }
func (s *stubManager) List(_ context.Context) ([]*session.Session, error) { return nil, nil }

// stubStore satisfies Store for compile-time interface verification.
type stubStore struct{}

func (s *stubStore) Set(_ context.Context, _ string, _ *session.Session) error { return nil }
func (s *stubStore) Get(_ context.Context, _ string) (*session.Session, error) { return nil, nil }
func (s *stubStore) Delete(_ context.Context, _ string) error                  { return nil }
func (s *stubStore) ListAll(_ context.Context) ([]*session.Session, error)     { return nil, nil }

// TestManagerInterfaceSatisfied verifies Manager can be satisfied by a concrete type.
func TestManagerInterfaceSatisfied(t *testing.T) {
	var _ session.Manager = (*stubManager)(nil)
}

// TestStoreInterfaceSatisfied verifies Store can be satisfied by a concrete type.
func TestStoreInterfaceSatisfied(t *testing.T) {
	var _ session.Store = (*stubStore)(nil)
}

// TestSentinelsAreDistinctErrors verifies all error sentinels are distinct non-nil values.
func TestSentinelsAreDistinctErrors(t *testing.T) {
	sentinels := map[string]error{
		"ErrNotAdmin":        session.ErrNotAdmin,
		"ErrSessionExpired":  session.ErrSessionExpired,
		"ErrSessionRevoked":  session.ErrSessionRevoked,
		"ErrSessionNotFound": session.ErrSessionNotFound,
	}

	for name, err := range sentinels {
		if err == nil {
			t.Errorf("%s must not be nil", name)
		}
	}

	// Verify each sentinel is distinct from every other.
	names := []string{"ErrNotAdmin", "ErrSessionExpired", "ErrSessionRevoked", "ErrSessionNotFound"}
	errs := []error{session.ErrNotAdmin, session.ErrSessionExpired, session.ErrSessionRevoked, session.ErrSessionNotFound}
	for i := range errs {
		for j := range errs {
			if i == j {
				continue
			}
			if errors.Is(errs[i], errs[j]) {
				t.Errorf("%s and %s must be distinct error values", names[i], names[j])
			}
		}
	}
}

// TestSessionStruct verifies the Session struct has the required fields with correct zero values.
func TestSessionStruct(t *testing.T) {
	s := session.Session{}
	// Verify string fields exist and are zero-valued
	if s.ID != "" || s.ConnectionName != "" || s.PrincipalID != "" || s.TenantID != "" {
		t.Error("Session string fields must be empty by default")
	}
	// Verify time fields exist and are zero-valued
	if !s.IssuedAt.IsZero() || !s.LastActivity.IsZero() || !s.AbsoluteExpiresAt.IsZero() {
		t.Error("Session time fields must be zero by default")
	}
}

// ---- Shared Store contract suite -----------------------------------------------

// makeTestSession returns a minimal session ready for store insertion.
func makeTestSession(id string, cfg session.Config) *session.Session {
	now := time.Now()
	return &session.Session{
		ID:                id,
		PrincipalID:       "test-principal",
		ConnectionName:    "test-ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(cfg.AbsoluteTimeout),
	}
}

// RunStoreContractSuite executes the shared contract test suite against any session.Store
// implementation. It covers Set/Get, Get-miss, Delete (revocation), ListAll dedup, and
// the invariant that the raw token is never a valid store key.
func RunStoreContractSuite(t *testing.T, store session.Store) {
	t.Helper()
	cfg := session.DefaultConfig()
	ctx := context.Background()

	t.Run("SetAndGetByHash", func(t *testing.T) {
		tok, err := session.GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		hash := session.HashToken(tok)
		sess := makeTestSession("sc-set-get", cfg)

		if err := store.Set(ctx, hash, sess); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := store.Get(ctx, hash)
		if err != nil {
			t.Fatalf("Get by hash: %v", err)
		}
		if got.ID != sess.ID {
			t.Errorf("session ID: got %q, want %q", got.ID, sess.ID)
		}
		if got.PrincipalID != sess.PrincipalID {
			t.Errorf("PrincipalID: got %q, want %q", got.PrincipalID, sess.PrincipalID)
		}
	})

	t.Run("RawTokenNotAValidKey", func(t *testing.T) {
		tok, err := session.GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		hash := session.HashToken(tok)
		sess := makeTestSession("sc-raw-token", cfg)
		if err := store.Set(ctx, hash, sess); err != nil {
			t.Fatalf("Set: %v", err)
		}
		// Looking up the raw token (not its hash) must miss — the raw token is never persisted.
		_, err = store.Get(ctx, tok)
		if !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("raw-token lookup: got %v, want ErrSessionNotFound", err)
		}
		// Hash lookup must hit.
		if _, err := store.Get(ctx, hash); err != nil {
			t.Errorf("hash lookup: unexpected error %v", err)
		}
	})

	t.Run("GetMissingHashReturnsNotFound", func(t *testing.T) {
		_, err := store.Get(ctx, "0000000000000000000000000000000000000000000000000000000000000000")
		if !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("missing hash: got %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("DeleteBySessionIDRemovesAllHashes", func(t *testing.T) {
		t1, _ := session.GenerateToken()
		t2, _ := session.GenerateToken()
		h1, h2 := session.HashToken(t1), session.HashToken(t2)
		sess := makeTestSession("sc-delete", cfg)

		if err := store.Set(ctx, h1, sess); err != nil {
			t.Fatalf("Set h1: %v", err)
		}
		if err := store.Set(ctx, h2, sess); err != nil {
			t.Fatalf("Set h2: %v", err)
		}
		if err := store.Delete(ctx, sess.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := store.Get(ctx, h1); !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("after Delete, Get h1: got %v, want ErrSessionNotFound", err)
		}
		if _, err := store.Get(ctx, h2); !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("after Delete, Get h2: got %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("DeleteIdempotent", func(t *testing.T) {
		tok, _ := session.GenerateToken()
		sess := makeTestSession("sc-delete-idem", cfg)
		if err := store.Set(ctx, session.HashToken(tok), sess); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if err := store.Delete(ctx, sess.ID); err != nil {
			t.Errorf("first Delete: %v", err)
		}
		// Second Delete finds no records and returns ErrSessionNotFound — safe to call.
		if err := store.Delete(ctx, sess.ID); !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("second Delete: got %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("SetUpdatesExistingEntry", func(t *testing.T) {
		tok, _ := session.GenerateToken()
		hash := session.HashToken(tok)
		sess := makeTestSession("sc-update", cfg)
		if err := store.Set(ctx, hash, sess); err != nil {
			t.Fatalf("initial Set: %v", err)
		}
		// Update LastActivity.
		updated := *sess
		updated.LastActivity = updated.LastActivity.Add(5 * time.Minute)
		if err := store.Set(ctx, hash, &updated); err != nil {
			t.Fatalf("update Set: %v", err)
		}
		got, err := store.Get(ctx, hash)
		if err != nil {
			t.Fatalf("Get after update: %v", err)
		}
		if !got.LastActivity.Equal(updated.LastActivity) {
			t.Errorf("LastActivity: got %v, want %v", got.LastActivity, updated.LastActivity)
		}
	})

	t.Run("ListAllDedupsBySessionID", func(t *testing.T) {
		// s1: single hash entry.
		t1, _ := session.GenerateToken()
		s1 := makeTestSession("sc-list-s1", cfg)
		if err := store.Set(ctx, session.HashToken(t1), s1); err != nil {
			t.Fatalf("Set s1: %v", err)
		}
		// s2: two hash entries (current + prior-token grace), as produced by a Renew.
		t2a, _ := session.GenerateToken()
		t2b, _ := session.GenerateToken()
		s2 := makeTestSession("sc-list-s2", cfg)
		if err := store.Set(ctx, session.HashToken(t2a), s2); err != nil {
			t.Fatalf("Set s2a: %v", err)
		}
		if err := store.Set(ctx, session.HashToken(t2b), s2); err != nil {
			t.Fatalf("Set s2b: %v", err)
		}

		all, err := store.ListAll(ctx)
		if err != nil {
			t.Fatalf("ListAll: %v", err)
		}
		counts := make(map[string]int)
		for _, s := range all {
			counts[s.ID]++
		}
		if counts["sc-list-s1"] != 1 {
			t.Errorf("s1 count = %d, want 1", counts["sc-list-s1"])
		}
		if counts["sc-list-s2"] != 1 {
			t.Errorf("s2 count = %d, want 1 (dedup expected); full list: %v", counts["sc-list-s2"], all)
		}
	})

	t.Run("GraceWindowRenewalRoundTrip", func(t *testing.T) {
		// Simulate the two-hash state produced by Manager.Renew:
		// hashOld = prior-token (in grace), hashNew = current.
		tokOld, _ := session.GenerateToken()
		tokNew, _ := session.GenerateToken()
		hashOld, hashNew := session.HashToken(tokOld), session.HashToken(tokNew)
		sess := makeTestSession("sc-grace", cfg)

		// Both hashes point at the same session record.
		if err := store.Set(ctx, hashOld, sess); err != nil {
			t.Fatalf("Set hashOld: %v", err)
		}
		if err := store.Set(ctx, hashNew, sess); err != nil {
			t.Fatalf("Set hashNew: %v", err)
		}
		// Both must be retrievable by their respective hash.
		if _, err := store.Get(ctx, hashOld); err != nil {
			t.Errorf("Get hashOld: %v", err)
		}
		if _, err := store.Get(ctx, hashNew); err != nil {
			t.Errorf("Get hashNew: %v", err)
		}
		// After revocation (Delete by session ID) both must be gone.
		if err := store.Delete(ctx, sess.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := store.Get(ctx, hashOld); !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("after Delete, Get hashOld: got %v, want ErrSessionNotFound", err)
		}
		if _, err := store.Get(ctx, hashNew); !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("after Delete, Get hashNew: got %v, want ErrSessionNotFound", err)
		}
	})
}

// TestStoreContract_MemStore runs the shared contract suite against the in-memory MemStore.
func TestStoreContract_MemStore(t *testing.T) {
	cfg := session.DefaultConfig()
	store := session.NewMemStore(cfg, time.Now)
	t.Cleanup(store.Close)
	RunStoreContractSuite(t, store)
}
