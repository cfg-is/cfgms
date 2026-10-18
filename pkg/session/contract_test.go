// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
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
func (s *stubManager) IssueRootScoped(_ context.Context, _, _, _ string) (*session.Session, string, error) {
	return nil, "", nil
}
func (s *stubManager) Validate(_ context.Context, _ string) (*session.Session, error) {
	return nil, nil
}
func (s *stubManager) Renew(_ context.Context, _ string) (*session.Session, string, error) {
	return nil, "", nil
}
func (s *stubManager) Revoke(_ context.Context, _ string) error                      { return nil }
func (s *stubManager) List(_ context.Context) ([]*session.Session, error)            { return nil, nil }
func (s *stubManager) GetByID(_ context.Context, _ string) (*session.Session, error) { return nil, nil }
func (s *stubManager) Elevate(_ context.Context, _ string, _ []byte, _ string) (*session.Session, string, error) {
	return nil, "", nil
}
func (s *stubManager) RevokeAllForPrincipal(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// stubStore satisfies Store for compile-time interface verification.
type stubStore struct{}

func (s *stubStore) Set(_ context.Context, _ string, _ *session.Session) error    { return nil }
func (s *stubStore) Update(_ context.Context, _ string, _ *session.Session) error { return nil }
func (s *stubStore) Rotate(_ context.Context, _, _ string, _ *session.Session, _ time.Time) error {
	return nil
}
func (s *stubStore) Get(_ context.Context, _ string) (*session.Session, error)     { return nil, nil }
func (s *stubStore) GetByID(_ context.Context, _ string) (*session.Session, error) { return nil, nil }
func (s *stubStore) Delete(_ context.Context, _ string) error                      { return nil }
func (s *stubStore) ListAll(_ context.Context) ([]*session.Session, error)         { return nil, nil }

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
		"ErrNotAdmin":               session.ErrNotAdmin,
		"ErrSessionExpired":         session.ErrSessionExpired,
		"ErrSessionRevoked":         session.ErrSessionRevoked,
		"ErrSessionNotFound":        session.ErrSessionNotFound,
		"ErrSessionChannelMismatch": session.ErrSessionChannelMismatch,
	}

	for name, err := range sentinels {
		if err == nil {
			t.Errorf("%s must not be nil", name)
		}
	}

	// Verify each sentinel is distinct from every other.
	names := []string{"ErrNotAdmin", "ErrSessionExpired", "ErrSessionRevoked", "ErrSessionNotFound", "ErrSessionChannelMismatch"}
	errs := []error{session.ErrNotAdmin, session.ErrSessionExpired, session.ErrSessionRevoked, session.ErrSessionNotFound, session.ErrSessionChannelMismatch}
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

// mustGenerateToken returns a fresh session token, failing the test if generation
// fails. GenerateToken draws from crypto/rand; a discarded error would leave an
// empty token whose SHA-256 is still a well-formed store key, silently corrupting
// the test state (all empty tokens collide on one hash) instead of failing.
func mustGenerateToken(t *testing.T) string {
	t.Helper()
	tok, err := session.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	return tok
}

// RunStoreContractSuite executes the shared contract test suite against any session.Store
// implementation. It covers Set/Get, Get-miss, Delete (revocation), ListAll dedup, and
// the invariant that the raw token is never a valid store key.
func RunStoreContractSuite(t *testing.T, store session.Store) {
	t.Helper()
	cfg := session.DefaultConfig()
	ctx := context.Background()

	t.Run("SetAndGetByHash", func(t *testing.T) {
		tok := mustGenerateToken(t)
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
		tok := mustGenerateToken(t)
		hash := session.HashToken(tok)
		sess := makeTestSession("sc-raw-token", cfg)
		if err := store.Set(ctx, hash, sess); err != nil {
			t.Fatalf("Set: %v", err)
		}
		// Looking up the raw token (not its hash) must miss — the raw token is never persisted.
		_, err := store.Get(ctx, tok)
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
		t1 := mustGenerateToken(t)
		t2 := mustGenerateToken(t)
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
		tok := mustGenerateToken(t)
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
		tok := mustGenerateToken(t)
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
		t1 := mustGenerateToken(t)
		s1 := makeTestSession("sc-list-s1", cfg)
		if err := store.Set(ctx, session.HashToken(t1), s1); err != nil {
			t.Fatalf("Set s1: %v", err)
		}
		// s2: two hash entries (current + prior-token grace), as produced by a Renew.
		t2a := mustGenerateToken(t)
		t2b := mustGenerateToken(t)
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

	t.Run("GetByIDReturnsSessionRecord", func(t *testing.T) {
		tok := mustGenerateToken(t)
		hash := session.HashToken(tok)
		sess := makeTestSession("sc-get-by-id", cfg)
		sess.Channel = "cli"

		if err := store.Set(ctx, hash, sess); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := store.GetByID(ctx, sess.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.ID != sess.ID {
			t.Errorf("GetByID session ID: got %q, want %q", got.ID, sess.ID)
		}
		if got.Channel != "cli" {
			t.Errorf("GetByID channel: got %q, want %q", got.Channel, "cli")
		}
	})

	t.Run("GetByIDMissingReturnsNotFound", func(t *testing.T) {
		_, err := store.GetByID(ctx, "no-such-session-id-00000000000000000000")
		if !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("GetByID missing: got %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("GetByIDAfterDeleteReturnsNotFound", func(t *testing.T) {
		tok := mustGenerateToken(t)
		sess := makeTestSession("sc-get-by-id-del", cfg)
		if err := store.Set(ctx, session.HashToken(tok), sess); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if err := store.Delete(ctx, sess.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		_, err := store.GetByID(ctx, sess.ID)
		if !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("GetByID after Delete: got %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("GraceWindowRenewalRoundTrip", func(t *testing.T) {
		// Simulate the two-hash state produced by Manager.Renew:
		// hashOld = prior-token (in grace), hashNew = current.
		tokOld := mustGenerateToken(t)
		tokNew := mustGenerateToken(t)
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

	// ContinuityFieldsRoundTrip verifies that all four device-continuity fields
	// (Assurance, CredentialID, BoundIP, LastProvenAt) plus the ADR-025 Amendment 1
	// A1.3 RootScoped marker survive a Set → Get round-trip with non-zero / non-nil
	// values. This exercises the nullable-column deserialization branches in SQLite and
	// Postgres stores that are never reached by makeTestSession (which always leaves
	// these fields at their zero defaults). RootScoped is security-relevant: a session
	// that loses the marker on reload is silently promoted from a boundary-checked
	// root-scoped operator to an unrestricted unscoped superadmin.
	t.Run("ContinuityFieldsRoundTrip", func(t *testing.T) {
		tok := mustGenerateToken(t)
		hash := session.HashToken(tok)
		now := time.Now().UTC().Truncate(time.Second)
		credID := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
		loginCredID := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x05, 0x06}

		sess := &session.Session{
			ID:                "sc-continuity",
			PrincipalID:       "carol",
			ConnectionName:    "ctrl",
			TenantID:          "tenant-continuity",
			IssuedAt:          now,
			LastActivity:      now,
			AbsoluteExpiresAt: now.Add(cfg.AbsoluteTimeout),
			Assurance:         session.AssuranceStrong,
			CredentialID:      credID,
			LoginCredentialID: loginCredID,
			BoundIP:           "198.51.100.42",
			LastProvenAt:      now,
			RootScoped:        true,
			Channel:           "cli",
		}

		if err := store.Set(ctx, hash, sess); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := store.Get(ctx, hash)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Assurance != session.AssuranceStrong {
			t.Errorf("Assurance: got %v, want AssuranceStrong", got.Assurance)
		}
		if got.BoundIP != "198.51.100.42" {
			t.Errorf("BoundIP: got %q, want %q", got.BoundIP, "198.51.100.42")
		}
		if got.LastProvenAt.IsZero() {
			t.Error("LastProvenAt: got zero, want non-zero")
		}
		if !got.RootScoped {
			t.Error("RootScoped: got false, want true — the ADR-025 A1.3 marker must survive Set → Get")
		}
		if got.Channel != "cli" {
			t.Errorf("Channel: got %q, want %q — the channel must survive Set → Get", got.Channel, "cli")
		}
		if !got.LastProvenAt.Equal(now) {
			t.Errorf("LastProvenAt: got %v, want %v", got.LastProvenAt, now)
		}
		if len(got.CredentialID) != len(credID) {
			t.Errorf("CredentialID length: got %d, want %d", len(got.CredentialID), len(credID))
		} else {
			for i, b := range credID {
				if got.CredentialID[i] != b {
					t.Errorf("CredentialID[%d]: got 0x%02x, want 0x%02x", i, got.CredentialID[i], b)
				}
			}
		}

		if !bytes.Equal(got.LoginCredentialID, loginCredID) {
			t.Errorf("LoginCredentialID: got %x, want %x", got.LoginCredentialID, loginCredID)
		}

		// ListAll must also return the continuity fields intact.
		all, err := store.ListAll(ctx)
		if err != nil {
			t.Fatalf("ListAll: %v", err)
		}
		var found *session.Session
		for _, s := range all {
			if s.ID == "sc-continuity" {
				found = s
				break
			}
		}
		if found == nil {
			t.Fatal("ListAll: sc-continuity session not found")
		}
		if found.Assurance != session.AssuranceStrong {
			t.Errorf("ListAll Assurance: got %v, want AssuranceStrong", found.Assurance)
		}
		if found.BoundIP != "198.51.100.42" {
			t.Errorf("ListAll BoundIP: got %q, want %q", found.BoundIP, "198.51.100.42")
		}
		if found.LastProvenAt.IsZero() {
			t.Error("ListAll LastProvenAt: got zero, want non-zero")
		}
		if !bytes.Equal(found.LoginCredentialID, loginCredID) {
			t.Errorf("ListAll LoginCredentialID: got %x, want %x", found.LoginCredentialID, loginCredID)
		}
		if len(found.CredentialID) != len(credID) {
			t.Errorf("ListAll CredentialID length: got %d, want %d", len(found.CredentialID), len(credID))
		}
		if !found.RootScoped {
			t.Error("ListAll RootScoped: got false, want true")
		}
		if found.Channel != "cli" {
			t.Errorf("ListAll Channel: got %q, want %q", found.Channel, "cli")
		}

		// A session that was never root-scoped must come back false from both read
		// paths — the marker is never inferred, and never leaks across rows.
		ordinaryTok := mustGenerateToken(t)
		ordinaryHash := session.HashToken(ordinaryTok)
		ordinary := makeTestSession("sc-not-root-scoped", cfg)
		if err := store.Set(ctx, ordinaryHash, ordinary); err != nil {
			t.Fatalf("Set (ordinary): %v", err)
		}
		gotOrdinary, err := store.Get(ctx, ordinaryHash)
		if err != nil {
			t.Fatalf("Get (ordinary): %v", err)
		}
		if gotOrdinary.RootScoped {
			t.Error("RootScoped: got true for a session issued without the marker, want false")
		}
	})

	t.Run("UpdateAfterDeleteFailsAndDoesNotResurrect", func(t *testing.T) {
		tok := mustGenerateToken(t)
		hash := session.HashToken(tok)
		sess := makeTestSession("sc-update-after-delete", cfg)
		if err := store.Set(ctx, hash, sess); err != nil {
			t.Fatalf("Set: %v", err)
		}
		// Update on a live session succeeds, for the same hash and a rotated one.
		newHash := session.HashToken(mustGenerateToken(t))
		if err := store.Update(ctx, hash, sess); err != nil {
			t.Fatalf("Update (live, same hash): %v", err)
		}
		if err := store.Update(ctx, newHash, sess); err != nil {
			t.Fatalf("Update (live, new hash): %v", err)
		}
		if err := store.Delete(ctx, sess.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		for name, h := range map[string]string{"same": hash, "new": newHash, "fresh": session.HashToken(mustGenerateToken(t))} {
			if err := store.Update(ctx, h, sess); !errors.Is(err, session.ErrSessionNotFound) {
				t.Errorf("Update after Delete (%s hash): got %v, want ErrSessionNotFound", name, err)
			}
			if _, err := store.Get(ctx, h); !errors.Is(err, session.ErrSessionNotFound) {
				t.Errorf("Get after rejected Update (%s hash): got %v, want ErrSessionNotFound", name, err)
			}
		}
		if _, err := store.GetByID(ctx, sess.ID); !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("GetByID after rejected Update: got %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("UpdateNeverCreatesUnknownSession", func(t *testing.T) {
		sess := makeTestSession("sc-update-unknown", cfg)
		hash := session.HashToken(mustGenerateToken(t))
		if err := store.Update(ctx, hash, sess); !errors.Is(err, session.ErrSessionNotFound) {
			t.Fatalf("Update of never-created session: got %v, want ErrSessionNotFound", err)
		}
		if _, err := store.Get(ctx, hash); !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("Get: got %v, want ErrSessionNotFound", err)
		}
	})

	t.Run("ConcurrentUpdateRacingDeleteLeavesNoLiveRow", func(t *testing.T) {
		const iterations = 100
		const writers = 4
		for i := 0; i < iterations; i++ {
			sess := makeTestSession(fmt.Sprintf("sc-race-%d", i), cfg)
			base := session.HashToken(mustGenerateToken(t))
			if err := store.Set(ctx, base, sess); err != nil {
				t.Fatalf("Set: %v", err)
			}
			hashes := make([]string, writers)
			for w := range hashes {
				hashes[w] = session.HashToken(mustGenerateToken(t))
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func(h string) {
					defer wg.Done()
					<-start
					// Either outcome is fine; the row must not survive Delete.
					_ = store.Update(ctx, h, sess)
				}(hashes[w])
			}
			var delErr error
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				delErr = store.Delete(ctx, sess.ID)
			}()
			close(start)
			wg.Wait()
			if delErr != nil {
				t.Fatalf("iteration %d: Delete: %v", i, delErr)
			}
			if _, err := store.GetByID(ctx, sess.ID); !errors.Is(err, session.ErrSessionNotFound) {
				t.Fatalf("iteration %d: live row after Delete returned: GetByID err=%v", i, err)
			}
			for _, h := range append(hashes, base) {
				if _, err := store.Get(ctx, h); !errors.Is(err, session.ErrSessionNotFound) {
					t.Fatalf("iteration %d: hash still live after Delete: %v", i, err)
				}
			}
		}
	})

	t.Run("RotateRecordsCurrentHashAndBoundsPrior", func(t *testing.T) {
		sess := makeTestSession("sc-rotate", cfg)
		h1 := session.HashToken(mustGenerateToken(t))
		h2 := session.HashToken(mustGenerateToken(t))
		h3 := session.HashToken(mustGenerateToken(t))
		if err := store.Set(ctx, h1, sess); err != nil {
			t.Fatalf("Set: %v", err)
		}
		// Rotate h1 -> h2 with a grace expiry already in the past: h1 must be refused
		// by the store itself while h2 and the session stay live.
		if err := store.Rotate(ctx, h1, h2, sess, time.Now().Add(-time.Second)); err != nil {
			t.Fatalf("Rotate h1->h2: %v", err)
		}
		if _, err := store.Get(ctx, h1); !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("Get(h1) after grace expiry: got %v, want ErrSessionNotFound", err)
		}
		if _, err := store.Get(ctx, h2); err != nil {
			t.Errorf("Get(h2): %v", err)
		}
		// The rotated-away hash is no longer current: it cannot be rotated again, even
		// though the session is live, and the failed attempt writes nothing.
		if err := store.Rotate(ctx, h1, h3, sess, time.Now().Add(time.Minute)); !errors.Is(err, session.ErrTokenRotated) {
			t.Fatalf("Rotate from rotated-away hash: got %v, want ErrTokenRotated", err)
		}
		if _, err := store.Get(ctx, h3); !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("Get(h3) after rejected Rotate: got %v, want ErrSessionNotFound", err)
		}
		// A Update through the stale hash must not clear its recorded expiry.
		if err := store.Update(ctx, h1, sess); err != nil {
			t.Fatalf("Update(h1): %v", err)
		}
		if _, err := store.Get(ctx, h1); !errors.Is(err, session.ErrSessionNotFound) {
			t.Errorf("Get(h1) after Update: got %v, want ErrSessionNotFound (expiry must survive Update)", err)
		}
		// Within grace the prior hash is still accepted.
		if err := store.Rotate(ctx, h2, h3, sess, time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("Rotate h2->h3: %v", err)
		}
		if _, err := store.Get(ctx, h2); err != nil {
			t.Errorf("Get(h2) within grace: %v", err)
		}
	})

	t.Run("RotateAfterDeleteFailsAndDoesNotResurrect", func(t *testing.T) {
		sess := makeTestSession("sc-rotate-deleted", cfg)
		h1 := session.HashToken(mustGenerateToken(t))
		h2 := session.HashToken(mustGenerateToken(t))
		if err := store.Set(ctx, h1, sess); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if err := store.Delete(ctx, sess.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := store.Rotate(ctx, h1, h2, sess, time.Now().Add(time.Minute)); !errors.Is(err, session.ErrSessionNotFound) {
			t.Fatalf("Rotate after Delete: got %v, want ErrSessionNotFound", err)
		}
		for _, h := range []string{h1, h2} {
			if _, err := store.Get(ctx, h); !errors.Is(err, session.ErrSessionNotFound) {
				t.Errorf("Get after rejected Rotate: got %v, want ErrSessionNotFound", err)
			}
		}
	})

	t.Run("ConcurrentRotatesFromOneHashSucceedExactlyOnce", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			sess := makeTestSession(fmt.Sprintf("sc-rotate-once-%d", i), cfg)
			h1 := session.HashToken(mustGenerateToken(t))
			if err := store.Set(ctx, h1, sess); err != nil {
				t.Fatalf("Set: %v", err)
			}
			const rotators = 4
			results := make([]error, rotators)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for r := 0; r < rotators; r++ {
				wg.Add(1)
				go func(r int) {
					defer wg.Done()
					<-start
					results[r] = store.Rotate(ctx, h1, session.HashToken(mustGenerateToken(t)), sess, time.Now().Add(time.Minute))
				}(r)
			}
			close(start)
			wg.Wait()
			ok := 0
			for _, err := range results {
				switch {
				case err == nil:
					ok++
				case !errors.Is(err, session.ErrTokenRotated):
					t.Fatalf("iteration %d: unexpected Rotate error %v", i, err)
				}
			}
			if ok != 1 {
				t.Fatalf("iteration %d: %d Rotates succeeded from the same hash, want exactly 1", i, ok)
			}
		}
	})

	t.Run("ConcurrentRotateRacingDeleteLeavesNoLiveRow", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			sess := makeTestSession(fmt.Sprintf("sc-rotate-race-%d", i), cfg)
			h1 := session.HashToken(mustGenerateToken(t))
			h2 := session.HashToken(mustGenerateToken(t))
			if err := store.Set(ctx, h1, sess); err != nil {
				t.Fatalf("Set: %v", err)
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			var delErr error
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				_ = store.Rotate(ctx, h1, h2, sess, time.Now().Add(time.Minute))
			}()
			go func() {
				defer wg.Done()
				<-start
				delErr = store.Delete(ctx, sess.ID)
			}()
			close(start)
			wg.Wait()
			if delErr != nil {
				t.Fatalf("iteration %d: Delete: %v", i, delErr)
			}
			for _, h := range []string{h1, h2} {
				if _, err := store.Get(ctx, h); !errors.Is(err, session.ErrSessionNotFound) {
					t.Fatalf("iteration %d: hash live after Delete returned: %v", i, err)
				}
			}
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
