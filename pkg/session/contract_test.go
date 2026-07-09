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
