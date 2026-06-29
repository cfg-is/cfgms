// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package credential_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cfgis/cfgms/pkg/credential"
)

// stubUnlocker satisfies CredentialUnlocker for compile-time interface verification.
type stubUnlocker struct{}

func (s *stubUnlocker) Unlock(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (s *stubUnlocker) Lock(_ context.Context, _ string) error             { return nil }

// TestCredentialUnlockerInterfaceSatisfied verifies the interface can be satisfied by a concrete type.
func TestCredentialUnlockerInterfaceSatisfied(t *testing.T) {
	var _ credential.CredentialUnlocker = (*stubUnlocker)(nil)
}

// TestSentinelsAreDistinctErrors verifies ErrLocked and ErrNoUnlocker are separate sentinel values.
func TestSentinelsAreDistinctErrors(t *testing.T) {
	if credential.ErrLocked == nil {
		t.Fatal("ErrLocked must not be nil")
	}
	if credential.ErrNoUnlocker == nil {
		t.Fatal("ErrNoUnlocker must not be nil")
	}
	if errors.Is(credential.ErrLocked, credential.ErrNoUnlocker) {
		t.Fatal("ErrLocked and ErrNoUnlocker must be distinct error values")
	}
	if errors.Is(credential.ErrNoUnlocker, credential.ErrLocked) {
		t.Fatal("ErrNoUnlocker and ErrLocked must be distinct error values")
	}
}

// TestSentinelWrapping verifies sentinels are identifiable via errors.Is when wrapped.
func TestSentinelWrapping(t *testing.T) {
	wrapped := errors.Join(credential.ErrLocked, errors.New("additional context"))
	if !errors.Is(wrapped, credential.ErrLocked) {
		t.Fatal("wrapped ErrLocked must be identifiable via errors.Is")
	}
}
