// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"fmt"
	"sort"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

// SigningMigrationSet is what the steward-side migration (Issue #4797) needs from
// the shared store: the shared signing identity and every legacy node-local
// signer held in the migration namespace. Its fields hold private key material
// and must never be logged.
type SigningMigrationSet struct {
	// Shared is the material of the serial the shared cursor names. Nil unless
	// the Manager is in Shared identity mode.
	Shared *certinterfaces.SigningKeyMaterial
	// Legacy is the migration-namespace material of every serial other than the
	// shared one that is not revoked, sorted by serial. A revoked key is never
	// used to sign.
	Legacy []*certinterfaces.SigningKeyMaterial
	// LegacySerials is every migration-namespace serial other than the shared
	// one, revoked or not, sorted. A steward is told to retire all of them.
	LegacySerials []string
}

// SigningMigrationSet reads the shared signing identity and the legacy migration
// signers. It returns ErrNoSigningKeyStore when the Manager has no shared store.
// Outside Shared mode Shared is nil and nothing else is read: there is no shared
// certificate to deliver. A failed read is an error, never a partial set.
func (m *Manager) SigningMigrationSet(ctx context.Context) (*SigningMigrationSet, error) {
	if m.signingKeys == nil {
		return nil, ErrNoSigningKeyStore
	}
	mode, shared, err := m.resolveSigningIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve signing identity: %w", err)
	}
	set := &SigningMigrationSet{}
	if mode != SigningIdentityShared || shared == nil {
		return set, nil
	}
	set.Shared = shared

	serials, err := m.signingKeys.ListMigrationSigners(ctx)
	if err != nil {
		return nil, fmt.Errorf("list migration signers: %w", err)
	}
	sort.Strings(serials)
	for _, serial := range serials {
		if serial == shared.Serial {
			continue
		}
		set.LegacySerials = append(set.LegacySerials, serial)
		revoked, err := m.IsRevoked(serial)
		if err != nil {
			return nil, fmt.Errorf("check revocation of migration signer: %w", err)
		}
		if revoked {
			continue
		}
		mat, err := m.signingKeys.GetMigrationSigner(ctx, serial)
		if err != nil {
			return nil, fmt.Errorf("read migration signer: %w", err)
		}
		set.Legacy = append(set.Legacy, mat)
	}
	return set, nil
}
