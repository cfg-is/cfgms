// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Contract test for RevocationStore and SigningCursorStore (Issue #3852, AC7).
// Runs the same semantics against every implementation: pkg/cert's file-backed
// store (single-node, always exercised) and the Postgres-backed store
// (pkg/storage/providers/database; skipped when no test database is reachable,
// matching the convention pkg/storage/providers/database's own tests use).
package interfaces_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

// storeProviderCase names one implementation pair to run the shared contract
// against. newStores returns fresh, isolated stores or an empty skip reason.
type storeProviderCase struct {
	name      string
	newStores func(t *testing.T) (certinterfaces.RevocationStore, certinterfaces.SigningCursorStore, string /* skip reason */)
}

// registeredProviderCases holds cases contributed by providers_test.go
// (the database-backed case), which must live in a *providers_test.go file
// so it — not this file — carries the pkg/storage/providers/database import
// (see scripts/check-providers.sh's storage-provider-import allowlist).
var registeredProviderCases []storeProviderCase

func storeProviderCases() []storeProviderCase {
	cases := []storeProviderCase{
		{
			name: "file",
			newStores: func(t *testing.T) (certinterfaces.RevocationStore, certinterfaces.SigningCursorStore, string) {
				dir := t.TempDir()
				rev, err := cert.NewFileRevocationStore(dir)
				require.NoError(t, err)
				cur, err := cert.NewFileSigningCursorStore(dir)
				require.NoError(t, err)
				return rev, cur, ""
			},
		},
	}
	return append(cases, registeredProviderCases...)
}

func TestRevocationStore_Contract(t *testing.T) {
	for _, tc := range storeProviderCases() {
		t.Run(tc.name, func(t *testing.T) {
			revStore, _, skip := tc.newStores(t)
			if skip != "" {
				t.Skip(skip)
			}
			ctx := context.Background()

			revoked, err := revStore.IsRevoked(ctx, "serial-1")
			require.NoError(t, err)
			assert.False(t, revoked, "an unrevoked serial must report false")

			first := time.Now().UTC().Truncate(time.Second)
			require.NoError(t, revStore.Revoke(ctx, certinterfaces.RevocationEntry{
				Serial: "serial-1", RevokedAt: first, Reason: "compromised",
			}))

			revoked, err = revStore.IsRevoked(ctx, "serial-1")
			require.NoError(t, err)
			assert.True(t, revoked)

			// Repeated revoke of the same serial is a no-op: original RevokedAt wins.
			require.NoError(t, revStore.Revoke(ctx, certinterfaces.RevocationEntry{
				Serial: "serial-1", RevokedAt: first.Add(time.Hour), Reason: "attacker-supplied",
			}))
			entries, err := revStore.ListRevoked(ctx)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.True(t, first.Equal(entries[0].RevokedAt), "original RevokedAt must be preserved on double-revoke")

			revoked, err = revStore.IsRevoked(ctx, "serial-never-revoked")
			require.NoError(t, err)
			assert.False(t, revoked)
		})
	}
}

func TestSigningCursorStore_Contract(t *testing.T) {
	for _, tc := range storeProviderCases() {
		t.Run(tc.name, func(t *testing.T) {
			_, curStore, skip := tc.newStores(t)
			if skip != "" {
				t.Skip(skip)
			}
			ctx := context.Background()

			cursor, err := curStore.LoadCursor(ctx)
			require.NoError(t, err)
			assert.Nil(t, cursor, "no rotation has occurred yet")

			cursor, err = curStore.TransitionCursor(ctx, "serial-v1", 30, false)
			require.NoError(t, err)
			require.NotNil(t, cursor)
			assert.Equal(t, "serial-v1", cursor.CurrentSerial)
			assert.Empty(t, cursor.RotatingSerial)

			cursor, err = curStore.TransitionCursor(ctx, "serial-v2", 30, false)
			require.NoError(t, err)
			assert.Equal(t, "serial-v2", cursor.CurrentSerial)
			assert.Equal(t, "serial-v1", cursor.RotatingSerial)

			// A third transition within the 30-day overlap window must be rejected.
			_, err = curStore.TransitionCursor(ctx, "serial-v3", 30, false)
			require.Error(t, err)
			assert.True(t, errors.Is(err, certinterfaces.ErrSigningRotationInProgress))

			loaded, err := curStore.LoadCursor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "serial-v2", loaded.CurrentSerial, "cursor must be unchanged after a rejected transition")

			// force bypasses the in-progress guard.
			cursor, err = curStore.TransitionCursor(ctx, "serial-v3", 7, true)
			require.NoError(t, err)
			assert.Equal(t, "serial-v3", cursor.CurrentSerial)
			assert.Equal(t, "serial-v2", cursor.RotatingSerial)
		})
	}
}

// TestSigningCursorStore_MarkRetired_Contract: MarkRetired sets RetiredAt once,
// only for the named rotating serial, and never changes anything on a repeat
// or mismatched call (Issue #4795).
func TestSigningCursorStore_MarkRetired_Contract(t *testing.T) {
	for _, tc := range storeProviderCases() {
		t.Run(tc.name, func(t *testing.T) {
			_, curStore, skip := tc.newStores(t)
			if skip != "" {
				t.Skip(skip)
			}
			ctx := context.Background()

			// No cursor yet: nothing to retire.
			got, err := curStore.MarkRetired(ctx, "serial-v1", time.Now())
			require.NoError(t, err)
			assert.Nil(t, got, "no cursor means nothing is retired")

			_, err = curStore.TransitionCursor(ctx, "serial-v1", 0, false)
			require.NoError(t, err)
			_, err = curStore.TransitionCursor(ctx, "serial-v2", 0, false)
			require.NoError(t, err)

			// Mismatched serial changes nothing.
			got, err = curStore.MarkRetired(ctx, "not-the-rotating-serial", time.Now())
			require.NoError(t, err)
			assert.Nil(t, got)
			loaded, err := curStore.LoadCursor(ctx)
			require.NoError(t, err)
			assert.Nil(t, loaded.RetiredAt)

			first := time.Now().UTC().Truncate(time.Second)
			got, err = curStore.MarkRetired(ctx, "serial-v1", first)
			require.NoError(t, err)
			require.NotNil(t, got)
			require.NotNil(t, got.RetiredAt)
			assert.Equal(t, "serial-v1", got.RotatingSerial)

			// A second call keeps the first timestamp and reports no change.
			got, err = curStore.MarkRetired(ctx, "serial-v1", first.Add(time.Hour))
			require.NoError(t, err)
			assert.Nil(t, got, "a repeat call changes nothing")
			loaded, err = curStore.LoadCursor(ctx)
			require.NoError(t, err)
			require.NotNil(t, loaded.RetiredAt)
			assert.WithinDuration(t, first, *loaded.RetiredAt, time.Second)

			// A later rotation starts a fresh, un-retired window.
			_, err = curStore.TransitionCursor(ctx, "serial-v3", 0, false)
			require.NoError(t, err)
			loaded, err = curStore.LoadCursor(ctx)
			require.NoError(t, err)
			assert.Equal(t, "serial-v2", loaded.RotatingSerial)
			assert.Nil(t, loaded.RetiredAt)
		})
	}
}

// ackStoreCase names one SigningTrustAckStore implementation to run the shared
// contract against (Issue #4691). newStore returns a fresh, isolated store or
// a non-empty skip reason.
type ackStoreCase struct {
	name     string
	newStore func(t *testing.T) (certinterfaces.SigningTrustAckStore, string /* skip reason */)
}

// registeredAckCases holds cases contributed by providers_test.go (database).
var registeredAckCases []ackStoreCase

func ackStoreCases() []ackStoreCase {
	cases := []ackStoreCase{
		{
			name: "file",
			newStore: func(t *testing.T) (certinterfaces.SigningTrustAckStore, string) {
				s, err := cert.NewFileSigningTrustAckStore(t.TempDir())
				require.NoError(t, err)
				return s, ""
			},
		},
	}
	return append(cases, registeredAckCases...)
}

func TestSigningTrustAckStore_Contract(t *testing.T) {
	for _, tc := range ackStoreCases() {
		t.Run(tc.name, func(t *testing.T) {
			store, skip := tc.newStore(t)
			if skip != "" {
				t.Skip(skip)
			}
			ctx := context.Background()

			got, err := store.GetAck(ctx, "steward-1", "serial-a")
			require.NoError(t, err)
			assert.Nil(t, got, "GetAck must be nil before RecordAck")

			listed, err := store.ListAcked(ctx, "serial-a")
			require.NoError(t, err)
			assert.Empty(t, listed)

			before := time.Now().Add(-time.Minute)
			require.NoError(t, store.RecordAck(ctx, "steward-1", "serial-a"))
			got, err = store.GetAck(ctx, "steward-1", "serial-a")
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, "steward-1", got.StewardID)
			assert.Equal(t, "serial-a", got.Serial)
			assert.True(t, got.AcknowledgedAt.After(before), "AcknowledgedAt must be set to roughly now")

			// A second RecordAck keeps the first AcknowledgedAt.
			time.Sleep(20 * time.Millisecond)
			require.NoError(t, store.RecordAck(ctx, "steward-1", "serial-a"))
			again, err := store.GetAck(ctx, "steward-1", "serial-a")
			require.NoError(t, err)
			require.NotNil(t, again)
			assert.True(t, got.AcknowledgedAt.Equal(again.AcknowledgedAt), "first AcknowledgedAt must win")

			// Different stewards and serials do not collide.
			require.NoError(t, store.RecordAck(ctx, "steward-2", "serial-a"))
			require.NoError(t, store.RecordAck(ctx, "steward-1", "serial-b"))
			require.NoError(t, store.RecordAck(ctx, "steward-3", "serial-b"))

			listed, err = store.ListAcked(ctx, "serial-a")
			require.NoError(t, err)
			require.Len(t, listed, 2)
			assert.Equal(t, "steward-1", listed[0].StewardID)
			assert.Equal(t, "steward-2", listed[1].StewardID)

			listed, err = store.ListAcked(ctx, "serial-b")
			require.NoError(t, err)
			require.Len(t, listed, 2)
			assert.Equal(t, "steward-1", listed[0].StewardID)
			assert.Equal(t, "steward-3", listed[1].StewardID)

			missing, err := store.GetAck(ctx, "steward-2", "serial-b")
			require.NoError(t, err)
			assert.Nil(t, missing)

			// Empty identifiers are rejected.
			assert.Error(t, store.RecordAck(ctx, "", "serial-a"))
			assert.Error(t, store.RecordAck(ctx, "steward-1", ""))
		})
	}
}
