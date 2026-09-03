// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRevokeAdminBundle_PersistsAcrossRestart verifies that a revoked serial
// survives a Manager restart by re-reading the revocation.json file.
func TestRevokeAdminBundle_PersistsAcrossRestart(t *testing.T) {
	tempDir := t.TempDir()

	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	c, err := manager.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "test-operator",
		Organization: "CFGMS",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	require.NoError(t, manager.Revoke(c.SerialNumber))
	revoked, err := manager.IsRevoked(c.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked)

	// Simulate restart: new Manager, same storage path
	manager2, err := NewManager(&ManagerConfig{
		StoragePath:    tempDir,
		LoadExistingCA: true,
	})
	require.NoError(t, err)

	revoked, err = manager2.IsRevoked(c.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked, "revocation must persist across Manager restart")
}

// TestRevoke_UnknownSerial_SucceedsClusterWide verifies that revoking a
// serial not found in this node's local certificate store still succeeds,
// rather than erroring. The certificate store (pkg/cert's FileStore) stays
// node-local by design (Issue #3852 keeps it out of scope), so on a
// clustered controller a serial issued on another node is legitimately
// absent locally; requiring local presence made revocation silently fail
// off the issuing node (Issue #3761 escalation finding 2). Only an empty
// serial is now rejected — see TestRevoke_EmptySerial_Errors.
func TestRevoke_UnknownSerial_SucceedsClusterWide(t *testing.T) {
	manager := setupTestManager(t)

	err := manager.Revoke("00000000-nonexistent-serial-9999")
	require.NoError(t, err, "revoking a serial absent from this node's local store must not error")

	revoked, err := manager.IsRevoked("00000000-nonexistent-serial-9999")
	require.NoError(t, err)
	assert.True(t, revoked)
}

// TestRevoke_EmptySerial_Errors verifies that revoking an empty serial
// returns an error — the one input validation Revoke still performs.
func TestRevoke_EmptySerial_Errors(t *testing.T) {
	manager := setupTestManager(t)

	err := manager.Revoke("")
	assert.Error(t, err)
}

// TestIsRevoked_FalseBeforeRevoke verifies that a freshly-issued cert is not revoked.
func TestIsRevoked_FalseBeforeRevoke(t *testing.T) {
	manager := setupTestManager(t)

	c, err := manager.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "alice",
		Organization: "CFGMS",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	revoked, err := manager.IsRevoked(c.SerialNumber)
	require.NoError(t, err)
	assert.False(t, revoked, "freshly-issued cert must not be revoked")
}

// TestListRevoked_ReturnsEntry verifies that ListRevoked returns the revoked serial.
func TestListRevoked_ReturnsEntry(t *testing.T) {
	tempDir := t.TempDir()

	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	c, err := manager.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "bob",
		Organization: "CFGMS",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	require.NoError(t, manager.Revoke(c.SerialNumber))

	entries, err := manager.ListRevoked()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, c.SerialNumber, entries[0].Serial)
	assert.False(t, entries[0].RevokedAt.IsZero())
}

// TestRevocationConcurrentAccess verifies that concurrent reads and a write
// do not race (run with -race to confirm).
func TestRevocationConcurrentAccess(t *testing.T) {
	tempDir := t.TempDir()

	manager, err := NewManager(&ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)

	c, err := manager.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "concurrency-test",
		Organization: "CFGMS",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	const readers = 50
	var wg sync.WaitGroup
	wg.Add(readers + 1)

	// Spawn concurrent readers
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			_, _ = manager.IsRevoked(c.SerialNumber)
		}()
	}

	// Concurrent writer
	go func() {
		defer wg.Done()
		_ = manager.Revoke(c.SerialNumber)
	}()

	wg.Wait()
	// Race correctness verified by the race detector; also confirm the revoke actually persisted.
	revoked, err := manager.IsRevoked(c.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked, "revoke must persist after concurrent access")
}

// TestRevokeIdempotent verifies that revoking the same serial twice is a no-op and
// the original RevokedAt timestamp is preserved.
func TestRevokeIdempotent(t *testing.T) {
	manager := setupTestManager(t)

	c, err := manager.GenerateClientCertificate(&ClientCertConfig{
		CommonName:   "idempotent-test",
		Organization: "CFGMS",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	require.NoError(t, manager.Revoke(c.SerialNumber))

	entries1, err := manager.ListRevoked()
	require.NoError(t, err)
	require.Len(t, entries1, 1)
	firstRevokedAt := entries1[0].RevokedAt

	require.NoError(t, manager.Revoke(c.SerialNumber), "double-revoke must not error")

	entries2, err := manager.ListRevoked()
	require.NoError(t, err)
	require.Len(t, entries2, 1, "revocation list must not grow on double-revoke")
	assert.Equal(t, firstRevokedAt, entries2[0].RevokedAt,
		"original RevokedAt timestamp must be preserved on double-revoke")
}
