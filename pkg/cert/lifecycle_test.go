// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestManager creates a Manager backed by a temp directory.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(&ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig: &CAConfig{
			Organization: "Test",
			Country:      "US",
			ValidityDays: 365,
		},
	})
	require.NoError(t, err)
	return m
}

// TestSigningCursorPersistence verifies that a cursor written with saveSigningCursor
// can be read back via loadSigningCursor with byte-identical field values.
func TestSigningCursorPersistence(t *testing.T) {
	dir := t.TempDir()

	retiredAt := time.Now().UTC().Truncate(time.Second).Add(-48 * time.Hour)
	cursor := &SigningCertCursor{
		CurrentSerial:     "current-serial-abc123",
		RotatingSerial:    "rotating-serial-def456",
		OverlapWindowDays: 30,
		RotatedAt:         time.Now().UTC().Truncate(time.Second).Add(-24 * time.Hour),
		RetiredAt:         &retiredAt,
	}

	require.NoError(t, saveSigningCursor(dir, cursor))

	loaded, err := loadSigningCursor(dir)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, cursor.CurrentSerial, loaded.CurrentSerial)
	assert.Equal(t, cursor.RotatingSerial, loaded.RotatingSerial)
	assert.Equal(t, cursor.OverlapWindowDays, loaded.OverlapWindowDays)
	assert.True(t, cursor.RotatedAt.Equal(loaded.RotatedAt), "RotatedAt mismatch: %v vs %v", cursor.RotatedAt, loaded.RotatedAt)
	require.NotNil(t, loaded.RetiredAt)
	assert.True(t, cursor.RetiredAt.Equal(*loaded.RetiredAt), "RetiredAt mismatch: %v vs %v", *cursor.RetiredAt, *loaded.RetiredAt)
}

// TestSigningCursorPersistence_NilRetiredAt verifies cursor round-trip when RetiredAt is nil.
func TestSigningCursorPersistence_NilRetiredAt(t *testing.T) {
	dir := t.TempDir()

	cursor := &SigningCertCursor{
		CurrentSerial:     "current-serial-xyz",
		OverlapWindowDays: 30,
		RotatedAt:         time.Now().UTC().Truncate(time.Second),
	}

	require.NoError(t, saveSigningCursor(dir, cursor))

	loaded, err := loadSigningCursor(dir)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, cursor.CurrentSerial, loaded.CurrentSerial)
	assert.Empty(t, loaded.RotatingSerial)
	assert.Nil(t, loaded.RetiredAt)
}

// TestLoadSigningCursor_MissingFile verifies that a missing cursor file returns nil, nil.
func TestLoadSigningCursor_MissingFile(t *testing.T) {
	dir := t.TempDir()

	cursor, err := loadSigningCursor(dir)
	require.NoError(t, err)
	assert.Nil(t, cursor)
}

// TestLoadSigningCursor_CorruptFile verifies that a malformed cursor file returns an error.
func TestLoadSigningCursor_CorruptFile(t *testing.T) {
	dir := t.TempDir()

	// Write unparseable JSON to the cursor file
	cursorPath := dir + "/signing-cursor.json"
	require.NoError(t, os.WriteFile(cursorPath, []byte("{not valid json"), 0600))

	cursor, err := loadSigningCursor(dir)
	require.Error(t, err)
	assert.Nil(t, cursor)
	assert.Contains(t, err.Error(), "failed to parse signing cursor")
}

// TestTransitionSigningCursor_FirstTransition verifies that the first transition (no existing
// cursor) sets CurrentSerial and leaves RotatingSerial empty.
func TestTransitionSigningCursor_FirstTransition(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	require.NoError(t, transitionSigningCursor(store, dir, "serial-v1", 30))

	cursor, err := loadSigningCursor(dir)
	require.NoError(t, err)
	require.NotNil(t, cursor)

	assert.Equal(t, "serial-v1", cursor.CurrentSerial)
	assert.Empty(t, cursor.RotatingSerial)
	assert.Equal(t, 30, cursor.OverlapWindowDays)
	assert.False(t, cursor.RotatedAt.IsZero())
}

// TestTransitionSigningCursor_SecondTransition verifies that a second transition
// promotes the new serial to CurrentSerial and moves the old one to RotatingSerial.
func TestTransitionSigningCursor_SecondTransition(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	// First transition: establish initial signer
	require.NoError(t, transitionSigningCursor(store, dir, "serial-v1", 30))

	// Advance the RotatedAt time so the overlap window is considered expired
	cursor, err := loadSigningCursor(dir)
	require.NoError(t, err)
	// Manually backdate RotatedAt so the overlap window has expired
	cursor.RotatedAt = time.Now().UTC().Add(-31 * 24 * time.Hour)
	require.NoError(t, saveSigningCursor(dir, cursor))

	// Second transition: promote serial-v2, move serial-v1 to rotating
	require.NoError(t, transitionSigningCursor(store, dir, "serial-v2", 30))

	loaded, err := loadSigningCursor(dir)
	require.NoError(t, err)
	require.NotNil(t, loaded)

	assert.Equal(t, "serial-v2", loaded.CurrentSerial)
	assert.Equal(t, "serial-v1", loaded.RotatingSerial)
}

// TestTransitionSigningCursor_BlockedByActiveRotation verifies that a transition
// fails when RotatingSerial is set and the overlap window has not expired.
func TestTransitionSigningCursor_BlockedByActiveRotation(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	// Set up a cursor with an active rotation (RotatedAt within overlap window)
	cursor := &SigningCertCursor{
		CurrentSerial:     "serial-v2",
		RotatingSerial:    "serial-v1",
		OverlapWindowDays: 30,
		RotatedAt:         time.Now().UTC(), // just happened
	}
	require.NoError(t, saveSigningCursor(dir, cursor))

	// Trying another transition should fail
	err = transitionSigningCursor(store, dir, "serial-v3", 30)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rotation already in progress")

	// Cursor should be unchanged
	loaded, err := loadSigningCursor(dir)
	require.NoError(t, err)
	assert.Equal(t, "serial-v2", loaded.CurrentSerial)
	assert.Equal(t, "serial-v1", loaded.RotatingSerial)
}

// TestTransitionSigningCursor_AllowedAfterWindowExpired verifies that a transition
// succeeds once the overlap window has expired.
func TestTransitionSigningCursor_AllowedAfterWindowExpired(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	// Set up a cursor with an expired rotation window
	cursor := &SigningCertCursor{
		CurrentSerial:     "serial-v2",
		RotatingSerial:    "serial-v1",
		OverlapWindowDays: 30,
		RotatedAt:         time.Now().UTC().Add(-31 * 24 * time.Hour),
	}
	require.NoError(t, saveSigningCursor(dir, cursor))

	// Transition should succeed
	require.NoError(t, transitionSigningCursor(store, dir, "serial-v3", 30))

	loaded, err := loadSigningCursor(dir)
	require.NoError(t, err)
	assert.Equal(t, "serial-v3", loaded.CurrentSerial)
	assert.Equal(t, "serial-v2", loaded.RotatingSerial)
}

// TestTransitionSigningCursorConcurrency verifies that concurrent calls do not
// both succeed when RotatingSerial would be set. Exactly one goroutine's transition
// wins; all others are rejected with "rotation already in progress".
// Run with: go test -race ./pkg/cert/...
func TestTransitionSigningCursorConcurrency(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	require.NoError(t, err)

	// Establish an initial cursor (CurrentSerial only, no rotation in progress)
	initialCursor := &SigningCertCursor{
		CurrentSerial:     "old-serial",
		OverlapWindowDays: 30,
		RotatedAt:         time.Now().UTC().Add(-40 * 24 * time.Hour), // expired window
	}
	require.NoError(t, saveSigningCursor(dir, initialCursor))

	const goroutines = 20
	results := make(chan error, goroutines)

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- transitionSigningCursor(store, dir, fmt.Sprintf("new-serial-%d", i), 30)
		}(i)
	}

	wg.Wait()
	close(results)

	var successes int
	for err := range results {
		if err == nil {
			successes++
		}
	}

	assert.Equal(t, 1, successes, "exactly one concurrent transition must succeed")
}

// TestGetSigningCursorState_NoCursor verifies that GetSigningCursorState returns nil when
// no cursor file has been written.
func TestGetSigningCursorState_NoCursor(t *testing.T) {
	m := newTestManager(t)

	cursor, err := m.GetSigningCursorState()
	require.NoError(t, err)
	assert.Nil(t, cursor)
}

// TestGetSigningCursorState_WithCursor verifies that GetSigningCursorState returns the
// cursor that was written via transitionSigningCursor.
func TestGetSigningCursorState_WithCursor(t *testing.T) {
	m := newTestManager(t)

	require.NoError(t, transitionSigningCursor(m.store, m.store.basePath, "serial-v1", 30))

	cursor, err := m.GetSigningCursorState()
	require.NoError(t, err)
	require.NotNil(t, cursor)
	assert.Equal(t, "serial-v1", cursor.CurrentSerial)
}

// TestGetAllValidSigningCertificates_NoCursor verifies that when no cursor exists all
// valid signing certs are returned.
func TestGetAllValidSigningCertificates_NoCursor(t *testing.T) {
	m := newTestManager(t)

	// Generate a signing cert (no cursor written)
	sigCert, err := m.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	certs, err := m.GetAllValidSigningCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, sigCert.SerialNumber, certs[0].SerialNumber)
}

// TestGetAllValidSigningCertificates_CurrentOnly verifies that when the cursor has only a
// CurrentSerial, that certificate is returned.
func TestGetAllValidSigningCertificates_CurrentOnly(t *testing.T) {
	m := newTestManager(t)

	sigCert, err := m.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Establish cursor pointing at the cert
	require.NoError(t, transitionSigningCursor(m.store, m.store.basePath, sigCert.SerialNumber, 30))

	certs, err := m.GetAllValidSigningCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, sigCert.SerialNumber, certs[0].SerialNumber)
}

// TestGetAllValidSigningCertificates_IncludesRotatingWithinWindow verifies that
// RotatingSerial is included when the overlap window has not expired.
func TestGetAllValidSigningCertificates_IncludesRotatingWithinWindow(t *testing.T) {
	m := newTestManager(t)

	oldCert, err := m.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer-old",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	newCert, err := m.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer-new",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Set up cursor: new is current, old is rotating, overlap window active
	cursor := &SigningCertCursor{
		CurrentSerial:     newCert.SerialNumber,
		RotatingSerial:    oldCert.SerialNumber,
		OverlapWindowDays: 30,
		RotatedAt:         time.Now().UTC(), // just rotated, window is open
	}
	require.NoError(t, saveSigningCursor(m.store.basePath, cursor))

	certs, err := m.GetAllValidSigningCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 2, "both current and rotating certs must be returned within overlap window")

	serials := make(map[string]bool, 2)
	for _, c := range certs {
		serials[c.SerialNumber] = true
	}
	assert.True(t, serials[newCert.SerialNumber], "current cert must be included")
	assert.True(t, serials[oldCert.SerialNumber], "rotating cert must be included within window")
}

// TestGetAllValidSigningCertificates_ExcludesRotatingAfterWindow verifies that
// RotatingSerial is excluded once the overlap window has expired.
func TestGetAllValidSigningCertificates_ExcludesRotatingAfterWindow(t *testing.T) {
	m := newTestManager(t)

	oldCert, err := m.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer-old",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	newCert, err := m.GenerateSigningCertificate(&SigningCertConfig{
		CommonName:   "cfgms-config-signer-new",
		ValidityDays: 365,
	})
	require.NoError(t, err)

	// Set up cursor with an expired overlap window
	cursor := &SigningCertCursor{
		CurrentSerial:     newCert.SerialNumber,
		RotatingSerial:    oldCert.SerialNumber,
		OverlapWindowDays: 30,
		RotatedAt:         time.Now().UTC().Add(-31 * 24 * time.Hour), // window expired
	}
	require.NoError(t, saveSigningCursor(m.store.basePath, cursor))

	certs, err := m.GetAllValidSigningCertificates()
	require.NoError(t, err)
	require.Len(t, certs, 1, "only current cert must be returned after overlap window expires")
	assert.Equal(t, newCert.SerialNumber, certs[0].SerialNumber)
}
