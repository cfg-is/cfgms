// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sharedStoreManagers returns two Managers that share one revocation store and
// one signing cursor store, as two controller nodes of a cluster would.
func sharedStoreManagers(t *testing.T) (*Manager, *Manager) {
	t.Helper()
	shared := t.TempDir()
	rev, err := NewFileRevocationStore(shared)
	require.NoError(t, err)
	cur, err := NewFileSigningCursorStore(shared)
	require.NoError(t, err)
	mk := func() *Manager {
		m, mErr := NewManager(&ManagerConfig{
			StoragePath:        t.TempDir(),
			CAConfig:           &CAConfig{Organization: "Test", Country: "US", ValidityDays: 365},
			RevocationStore:    rev,
			SigningCursorStore: cur,
		})
		require.NoError(t, mErr)
		return m
	}
	return mk(), mk()
}

func TestRevokeSigningCertificate_RecordsReasonVisibleToOtherManager(t *testing.T) {
	a, b := sharedStoreManagers(t)
	require.NoError(t, a.RevokeSigningCertificate("superseded-1", "key leaked"))

	serials, err := b.ListRevokedSigningSerials()
	require.NoError(t, err)
	assert.Equal(t, []string{"superseded-1"}, serials)

	entries, err := b.ListRevoked()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, strings.HasPrefix(entries[0].Reason, RevocationReasonSigningCert))
	assert.Contains(t, entries[0].Reason, "key leaked")

	ok, err := b.IsRevoked("superseded-1")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestListRevokedSigningSerials_IgnoresOperatorCertificates(t *testing.T) {
	a, _ := sharedStoreManagers(t)
	require.NoError(t, a.Revoke("operator-cert-1"))
	require.NoError(t, a.RevokeSigningCertificate("signing-1", ""))

	serials, err := a.ListRevokedSigningSerials()
	require.NoError(t, err)
	assert.Equal(t, []string{"signing-1"}, serials)

}

func TestRevokeSigningCertificate_RefusesCurrentAndMalformed(t *testing.T) {
	a, _ := sharedStoreManagers(t)
	first, err := a.RotateSigningCertificate(0)
	require.NoError(t, err)

	err = a.RevokeSigningCertificate(first.SerialNumber, "x")
	require.ErrorIs(t, err, ErrRevokeCurrentSigningCert)
	revoked, err := a.IsRevoked(first.SerialNumber)
	require.NoError(t, err)
	assert.False(t, revoked, "a refused revoke records nothing")

	require.ErrorIs(t, a.RevokeSigningCertificate("../etc", "x"), ErrInvalidSerial)
	require.ErrorIs(t, a.RevokeSigningCertificate("", "x"), ErrInvalidSerial)
	require.Error(t, a.RevokeSigningCertificate("ok-serial", strings.Repeat("a", 257)))
}

func TestRevokeSigningCertificate_RetiresRotatingSerialFromCursor(t *testing.T) {
	a, b := sharedStoreManagers(t)
	first, err := a.RotateSigningCertificate(0)
	require.NoError(t, err)
	second, err := a.RotateSigningCertificate(30) // first becomes rotating, window open
	require.NoError(t, err)

	cursor, err := b.GetSigningCursorState()
	require.NoError(t, err)
	require.Equal(t, first.SerialNumber, cursor.RotatingSerial)
	require.Nil(t, cursor.RetiredAt)

	require.NoError(t, a.RevokeSigningCertificate(first.SerialNumber, "compromised"))

	cursor, err = b.GetSigningCursorState()
	require.NoError(t, err)
	require.NotNil(t, cursor.RetiredAt, "revoking the rotating serial retires it in the cursor")

	valid, err := b.GetAllValidSigningCertificates()
	require.NoError(t, err)
	for _, info := range valid {
		assert.NotEqual(t, first.SerialNumber, info.SerialNumber, "a retired rotating serial is no longer a valid signer")
	}
	assert.Equal(t, second.SerialNumber, cursor.CurrentSerial)
}

func TestRetireRotatingSigningCertificate_OnceOnly(t *testing.T) {
	a, _ := sharedStoreManagers(t)
	first, err := a.RotateSigningCertificate(0)
	require.NoError(t, err)
	_, err = a.RotateSigningCertificate(30)
	require.NoError(t, err)

	did, err := a.RetireRotatingSigningCertificate(first.SerialNumber)
	require.NoError(t, err)
	assert.True(t, did)
	did, err = a.RetireRotatingSigningCertificate(first.SerialNumber)
	require.NoError(t, err)
	assert.False(t, did, "second retirement is a no-op")
}
