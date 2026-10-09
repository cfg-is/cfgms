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

// supersededSigningSerial rotates the signing certificate twice on m and
// returns the serial of the first, now superseded, signing certificate.
func supersededSigningSerial(t *testing.T, m *Manager) string {
	t.Helper()
	first, err := m.RotateSigningCertificate(0)
	require.NoError(t, err)
	_, err = m.ForceRotateSigningCertificate(30)
	require.NoError(t, err)
	return first.SerialNumber
}

func TestRevokeSigningCertificate_RecordsReasonVisibleToOtherManager(t *testing.T) {
	a, b := sharedStoreManagers(t)
	superseded := supersededSigningSerial(t, a)
	require.NoError(t, a.RevokeSigningCertificate(superseded, "key leaked"))

	serials, err := b.ListRevokedSigningSerials()
	require.NoError(t, err)
	assert.Equal(t, []string{superseded}, serials)

	entries, err := b.ListRevoked()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.True(t, strings.HasPrefix(entries[0].Reason, RevocationReasonSigningCert))
	assert.Contains(t, entries[0].Reason, "key leaked")

	ok, err := b.IsRevoked(superseded)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestListRevokedSigningSerials_IgnoresOperatorCertificates(t *testing.T) {
	a, _ := sharedStoreManagers(t)
	superseded := supersededSigningSerial(t, a)
	require.NoError(t, a.Revoke("operator-cert-1"))
	require.NoError(t, a.RevokeSigningCertificate(superseded, ""))

	serials, err := a.ListRevokedSigningSerials()
	require.NoError(t, err)
	assert.Equal(t, []string{superseded}, serials)
}

// The signing revoke shares the revocation store that gates mTLS admin login and
// steward connections, so it must refuse any serial that is not a known signing
// certificate and record nothing for it.
func TestRevokeSigningCertificate_RefusesNonSigningCertificates(t *testing.T) {
	a, b := sharedStoreManagers(t)
	supersededSigningSerial(t, a)

	admin, err := a.GenerateClientCertificate(&ClientCertConfig{
		CommonName: "operator-admin", Organization: "Test", ValidityDays: 1, TemplateModifier: SetAdminMarker,
	})
	require.NoError(t, err)
	client, err := a.GenerateClientCertificate(&ClientCertConfig{
		CommonName: "steward-1", Organization: "Test", ValidityDays: 1,
	})
	require.NoError(t, err)

	for name, serial := range map[string]string{
		"admin_cert":     admin.SerialNumber,
		"client_cert":    client.SerialNumber,
		"unknown_serial": "0123456789abcdef",
	} {
		t.Run(name, func(t *testing.T) {
			err := a.RevokeSigningCertificate(serial, "x")
			require.ErrorIs(t, err, ErrNotSigningCertificate)
			require.ErrorIs(t, err, ErrInvalidSerial, "maps to 400 at the API")
			for _, m := range []*Manager{a, b} {
				revoked, rErr := m.IsRevoked(serial)
				require.NoError(t, rErr)
				assert.False(t, revoked, "a refused signing revoke writes nothing to the revocation store")
			}
		})
	}

	entries, err := b.ListRevoked()
	require.NoError(t, err)
	assert.Empty(t, entries)
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
	require.Error(t, a.RevokeSigningCertificate(first.SerialNumber, strings.Repeat("a", 257)))
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

// In cluster mode a node may not hold a superseded signing certificate locally;
// the shared signing key store is what identifies it as a signing certificate.
func TestRevokeSigningCertificate_ClusterResolvesThroughKeyStore(t *testing.T) {
	c := newSigningCluster(t)
	a, _ := c.node(t, c.secrets, true)
	b, _ := c.node(t, c.secrets, true)
	require.NoError(t, a.EnsureSigningCertificate(fastSigningCfg))

	oldest, err := a.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	_, err = a.ForceRotateSigningCertificate(30)
	require.NoError(t, err)
	_, err = a.ForceRotateSigningCertificate(30) // oldest leaves the cursor
	require.NoError(t, err)

	cursor, err := b.GetSigningCursorState()
	require.NoError(t, err)
	require.NotEqual(t, oldest.SerialNumber, cursor.RotatingSerial)
	require.NotEqual(t, oldest.SerialNumber, cursor.CurrentSerial)

	require.NoError(t, b.RevokeSigningCertificate(oldest.SerialNumber, "compromised"))
	revoked, err := b.IsRevoked(oldest.SerialNumber)
	require.NoError(t, err)
	assert.True(t, revoked)

	admin, err := b.GenerateClientCertificate(&ClientCertConfig{
		CommonName: "operator-admin", Organization: "Test", ValidityDays: 1, TemplateModifier: SetAdminMarker,
	})
	require.NoError(t, err)
	require.ErrorIs(t, b.RevokeSigningCertificate(admin.SerialNumber, "x"), ErrNotSigningCertificate)
	revoked, err = b.IsRevoked(admin.SerialNumber)
	require.NoError(t, err)
	assert.False(t, revoked)
}
