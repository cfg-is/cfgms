// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

// preUpgradeManager builds a Manager with no key store (the pre-#4692 shape) and
// provisions its signing certificate, then returns it and the directory.
func preUpgradeManager(t *testing.T) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	m, err := NewManager(&ManagerConfig{
		StoragePath: dir,
		CAConfig:    &CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
	})
	require.NoError(t, err)
	require.NoError(t, m.EnsureSigningCertificate(fastSigningCfg))
	return m, dir
}

// upgradedManager reopens dir with a single-node key store, as the controller
// does on the first start after upgrade.
func upgradedManager(t *testing.T, dir string, ks certinterfaces.SigningKeyStore) *Manager {
	t.Helper()
	m, err := NewManager(&ManagerConfig{StoragePath: dir, LoadExistingCA: true, SigningKeyStore: ks})
	require.NoError(t, err)
	return m
}

func singleNodeKeyStore(t *testing.T, secrets *inMemSecretStore) certinterfaces.SigningKeyStore {
	t.Helper()
	ks, err := NewSingleNodeSigningKeyStore(secrets, testSigningTenant, "")
	require.NoError(t, err)
	return ks
}

func TestAdoptLocalSigningIdentity_KeepsSerialAndKey(t *testing.T) {
	ctx := context.Background()
	pre, dir := preUpgradeManager(t)
	before, err := pre.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)

	m := upgradedManager(t, dir, singleNodeKeyStore(t, newInMemSecretStore()))
	mode, err := m.SigningIdentityMode(ctx)
	require.NoError(t, err)
	assert.Equal(t, SigningIdentityLegacyLocal, mode)

	res, err := m.AdoptLocalSigningIdentity(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{before.SerialNumber}, res.AdoptedSerials)
	assert.Equal(t, []string{before.SerialNumber}, res.RemovedKeySerials)
	assert.Empty(t, res.RefusedSerials)

	mode, err = m.SigningIdentityMode(ctx)
	require.NoError(t, err)
	assert.Equal(t, SigningIdentityShared, mode)

	after, err := m.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	assert.Equal(t, before.SerialNumber, after.SerialNumber)
	assert.Equal(t, before.CertificatePEM, after.CertificatePEM)

	certPEM, keyPEM, err := m.ExportCertificate(before.SerialNumber, true, false)
	require.NoError(t, err)
	require.NoError(t, ValidateKeyPair(before.CertificatePEM, keyPEM))
	assert.Equal(t, before.CertificatePEM, certPEM)

	cursor, err := m.cursor.LoadCursor(ctx)
	require.NoError(t, err)
	require.NotNil(t, cursor)
	assert.Equal(t, before.SerialNumber, cursor.CurrentSerial)
}

func TestAdoptLocalSigningIdentity_AdoptsRotatingSerial(t *testing.T) {
	ctx := context.Background()
	pre, dir := preUpgradeManager(t)
	old, err := pre.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	rotated, err := pre.RotateSigningCertificate(7)
	require.NoError(t, err)

	secrets := newInMemSecretStore()
	ks := singleNodeKeyStore(t, secrets)
	m := upgradedManager(t, dir, ks)
	cursorBefore, err := m.cursor.LoadCursor(ctx)
	require.NoError(t, err)

	res, err := m.AdoptLocalSigningIdentity(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{old.SerialNumber, rotated.SerialNumber}, res.AdoptedSerials)
	assert.ElementsMatch(t, []string{old.SerialNumber, rotated.SerialNumber}, res.RemovedKeySerials)

	cursorAfter, err := m.cursor.LoadCursor(ctx)
	require.NoError(t, err)
	assert.Equal(t, cursorBefore, cursorAfter, "adoption leaves the cursor unchanged")
	assert.Equal(t, old.SerialNumber, cursorAfter.RotatingSerial)

	certPEM, keyPEM, err := m.ExportCertificate(old.SerialNumber, true, false)
	require.NoError(t, err)
	require.NoError(t, ValidateKeyPair(certPEM, keyPEM))
	assert.Empty(t, signingKeyFiles(t, dir))
}

// getFailKeyStore wraps a SigningKeyStore and corrupts or fails GetSigningKey.
type getFailKeyStore struct {
	certinterfaces.SigningKeyStore
	other *certinterfaces.SigningKeyMaterial
	err   error
}

func (g *getFailKeyStore) GetSigningKey(ctx context.Context, serial string) (*certinterfaces.SigningKeyMaterial, error) {
	if g.err != nil {
		return nil, g.err
	}
	if g.other != nil {
		out := *g.other
		out.Serial = serial
		return &out, nil
	}
	return g.SigningKeyStore.GetSigningKey(ctx, serial)
}

func TestAdoptLocalSigningIdentity_RemovesKeysOnlyAfterReadBack(t *testing.T) {
	ctx := context.Background()

	t.Run("success removes every signing key.pem and keeps cert.pem", func(t *testing.T) {
		pre, dir := preUpgradeManager(t)
		cur, err := pre.GetCurrentCertForPurpose(PurposeSigning)
		require.NoError(t, err)
		require.NotEmpty(t, signingKeyFiles(t, dir))

		m := upgradedManager(t, dir, singleNodeKeyStore(t, newInMemSecretStore()))
		_, err = m.AdoptLocalSigningIdentity(ctx)
		require.NoError(t, err)
		assert.Empty(t, signingKeyFiles(t, dir))
		local, err := m.store.GetCertificate(cur.SerialNumber)
		require.NoError(t, err)
		assert.NotEmpty(t, local.CertificatePEM, "cert.pem stays")
		assert.Empty(t, local.PrivateKeyPEM)
	})

	other := preMaterial(t)
	cases := map[string]*getFailKeyStore{
		"different material on read-back": {other: other},
		"read-back error":                 {err: errors.New("store unavailable")},
	}
	for name, wrap := range cases {
		t.Run(name, func(t *testing.T) {
			_, dir := preUpgradeManager(t)
			wrap.SigningKeyStore = singleNodeKeyStore(t, newInMemSecretStore())
			m := upgradedManager(t, dir, wrap)
			before := signingKeyFiles(t, dir)
			require.NotEmpty(t, before)

			_, err := m.AdoptLocalSigningIdentity(ctx)
			require.Error(t, err)
			assert.Equal(t, before, signingKeyFiles(t, dir), "no local key removed")
			assert.NotContains(t, err.Error(), "PRIVATE KEY")
		})
	}
}

// preMaterial returns signing material for an unrelated certificate.
func preMaterial(t *testing.T) *certinterfaces.SigningKeyMaterial {
	t.Helper()
	m, _ := preUpgradeManager(t)
	c, err := m.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	return signingMaterialFromCertificate(c)
}

func TestAdoptLocalSigningIdentity_RefusesInvalidCurrentCertificate(t *testing.T) {
	ctx := context.Background()
	foreign := newSigningCluster(t)
	foreignNode, _ := foreign.node(t, foreign.secrets, true)

	cases := []struct {
		name   string
		opts   customSigningOpts
		reason string
	}{
		{"foreign CA", customSigningOpts{issuer: foreignNode}, "not issued by the cluster CA"},
		{"expired", customSigningOpts{expired: true}, "expired"},
		{"no CodeSigning EKU", customSigningOpts{noEKU: true}, "CodeSigning"},
		{"key mismatch", customSigningOpts{wrongKey: true}, "does not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A CA with no signing certificate of its own, so the defective one is current.
			dir := t.TempDir()
			bare, err := NewManager(&ManagerConfig{
				StoragePath: dir,
				CAConfig:    &CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
			})
			require.NoError(t, err)
			require.NoError(t, bare.Close())
			secrets := newInMemSecretStore()
			m := upgradedManager(t, dir, singleNodeKeyStore(t, secrets))
			// A defective certificate that is the newest, so it is the current one.
			serial := storeCustomSigningCert(t, m, tc.opts)
			if tc.opts.expired {
				// An expired certificate is never "current"; name it through the cursor.
				_, _, err := m.cursor.SeedCursorIfAbsent(ctx, serial)
				require.NoError(t, err)
			}
			before := signingKeyFiles(t, dir)

			res, err := m.AdoptLocalSigningIdentity(ctx)
			require.NoError(t, err)
			require.Len(t, res.RefusedSerials, 1)
			assert.Equal(t, serial, res.RefusedSerials[0].Serial)
			assert.Contains(t, res.RefusedSerials[0].Reason, tc.reason)
			assert.Empty(t, res.AdoptedSerials)
			assert.Empty(t, res.RemovedKeySerials)

			serials, err := m.signingKeys.ListSigningSerials(ctx)
			require.NoError(t, err)
			assert.Empty(t, serials, "the key store is unchanged")
			assert.Equal(t, before, signingKeyFiles(t, dir), "no local file removed")
			mode, err := m.SigningIdentityMode(ctx)
			require.NoError(t, err)
			assert.Equal(t, SigningIdentityLegacyLocal, mode)
		})
	}
}

func TestAdoptLocalSigningIdentity_IdempotentAcrossRestarts(t *testing.T) {
	ctx := context.Background()
	_, dir := preUpgradeManager(t)

	m := upgradedManager(t, dir, singleNodeKeyStore(t, newInMemSecretStore()))
	first, err := m.AdoptLocalSigningIdentity(ctx)
	require.NoError(t, err)
	require.Len(t, first.AdoptedSerials, 1)

	again, err := m.AdoptLocalSigningIdentity(ctx)
	require.NoError(t, err)
	assert.Empty(t, again.AdoptedSerials)
	assert.Empty(t, again.RefusedSerials)
	assert.Empty(t, again.RemovedKeySerials)

	t.Run("stop after PutSigningKey completes on the next call", func(t *testing.T) {
		pre2, dir2 := preUpgradeManager(t)
		cur2, err := pre2.GetCurrentCertForPurpose(PurposeSigning)
		require.NoError(t, err)
		m2 := upgradedManager(t, dir2, singleNodeKeyStore(t, newInMemSecretStore()))
		require.NoError(t, m2.signingKeys.PutSigningKey(ctx, signingMaterialFromCertificate(cur2)))
		require.NotEmpty(t, signingKeyFiles(t, dir2))
		cursor, err := m2.cursor.LoadCursor(ctx)
		require.NoError(t, err)
		require.Nil(t, cursor)

		res, err := m2.AdoptLocalSigningIdentity(ctx)
		require.NoError(t, err)
		assert.Equal(t, []string{cur2.SerialNumber}, res.RemovedKeySerials)
		cursor, err = m2.cursor.LoadCursor(ctx)
		require.NoError(t, err)
		require.NotNil(t, cursor)
		assert.Equal(t, cur2.SerialNumber, cursor.CurrentSerial)
		assert.Empty(t, signingKeyFiles(t, dir2))
	})
}

func TestAdoptLocalSigningIdentity_RefusesClusterKeyStore(t *testing.T) {
	ctx := context.Background()
	c := newSigningCluster(t)
	dir := t.TempDir()
	legacy := c.nodeAt(t, dir, c.secrets, false)
	require.NoError(t, legacy.EnsureSigningCertificate(fastSigningCfg))
	node := c.nodeAt(t, dir, c.secrets, true)
	require.True(t, SigningKeyStoreIsClusterAtomic(node.signingKeys))
	before := signingKeyFiles(t, dir)

	res, err := node.AdoptLocalSigningIdentity(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSigningAdoptionUnavailable)
	assert.Nil(t, res)
	assert.Equal(t, before, signingKeyFiles(t, dir))
	serials, lerr := node.signingKeys.ListSigningSerials(ctx)
	require.NoError(t, lerr)
	assert.Empty(t, serials)
	cursor, lerr := c.cursor.LoadCursor(ctx)
	require.NoError(t, lerr)
	assert.Nil(t, cursor)

	noStore, _ := preUpgradeManager(t)
	_, err = noStore.AdoptLocalSigningIdentity(ctx)
	assert.ErrorIs(t, err, ErrSigningAdoptionUnavailable)
}
