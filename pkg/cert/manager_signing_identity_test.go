// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

var fastSigningCfg = &SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 365, KeySize: 2048}

// signingCluster is the state every node of a test cluster shares.
type signingCluster struct {
	secrets *inMemSecretStore
	cursor  certinterfaces.SigningCursorStore
}

func newSigningCluster(t *testing.T) *signingCluster {
	t.Helper()
	cursor, err := NewFileSigningCursorStore(t.TempDir())
	require.NoError(t, err)
	return &signingCluster{secrets: newInMemSecretStore(), cursor: cursor}
}

// node builds one controller node: its own certificate directory, the cluster's
// shared CA, cursor and key store.
func (c *signingCluster) node(t *testing.T, store secretsinterfaces.SecretStore, withKeyStore bool) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	return c.nodeAt(t, dir, store, withKeyStore), dir
}

func (c *signingCluster) nodeAt(t *testing.T, dir string, store secretsinterfaces.SecretStore, withKeyStore bool) *Manager {
	t.Helper()
	cfg := &ManagerConfig{
		StoragePath:        dir,
		CAConfig:           &CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
		SigningCursorStore: c.cursor,
	}
	if withKeyStore {
		ks, err := NewSecretStoreSigningKeyStore(store, testSigningTenant, "")
		require.NoError(t, err)
		cfg.SigningKeyStore = ks
	}
	m, err := NewManagerFromSecretStore(context.Background(), c.secrets, testSigningTenant, "cluster-ca", cfg)
	require.NoError(t, err)
	return m
}

func signingKeyFiles(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "key.pem" {
			found = append(found, p)
		}
		return err
	}))
	return found
}

func TestSigningIdentity_NodesResolveOneIdentityAndCrossVerify(t *testing.T) {
	c := newSigningCluster(t)
	a, dirA := c.node(t, c.secrets, true)
	b, dirB := c.node(t, c.secrets, true)

	require.NoError(t, a.EnsureSigningCertificate(fastSigningCfg))
	require.NoError(t, b.EnsureSigningCertificate(fastSigningCfg))

	certA, err := a.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	certB, err := b.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	assert.Equal(t, certA.SerialNumber, certB.SerialNumber, "all nodes sign with one identity")

	mode, err := a.SigningIdentityMode(context.Background())
	require.NoError(t, err)
	assert.Equal(t, SigningIdentityShared, mode)

	// A payload signed through A verifies against the certificate B holds.
	keyAny, err := ParsePrivateKeyFromPEM(certA.PrivateKeyPEM)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("payload"))
	sig, err := rsa.SignPKCS1v15(rand.Reader, keyAny.(*rsa.PrivateKey), crypto.SHA256, digest[:])
	require.NoError(t, err)
	pubPEM, err := b.GetSigningCertificate()
	require.NoError(t, err)
	x509B, err := ParseCertificateFromPEM(pubPEM)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(x509B.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig))

	// Certificate-only export of the shared serial works from the local store,
	// and a key export is served from the key store.
	exported, noKey, err := b.ExportCertificate(certB.SerialNumber, false, false)
	require.NoError(t, err)
	assert.NotEmpty(t, exported)
	assert.Empty(t, noKey)
	_, withKey, err := b.ExportCertificate(certB.SerialNumber, true, false)
	require.NoError(t, err)
	assert.Equal(t, certA.PrivateKeyPEM, withKey)

	valid, err := b.GetAllValidSigningCertificates()
	require.NoError(t, err)
	require.Len(t, valid, 1)
	assert.Equal(t, certA.SerialNumber, valid[0].SerialNumber)

	assert.Empty(t, signingKeyFiles(t, dirA), "no signing key on node A's disk")
	assert.Empty(t, signingKeyFiles(t, dirB), "no signing key on node B's disk")
}

func TestSigningIdentity_ConcurrentBootstrapProducesOneIdentity(t *testing.T) {
	c := newSigningCluster(t)
	const nodes = 6
	managers := make([]*Manager, nodes)
	dirs := make([]string, nodes)
	for i := range managers {
		managers[i], dirs[i] = c.node(t, c.secrets, true)
	}

	var wg sync.WaitGroup
	errs := make(chan error, nodes)
	for _, m := range managers {
		wg.Add(1)
		go func(m *Manager) {
			defer wg.Done()
			errs <- m.EnsureSigningCertificate(fastSigningCfg)
		}(m)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	ks, err := NewSecretStoreSigningKeyStore(c.secrets, testSigningTenant, "")
	require.NoError(t, err)
	serials, err := ks.ListSigningSerials(context.Background())
	require.NoError(t, err)
	require.Len(t, serials, 1, "exactly one stored serial")

	cursor, err := c.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	require.NotNil(t, cursor)
	assert.Equal(t, serials[0], cursor.CurrentSerial)
	assert.Empty(t, cursor.RotatingSerial, "no spurious rotation")

	for i, m := range managers {
		got, err := m.GetCurrentCertForPurpose(PurposeSigning)
		require.NoError(t, err)
		assert.Equal(t, serials[0], got.SerialNumber)
		assert.Empty(t, signingKeyFiles(t, dirs[i]))
	}
}

func TestSigningIdentity_FailsClosedWhenStoreUnreadable(t *testing.T) {
	c := newSigningCluster(t)
	faulty := newFaultySecretStore(c.secrets)
	m, dir := c.node(t, faulty, true)
	require.NoError(t, m.EnsureSigningCertificate(fastSigningCfg))

	ttl := time.Duration(0)
	m.signingCacheTTLOverride = &ttl

	cur, err := m.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	faulty.failReads(testSigningTenant+"/config-signing/shared/"+cur.SerialNumber, fmt.Errorf("token expired"))

	got, err := m.GetCurrentCertForPurpose(PurposeSigning)
	require.Error(t, err, "signing must fail when the key store cannot be read")
	assert.Nil(t, got)
	_, key, err := m.ExportCertificate(cur.SerialNumber, true, false)
	assert.Error(t, err)
	assert.Empty(t, key)
	assert.Empty(t, signingKeyFiles(t, dir), "there is no local key to fall back to")
}

func TestSigningIdentity_LegacyLocalKeepsSigningLocally(t *testing.T) {
	c := newSigningCluster(t)
	dir := t.TempDir()

	legacy := c.nodeAt(t, dir, c.secrets, false)
	require.NoError(t, legacy.EnsureSigningCertificate(fastSigningCfg))
	localCert, err := legacy.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)

	upgraded := c.nodeAt(t, dir, c.secrets, true)
	mode, err := upgraded.SigningIdentityMode(context.Background())
	require.NoError(t, err)
	assert.Equal(t, SigningIdentityLegacyLocal, mode)

	require.NoError(t, upgraded.EnsureSigningCertificate(fastSigningCfg))
	got, err := upgraded.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	assert.Equal(t, localCert.SerialNumber, got.SerialNumber)
	assert.NotEmpty(t, got.PrivateKeyPEM)

	ks, err := NewSecretStoreSigningKeyStore(c.secrets, testSigningTenant, "")
	require.NoError(t, err)
	serials, err := ks.ListSigningSerials(context.Background())
	require.NoError(t, err)
	assert.Empty(t, serials, "legacy mode publishes nothing")
	cursor, err := c.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	assert.Nil(t, cursor)

	// Rotation is refused with the documented sentinel and changes nothing.
	_, err = upgraded.RotateSigningCertificate(7)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSigningMigrationPending))
}

func TestSigningIdentity_UnresolvableCursorDoesNotBootstrap(t *testing.T) {
	c := newSigningCluster(t)
	a, _ := c.node(t, c.secrets, true)
	require.NoError(t, a.EnsureSigningCertificate(fastSigningCfg))
	before, err := c.cursor.LoadCursor(context.Background())
	require.NoError(t, err)

	// A node whose key store does not hold the serial the cursor names.
	emptySecrets := newInMemSecretStore()
	joiner, dir := c.node(t, emptySecrets, true)
	err = joiner.EnsureSigningCertificate(fastSigningCfg)
	require.Error(t, err)

	after, err := c.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	assert.Equal(t, before, after, "the cursor must not move")
	ks, err := NewSecretStoreSigningKeyStore(emptySecrets, testSigningTenant, "")
	require.NoError(t, err)
	serials, err := ks.ListSigningSerials(context.Background())
	require.NoError(t, err)
	assert.Empty(t, serials)
	infos, err := joiner.GetAllValidCertificatesForPurpose(PurposeSigning)
	require.NoError(t, err)
	assert.Empty(t, infos)
	assert.Empty(t, signingKeyFiles(t, dir))
}

func TestSigningIdentity_RotationRefusedWhenShared(t *testing.T) {
	c := newSigningCluster(t)
	m, _ := c.node(t, c.secrets, true)
	require.NoError(t, m.EnsureSigningCertificate(fastSigningCfg))
	before, err := c.cursor.LoadCursor(context.Background())
	require.NoError(t, err)

	for _, rotate := range []func(int) (*Certificate, error){m.RotateSigningCertificate, m.ForceRotateSigningCertificate} {
		got, err := rotate(7)
		require.Error(t, err)
		assert.Nil(t, got)
	}

	after, err := c.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	assert.Equal(t, before, after)
	ks, err := NewSecretStoreSigningKeyStore(c.secrets, testSigningTenant, "")
	require.NoError(t, err)
	serials, err := ks.ListSigningSerials(context.Background())
	require.NoError(t, err)
	assert.Len(t, serials, 1)
}

func TestSigningIdentity_ResolutionCacheIsBoundedAndObservesRotation(t *testing.T) {
	assert.LessOrEqual(t, signingResolveCacheTTL, 5*time.Second)

	c := newSigningCluster(t)
	a, _ := c.node(t, c.secrets, true)
	b, _ := c.node(t, c.secrets, true)
	ttl := 300 * time.Millisecond
	b.signingCacheTTLOverride = &ttl
	require.NoError(t, a.EnsureSigningCertificate(fastSigningCfg))

	first, err := b.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)

	// Another node publishes a new identity and advances the shared cursor.
	ctx := context.Background()
	next, err := a.ca.GenerateSigningCertificate(fastSigningCfg)
	require.NoError(t, err)
	require.NoError(t, a.signingKeys.PutSigningKey(ctx, &certinterfaces.SigningKeyMaterial{
		Serial: next.SerialNumber, CertificatePEM: next.CertificatePEM, PrivateKeyPEM: next.PrivateKeyPEM,
	}))
	_, err = c.cursor.TransitionCursor(ctx, next.SerialNumber, 7, false)
	require.NoError(t, err)

	cached, err := b.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	assert.Equal(t, first.SerialNumber, cached.SerialNumber, "resolution is served from cache within the bound")

	require.Eventually(t, func() bool {
		got, err := b.GetCurrentCertForPurpose(PurposeSigning)
		return err == nil && got.SerialNumber == next.SerialNumber
	}, 5*time.Second, 50*time.Millisecond, "a serial change must be observed within the cache bound")

	valid, err := b.GetAllValidSigningCertificates()
	require.NoError(t, err)
	assert.Len(t, valid, 2, "current and the rotating serial are both accepted")
}

func TestSigningIdentity_ManagerWithoutKeyStoreIsUnchanged(t *testing.T) {
	c := newSigningCluster(t)
	m, _ := c.node(t, c.secrets, false)
	mode, err := m.SigningIdentityMode(context.Background())
	require.NoError(t, err)
	assert.Equal(t, SigningIdentityNodeLocal, mode)
	require.NoError(t, m.EnsureSigningCertificate(fastSigningCfg))
	got, err := m.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	assert.NotEmpty(t, got.PrivateKeyPEM)
}

func TestSigningIdentity_RenewalRefusesSigningCertsWithKeyStore(t *testing.T) {
	c := newSigningCluster(t)
	m, _ := c.node(t, c.secrets, true)
	require.NoError(t, m.EnsureSigningCertificate(fastSigningCfg))
	cur, err := m.GetCurrentCertForPurpose(PurposeSigning)
	require.NoError(t, err)
	_, err = m.RenewCertificate(cur.SerialNumber, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSigningMigrationPending))
	_, err = m.GenerateSigningCertificate(fastSigningCfg)
	assert.True(t, errors.Is(err, ErrSigningMigrationPending))
}
