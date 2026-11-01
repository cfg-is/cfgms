// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

// migrationEvents collects audit events from a Manager.
type migrationEvents struct {
	mu     sync.Mutex
	events []SigningMigrationEvent
}

func (e *migrationEvents) sink(_ context.Context, ev SigningMigrationEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
}

func (e *migrationEvents) byAction(action string) []SigningMigrationEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []SigningMigrationEvent
	for _, ev := range e.events {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

// legacyClusterNode builds a node that held its own signing certificate before
// the shared store existed, then restarts it with the shared key store attached.
func legacyClusterNode(t *testing.T, c *signingCluster) (*Manager, string, *migrationEvents) {
	t.Helper()
	dir := t.TempDir()
	legacy := c.nodeAt(t, dir, c.secrets, false)
	require.NoError(t, legacy.EnsureSigningCertificate(fastSigningCfg))
	m := c.nodeAt(t, dir, c.secrets, true)
	ev := &migrationEvents{}
	m.SetSigningMigrationAuditSink(ev.sink)
	return m, dir, ev
}

func (c *signingCluster) keyStore(t *testing.T) certinterfaces.SigningKeyStore {
	t.Helper()
	ks, err := NewSecretStoreSigningKeyStore(c.secrets, testSigningTenant, "")
	require.NoError(t, err)
	return ks
}

func localSigningSerial(t *testing.T, m *Manager) string {
	t.Helper()
	cert, err := m.localCurrentSigningCert()
	require.NoError(t, err)
	return cert.SerialNumber
}

type customSigningOpts struct {
	issuer   *Manager // whose CA signs the certificate
	expired  bool
	noEKU    bool
	wrongKey bool
}

// storeCustomSigningCert writes a signing certificate with deliberate defects
// into m's local store and returns its serial.
func storeCustomSigningCert(t *testing.T, m *Manager, o customSigningOpts) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<60))
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "cfgms-config-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if o.expired {
		tmpl.NotBefore = time.Now().Add(-48 * time.Hour)
		tmpl.NotAfter = time.Now().Add(-24 * time.Hour)
	}
	if o.noEKU {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	issuer := o.issuer
	if issuer == nil {
		issuer = m
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.ca.certificate, &key.PublicKey, issuer.ca.privateKey)
	require.NoError(t, err)
	signKey := key
	if o.wrongKey {
		signKey, err = rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
	}
	require.NoError(t, m.store.StoreCertificate(&Certificate{
		Type:           CertificateTypeConfigSigning,
		CommonName:     "cfgms-config-signer",
		SerialNumber:   serial.String(),
		CreatedAt:      tmpl.NotBefore,
		ExpiresAt:      tmpl.NotAfter,
		IsValid:        !o.expired,
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signKey)}),
	}))
	return serial.String()
}

func sorted(s []string) []string {
	out := append([]string{}, s...)
	sort.Strings(out)
	return out
}

func TestSigningMigration_ImportRefusals(t *testing.T) {
	c := newSigningCluster(t)
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
			dir := t.TempDir()
			m := c.nodeAt(t, dir, c.secrets, true)
			ev := &migrationEvents{}
			m.SetSigningMigrationAuditSink(ev.sink)
			serial := storeCustomSigningCert(t, m, tc.opts)

			results, err := m.ImportLocalSigningCertificates(context.Background())
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.Equal(t, serial, results[0].Serial)
			assert.True(t, results[0].Refused)
			assert.False(t, results[0].Imported)
			assert.Contains(t, results[0].Reason, tc.reason)

			refused := ev.byAction(SigningMigrationRefused)
			require.Len(t, refused, 1)
			assert.Equal(t, serial, refused[0].Serial)
			assert.NotContains(t, refused[0].Reason, "PRIVATE KEY")
			assert.Empty(t, ev.byAction(SigningMigrationImported))

			migrated, err := c.keyStore(t).ListMigrationSigners(context.Background())
			require.NoError(t, err)
			assert.Empty(t, migrated, "a refused certificate never enters the migration namespace")
		})
	}
}

func TestSigningMigration_ConflictingMaterialIsRefused(t *testing.T) {
	c := newSigningCluster(t)
	a, _, evA := legacyClusterNode(t, c)
	ctx := context.Background()
	_, err := a.ImportLocalSigningCertificates(ctx)
	require.NoError(t, err)
	serial := localSigningSerial(t, a)

	// A different key for the same serial must not replace what is stored.
	local, err := a.store.GetCertificate(serial)
	require.NoError(t, err)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	err = c.keyStore(t).PutMigrationSigner(ctx, &certinterfaces.SigningKeyMaterial{
		Serial:         serial,
		CertificatePEM: local.CertificatePEM,
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)}),
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "PRIVATE KEY")
	assert.Len(t, evA.byAction(SigningMigrationImported), 1)
}

func TestSigningMigration_ThreeNodesImportIdempotentlyAndConcurrently(t *testing.T) {
	c := newSigningCluster(t)
	var nodes []*Manager
	var want []string
	var sinks []*migrationEvents
	for i := 0; i < 3; i++ {
		m, _, ev := legacyClusterNode(t, c)
		nodes = append(nodes, m)
		sinks = append(sinks, ev)
		want = append(want, localSigningSerial(t, m))
	}

	var wg sync.WaitGroup
	for round := 0; round < 2; round++ {
		for _, m := range nodes {
			wg.Add(1)
			go func(m *Manager) {
				defer wg.Done()
				results, err := m.ImportLocalSigningCertificates(context.Background())
				assert.NoError(t, err)
				for _, r := range results {
					assert.True(t, r.Imported, r.Reason)
				}
			}(m)
		}
	}
	wg.Wait()

	got, err := c.keyStore(t).ListMigrationSigners(context.Background())
	require.NoError(t, err)
	assert.Equal(t, sorted(want), sorted(got))
	shared, err := c.keyStore(t).ListSigningSerials(context.Background())
	require.NoError(t, err)
	assert.Empty(t, shared, "import never touches the shared namespace")
	for _, ev := range sinks {
		assert.NotEmpty(t, ev.byAction(SigningMigrationImported))
	}
}

func TestSigningMigration_EmptyCursorElectsNothing(t *testing.T) {
	c := newSigningCluster(t)
	var nodes []*Manager
	for i := 0; i < 3; i++ {
		m, _, _ := legacyClusterNode(t, c)
		nodes = append(nodes, m)
		_, err := m.ImportLocalSigningCertificates(context.Background())
		require.NoError(t, err)
	}
	for _, m := range nodes {
		serial, promoted, err := m.PromoteElectedSigner(context.Background())
		require.NoError(t, err)
		assert.False(t, promoted)
		assert.Empty(t, serial)
		mode, err := m.SigningIdentityMode(context.Background())
		require.NoError(t, err)
		assert.Equal(t, SigningIdentityLegacyLocal, mode)
	}
	cursor, err := c.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	assert.Nil(t, cursor)
	shared, err := c.keyStore(t).ListSigningSerials(context.Background())
	require.NoError(t, err)
	assert.Empty(t, shared)
}

// migrateThreeNodes returns three imported legacy nodes, with the serial each
// holds in creation order (so the last is the newest).
func migrateThreeNodes(t *testing.T, c *signingCluster) ([]*Manager, []string, []string, []*migrationEvents) {
	t.Helper()
	var nodes []*Manager
	var serials, dirs []string
	var sinks []*migrationEvents
	for i := 0; i < 3; i++ {
		m, dir, ev := legacyClusterNode(t, c)
		_, err := m.ImportLocalSigningCertificates(context.Background())
		require.NoError(t, err)
		nodes, dirs, sinks = append(nodes, m), append(dirs, dir), append(sinks, ev)
		serials = append(serials, localSigningSerial(t, m))
	}
	return nodes, serials, dirs, sinks
}

func TestSigningMigration_CursorSerialWinsOverNewerCertificate(t *testing.T) {
	c := newSigningCluster(t)
	nodes, serials, _, sinks := migrateThreeNodes(t, c)
	ctx := context.Background()

	// The cursor names the oldest certificate although a newer one is held elsewhere.
	elected := serials[0]
	cursor, created, err := nodes[2].ElectSharedSigningSerial(ctx, elected)
	require.NoError(t, err)
	require.True(t, created)
	assert.Equal(t, elected, cursor.CurrentSerial)
	assert.Empty(t, cursor.RotatingSerial)

	for i, m := range nodes {
		mode, err := m.SigningIdentityMode(ctx)
		require.NoError(t, err)
		assert.Equal(t, SigningIdentityShared, mode, "node %d", i)
		signer, err := m.GetCurrentCertForPurpose(PurposeSigning)
		require.NoError(t, err)
		assert.Equal(t, elected, signer.SerialNumber, "node %d signs with the elected serial", i)
	}
	shared, err := c.keyStore(t).ListSigningSerials(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{elected}, shared)

	var promotions int
	for _, ev := range sinks {
		promotions += len(ev.byAction(SigningMigrationPromoted))
	}
	assert.Equal(t, 1, promotions, "promotion is audited")
}

func TestSigningMigration_PromoteElectedSignerFromCursor(t *testing.T) {
	c := newSigningCluster(t)
	nodes, serials, _, _ := migrateThreeNodes(t, c)
	ctx := context.Background()

	_, created, err := c.cursor.SeedCursorIfAbsent(ctx, serials[1])
	require.NoError(t, err)
	require.True(t, created)

	serial, promoted, err := nodes[0].PromoteElectedSigner(ctx)
	require.NoError(t, err)
	assert.True(t, promoted)
	assert.Equal(t, serials[1], serial)
	_, promoted, err = nodes[2].PromoteElectedSigner(ctx)
	require.NoError(t, err)
	assert.False(t, promoted, "the second promotion is a no-op")
}

func TestSigningMigration_ElectionRules(t *testing.T) {
	c := newSigningCluster(t)
	nodes, serials, _, _ := migrateThreeNodes(t, c)
	ctx := context.Background()

	_, _, err := nodes[0].ElectSharedSigningSerial(ctx, "123456789")
	assert.ErrorIs(t, err, ErrSigningSerialNotMigrated)
	_, _, err = nodes[0].ElectSharedSigningSerial(ctx, "../etc")
	assert.ErrorIs(t, err, ErrInvalidSerial)
	cursor, err := c.cursor.LoadCursor(ctx)
	require.NoError(t, err)
	assert.Nil(t, cursor)

	// Concurrent elections of different serials produce exactly one cursor.
	var wg sync.WaitGroup
	var mu sync.Mutex
	createdBy := 0
	for i, m := range nodes {
		wg.Add(1)
		go func(i int, m *Manager) {
			defer wg.Done()
			_, created, err := m.ElectSharedSigningSerial(ctx, serials[i])
			assert.NoError(t, err)
			if created {
				mu.Lock()
				createdBy++
				mu.Unlock()
			}
		}(i, m)
	}
	wg.Wait()
	assert.Equal(t, 1, createdBy)

	winner, err := c.cursor.LoadCursor(ctx)
	require.NoError(t, err)
	require.NotNil(t, winner)
	assert.Empty(t, winner.RotatingSerial)
	shared, err := c.keyStore(t).ListSigningSerials(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{winner.CurrentSerial}, shared)

	// A later election never overrides the existing cursor.
	other := serials[0]
	if other == winner.CurrentSerial {
		other = serials[1]
	}
	existing, created, err := nodes[0].ElectSharedSigningSerial(ctx, other)
	require.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, winner.CurrentSerial, existing.CurrentSerial)
}

func TestSigningMigration_RemovesLocalKeysOnlyAfterVerification(t *testing.T) {
	c := newSigningCluster(t)
	nodes, serials, dirs, sinks := migrateThreeNodes(t, c)
	ctx := context.Background()

	// Not in Shared mode: nothing is deleted.
	results, err := nodes[0].RemoveVerifiedLocalSigningKeys(ctx)
	require.NoError(t, err)
	assert.Empty(t, results)
	assert.Len(t, signingKeyFiles(t, dirs[0]), 1)

	_, _, err = nodes[0].ElectSharedSigningSerial(ctx, serials[0])
	require.NoError(t, err)

	// Node 1's local key no longer matches what the store holds for its serial.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tampered := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)})
	require.NoError(t, os.WriteFile(filepath.Join(dirs[1], serials[1], "key.pem"), tampered, 0600))

	for i, m := range nodes {
		results, err := m.RemoveVerifiedLocalSigningKeys(ctx)
		require.NoError(t, err, "node %d", i)
		require.Len(t, results, 1, "node %d", i)
		if i == 1 {
			assert.False(t, results[0].Removed)
			assert.NotEmpty(t, results[0].Reason)
			assert.Len(t, signingKeyFiles(t, dirs[i]), 1, "a key that does not read back equal stays")
			assert.Empty(t, sinks[i].byAction(SigningMigrationKeyRemoved))
			continue
		}
		assert.True(t, results[0].Removed, "node %d", i)
		assert.Empty(t, signingKeyFiles(t, dirs[i]), "node %d keeps no signing key.pem", i)
		assert.Len(t, sinks[i].byAction(SigningMigrationKeyRemoved), 1)
		// The public half stays for trust-path listings.
		_, statErr := os.Stat(filepath.Join(dirs[i], serials[i], "cert.pem"))
		assert.NoError(t, statErr)
	}

	// Removal is idempotent and the nodes still sign.
	for _, i := range []int{0, 2} {
		results, err := nodes[i].RemoveVerifiedLocalSigningKeys(ctx)
		require.NoError(t, err)
		assert.Empty(t, results)
		signer, err := nodes[i].GetCurrentCertForPurpose(PurposeSigning)
		require.NoError(t, err)
		assert.Equal(t, serials[0], signer.SerialNumber)
		assert.NotEmpty(t, signer.PrivateKeyPEM)
	}
}

func TestSigningMigration_UnverifiableKeyKeepsEveryKey(t *testing.T) {
	c := newSigningCluster(t)
	nodes, serials, dirs, _ := migrateThreeNodes(t, c)
	ctx := context.Background()
	_, _, err := nodes[0].ElectSharedSigningSerial(ctx, serials[0])
	require.NoError(t, err)

	// Node 0 also holds a second local signing key that was never imported.
	storeCustomSigningCert(t, nodes[0], customSigningOpts{})

	results, err := nodes[0].RemoveVerifiedLocalSigningKeys(ctx)
	require.NoError(t, err)
	require.Len(t, results, 2)
	for _, r := range results {
		assert.False(t, r.Removed)
	}
	assert.Len(t, signingKeyFiles(t, dirs[0]), 2)
}

func TestSigningMigration_EventsCarryNoKeyMaterial(t *testing.T) {
	c := newSigningCluster(t)
	nodes, serials, _, sinks := migrateThreeNodes(t, c)
	ctx := context.Background()
	_, _, err := nodes[0].ElectSharedSigningSerial(ctx, serials[0])
	require.NoError(t, err)
	_, err = nodes[0].RemoveVerifiedLocalSigningKeys(ctx)
	require.NoError(t, err)
	for _, s := range sinks {
		for _, ev := range s.events {
			assert.NotContains(t, strings.Join([]string{ev.Action, ev.Serial, ev.Fingerprint, ev.Reason}, " "), "-----BEGIN")
		}
	}
}

func TestSigningMigration_WithoutKeyStoreIsRefused(t *testing.T) {
	c := newSigningCluster(t)
	m, _ := c.node(t, c.secrets, false)
	_, err := m.ImportLocalSigningCertificates(context.Background())
	assert.ErrorIs(t, err, ErrNoSigningKeyStore)
	_, _, err = m.PromoteElectedSigner(context.Background())
	assert.ErrorIs(t, err, ErrNoSigningKeyStore)
	_, _, err = m.ElectSharedSigningSerial(context.Background(), "1")
	assert.ErrorIs(t, err, ErrNoSigningKeyStore)
	_, err = m.RemoveVerifiedLocalSigningKeys(context.Background())
	assert.ErrorIs(t, err, ErrNoSigningKeyStore)
}

// revokeSigningSerial records serial as a withdrawn signing certificate in m's
// revocation store, as RevokeSigningCertificate does.
func revokeSigningSerial(t *testing.T, m *Manager, serial string) {
	t.Helper()
	require.NoError(t, m.revocation.Revoke(context.Background(), RevocationEntry{
		Serial:    serial,
		RevokedAt: time.Now().UTC(),
		Reason:    RevocationReasonSigningCert,
	}))
}

func TestSigningMigration_RevokedSerialIsNotImported(t *testing.T) {
	c := newSigningCluster(t)
	m, _, ev := legacyClusterNode(t, c)
	serial := localSigningSerial(t, m)
	revokeSigningSerial(t, m, serial)

	results, err := m.ImportLocalSigningCertificates(context.Background())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.True(t, results[0].Refused)
	assert.False(t, results[0].Imported)
	assert.Contains(t, results[0].Reason, "revoked")

	refused := ev.byAction(SigningMigrationRefused)
	require.Len(t, refused, 1)
	assert.Equal(t, serial, refused[0].Serial)
	assert.Empty(t, ev.byAction(SigningMigrationImported))

	migrated, err := c.keyStore(t).ListMigrationSigners(context.Background())
	require.NoError(t, err)
	assert.Empty(t, migrated, "a revoked certificate never enters the migration namespace")
}

func TestSigningMigration_RevokedSerialIsNotElectable(t *testing.T) {
	c := newSigningCluster(t)
	nodes, serials, _, sinks := migrateThreeNodes(t, c)
	ctx := context.Background()
	revokeSigningSerial(t, nodes[0], serials[0])

	_, created, err := nodes[0].ElectSharedSigningSerial(ctx, serials[0])
	require.ErrorIs(t, err, ErrSigningSerialRevoked)
	assert.False(t, created)

	cursor, err := c.cursor.LoadCursor(ctx)
	require.NoError(t, err)
	assert.Nil(t, cursor, "a revoked serial creates no cursor")
	shared, err := c.keyStore(t).ListSigningSerials(ctx)
	require.NoError(t, err)
	assert.Empty(t, shared)

	refused := sinks[0].byAction(SigningMigrationRefused)
	require.Len(t, refused, 1)
	assert.Equal(t, serials[0], refused[0].Serial)
	assert.Contains(t, refused[0].Reason, "election")
}

func TestSigningMigration_RevokedSerialIsNotPromoted(t *testing.T) {
	c := newSigningCluster(t)
	nodes, serials, _, sinks := migrateThreeNodes(t, c)
	ctx := context.Background()

	// The cursor already names the serial (elected before the revocation, or
	// written by another node); promotion must still refuse it.
	_, created, err := c.cursor.SeedCursorIfAbsent(ctx, serials[1])
	require.NoError(t, err)
	require.True(t, created)
	revokeSigningSerial(t, nodes[0], serials[1])

	serial, promoted, err := nodes[0].PromoteElectedSigner(ctx)
	require.ErrorIs(t, err, ErrSigningSerialRevoked)
	assert.False(t, promoted)
	assert.Equal(t, serials[1], serial)

	shared, err := c.keyStore(t).ListSigningSerials(ctx)
	require.NoError(t, err)
	assert.Empty(t, shared, "a revoked serial never enters the shared namespace")
	assert.Empty(t, sinks[0].byAction(SigningMigrationPromoted))
	refused := sinks[0].byAction(SigningMigrationRefused)
	require.Len(t, refused, 1)
	assert.Equal(t, serials[1], refused[0].Serial)
	assert.Contains(t, refused[0].Reason, "promotion")
}
