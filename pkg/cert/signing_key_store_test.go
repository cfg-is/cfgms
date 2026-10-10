// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cert

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

const testSigningTenant = "cluster-ca-tenant"

// newTestCAForSigning returns a CA able to issue signing certificates quickly.
func newTestCAForSigning(t *testing.T) *CA {
	t.Helper()
	cfg := &CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048}
	ca, err := NewCA(cfg)
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(cfg))
	return ca
}

func newSigningMaterial(t *testing.T, ca *CA) *certinterfaces.SigningKeyMaterial {
	t.Helper()
	c, err := ca.GenerateSigningCertificate(&SigningCertConfig{KeySize: 2048})
	require.NoError(t, err)
	return &certinterfaces.SigningKeyMaterial{
		Serial:         c.SerialNumber,
		CertificatePEM: c.CertificatePEM,
		PrivateKeyPEM:  c.PrivateKeyPEM,
		IssuerChainPEM: c.IssuerChainPEM,
	}
}

func newTestSigningKeyStore(t *testing.T, store secretsinterfaces.SecretStore) certinterfaces.SigningKeyStore {
	t.Helper()
	ks, err := NewSecretStoreSigningKeyStore(store, testSigningTenant, "")
	require.NoError(t, err)
	return ks
}

// nonAtomicStore hides CompareAndSwapIsClusterAtomic by embedding only the interface.
type nonAtomicStore struct{ secretsinterfaces.SecretStore }

func TestSigningKeyStore_RequiresClusterAtomicStore(t *testing.T) {
	_, err := NewSecretStoreSigningKeyStore(&nonAtomicStore{newInMemSecretStore()}, testSigningTenant, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "atomic")

	_, err = NewSecretStoreSigningKeyStore(nil, testSigningTenant, "")
	require.Error(t, err)
	_, err = NewSecretStoreSigningKeyStore(newInMemSecretStore(), "", "")
	require.Error(t, err)
}

func TestSigningKeyStore_PutGetListRoundTrip(t *testing.T) {
	ctx := context.Background()
	ks := newTestSigningKeyStore(t, newInMemSecretStore())
	ca := newTestCAForSigning(t)

	serials, err := ks.ListSigningSerials(ctx)
	require.NoError(t, err)
	assert.Empty(t, serials)

	mat := newSigningMaterial(t, ca)
	require.NoError(t, ks.PutSigningKey(ctx, mat))

	got, err := ks.GetSigningKey(ctx, mat.Serial)
	require.NoError(t, err)
	assert.Equal(t, mat.Serial, got.Serial)
	assert.Equal(t, mat.CertificatePEM, got.CertificatePEM)
	assert.Equal(t, mat.PrivateKeyPEM, got.PrivateKeyPEM)

	second := newSigningMaterial(t, ca)
	require.NoError(t, ks.PutSigningKey(ctx, second))
	serials, err = ks.ListSigningSerials(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{mat.Serial, second.Serial}, serials)
}

func TestSigningKeyStore_PutIsCreateIfAbsent(t *testing.T) {
	ctx := context.Background()
	inner := newInMemSecretStore()
	ks := newTestSigningKeyStore(t, inner)
	ca := newTestCAForSigning(t)

	mat := newSigningMaterial(t, ca)
	require.NoError(t, ks.PutSigningKey(ctx, mat))
	require.NoError(t, ks.PutSigningKey(ctx, mat), "same material is an idempotent success")

	// Plant different material under the serial's key and attempt the original.
	other := newSigningMaterial(t, ca)
	otherKS := newTestSigningKeyStore(t, newInMemSecretStore())
	require.NoError(t, otherKS.PutSigningKey(ctx, other))
	planted, err := marshalSigningRecord(&certinterfaces.SigningKeyMaterial{
		Serial: mat.Serial, CertificatePEM: other.CertificatePEM, PrivateKeyPEM: other.PrivateKeyPEM,
	})
	require.NoError(t, err)
	conflict := newInMemSecretStore()
	require.NoError(t, conflict.StoreSecret(ctx, &secretsinterfaces.SecretRequest{
		TenantID: testSigningTenant, Key: "config-signing/shared/" + mat.Serial, Value: planted,
	}))
	err = newTestSigningKeyStore(t, conflict).PutSigningKey(ctx, mat)
	require.Error(t, err, "different material for an existing serial must be refused")
	assert.NotContains(t, err.Error(), "PRIVATE KEY")
	assert.NotContains(t, err.Error(), string(mat.PrivateKeyPEM))
	assert.Contains(t, err.Error(), "fingerprint")

	// The original entry is untouched.
	got, err := ks.GetSigningKey(ctx, mat.Serial)
	require.NoError(t, err)
	assert.Equal(t, mat.PrivateKeyPEM, got.PrivateKeyPEM)
}

func TestSigningKeyStore_PutRejectsBadMaterial(t *testing.T) {
	ctx := context.Background()
	ks := newTestSigningKeyStore(t, newInMemSecretStore())
	ca := newTestCAForSigning(t)
	a, b := newSigningMaterial(t, ca), newSigningMaterial(t, ca)

	assert.Error(t, ks.PutSigningKey(ctx, nil))
	assert.Error(t, ks.PutSigningKey(ctx, &certinterfaces.SigningKeyMaterial{Serial: a.Serial, CertificatePEM: a.CertificatePEM}))
	mismatched := &certinterfaces.SigningKeyMaterial{Serial: a.Serial, CertificatePEM: a.CertificatePEM, PrivateKeyPEM: b.PrivateKeyPEM}
	assert.Error(t, ks.PutSigningKey(ctx, mismatched), "key must match certificate")
	wrongSerial := &certinterfaces.SigningKeyMaterial{Serial: "1", CertificatePEM: a.CertificatePEM, PrivateKeyPEM: a.PrivateKeyPEM}
	assert.Error(t, ks.PutSigningKey(ctx, wrongSerial), "serial must match certificate")
}

func TestSigningKeyStore_GetDistinguishesAbsentFromReadFailure(t *testing.T) {
	ctx := context.Background()
	faulty := newFaultySecretStore(newInMemSecretStore())
	ks := newTestSigningKeyStore(t, faulty)
	ca := newTestCAForSigning(t)
	mat := newSigningMaterial(t, ca)

	_, err := ks.GetSigningKey(ctx, mat.Serial)
	require.Error(t, err)
	assert.True(t, errors.Is(err, certinterfaces.ErrSigningKeyNotFound))

	require.NoError(t, ks.PutSigningKey(ctx, mat))
	faulty.failReads(testSigningTenant+"/config-signing/shared/"+mat.Serial, fmt.Errorf("permission denied"))
	_, err = ks.GetSigningKey(ctx, mat.Serial)
	require.Error(t, err)
	assert.False(t, errors.Is(err, certinterfaces.ErrSigningKeyNotFound), "a read failure is not an absent key")

	_, err = ks.GetSigningKey(ctx, "../../etc/passwd")
	require.Error(t, err)
	assert.False(t, errors.Is(err, certinterfaces.ErrSigningKeyNotFound))
}

func TestSigningKeyStore_ConcurrentPutSameSerialIsSafe(t *testing.T) {
	ctx := context.Background()
	ks := newTestSigningKeyStore(t, newInMemSecretStore())
	mat := newSigningMaterial(t, newTestCAForSigning(t))

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- ks.PutSigningKey(ctx, mat)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	serials, err := ks.ListSigningSerials(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{mat.Serial}, serials)
}

func TestSigningKeyStore_BootstrapClaimIsExclusive(t *testing.T) {
	ctx := context.Background()
	inner := newInMemSecretStore()
	a := newTestSigningKeyStore(t, inner).(certinterfaces.SigningBootstrapClaimer)
	b := newTestSigningKeyStore(t, inner).(certinterfaces.SigningBootstrapClaimer)

	won, err := a.ClaimSigningBootstrap(ctx)
	require.NoError(t, err)
	assert.True(t, won)
	won, err = b.ClaimSigningBootstrap(ctx)
	require.NoError(t, err)
	assert.False(t, won, "a second claimant must lose while the claim is held")
}

func TestSigningKeyStore_MigrationNamespaceIsSeparate(t *testing.T) {
	ctx := context.Background()
	ks := newTestSigningKeyStore(t, newInMemSecretStore())
	mat := newSigningMaterial(t, newTestCAForSigning(t))

	_, err := ks.GetMigrationSigner(ctx, mat.Serial)
	assert.True(t, errors.Is(err, certinterfaces.ErrSigningKeyNotFound))

	require.NoError(t, ks.PutMigrationSigner(ctx, mat))
	require.NoError(t, ks.PutMigrationSigner(ctx, mat), "same material is idempotent")

	got, err := ks.GetMigrationSigner(ctx, mat.Serial)
	require.NoError(t, err)
	assert.Equal(t, mat.PrivateKeyPEM, got.PrivateKeyPEM)

	migrated, err := ks.ListMigrationSigners(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{mat.Serial}, migrated)
	shared, err := ks.ListSigningSerials(ctx)
	require.NoError(t, err)
	assert.Empty(t, shared, "migration entries are not shared signing identities")
	_, err = ks.GetSigningKey(ctx, mat.Serial)
	assert.True(t, errors.Is(err, certinterfaces.ErrSigningKeyNotFound))

	// Different material for the same serial is refused, naming no key bytes.
	other := newSigningMaterial(t, newTestCAForSigning(t))
	other.Serial = mat.Serial
	err = ks.PutMigrationSigner(ctx, other)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "PRIVATE KEY")
}
