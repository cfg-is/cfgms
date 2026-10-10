// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package initialization

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops" // register the SOPS provider
)

// newSOPSFlatfileStore builds the single-node secret store: SOPS over the
// flatfile backend, whose compare-and-swap is a host file lock.
func newSOPSFlatfileStore(t *testing.T) secretsinterfaces.SecretStore {
	t.Helper()
	base := t.TempDir()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyPath := filepath.Join(base, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	store, err := secretsinterfaces.CreateSecretStoreFromConfig("sops", map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": filepath.Join(base, "data")},
		"cache_enabled":    false,
		"key_file":         keyPath,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestWireSingleNodeSigningKeyStore_RefusesClusterMode(t *testing.T) {
	managerCfg := &cert.ManagerConfig{}
	err := WireSingleNodeSigningKeyStore(managerCfg, certStoreTestConfig("cluster"), newInMemSecretStore())
	require.Error(t, err)
	assert.Nil(t, managerCfg.SigningKeyStore)

	err = WireSingleNodeSigningKeyStore(managerCfg, certStoreTestConfig(""), nil)
	require.Error(t, err, "a nil store is refused")
	assert.Nil(t, managerCfg.SigningKeyStore)

	require.NoError(t, WireSingleNodeSigningKeyStore(managerCfg, certStoreTestConfig(""), newInMemSecretStore()))
	require.NotNil(t, managerCfg.SigningKeyStore)
	assert.False(t, cert.SigningKeyStoreIsClusterAtomic(managerCfg.SigningKeyStore))
}

func TestInitClusterCAWithStore_RefusesSingleNodeSigningKeyStore(t *testing.T) {
	fx := newCertStoreFixture(t)
	cfg := clusterSigningConfig()
	managerCfg, err := newClusterManagerConfig(cfg, t.TempDir(), fx.storageManager)
	require.NoError(t, err)
	vault := newInMemSecretStore()
	single, err := cert.NewSingleNodeSigningKeyStore(vault, "signing-tenant", "")
	require.NoError(t, err)
	managerCfg.SigningKeyStore = single

	mgr, err := initClusterCAWithStore(context.Background(), cfg, managerCfg, vault, logging.NewNoopLogger())
	require.Error(t, err)
	assert.Nil(t, mgr)
}

func TestSingleNodeSigningKeyStore_SOPSFlatfileRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newSOPSFlatfileStore(t)
	require.False(t, secretsinterfaces.CompareAndSwapIsClusterAtomic(store), "file-lock CAS is not cluster-atomic")

	var keys []certinterfaces.SigningKeyStore
	for i := 0; i < 2; i++ {
		ks, err := cert.NewSingleNodeSigningKeyStore(store, singleNodeSigningKeyTenant, "")
		require.NoError(t, err)
		keys = append(keys, ks)
	}
	ks := keys[0]

	// Real signing material from a throwaway CA.
	newMaterial := func() *certinterfaces.SigningKeyMaterial {
		m, err := cert.NewManager(&cert.ManagerConfig{
			StoragePath: t.TempDir(),
			CAConfig:    &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 30, KeySize: 2048},
		})
		require.NoError(t, err)
		c, err := m.GenerateSigningCertificate(&cert.SigningCertConfig{CommonName: "signer", ValidityDays: 30, KeySize: 2048})
		require.NoError(t, err)
		return &certinterfaces.SigningKeyMaterial{Serial: c.SerialNumber, CertificatePEM: c.CertificatePEM, PrivateKeyPEM: c.PrivateKeyPEM}
	}
	mat := newMaterial()
	require.NoError(t, ks.PutSigningKey(ctx, mat))

	got, err := ks.GetSigningKey(ctx, mat.Serial)
	require.NoError(t, err)
	assert.Equal(t, mat.PrivateKeyPEM, got.PrivateKeyPEM)
	assert.Equal(t, mat.CertificatePEM, got.CertificatePEM)

	serials, err := ks.ListSigningSerials(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{mat.Serial}, serials)

	other := newMaterial()
	conflicting := &certinterfaces.SigningKeyMaterial{Serial: mat.Serial, CertificatePEM: other.CertificatePEM, PrivateKeyPEM: other.PrivateKeyPEM}
	require.Error(t, ks.PutSigningKey(ctx, conflicting), "different material for an existing serial is refused")
	got, err = ks.GetSigningKey(ctx, mat.Serial)
	require.NoError(t, err)
	assert.Equal(t, mat.PrivateKeyPEM, got.PrivateKeyPEM, "the stored key is untouched")

	var wins sync.WaitGroup
	results := make([]bool, len(keys))
	for i, k := range keys {
		wins.Add(1)
		go func(i int, k certinterfaces.SigningKeyStore) {
			defer wins.Done()
			claimer, ok := k.(certinterfaces.SigningBootstrapClaimer)
			if !ok {
				return
			}
			won, cerr := claimer.ClaimSigningBootstrap(ctx)
			if cerr == nil {
				results[i] = won
			}
		}(i, k)
	}
	wins.Wait()
	won := 0
	for _, r := range results {
		if r {
			won++
		}
	}
	assert.Equal(t, 1, won, "exactly one concurrent caller wins the bootstrap claim")
}

func TestRun_SingleNodeCreatesNoSigningCertificate(t *testing.T) {
	tempDir := t.TempDir()
	caDir := filepath.Join(tempDir, "ca")
	cfg := makeTestConfig(t, tempDir, caDir, filepath.Join(tempDir, "admin.bundle.yaml"))

	_, err := Run(cfg, logging.NewNoopLogger())
	require.NoError(t, err)

	m, err := cert.NewManager(&cert.ManagerConfig{StoragePath: tempDir, LoadExistingCA: true})
	require.NoError(t, err)
	certs, err := m.ListCertificates()
	require.NoError(t, err)
	var types []cert.CertificateType
	for _, c := range certs {
		types = append(types, c.Type)
	}
	assert.Contains(t, types, cert.CertificateTypeInternalServer)
	assert.NotContains(t, types, cert.CertificateTypeConfigSigning)
}
