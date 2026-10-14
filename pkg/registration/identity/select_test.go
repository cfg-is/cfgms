// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// p256TestStore is a real in-memory P-256 KeyStore standing in for a hardware backend.
type p256TestStore struct {
	mu       sync.Mutex
	priv     *ecdsa.PrivateKey
	level    ProtectionLevel
	loadFail error
	removed  int
}

func (s *p256TestStore) GenerateOrLoad(context.Context) (crypto.PublicKey, Algorithm, error) {
	if s.loadFail != nil {
		return nil, "", s.loadFail
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	s.priv = k
	return &k.PublicKey, AlgorithmECDSAP256, nil
}
func (s *p256TestStore) Regenerate(ctx context.Context) (crypto.PublicKey, Algorithm, error) {
	return s.GenerateOrLoad(ctx)
}
func (s *p256TestStore) RemoveKey() error                 { s.removed++; return nil }
func (s *p256TestStore) Algorithm() Algorithm             { return AlgorithmECDSAP256 }
func (s *p256TestStore) ProtectionLevel() ProtectionLevel { return s.level }
func (s *p256TestStore) DeviceID() string {
	if s.priv == nil {
		return ""
	}
	id, _ := ComputeDeviceID(AlgorithmECDSAP256, &s.priv.PublicKey)
	return id
}
func (s *p256TestStore) PublicKey() crypto.PublicKey {
	if s.priv == nil {
		return nil
	}
	return &s.priv.PublicKey
}
func (s *p256TestStore) Sign(m []byte) ([]byte, error) {
	d := sha256.Sum256(m)
	return ecdsa.SignASN1(rand.Reader, s.priv, d[:])
}

// withBackends swaps the registry and the file-store constructor for one test.
func withBackends(t *testing.T, bs ...backend) {
	t.Helper()
	backendsMu.Lock()
	saved := backends
	backends = bs
	backendsMu.Unlock()
	savedFactory := newFileStore
	newFileStore = func(dir string) (*FileKeyStore, error) { return NewFileKeyStoreForTesting(dir) }
	t.Cleanup(func() {
		backendsMu.Lock()
		backends = saved
		backendsMu.Unlock()
		newFileStore = savedFactory
	})
}

func testBackend(level ProtectionLevel, calls *int, failWith error) backend {
	return backend{
		level: level,
		open: func(context.Context, string, logging.Logger) (KeyStore, error) {
			*calls++
			return &p256TestStore{level: level, loadFail: failWith}, nil
		},
	}
}

func testLogger() logging.Logger { return logging.NewLogger("debug") }

func TestOpen_NoBackends_UsesFile(t *testing.T) {
	withBackends(t)
	ks, err := Open(context.Background(), t.TempDir(), testLogger())
	require.NoError(t, err)
	assert.Equal(t, AlgorithmEd25519, ks.Algorithm())
	assert.Equal(t, ProtectionFile, ks.ProtectionLevel())
	assert.Len(t, ks.DeviceID(), 64)
}

func TestOpen_FailingBackendFallsBackToFile(t *testing.T) {
	var calls int
	withBackends(t, testBackend(ProtectionTPM, &calls, errors.New("no tpm device")))
	dir := t.TempDir()
	ks, err := Open(context.Background(), dir, testLogger())
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
	assert.Equal(t, ProtectionFile, ks.ProtectionLevel())
	_, statErr := os.Stat(filepath.Join(dir, keyFileName))
	assert.NoError(t, statErr, "fallback creates the file key")
}

func TestOpen_SucceedingBackendIsUsed(t *testing.T) {
	var calls int
	withBackends(t, testBackend(ProtectionTPM, &calls, nil))
	dir := t.TempDir()
	ks, err := Open(context.Background(), dir, testLogger())
	require.NoError(t, err)
	assert.Equal(t, ProtectionTPM, ks.ProtectionLevel())
	assert.Equal(t, AlgorithmECDSAP256, ks.Algorithm())
	_, statErr := os.Stat(filepath.Join(dir, keyFileName))
	assert.True(t, os.IsNotExist(statErr), "no file key when hardware succeeds")
}

func TestOpen_ExistingFileKeyProbesNoBackend(t *testing.T) {
	var calls int
	withBackends(t, testBackend(ProtectionTPM, &calls, nil))
	dir := t.TempDir()
	first, err := NewFileKeyStoreForTesting(dir)
	require.NoError(t, err)
	_, _, err = first.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	ks, err := Open(context.Background(), dir, testLogger())
	require.NoError(t, err)
	assert.Zero(t, calls, "no hardware backend may be probed when device_identity.enc exists")
	assert.Equal(t, first.DeviceID(), ks.DeviceID())
	assert.Equal(t, ProtectionFile, ks.ProtectionLevel())
}

// A steward whose stored identity records a hardware key never falls back to a file key.
func TestOpen_RecordedHardwareKeyNeverFallsBack(t *testing.T) {
	var calls int
	withBackends(t, testBackend(ProtectionTPM, &calls, errors.New("device absent")))
	dir := t.TempDir()
	rec := []byte(`{"steward_id":"s","device_id":"abc","key_protection_level":"tpm"}`)
	recPath := filepath.Join(dir, storedIdentityFileName)
	require.NoError(t, os.WriteFile(recPath, rec, 0600))

	ks, err := Open(context.Background(), dir, testLogger())
	require.Error(t, err)
	assert.Nil(t, ks)
	assert.True(t, errors.Is(err, ErrHardwareKeyUnavailable))
	_, statErr := os.Stat(filepath.Join(dir, keyFileName))
	assert.True(t, os.IsNotExist(statErr), "no device_identity.enc may be written")
	got, readErr := os.ReadFile(recPath)
	require.NoError(t, readErr)
	assert.Equal(t, rec, got, "stored identity unchanged")
}

func TestOpen_RecordedHardwareKeyWithNoBackendInBuild(t *testing.T) {
	withBackends(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, storedIdentityFileName), []byte(`{"key_protection_level":"secure-enclave"}`), 0600))
	_, err := Open(context.Background(), dir, testLogger())
	assert.True(t, errors.Is(err, ErrHardwareKeyUnavailable))
	_, statErr := os.Stat(filepath.Join(dir, keyFileName))
	assert.True(t, os.IsNotExist(statErr))
}

func TestOpen_FileBackendFailureReturnsError(t *testing.T) {
	withBackends(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, keyFileName), []byte("not a valid ciphertext"), 0600))
	_, err := Open(context.Background(), dir, testLogger())
	assert.Error(t, err)
}

func TestRemoveAllStoredKeys_RemovesFileAndBackendKeys(t *testing.T) {
	removed := 0
	withBackends(t, backend{level: ProtectionTPM, remove: func(string) error { removed++; return nil }})
	dir := t.TempDir()
	ks, err := NewFileKeyStoreForTesting(dir)
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	require.NoError(t, RemoveAllStoredKeys(dir))
	assert.Equal(t, 1, removed)
	_, statErr := os.Stat(filepath.Join(dir, keyFileName))
	assert.True(t, os.IsNotExist(statErr))
}
