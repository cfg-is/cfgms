// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	stewardcrypto "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestKeyStoreInDir creates a FileKeyStore using a real AES-256-GCM encryptor
// seeded with a fixed machine ID. This avoids the /etc/machine-id dependency in
// test environments while still exercising real encryption (not a mock).
func newTestKeyStoreInDir(t *testing.T, dir string) *FileKeyStore {
	t.Helper()
	enc, err := stewardcrypto.NewEncryptorFromBytes([]byte("cfgms-test-machine-id"), dir)
	require.NoError(t, err)
	return newFileKeyStoreWithEncryptor(dir, enc)
}

// TestFileKeyStore_KeyEncryptedAtRest verifies that the private key on disk is opaque
// ciphertext — not valid PEM and not a valid PKCS8 structure.
// This proves the plaintext private key is never written to disk.
func TestFileKeyStore_KeyEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeyStoreInDir(t, dir)

	_, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, keyFileName))
	require.NoError(t, err, "device_identity.enc must exist after GenerateOrLoad")

	block, _ := pem.Decode(data)
	assert.Nil(t, block, "on-disk bytes must not be valid PEM (plaintext key never written to disk)")

	_, pkcs8Err := x509.ParsePKCS8PrivateKey(data)
	assert.Error(t, pkcs8Err, "on-disk bytes must not parse as PKCS8 (plaintext key never written to disk)")
}

// TestFileKeyStore_RoundTrip verifies that loading a previously generated key from disk
// yields the same public key bytes and DeviceID as the original generation.
func TestFileKeyStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	ks1 := newTestKeyStoreInDir(t, dir)

	pub1, _, err := ks1.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	deviceID1 := ks1.DeviceID()
	require.NotEmpty(t, deviceID1, "DeviceID must be set after GenerateOrLoad")
	assert.Len(t, deviceID1, 64, "DeviceID must be 64-char lowercase hex")

	// Load from the same directory with a new FileKeyStore instance.
	ks2 := newTestKeyStoreInDir(t, dir)
	pub2, _, err := ks2.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	deviceID2 := ks2.DeviceID()

	assert.Equal(t, pub1, pub2, "public key must be identical across load cycles")
	assert.Equal(t, deviceID1, deviceID2, "DeviceID must be stable across load cycles")
}

// TestFileKeyStore_DeviceID_IsHexSHA256OfPublicKey proves the DeviceID formula:
// hex(sha256(publicKeyBytes)) == 64-char lowercase hex.
func TestFileKeyStore_DeviceID_IsHexSHA256OfPublicKey(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeyStoreInDir(t, dir)

	pub, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	expected, err := ComputeDeviceID(AlgorithmEd25519, pub)
	require.NoError(t, err)
	assert.Equal(t, expected, ks.DeviceID())
	assert.Len(t, ks.DeviceID(), 64)
}

// TestFileKeyStore_Sign verifies that Sign produces a valid Ed25519 signature
// verifiable with the corresponding public key.
func TestFileKeyStore_Sign(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeyStoreInDir(t, dir)

	pub, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	msg := []byte("test-digest-bytes")
	sig, err := ks.Sign(msg)
	require.NoError(t, err)
	assert.Len(t, sig, ed25519.SignatureSize)
	assert.True(t, ed25519.Verify(pub.(ed25519.PublicKey), msg, sig), "signature must verify with the corresponding public key")
}

// TestFileKeyStore_Sign_BeforeLoad returns an error when Sign is called without GenerateOrLoad.
func TestFileKeyStore_Sign_BeforeLoad(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeyStoreInDir(t, dir)

	_, err := ks.Sign([]byte("message"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GenerateOrLoad")
}

// TestFileKeyStore_KeyFileMode verifies the on-disk key file has mode 0600.
func TestFileKeyStore_KeyFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission check not applicable on Windows")
	}
	dir := t.TempDir()
	ks := newTestKeyStoreInDir(t, dir)

	_, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(dir, keyFileName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// TestFileKeyStore_GenerateOrLoad_Idempotent verifies that calling GenerateOrLoad twice
// on the same FileKeyStore returns the same key (cached, not re-generated).
func TestFileKeyStore_GenerateOrLoad_Idempotent(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeyStoreInDir(t, dir)

	pub1, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	pub2, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	assert.Equal(t, pub1, pub2)
}

// TestFileKeyStore_PublicKey returns the key loaded by GenerateOrLoad.
func TestFileKeyStore_PublicKey(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeyStoreInDir(t, dir)

	assert.Nil(t, ks.PublicKey(), "PublicKey must be nil before GenerateOrLoad")

	pub, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	assert.Equal(t, pub, ks.PublicKey())
}

func TestRemoveStoredKey_NextLoadGeneratesNewDeviceID(t *testing.T) {
	dir := t.TempDir()
	ks, err := NewFileKeyStoreForTesting(dir)
	require.NoError(t, err)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	before := ks.DeviceID()

	require.NoError(t, RemoveStoredKey(dir))
	_, statErr := os.Stat(filepath.Join(dir, StoredKeyFileName()))
	assert.True(t, os.IsNotExist(statErr))

	ks2, err := NewFileKeyStoreForTesting(dir)
	require.NoError(t, err)
	_, _, err = ks2.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, before, ks2.DeviceID())
}

func TestRemoveStoredKey_MissingKeyIsNotAnError(t *testing.T) {
	require.NoError(t, RemoveStoredKey(t.TempDir()))
}

// TestFileKeyStore_Regenerate_ReplacesKeyAndDeviceID verifies Regenerate swaps in a
// new key and DeviceID, keeps the file encrypted, and leaves the old key unloadable.
func TestFileKeyStore_Regenerate_ReplacesKeyAndDeviceID(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeyStoreInDir(t, dir)
	oldPub, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	oldID := ks.DeviceID()

	newPub, alg, err := ks.Regenerate(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, oldPub, newPub, "new public key must differ")
	assert.NotEqual(t, oldID, ks.DeviceID(), "DeviceID must change with the key")
	assert.Equal(t, AlgorithmEd25519, alg)
	wantID, err := ComputeDeviceID(alg, newPub)
	require.NoError(t, err)
	assert.Equal(t, wantID, ks.DeviceID())

	data, err := os.ReadFile(filepath.Join(dir, keyFileName))
	require.NoError(t, err)
	assert.NotContains(t, string(data), string(ks.privateKey), "plaintext key never written to disk")
	block, _ := pem.Decode(data)
	assert.Nil(t, block, "on-disk bytes must be ciphertext")
	_, statErr := os.Stat(filepath.Join(dir, keyFileName+".tmp"))
	assert.True(t, os.IsNotExist(statErr), "no temp file left behind")

	// A fresh store on the same directory loads the new key, not the old one.
	reloaded := newTestKeyStoreInDir(t, dir)
	gotPub, _, err := reloaded.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.Equal(t, newPub, gotPub)
	assert.NotEqual(t, oldPub, gotPub, "old key is no longer loadable")

	// The new key signs; the old public key does not verify it.
	sig, err := ks.Sign([]byte("m"))
	require.NoError(t, err)
	assert.True(t, ed25519.Verify(newPub.(ed25519.PublicKey), []byte("m"), sig))
	assert.False(t, ed25519.Verify(oldPub.(ed25519.PublicKey), []byte("m"), sig))
}

// TestFileKeyStore_LoadsPreChangeFile proves a device_identity.enc written by the
// existing encryptor (raw Ed25519 private key, as before this change) loads with the
// same key and DeviceID and reports ed25519 / file.
func TestFileKeyStore_LoadsPreChangeFile(t *testing.T) {
	dir := t.TempDir()
	enc, err := stewardcrypto.NewEncryptorFromBytes([]byte("cfgms-test-machine-id"), dir)
	require.NoError(t, err)
	wantPub, wantPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ct, err := enc.Encrypt([]byte(wantPriv))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "device_identity.enc"), ct, 0600))

	ks := newFileKeyStoreWithEncryptor(dir, enc)
	pub, alg, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.Equal(t, wantPub, pub)
	assert.Equal(t, AlgorithmEd25519, alg)
	assert.Equal(t, AlgorithmEd25519, ks.Algorithm())
	assert.Equal(t, ProtectionFile, ks.ProtectionLevel())
	sum := sha256.Sum256(wantPub)
	assert.Equal(t, hex.EncodeToString(sum[:]), ks.DeviceID())
}

func TestComputeDeviceID_PerAlgorithm(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	got, err := ComputeDeviceID(AlgorithmEd25519, edPub)
	require.NoError(t, err)
	sum := sha256.Sum256(edPub)
	assert.Equal(t, hex.EncodeToString(sum[:]), got)

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	require.NoError(t, err)
	got, err = ComputeDeviceID(AlgorithmECDSAP256, &p256.PublicKey)
	require.NoError(t, err)
	dsum := sha256.Sum256(der)
	assert.Equal(t, hex.EncodeToString(dsum[:]), got)
	assert.Len(t, got, 64)
	assert.Equal(t, strings.ToLower(got), got)

	enc, err := EncodePublicKey(AlgorithmECDSAP256, &p256.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, base64.StdEncoding.EncodeToString(der), enc)
	enc, err = EncodePublicKey(AlgorithmEd25519, edPub)
	require.NoError(t, err)
	assert.Equal(t, base64.StdEncoding.EncodeToString(edPub), enc)

	_, err = ComputeDeviceID(AlgorithmEd25519, &p256.PublicKey)
	assert.Error(t, err, "algorithm and key type must agree")
	_, err = ComputeDeviceID(Algorithm("rsa"), edPub)
	assert.Error(t, err)
}

func TestFileKeyStore_RemoveKey(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeyStoreInDir(t, dir)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	require.NoError(t, ks.RemoveKey())
	_, statErr := os.Stat(filepath.Join(dir, keyFileName))
	assert.True(t, os.IsNotExist(statErr))
	assert.Empty(t, ks.DeviceID())
	assert.Nil(t, ks.PublicKey())
	require.NoError(t, ks.RemoveKey(), "removing an absent key is not an error")
}
