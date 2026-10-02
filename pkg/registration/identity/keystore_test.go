// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
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

	assert.Equal(t, []byte(pub1), []byte(pub2), "public key must be identical across load cycles")
	assert.Equal(t, deviceID1, deviceID2, "DeviceID must be stable across load cycles")
}

// TestFileKeyStore_DeviceID_IsHexSHA256OfPublicKey proves the DeviceID formula:
// hex(sha256(publicKeyBytes)) == 64-char lowercase hex.
func TestFileKeyStore_DeviceID_IsHexSHA256OfPublicKey(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeyStoreInDir(t, dir)

	pub, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	expected := computeDeviceID(pub)
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
	assert.True(t, ed25519.Verify(pub, msg, sig), "signature must verify with the corresponding public key")
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

	assert.Equal(t, []byte(pub1), []byte(pub2))
}

// TestFileKeyStore_PublicKey returns the key loaded by GenerateOrLoad.
func TestFileKeyStore_PublicKey(t *testing.T) {
	dir := t.TempDir()
	ks := newTestKeyStoreInDir(t, dir)

	assert.Nil(t, ks.PublicKey(), "PublicKey must be nil before GenerateOrLoad")

	pub, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	assert.Equal(t, []byte(pub), []byte(ks.PublicKey()))
}
