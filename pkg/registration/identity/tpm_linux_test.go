// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux && cgo

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// simTPM is a software TPM 2.0 (the reference implementation) with a fixed seed.
// Closing the transport per operation is a no-op so state survives between
// operations, as with a real device; the simulator itself closes at test end.
type simTPM struct{ sim *simulator.Simulator }

func (s *simTPM) Send(in []byte) ([]byte, error) { return tpmutil.RunCommandRaw(s.sim, in) }
func (s *simTPM) Close() error                   { return nil }

// shutdown stops the simulator, releasing the process-wide instance. Idempotent.
func (s *simTPM) shutdown() {
	if !s.sim.IsClosed() {
		_ = s.sim.Close()
	}
}

// newSimTPM starts a software TPM. Only one exists at a time; a second call
// blocks until the previous test's simulator is closed.
func newSimTPM(t *testing.T, seed int64) (*simTPM, tpmOpener) {
	t.Helper()
	sim, err := simulator.GetWithFixedSeedInsecure(seed)
	require.NoError(t, err)
	s := &simTPM{sim: sim}
	t.Cleanup(s.shutdown)
	return s, func() (transport.TPMCloser, error) { return s, nil }
}

func digestOf(msg string) []byte {
	d := sha256.Sum256([]byte(msg))
	return d[:]
}

// transientHandles lists handles the TPM still holds loaded.
func transientHandles(t *testing.T, tpm transport.TPM) int {
	t.Helper()
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTTransient) << 24,
		PropertyCount: 32,
	}.Execute(tpm)
	require.NoError(t, err)
	h, err := rsp.CapabilityData.Data.Handles()
	require.NoError(t, err)
	return len(h.Handle)
}

func TestTPMKeyStore_GenerateSignVerify(t *testing.T) {
	sim, open := newSimTPM(t, 1)
	dir := t.TempDir()
	ks := newTPMKeyStore(dir, open, nil)

	pub, alg, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AlgorithmECDSAP256, alg)
	assert.Equal(t, AlgorithmECDSAP256, ks.Algorithm())
	assert.Equal(t, ProtectionTPM, ks.ProtectionLevel())

	ecPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	wantID, err := ComputeDeviceID(AlgorithmECDSAP256, ecPub)
	require.NoError(t, err)
	assert.Equal(t, wantID, ks.DeviceID())

	digest := digestOf("challenge")
	sig, err := ks.Sign(digest)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(ecPub, digest, sig), "signature verifies over the digest with no second hash")
	assert.False(t, ecdsa.VerifyASN1(ecPub, digestOf("other"), sig))

	info, err := os.Stat(filepath.Join(dir, tpmBlobFileName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	_, statErr := os.Stat(filepath.Join(dir, keyFileName))
	assert.True(t, os.IsNotExist(statErr), "no file key is written")

	assert.Zero(t, transientHandles(t, sim), "transient handles must be flushed")
}

func TestTPMKeyStore_SignRejectsBadDigestAndUnloaded(t *testing.T) {
	_, open := newSimTPM(t, 1)
	ks := newTPMKeyStore(t.TempDir(), open, nil)
	_, err := ks.Sign(digestOf("x"))
	assert.Error(t, err, "unloaded store must not sign")
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	_, err = ks.Sign([]byte("short"))
	assert.Error(t, err)
}

func TestTPMKeyStore_ReloadReturnsSameKey(t *testing.T) {
	_, open := newSimTPM(t, 1)
	dir := t.TempDir()
	first := newTPMKeyStore(dir, open, nil)
	pub1, _, err := first.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	second := newTPMKeyStore(dir, open, nil)
	pub2, _, err := second.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.True(t, pub1.(*ecdsa.PublicKey).Equal(pub2))
	assert.Equal(t, first.DeviceID(), second.DeviceID())

	digest := digestOf("after reload")
	sig, err := second.Sign(digest)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(pub2.(*ecdsa.PublicKey), digest, sig))
}

func TestTPMKeyStore_BlobsFromAnotherTPMDoNotLoad(t *testing.T) {
	dir := t.TempDir()
	simA, openA := newSimTPM(t, 1)
	_, _, err := newTPMKeyStore(dir, openA, nil).GenerateOrLoad(context.Background())
	require.NoError(t, err)
	simA.shutdown() // only one software TPM can run at a time
	blobPath := filepath.Join(dir, tpmBlobFileName)
	before, err := os.ReadFile(blobPath)
	require.NoError(t, err)

	_, openB := newSimTPM(t, 2)
	other := newTPMKeyStore(dir, openB, nil)
	_, _, err = other.GenerateOrLoad(context.Background())
	require.Error(t, err, "a blob wrapped by another TPM's seed must not load")
	_, err = other.Sign(digestOf("x"))
	assert.Error(t, err, "and must not sign")

	after, err := os.ReadFile(blobPath)
	require.NoError(t, err)
	assert.Equal(t, before, after, "a load failure must not replace the key")

	// Through the seam: Open reports the reason and falls back to the file backend.
	useTPMOpener(t, openB)
	log := &recLogger{}
	ks, err := Open(context.Background(), dir, log)
	require.NoError(t, err)
	requireFileFallback(t, dir, ks, log)
	assert.Contains(t, log.joined(), "load key into TPM")
}

func TestOpen_UsesTPMWhenAvailable(t *testing.T) {
	_, open := newSimTPM(t, 1)
	useTPMOpener(t, open)
	dir := t.TempDir()
	ks, err := Open(context.Background(), dir, &recLogger{})
	require.NoError(t, err)
	assert.Equal(t, ProtectionTPM, ks.ProtectionLevel())
	assert.Equal(t, AlgorithmECDSAP256, ks.Algorithm())
	_, statErr := os.Stat(filepath.Join(dir, keyFileName))
	assert.True(t, os.IsNotExist(statErr))
}

func TestTPMKeyStore_RegenerateReplacesKey(t *testing.T) {
	_, open := newSimTPM(t, 1)
	dir := t.TempDir()
	ks := newTPMKeyStore(dir, open, nil)
	oldPub, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	oldID := ks.DeviceID()

	newPub, alg, err := ks.Regenerate(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AlgorithmECDSAP256, alg)
	assert.NotEqual(t, oldID, ks.DeviceID())

	digest := digestOf("post-regenerate")
	sig, err := ks.Sign(digest)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(newPub.(*ecdsa.PublicKey), digest, sig))
	assert.False(t, ecdsa.VerifyASN1(oldPub.(*ecdsa.PublicKey), digest, sig), "old key no longer signs")

	reloaded := newTPMKeyStore(dir, open, nil)
	_, _, err = reloaded.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.Equal(t, ks.DeviceID(), reloaded.DeviceID(), "the new key is the persisted one")
	_, statErr := os.Stat(filepath.Join(dir, tpmBlobFileName+".tmp"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestTPMKeyStore_RemoveKeyDeletesBlobs(t *testing.T) {
	_, open := newSimTPM(t, 1)
	dir := t.TempDir()
	ks := newTPMKeyStore(dir, open, nil)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	require.NoError(t, ks.RemoveKey())
	_, statErr := os.Stat(filepath.Join(dir, tpmBlobFileName))
	assert.True(t, os.IsNotExist(statErr))
	assert.Empty(t, ks.DeviceID())
	assert.Nil(t, ks.PublicKey())
	_, err = ks.Sign(digestOf("x"))
	assert.Error(t, err)
	assert.NoError(t, ks.RemoveKey(), "removing an absent key is not an error")

	// RemoveAllStoredKeys reaches the registered TPM backend.
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	require.NoError(t, RemoveAllStoredKeys(dir))
	_, statErr = os.Stat(filepath.Join(dir, tpmBlobFileName))
	assert.True(t, os.IsNotExist(statErr))
}
