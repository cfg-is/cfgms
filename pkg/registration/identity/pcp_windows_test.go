// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/cfgis/cfgms/pkg/logging"
)

// pcpTPMTestEnv selects TestPCP_RealTPM, which creates keys in this host's TPM.
const pcpTPMTestEnv = "CFGMS_TEST_PCP_TPM"

// cngLogger records Info messages and their string values.
type cngLogger struct {
	logging.NoopLogger
	mu   sync.Mutex
	logs []string
}

func (l *cngLogger) Info(msg string, kv ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	b.WriteString(msg)
	for _, v := range kv {
		if s, ok := v.(string); ok {
			b.WriteString(" " + s)
		}
	}
	l.logs = append(l.logs, b.String())
}

func (l *cngLogger) joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.logs, "\n")
}

func elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// testCNGConfig returns a per-test key namespace in provider. Keys are per-user
// unless machine is set, so the test needs no elevation. Every key the test
// leaves behind is deleted on cleanup.
func testCNGConfig(t *testing.T, provider string, machine bool) cngKeyConfig {
	t.Helper()
	var b [6]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	c := cngKeyConfig{provider: provider, keyPrefix: "cfgms-test-" + hex.EncodeToString(b[:]) + "-", machine: machine}
	return c
}

func cleanupKeys(t *testing.T, c cngKeyConfig, dir string) {
	t.Helper()
	t.Cleanup(func() { assert.NoError(t, removeCNGKeys(c, dir)) })
}

func softwareStore(t *testing.T) (*cngKeyStore, cngKeyConfig, string) {
	t.Helper()
	c := testCNGConfig(t, softwareKeyStorageProvider, false)
	dir := t.TempDir()
	cleanupKeys(t, c, dir)
	return newCNGKeyStore(c, dir, false, nil), c, dir
}

func testDigest(t *testing.T) []byte {
	t.Helper()
	var m [48]byte
	_, err := rand.Read(m[:])
	require.NoError(t, err)
	d := sha256.Sum256(m[:])
	return d[:]
}

// requireSignsDigest proves Sign signs the digest it is given as the hash input
// directly: the DER signature verifies over the digest and not over its hash.
func requireSignsDigest(t *testing.T, ks KeyStore) {
	t.Helper()
	pub, ok := ks.PublicKey().(*ecdsa.PublicKey)
	require.True(t, ok, "public key is *ecdsa.PublicKey")
	digest := testDigest(t)
	sig, err := ks.Sign(digest)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(pub, digest, sig), "signature verifies over the 32-byte digest")
	rehashed := sha256.Sum256(digest)
	assert.False(t, ecdsa.VerifyASN1(pub, rehashed[:], sig), "digest must not be hashed a second time")
}

// keyExists reports whether name is a persisted key in c's provider.
func keyExists(t *testing.T, c cngKeyConfig, name string) bool {
	t.Helper()
	prov, err := openProvider(c.provider)
	require.NoError(t, err)
	defer freeObject(prov)
	h, err := c.openKey(prov, name)
	if isKeyNotFound(err) {
		return false
	}
	require.NoError(t, err)
	freeObject(h)
	return true
}

func requireNotExportable(t *testing.T, c cngKeyConfig, name string) {
	t.Helper()
	prov, err := openProvider(c.provider)
	require.NoError(t, err)
	defer freeObject(prov)
	h, err := c.openKey(prov, name)
	require.NoError(t, err)
	defer freeObject(h)
	_, err = exportBlob(h, "ECCPUBLICBLOB")
	require.NoError(t, err, "public blob exports")
	priv, err := exportBlob(h, "ECCPRIVATEBLOB")
	assert.Error(t, err, "private blob export must fail")
	assert.Nil(t, priv)
}

func TestCNG_SoftwareProvider_CreatesP256KeyAndSignsDigest(t *testing.T) {
	ks, _, _ := softwareStore(t)
	assert.Nil(t, ks.PublicKey())
	assert.Empty(t, ks.DeviceID())

	pub, alg, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AlgorithmECDSAP256, alg)
	assert.Equal(t, AlgorithmECDSAP256, ks.Algorithm())
	assert.Equal(t, softwareKSPLevel, ks.ProtectionLevel(), "only the Platform Crypto Provider reports tpm")
	ec, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, elliptic.P256(), ec.Curve)

	id, err := ComputeDeviceID(AlgorithmECDSAP256, pub)
	require.NoError(t, err)
	assert.Equal(t, id, ks.DeviceID())
	requireSignsDigest(t, ks)
}

func TestCNG_ReloadReturnsSameKey(t *testing.T) {
	ks, c, dir := softwareStore(t)
	pub1, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	again := newCNGKeyStore(c, dir, true, nil)
	pub2, alg, err := again.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AlgorithmECDSAP256, alg)
	assert.True(t, pub1.(*ecdsa.PublicKey).Equal(pub2))
	assert.Equal(t, ks.DeviceID(), again.DeviceID())
	requireSignsDigest(t, again)
}

func TestCNG_PrivateKeyIsNotExportable(t *testing.T) {
	ks, c, dir := softwareStore(t)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	requireNotExportable(t, c, c.slots(dir)[0])
}

func TestCNG_RegenerateReplacesAndDeletesOldKey(t *testing.T) {
	ks, c, dir := softwareStore(t)
	slots := c.slots(dir)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	id1 := ks.DeviceID()

	pub2, alg, err := ks.Regenerate(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AlgorithmECDSAP256, alg)
	id2 := ks.DeviceID()
	assert.NotEqual(t, id1, id2)
	assert.False(t, keyExists(t, c, slots[0]), "previous key deleted")
	assert.True(t, keyExists(t, c, slots[1]))
	requireSignsDigest(t, ks)

	reloaded := newCNGKeyStore(c, dir, true, nil)
	pub, _, err := reloaded.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.True(t, pub2.(*ecdsa.PublicKey).Equal(pub))
	assert.Equal(t, id2, reloaded.DeviceID())

	// A second regenerate moves the key back to the primary slot.
	_, _, err = reloaded.Regenerate(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, id2, reloaded.DeviceID())
	assert.NotEqual(t, id1, reloaded.DeviceID())
	assert.True(t, keyExists(t, c, slots[0]))
	assert.False(t, keyExists(t, c, slots[1]), "previous key deleted")
	requireSignsDigest(t, reloaded)
}

func TestCNG_RegenerateBeforeLoadReplacesStoredKey(t *testing.T) {
	ks, c, dir := softwareStore(t)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	id1 := ks.DeviceID()

	fresh := newCNGKeyStore(c, dir, true, nil)
	_, _, err = fresh.Regenerate(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, id1, fresh.DeviceID())
	assert.False(t, keyExists(t, c, c.slots(dir)[0]), "previous key deleted")
}

func TestCNG_RemoveKeyDeletesPersistedKey(t *testing.T) {
	ks, c, dir := softwareStore(t)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	_, _, err = ks.Regenerate(context.Background())
	require.NoError(t, err)

	require.NoError(t, ks.RemoveKey())
	for _, name := range c.slots(dir) {
		assert.False(t, keyExists(t, c, name))
	}
	assert.Empty(t, ks.DeviceID())
	assert.Nil(t, ks.PublicKey())
	_, err = ks.Sign(testDigest(t))
	assert.Error(t, err)
	require.NoError(t, ks.RemoveKey(), "removing an absent key is not an error")

	again := newCNGKeyStore(c, dir, false, nil)
	_, _, err = again.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	require.NoError(t, removeCNGKeys(c, dir))
	assert.False(t, keyExists(t, c, c.slots(dir)[0]), "backend removal deletes the persisted key")
}

func TestCNG_RecordedKeyMissingIsNotMinted(t *testing.T) {
	c := testCNGConfig(t, softwareKeyStorageProvider, false)
	dir := t.TempDir()
	cleanupKeys(t, c, dir)
	ks := newCNGKeyStore(c, dir, true, nil)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.Error(t, err)
	for _, name := range c.slots(dir) {
		assert.False(t, keyExists(t, c, name), "no replacement key is created")
	}
}

// TestCNG_UnusableKeyIsNotReplaced stores an RSA key under the device key name:
// it opens but is not a P-256 key, so load must fail and leave it in place.
func TestCNG_UnusableKeyIsNotReplaced(t *testing.T) {
	c := testCNGConfig(t, softwareKeyStorageProvider, false)
	dir := t.TempDir()
	cleanupKeys(t, c, dir)
	name := c.slots(dir)[0]

	prov, err := openProvider(c.provider)
	require.NoError(t, err)
	defer freeObject(prov)
	alg, err := utf16("RSA")
	require.NoError(t, err)
	pname, err := utf16(name)
	require.NoError(t, err)
	var h uintptr
	r, _, _ := procNCryptCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(alg)), uintptr(unsafe.Pointer(pname)), 0, c.flags())
	require.NoError(t, cngResult("NCryptCreatePersistedKey", r))
	r, _, _ = procNCryptFinalizeKey.Call(h, ncryptSilentFlag)
	freeObject(h)
	require.NoError(t, cngResult("NCryptFinalizeKey", r))

	ks := newCNGKeyStore(c, dir, false, nil)
	_, _, err = ks.GenerateOrLoad(context.Background())
	require.Error(t, err)
	assert.Empty(t, ks.DeviceID())
	assert.True(t, keyExists(t, c, name), "the existing key is left in place")
	assert.False(t, keyExists(t, c, c.slots(dir)[1]), "no replacement key is created")
}

func TestCNG_SignRejectsNon32ByteDigest(t *testing.T) {
	ks, _, _ := softwareStore(t)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	_, err = ks.Sign(make([]byte, 31))
	assert.Error(t, err)
	_, err = ks.Sign([]byte("not a digest, longer than thirty-two bytes"))
	assert.Error(t, err)
}

func TestCNG_SignBeforeLoadFails(t *testing.T) {
	ks, _, _ := softwareStore(t)
	_, err := ks.Sign(testDigest(t))
	assert.Error(t, err)
}

func TestCNG_MachineKeyStore(t *testing.T) {
	if !elevated() {
		t.Skip("machine key store requires an elevated process; the per-user tests cover the same CNG calls")
	}
	c := testCNGConfig(t, softwareKeyStorageProvider, true)
	dir := t.TempDir()
	cleanupKeys(t, c, dir)
	ks := newCNGKeyStore(c, dir, false, nil)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	requireSignsDigest(t, ks)
	requireNotExportable(t, c, c.slots(dir)[0])
	require.NoError(t, ks.RemoveKey())
	assert.False(t, keyExists(t, c, c.slots(dir)[0]))
}

func TestCNG_SlotsDependOnIdentityDir(t *testing.T) {
	c := cngKeyConfig{provider: softwareKeyStorageProvider, keyPrefix: cngKeyNamePrefix}
	a, b := t.TempDir(), t.TempDir()
	assert.NotEqual(t, c.slots(a), c.slots(b))
	assert.Equal(t, c.slots(a), c.slots(strings.ToUpper(a)+`\`), "case and trailing separator do not change the name")
	assert.True(t, strings.HasPrefix(c.slots(a)[0], cngKeyNamePrefix))
	assert.Equal(t, c.slots(a)[0]+cngAltSlotSuffix, c.slots(a)[1])
}

func TestParseECCPublicBlob(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	point, err := priv.PublicKey.Bytes()
	require.NoError(t, err)
	blob := binary.LittleEndian.AppendUint32(nil, ecdsaP256PublicMagic)
	blob = binary.LittleEndian.AppendUint32(blob, p256CoordinateSize)
	blob = append(blob, point[1:]...)

	pub, err := parseECCPublicBlob(blob)
	require.NoError(t, err)
	assert.True(t, priv.PublicKey.Equal(pub))

	bad := append([]byte(nil), blob...)
	binary.LittleEndian.PutUint32(bad, 0x32534345) // "ECS2": P-256 private magic
	_, err = parseECCPublicBlob(bad)
	assert.Error(t, err)
	_, err = parseECCPublicBlob(blob[:len(blob)-1])
	assert.Error(t, err)
	_, err = parseECCPublicBlob(blob[:4])
	assert.Error(t, err)
	offCurve := append([]byte(nil), blob...)
	offCurve[len(offCurve)-1] ^= 1
	_, err = parseECCPublicBlob(offCurve)
	assert.Error(t, err)
}

func TestP1363ToDER(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	digest := testDigest(t)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	require.NoError(t, err)
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	der, err := p1363ToDER(raw)
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(&priv.PublicKey, digest, der))
	_, err = p1363ToDER(raw[:63])
	assert.Error(t, err)
}

// useCNGConfig points the registered backend at c for one test and gives Open a
// file backend independent of the host's DPAPI profile.
func useCNGConfig(t *testing.T, c cngKeyConfig) {
	t.Helper()
	savedCfg, savedFactory := defaultCNGKeyConfig, newFileStore
	defaultCNGKeyConfig = c
	newFileStore = func(dir string) (*FileKeyStore, error) { return NewFileKeyStoreForTesting(dir) }
	t.Cleanup(func() { defaultCNGKeyConfig, newFileStore = savedCfg, savedFactory })
}

func requireFileFallback(t *testing.T, dir string, ks KeyStore, log *cngLogger) {
	t.Helper()
	assert.Equal(t, ProtectionFile, ks.ProtectionLevel())
	assert.Equal(t, AlgorithmEd25519, ks.Algorithm())
	assert.Len(t, ks.DeviceID(), 64)
	_, err := os.Stat(filepath.Join(dir, keyFileName))
	assert.NoError(t, err, "fallback creates the file key")
	assert.Contains(t, log.joined(), "Hardware device key backend unavailable")
}

// tpmPresent asks the TPM Base Services, independently of CNG, whether this
// host has a TPM.
func tpmPresent() bool {
	proc := windows.NewLazySystemDLL("tbs.dll").NewProc("Tbsi_GetDeviceInfo")
	if proc.Find() != nil {
		return false
	}
	var info [4]uint32 // TPM_DEVICE_INFO
	r, _, _ := proc.Call(unsafe.Sizeof(info), uintptr(unsafe.Pointer(&info[0])))
	return r == 0
}

// TestOpen_PlatformCryptoProvider runs Open with the production provider. On a
// host without a TPM (the CI runner) the backend fails and Open returns a working
// file backend with the reason logged; on a host with one it returns the TPM key.
func TestOpen_PlatformCryptoProvider(t *testing.T) {
	c := testCNGConfig(t, platformCryptoProvider, elevated())
	useCNGConfig(t, c)
	dir := t.TempDir()
	cleanupKeys(t, c, dir)
	log := &cngLogger{}
	ks, err := Open(context.Background(), dir, log)
	require.NoError(t, err, "enrollment must not see a TPM error")

	if !tpmPresent() {
		t.Logf("no TPM on this host; fallback logged: %s", log.joined())
		requireFileFallback(t, dir, ks, log)
		return
	}
	t.Logf("TPM present; Open selected protection level %q (log: %s)", ks.ProtectionLevel(), log.joined())
	assert.Equal(t, ProtectionTPM, ks.ProtectionLevel())
	requireSignsDigest(t, ks)
}

func TestOpen_UnavailableProviderFallsBackToFile(t *testing.T) {
	useCNGConfig(t, cngKeyConfig{provider: "CFGMS Test Nonexistent Key Storage Provider", keyPrefix: "cfgms-test-none-"})
	dir := t.TempDir()
	log := &cngLogger{}
	ks, err := Open(context.Background(), dir, log)
	require.NoError(t, err)
	requireFileFallback(t, dir, ks, log)
	assert.Contains(t, log.joined(), "NCryptOpenStorageProvider")
	requireSignsDigestEd25519(t, ks)
}

func requireSignsDigestEd25519(t *testing.T, ks KeyStore) {
	t.Helper()
	sig, err := ks.Sign([]byte("message"))
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
}

func TestOpen_RecordedTPMKeyMissingIsUnavailable(t *testing.T) {
	c := testCNGConfig(t, softwareKeyStorageProvider, false)
	useCNGConfig(t, c)
	dir := t.TempDir()
	cleanupKeys(t, c, dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, storedIdentityFileName),
		[]byte(`{"key_protection_level":"tpm"}`), 0600))

	_, err := Open(context.Background(), dir, &cngLogger{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrHardwareKeyUnavailable))
	_, statErr := os.Stat(filepath.Join(dir, keyFileName))
	assert.True(t, os.IsNotExist(statErr), "no file key is created")
	assert.False(t, keyExists(t, c, c.slots(dir)[0]), "no replacement key is created")
}

func TestOpen_RecordedTPMKeyReloads(t *testing.T) {
	c := testCNGConfig(t, softwareKeyStorageProvider, false)
	useCNGConfig(t, c)
	dir := t.TempDir()
	cleanupKeys(t, c, dir)
	first := newCNGKeyStore(c, dir, false, nil)
	_, _, err := first.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, storedIdentityFileName),
		[]byte(`{"key_protection_level":"tpm"}`), 0600))

	ks, err := Open(context.Background(), dir, &cngLogger{})
	require.NoError(t, err)
	assert.Equal(t, first.DeviceID(), ks.DeviceID())
	requireSignsDigest(t, ks)
}

func TestRemoveAllStoredKeys_RemovesCNGKey(t *testing.T) {
	c := testCNGConfig(t, softwareKeyStorageProvider, false)
	useCNGConfig(t, c)
	dir := t.TempDir()
	cleanupKeys(t, c, dir)
	ks := newCNGKeyStore(c, dir, false, nil)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.NoError(t, err)

	require.NoError(t, RemoveAllStoredKeys(dir))
	assert.False(t, keyExists(t, c, c.slots(dir)[0]))
	require.NoError(t, RemoveAllStoredKeys(dir), "removing absent keys is not an error")
}

func TestRemoveAllStoredKeys_PlatformProviderWithoutKey(t *testing.T) {
	useCNGConfig(t, testCNGConfig(t, platformCryptoProvider, elevated()))
	assert.NoError(t, RemoveAllStoredKeys(t.TempDir()), "a host with no TPM key, or no TPM, has nothing to remove")
}

// TestPCP_RealTPM runs the backend against this host's TPM through the Platform
// Crypto Provider. It is selected by CFGMS_TEST_PCP_TPM=1 and is skipped, with
// the reason "no TPM", only where the provider cannot hold a key.
func TestPCP_RealTPM(t *testing.T) {
	if os.Getenv(pcpTPMTestEnv) != "1" {
		t.Skipf("set %s=1 to run against this host's TPM", pcpTPMTestEnv)
	}
	c := testCNGConfig(t, platformCryptoProvider, elevated())
	dir := t.TempDir()
	cleanupKeys(t, c, dir)
	ks := newCNGKeyStore(c, dir, false, nil)
	_, alg, err := ks.GenerateOrLoad(context.Background())
	if err != nil {
		if _, pErr := openProvider(c.provider); pErr != nil || keyCannotExist(err) {
			t.Skipf("no TPM: %v", err)
		}
		require.NoError(t, err)
	}
	t.Logf("provider=%q machine_key=%v protection_level=%s algorithm=%s device_id=%s",
		c.provider, c.machine, ks.ProtectionLevel(), alg, ks.DeviceID())
	assert.Equal(t, ProtectionTPM, ks.ProtectionLevel())
	assert.Equal(t, AlgorithmECDSAP256, alg)
	requireSignsDigest(t, ks)
	requireNotExportable(t, c, c.slots(dir)[0])

	again := newCNGKeyStore(c, dir, true, nil)
	_, _, err = again.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.Equal(t, ks.DeviceID(), again.DeviceID())

	id1 := again.DeviceID()
	_, _, err = again.Regenerate(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, id1, again.DeviceID())
	assert.False(t, keyExists(t, c, c.slots(dir)[0]), "previous key deleted")
	requireSignsDigest(t, again)

	require.NoError(t, again.RemoveKey())
	for _, name := range c.slots(dir) {
		assert.False(t, keyExists(t, c, name))
	}
}
