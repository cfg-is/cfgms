// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

func testTag(t *testing.T) string {
	t.Helper()
	var b [8]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return "io.cfgms.steward.test." + hex.EncodeToString(b[:])
}

func mustAPI(t *testing.T) *secAPI {
	t.Helper()
	api, err := loadSecAPI()
	require.NoError(t, err, "Security and CoreFoundation bindings must resolve on macOS")
	return api
}

// softwareClass is a Keychain software P-256 key: same API, token ID omitted.
func softwareClass(t *testing.T, permanent bool) keyClass {
	return keyClass{secureEnclave: false, permanent: permanent, tag: testTag(t)}
}

// requirePersistentSoftware skips when the runner has no usable Keychain; the
// non-persistent tests above it cover the same sign/DER/PKIX code path.
func requirePersistentSoftware(t *testing.T, api *secAPI, c keyClass) {
	t.Helper()
	key, err := api.create(c, c.tag)
	if err != nil {
		t.Skipf("no persistent Keychain key available on this host (%v); sign/DER/PKIX path is covered by TestSoftwareKey_SignsDigestWithoutSecondHash", err)
	}
	api.cfRelease(key)
	require.NoError(t, api.remove(c, c.tag))
}

func TestSecAPI_BindingsResolve(t *testing.T) {
	api := mustAPI(t)
	for name, v := range map[string]uintptr{
		"CFRelease":                    fnAddr(api.cfRelease != nil),
		"SecKeyCreateRandomKey":        fnAddr(api.secKeyCreateRandomKey != nil),
		"SecKeyCreateSignature":        fnAddr(api.secKeyCreateSignature != nil),
		"SecItemCopyMatching":          fnAddr(api.secItemCopyMatching != nil),
		"kSecAttrTokenIDSecureEnclave": api.kTokenIDSE,
		"kSecAttrTokenID":              api.kTokenID,
		"kSecAttrApplicationTag":       api.kAppTag,
		"digest algorithm":             api.kAlgECDSADigestX962SHA256,
		"kCFBooleanTrue":               api.cfTrue,
		"kCFBooleanFalse":              api.cfFalse,
	} {
		assert.NotZero(t, v, name)
	}
}

func fnAddr(ok bool) uintptr {
	if ok {
		return 1
	}
	return 0
}

// A Keychain software key through the same create/export/sign code verifies over
// the 32-byte digest itself, not over a second hash of it.
func TestSoftwareKey_SignsDigestWithoutSecondHash(t *testing.T) {
	api := mustAPI(t)
	c := softwareClass(t, false)
	key, err := api.create(c, c.tag)
	require.NoError(t, err)
	defer api.cfRelease(key)

	pub, err := api.publicKey(key)
	require.NoError(t, err)

	msg := sha256.Sum256([]byte("pop payload"))
	sig, err := api.sign(key, msg[:])
	require.NoError(t, err)

	assert.True(t, ecdsa.VerifyASN1(pub, msg[:], sig), "signature must verify over the digest passed to Sign")
	double := sha256.Sum256(msg[:])
	assert.False(t, ecdsa.VerifyASN1(pub, double[:], sig), "digest must not be hashed a second time")

	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	want := sha256.Sum256(der)
	id, err := ComputeDeviceID(AlgorithmECDSAP256, pub)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(want[:]), id)
}

func TestSecKeyStore_SignRejectsBadDigestAndUnloaded(t *testing.T) {
	api := mustAPI(t)
	ks := newSecKeyStore(api, softwareClass(t, false), false, nil)
	_, err := ks.Sign(make([]byte, 32))
	assert.Error(t, err, "unloaded store")
	_, err = ks.Sign(make([]byte, 31))
	assert.Error(t, err, "wrong digest length")
	assert.Nil(t, ks.PublicKey())
	assert.Empty(t, ks.DeviceID())
}

// A non-persistent key could not be reloaded and would change DeviceID on every
// start, so the store refuses to create one.
func TestSecKeyStore_NeverCreatesNonPersistentKey(t *testing.T) {
	api := mustAPI(t)
	ks := newSecKeyStore(api, softwareClass(t, false), false, nil)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.Error(t, err)
	assert.Nil(t, ks.PublicKey())
}

func TestSecKeyStore_MustExistDoesNotCreate(t *testing.T) {
	api := mustAPI(t)
	c := softwareClass(t, true)
	ks := newSecKeyStore(api, c, true, nil)
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.Error(t, err)
	key, lErr := api.lookup(c, c.tag)
	if lErr == nil {
		assert.Zero(t, key, "no key may be created for a recorded identity")
	}
}

func TestSecKeyStore_PersistentLifecycle(t *testing.T) {
	api := mustAPI(t)
	c := softwareClass(t, true)
	requirePersistentSoftware(t, api, c)
	ctx := context.Background()
	t.Cleanup(func() { _ = removeSecureEnclaveKey(c) })

	ks := newSecKeyStore(api, c, false, nil)
	pub, alg, err := ks.GenerateOrLoad(ctx)
	require.NoError(t, err)
	assert.Equal(t, AlgorithmECDSAP256, alg)
	id := ks.DeviceID()
	assert.Len(t, id, 64)

	// Restart: a new store reloads the same key.
	ks2 := newSecKeyStore(api, c, true, nil)
	pub2, _, err := ks2.GenerateOrLoad(ctx)
	require.NoError(t, err)
	assert.True(t, pub.(*ecdsa.PublicKey).Equal(pub2))
	assert.Equal(t, id, ks2.DeviceID())

	digest := sha256.Sum256([]byte("m"))
	sig, err := ks2.Sign(digest[:])
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(pub2.(*ecdsa.PublicKey), digest[:], sig))

	// Regenerate: new DeviceID, old key gone, new key reloads by the stable tag.
	newPub, _, err := ks2.Regenerate(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, id, ks2.DeviceID())
	assert.False(t, pub.(*ecdsa.PublicKey).Equal(newPub))
	ks3 := newSecKeyStore(api, c, true, nil)
	pub3, _, err := ks3.GenerateOrLoad(ctx)
	require.NoError(t, err)
	assert.True(t, newPub.(*ecdsa.PublicKey).Equal(pub3))

	// Removal.
	require.NoError(t, ks3.RemoveKey())
	assert.Nil(t, ks3.PublicKey())
	for _, tag := range []string{c.tag, c.tag + pendingSuffix} {
		key, lErr := api.lookup(c, tag)
		require.NoError(t, lErr)
		assert.Zero(t, key)
	}
	require.NoError(t, ks3.RemoveKey(), "removing an absent key is not an error")
}

// A self-test failure after a successful create leaves no key and none is used.
func TestSecKeyStore_SelfTestFailureLeavesNoKey(t *testing.T) {
	api := mustAPI(t)
	c := softwareClass(t, true)
	requirePersistentSoftware(t, api, c)
	t.Cleanup(func() { _ = removeSecureEnclaveKey(c) })

	ks := newSecKeyStore(api, c, false, nil)
	ran := false
	ks.selfTest = func(*secKeyStore, string, uintptr, *ecdsa.PublicKey) error {
		ran = true
		return errors.New("injected self-test failure")
	}
	_, _, err := ks.GenerateOrLoad(context.Background())
	require.Error(t, err)
	assert.True(t, ran, "self-test must run on first enrollment")
	assert.Contains(t, err.Error(), "injected self-test failure")
	assert.Nil(t, ks.PublicKey())
	assert.Empty(t, ks.DeviceID())
	_, signErr := ks.Sign(make([]byte, 32))
	assert.Error(t, signErr)
	key, lErr := api.lookup(c, c.tag)
	require.NoError(t, lErr)
	assert.Zero(t, key, "the created key must be deleted when the self-test fails")
}

func TestOpen_SelfTestFailureFallsBackToFile(t *testing.T) {
	api := mustAPI(t)
	c := softwareClass(t, true)
	requirePersistentSoftware(t, api, c)
	t.Cleanup(func() { _ = removeSecureEnclaveKey(c) })

	withBackends(t, backend{
		level: ProtectionSecureEnclave,
		open: func(_ context.Context, _ string, logger logging.Logger) (KeyStore, error) {
			ks := newSecKeyStore(api, c, false, logger)
			ks.selfTest = func(*secKeyStore, string, uintptr, *ecdsa.PublicKey) error {
				return errors.New("injected self-test failure")
			}
			return ks, nil
		},
	})
	logger := logging.NewCapturingLogger()
	dir := t.TempDir()
	ks, err := Open(context.Background(), dir, logger)
	require.NoError(t, err)
	assert.Equal(t, ProtectionFile, ks.ProtectionLevel())
	entry, ok := logger.FindInfo("Hardware device key backend unavailable; trying next")
	require.True(t, ok)
	assert.Contains(t, fmt.Sprint(entry["error"]), "injected self-test failure")
	_, statErr := os.Stat(filepath.Join(dir, keyFileName))
	assert.NoError(t, statErr)
	key, lErr := api.lookup(c, c.tag)
	require.NoError(t, lErr)
	assert.Zero(t, key)
}

// The Secure Enclave probe returns a definite result without panicking. On a
// runner without a usable Secure Enclave the failure carries the OSStatus; on a
// Mac that has one, the full lifecycle runs.
func TestSecureEnclave_ProbeIsDefinite(t *testing.T) {
	api := mustAPI(t)
	c := keyClass{secureEnclave: true, permanent: true, tag: testTag(t)}
	t.Cleanup(func() { _ = removeSecureEnclaveKey(c) })

	ks := newSecKeyStore(api, c, false, nil)
	pub, _, err := ks.GenerateOrLoad(context.Background())
	if err != nil {
		var se *osStatusError
		if errors.As(err, &se) {
			assert.NotZero(t, se.status)
			assert.Contains(t, err.Error(), "OSStatus")
		}
		assert.Nil(t, ks.PublicKey())
		t.Logf("Secure Enclave key not obtainable on this host: %v", err)
		return
	}
	t.Log("Secure Enclave key obtained; running lifecycle")
	id := ks.DeviceID()
	again := newSecKeyStore(api, c, true, nil)
	pub2, _, err := again.GenerateOrLoad(context.Background())
	require.NoError(t, err)
	assert.True(t, pub.(*ecdsa.PublicKey).Equal(pub2))
	assert.Equal(t, id, again.DeviceID())
	digest := sha256.Sum256([]byte("m"))
	sig, err := again.Sign(digest[:])
	require.NoError(t, err)
	assert.True(t, ecdsa.VerifyASN1(pub2.(*ecdsa.PublicKey), digest[:], sig))
	_, _, err = again.Regenerate(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, id, again.DeviceID())
	require.NoError(t, again.RemoveKey())
}

// With the production backend registered, Open on a host without a usable
// Secure Enclave returns a working file backend and logs the reason.
func TestOpen_RegisteredBackendFallsBackToFileWithReason(t *testing.T) {
	saved := defaultKeyClass
	defaultKeyClass = keyClass{secureEnclave: true, permanent: true, tag: testTag(t)}
	savedFactory := newFileStore
	newFileStore = func(dir string) (*FileKeyStore, error) { return NewFileKeyStoreForTesting(dir) }
	t.Cleanup(func() {
		_ = removeSecureEnclaveKey(defaultKeyClass)
		defaultKeyClass = saved
		newFileStore = savedFactory
	})

	logger := logging.NewCapturingLogger()
	ks, err := Open(context.Background(), t.TempDir(), logger)
	require.NoError(t, err)
	if ks.ProtectionLevel() == ProtectionSecureEnclave {
		t.Log("Secure Enclave available on this host; no fallback to assert")
		assert.Equal(t, AlgorithmECDSAP256, ks.Algorithm())
		return
	}
	assert.Equal(t, ProtectionFile, ks.ProtectionLevel())
	assert.Equal(t, AlgorithmEd25519, ks.Algorithm())
	entry, ok := logger.FindInfo("Hardware device key backend unavailable; trying next")
	require.True(t, ok, "fallback reason must be logged")
	assert.Equal(t, string(ProtectionSecureEnclave), entry["backend"])
	assert.Contains(t, fmt.Sprint(entry["error"]), "OSStatus")
}

func TestOpen_RecordedSecureEnclaveNeverFallsBack(t *testing.T) {
	saved := defaultKeyClass
	defaultKeyClass = keyClass{secureEnclave: true, permanent: true, tag: testTag(t)}
	t.Cleanup(func() {
		_ = removeSecureEnclaveKey(defaultKeyClass)
		defaultKeyClass = saved
	})
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, storedIdentityFileName),
		[]byte(`{"key_protection_level":"secure-enclave"}`), 0600))
	_, err := Open(context.Background(), dir, logging.NewCapturingLogger())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrHardwareKeyUnavailable))
	_, statErr := os.Stat(filepath.Join(dir, keyFileName))
	assert.True(t, os.IsNotExist(statErr))
}
