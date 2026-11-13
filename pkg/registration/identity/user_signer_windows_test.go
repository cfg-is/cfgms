// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// noSuchProvider is a CNG provider name that no host registers, so opening it
// fails the way a missing or broken provider does.
const noSuchProvider = "CFGMS Test Provider That Does Not Exist"

// withUserKeyProviders sets the order CreateUserKey tries for the rest of the
// test. Tests that call it must not run in parallel.
func withUserKeyProviders(t *testing.T, providers ...string) {
	t.Helper()
	orig := userKeyProviders
	userKeyProviders = providers
	t.Cleanup(func() { userKeyProviders = orig })
}

// createTestUserKey creates a user key and deletes it when the test ends.
func createTestUserKey(t *testing.T) *UserKeySigner {
	t.Helper()
	s, err := CreateUserKey()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, DeleteUserKey(s.Provider(), s.KeyName())) })
	return s
}

func validUserKeyName(t *testing.T) string {
	t.Helper()
	var b [userKeySuffixBytes]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return userKeyNamePrefix + hex.EncodeToString(b[:])
}

func TestValidateUserKeyRef(t *testing.T) {
	good := validUserKeyName(t)
	suffix := strings.TrimPrefix(good, userKeyNamePrefix)
	cases := []struct {
		name, provider, keyName string
		ok                      bool
	}{
		{"software provider", softwareKeyStorageProvider, good, true},
		{"platform provider", platformCryptoProvider, good, true},
		{"unknown provider", "Microsoft Smart Card Key Storage Provider", good, false},
		{"empty provider", "", good, false},
		{"device key name", softwareKeyStorageProvider, "cfgms-device-key-" + suffix, false},
		{"missing prefix", softwareKeyStorageProvider, suffix, false},
		{"short suffix", softwareKeyStorageProvider, userKeyNamePrefix + suffix[:30], false},
		{"long suffix", softwareKeyStorageProvider, good + "00", false},
		{"non-hex suffix", softwareKeyStorageProvider, userKeyNamePrefix + strings.Repeat("zz", userKeySuffixBytes), false},
		{"uppercase hex", softwareKeyStorageProvider, userKeyNamePrefix + strings.Repeat("AB", userKeySuffixBytes), false},
		{"path separator", softwareKeyStorageProvider, userKeyNamePrefix + `..\` + suffix[3:], false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUserKeyRef(tc.provider, tc.keyName)
			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestUserKey_SoftwareProviderLifecycle creates a key in the Software Key
// Storage Provider, proves it is a non-exportable per-user key that signs, and
// deletes it.
func TestUserKey_SoftwareProviderLifecycle(t *testing.T) {
	withUserKeyProviders(t, softwareKeyStorageProvider)
	s, err := CreateUserKey()
	require.NoError(t, err)
	require.Equal(t, softwareKeyStorageProvider, s.Provider())
	require.NoError(t, validateUserKeyRef(s.Provider(), s.KeyName()))

	c := userKeyConfig(s.Provider())
	require.False(t, c.machine, "user keys carry no machine-key flag")
	requireNotExportable(t, c, s.KeyName())

	opened, err := OpenUserKey(s.Provider(), s.KeyName())
	require.NoError(t, err)
	assert.True(t, s.pub.Equal(opened.Public()), "reopened key has the same public key")

	digest := testDigest(t)
	sig, err := opened.Sign(rand.Reader, digest, crypto.SHA256)
	require.NoError(t, err)
	pub, ok := opened.Public().(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, ecdsa.VerifyASN1(pub, digest, sig), "signature verifies over the digest")

	require.NoError(t, DeleteUserKey(s.Provider(), s.KeyName()))
	assert.False(t, keyExists(t, c, s.KeyName()), "key is gone after delete")
	assert.NoError(t, DeleteUserKey(s.Provider(), s.KeyName()), "deleting an absent key is not an error")

	_, err = OpenUserKey(s.Provider(), s.KeyName())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestCreateUserKey_SkipsProviderThatCannotOpen proves a provider that cannot
// be opened is passed over for the next one.
func TestCreateUserKey_SkipsProviderThatCannotOpen(t *testing.T) {
	withUserKeyProviders(t, noSuchProvider, softwareKeyStorageProvider)
	s := createTestUserKey(t)
	assert.Equal(t, softwareKeyStorageProvider, s.Provider())
}

// TestCreateUserKey_NoUsableProviderIsUnavailable proves that when every
// provider is passed over the result is ErrUserKeyUnavailable, which callers
// may fall back on.
func TestCreateUserKey_NoUsableProviderIsUnavailable(t *testing.T) {
	withUserKeyProviders(t, noSuchProvider)
	s, err := CreateUserKey()
	require.Error(t, err)
	assert.Nil(t, s)
	assert.True(t, errors.Is(err, ErrUserKeyUnavailable), "got %v", err)
}

// TestUserKey_RefsRejectedBeforeCNG proves a stored reference that is not one
// CreateUserKey makes is refused by both OpenUserKey and DeleteUserKey.
func TestUserKey_RefsRejectedBeforeCNG(t *testing.T) {
	name := validUserKeyName(t)
	for _, ref := range []struct{ provider, keyName string }{
		{"Microsoft Smart Card Key Storage Provider", name},
		{softwareKeyStorageProvider, "cfgms-device-key-0"},
	} {
		_, err := OpenUserKey(ref.provider, ref.keyName)
		assert.Error(t, err, "open %+v", ref)
		assert.Error(t, DeleteUserKey(ref.provider, ref.keyName), "delete %+v", ref)
	}
}

// TestDeleteUserKey_ProviderThatCannotOpenHasNothingToRemove proves delete
// does not wedge on a provider that is gone, as removeCNGKeys does not.
func TestDeleteUserKey_ProviderThatCannotOpenHasNothingToRemove(t *testing.T) {
	withUserKeyProviders(t, noSuchProvider)
	assert.NoError(t, DeleteUserKey(noSuchProvider, validUserKeyName(t)))
}

func TestUserKeySigner_SignRejectsWrongDigest(t *testing.T) {
	withUserKeyProviders(t, softwareKeyStorageProvider)
	s := createTestUserKey(t)
	d := sha256.Sum256([]byte("x"))

	_, err := s.Sign(rand.Reader, d[:], crypto.SHA384)
	assert.Error(t, err, "non-SHA-256 hash refused")
	_, err = s.Sign(rand.Reader, d[:], nil)
	assert.Error(t, err, "nil opts refused")
	_, err = s.Sign(rand.Reader, d[:31], crypto.SHA256)
	assert.Error(t, err, "short digest refused")
}
