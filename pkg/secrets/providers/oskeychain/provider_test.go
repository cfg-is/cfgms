// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package oskeychain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface conformance.
var (
	_ interfaces.SecretProvider = (*Provider)(nil)
	_ interfaces.SecretStore    = (*Store)(nil)
)

// platformBackend returns the real backend this host selects: Windows
// Credential Manager, macOS Keychain, Linux Secret Service or kernel session
// keyring, or the Linux unavailableBackend when the host offers neither. Every
// platform constructor yields a usable value, so tests always run against the
// production backend — CFGMS forbids substituting a stand-in for it.
func platformBackend(t *testing.T) backend {
	t.Helper()
	b, err := platformNewBackend()
	require.NoError(t, err)
	require.NotNil(t, b, "platformNewBackend must always return a backend")
	return b
}

func TestProviderMetadata(t *testing.T) {
	p := &Provider{}
	assert.Equal(t, "oskeychain", p.Name())
	assert.NotEmpty(t, p.Description())
	assert.NotEmpty(t, p.GetVersion())

	caps := p.GetCapabilities()
	assert.True(t, caps.SupportsEncryption, "OS keychain encrypts at rest")
	assert.True(t, caps.SupportsRevocation, "DeleteSecret revokes immediately")
	assert.GreaterOrEqual(t, caps.MaxSecretSize, 0)
	assert.GreaterOrEqual(t, caps.MaxKeyLength, 0)
}

func TestProviderRegistered(t *testing.T) {
	names := interfaces.GetRegisteredProviderNames()
	assert.Contains(t, names, "oskeychain", "provider should auto-register via init()")
}

// TestStoreValidation covers the request rejections StoreSecret performs before
// it reaches the keychain. It runs against the real platform backend on every
// host — including hosts with no usable keychain — because a rejected request
// never touches the backend.
func TestStoreValidation(t *testing.T) {
	store := newStore(platformBackend(t))
	ctx := context.Background()

	assert.Error(t, store.StoreSecret(ctx, nil), "nil request")
	assert.Error(t, store.StoreSecret(ctx, &interfaces.SecretRequest{Key: "", Value: "x"}), "empty key")
	assert.Error(t, store.StoreSecret(ctx, &interfaces.SecretRequest{Key: "k", Value: ""}), "empty value")

	longKey := make([]byte, maxKeyLength+1)
	for i := range longKey {
		longKey[i] = 'a'
	}
	assert.Error(t, store.StoreSecret(ctx, &interfaces.SecretRequest{Key: string(longKey), Value: "x"}), "oversized key")

	bigVal := make([]byte, maxSecretSize+1)
	for i := range bigVal {
		bigVal[i] = 'a'
	}
	assert.Error(t, store.StoreSecret(ctx, &interfaces.SecretRequest{Key: "k", Value: string(bigVal)}), "oversized value")
}

// TestUnsupportedOps covers the contract methods the provider deliberately does
// not implement. Like the validation test it runs on every host: each of these
// returns before reaching the keychain.
func TestUnsupportedOps(t *testing.T) {
	store := newStore(platformBackend(t))
	ctx := context.Background()

	_, err := store.ListSecrets(ctx, nil)
	assert.ErrorIs(t, err, errors.ErrUnsupported)
	_, err = store.GetSecrets(ctx, []string{"k"})
	assert.ErrorIs(t, err, errors.ErrUnsupported)
	assert.ErrorIs(t, store.StoreSecrets(ctx, nil), errors.ErrUnsupported)
	_, err = store.GetSecretVersion(ctx, "k", 1)
	assert.ErrorIs(t, err, errors.ErrUnsupported)
	_, err = store.ListSecretVersions(ctx, "k")
	assert.ErrorIs(t, err, errors.ErrUnsupported)
	_, err = store.GetSecretMetadata(ctx, "k")
	assert.ErrorIs(t, err, errors.ErrUnsupported)
	assert.ErrorIs(t, store.UpdateSecretMetadata(ctx, "k", nil), errors.ErrUnsupported)
	assert.ErrorIs(t, store.RotateSecret(ctx, "k", "v"), errors.ErrUnsupported)
	assert.ErrorIs(t, store.ExpireSecret(ctx, "k"), errors.ErrUnsupported)

	// HealthCheck and Close are no-ops.
	assert.NoError(t, store.HealthCheck(ctx))
	assert.NoError(t, store.Close())
}

// TestAvailableTracksPlatformBackend verifies Available() against the real
// backend this host selects. Two contract points hold on every host: Available
// never returns an error (callers fall back to the one-shot --bundle path
// rather than failing hard), and its answer matches the backend's own
// availability. CreateSecretStore must then succeed exactly when Available says
// it will — the unavailable half of that branch is additionally exercised
// directly against unavailableBackend in provider_linux_test.go.
func TestAvailableTracksPlatformBackend(t *testing.T) {
	b := platformBackend(t)
	t.Logf("platform backend: %s (available=%v)", b.name(), b.available())

	p := &Provider{}
	ok, err := p.Available()
	require.NoError(t, err, "Available must never error, even with no usable backend")
	assert.Equal(t, b.available(), ok, "Available must report the platform backend's availability")

	store, err := p.CreateSecretStore(nil)
	if ok {
		require.NoError(t, err)
		assert.NotNil(t, store)
		return
	}
	assert.Error(t, err, "CreateSecretStore must fail when no backend is available")
	assert.Nil(t, store)
}

// TestRealBackendRoundTrip is the core store/get/delete test. It exercises the
// actual OS keychain on the build platform (live Credential Manager on Windows,
// Keychain on macOS, Secret Service / keyring on Linux). Skips when no backend
// is usable (e.g. a headless Linux host with neither Secret Service nor a
// kernel keyring).
func TestRealBackendRoundTrip(t *testing.T) {
	b := platformBackend(t)
	if !b.available() {
		t.Skipf("no OS keychain backend available on this host (%s); nothing to round-trip", b.name())
	}
	t.Logf("exercising backend: %s", b.name())

	store := newStore(b)
	ctx := context.Background()
	key := "cfgms/session/roundtrip-" + randHex(t, 6)
	token := "tok-" + randHex(t, 16)

	t.Cleanup(func() { _ = store.DeleteSecret(ctx, key) })

	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{Key: key, Value: token}))

	got, err := store.GetSecret(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, token, got.Value)

	require.NoError(t, store.DeleteSecret(ctx, key))
	_, err = store.GetSecret(ctx, key)
	assert.ErrorIs(t, err, interfaces.ErrSecretNotFound)
}

// TestNoCleartextOnDisk is the [REQUIRED TEST] no-cleartext-on-disk acceptance
// check: after StoreSecret, neither os.UserConfigDir()/cfgms nor the working
// tree contains a file holding the token value — the secret lives only in the
// OS store / keyring.
func TestNoCleartextOnDisk(t *testing.T) {
	b := platformBackend(t)
	if !b.available() {
		t.Skipf("no OS keychain backend available on this host (%s); cannot prove no-disk behavior", b.name())
	}

	store := newStore(b)
	ctx := context.Background()
	key := "cfgms/session/nodisk-" + randHex(t, 6)
	token := "NODISK-" + randHex(t, 24) // unique, won't pre-exist in any file

	t.Cleanup(func() { _ = store.DeleteSecret(ctx, key) })
	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{Key: key, Value: token}))

	roots := scanRoots(t)
	require.NotEmpty(t, roots, "expected at least one scan root")
	for _, root := range roots {
		if hit := findTokenInTree(t, root, token); hit != "" {
			t.Fatalf("token found in cleartext on disk at %s — provider must never write the secret to a file", hit)
		}
	}
}

// scanRoots returns the directories the no-disk test scans: the CFGMS user
// config dir and the module working tree.
func scanRoots(t *testing.T) []string {
	t.Helper()
	var roots []string
	if cfgDir, err := os.UserConfigDir(); err == nil {
		roots = append(roots, filepath.Join(cfgDir, "cfgms"))
	}
	if modRoot := moduleRoot(t); modRoot != "" {
		roots = append(roots, modRoot)
	}
	return roots
}

// moduleRoot walks up from the test's working directory to the directory
// containing go.mod (the repository working tree root).
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// findTokenInTree scans root recursively for the token, skipping .git and large
// files. Returns the path of the first file containing the token, or "".
func findTokenInTree(t *testing.T, root, token string) string {
	t.Helper()
	if _, err := os.Stat(root); err != nil {
		return "" // root absent (e.g. user config dir never created) — nothing to scan
	}
	needle := []byte(token)
	var found string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry — skip
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 4*1024*1024 {
			return nil // skip large/binary files
		}
		data, err := os.ReadFile(path) //#nosec G304 -- test scans the working tree for the token
		if err != nil {
			return nil
		}
		if contains(data, needle) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// contains reports whether haystack contains needle.
func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return false
	}
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return hex.EncodeToString(buf)
}

func TestOSKeychainProvider_ClusterCapable_False(t *testing.T) {
	p := &Provider{}
	assert.False(t, p.ClusterCapable(), "Provider must not be cluster-capable (OS keychain is host-local, inaccessible from other controller nodes)")
}
