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
	"sync"
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

// fakeBackend is an in-memory backend for deterministic, platform-independent
// tests of the Store/Provider logic.
type fakeBackend struct {
	mu    sync.Mutex
	m     map[string][]byte
	avail bool
	nm    string
}

func newFakeBackend(avail bool) *fakeBackend {
	return &fakeBackend{m: make(map[string][]byte), avail: avail, nm: "fake"}
}

func (f *fakeBackend) set(key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	f.m[key] = cp
	return nil
}

func (f *fakeBackend) get(key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[key]
	if !ok {
		return nil, errSecretNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (f *fakeBackend) del(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, key)
	return nil
}

func (f *fakeBackend) available() bool { return f.avail }
func (f *fakeBackend) name() string    { return f.nm }

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

func TestStoreCoreOps(t *testing.T) {
	store := newStore(newFakeBackend(true))
	ctx := context.Background()
	key := "cfgms/session/test-conn"
	token := "session-token-abc123"

	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{Key: key, Value: token}))

	got, err := store.GetSecret(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, token, got.Value)
	assert.Equal(t, key, got.Key)

	require.NoError(t, store.DeleteSecret(ctx, key))

	_, err = store.GetSecret(ctx, key)
	require.Error(t, err)
	assert.ErrorIs(t, err, interfaces.ErrSecretNotFound)
}

func TestStoreValidation(t *testing.T) {
	store := newStore(newFakeBackend(true))
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

func TestUnsupportedOps(t *testing.T) {
	store := newStore(newFakeBackend(true))
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

// TestAvailableReportsNoBackend verifies Available() returns (false, nil) — not
// an error — when no platform backend is usable, so callers fall back to the
// one-shot --bundle path rather than failing hard.
func TestAvailableReportsNoBackend(t *testing.T) {
	orig := newBackend
	t.Cleanup(func() { newBackend = orig })

	newBackend = func() (backend, error) { return newFakeBackend(false), nil }

	p := &Provider{}
	ok, err := p.Available()
	assert.NoError(t, err, "Available must not error when no backend exists")
	assert.False(t, ok)

	_, err = p.CreateSecretStore(nil)
	assert.Error(t, err, "CreateSecretStore must fail when no backend is available")
}

func TestAvailableReportsBackendPresent(t *testing.T) {
	orig := newBackend
	t.Cleanup(func() { newBackend = orig })

	newBackend = func() (backend, error) { return newFakeBackend(true), nil }

	p := &Provider{}
	ok, err := p.Available()
	require.NoError(t, err)
	assert.True(t, ok)

	store, err := p.CreateSecretStore(nil)
	require.NoError(t, err)
	assert.NotNil(t, store)
}

// TestRealBackendRoundTrip exercises the actual OS keychain on the build
// platform (live Credential Manager on Windows, Keychain on macOS, Secret
// Service / keyring on Linux). Skips when no backend is usable (e.g. a headless
// Linux host with neither Secret Service nor a kernel keyring).
func TestRealBackendRoundTrip(t *testing.T) {
	b, err := newBackend()
	require.NoError(t, err)
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
	b, err := newBackend()
	require.NoError(t, err)
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
