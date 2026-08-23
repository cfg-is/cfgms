// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package oskeychain

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUnavailableBackendRejectsOperations exercises the backend
// platformNewBackend really selects on a Linux host with neither a Secret
// Service nor a usable kernel keyring. It must report itself unavailable and
// fail every operation with a wrapped error, so a caller that ignores
// Provider.Available and stores anyway is told the token was not persisted
// rather than silently losing it.
func TestUnavailableBackendRejectsOperations(t *testing.T) {
	b := unavailableBackend{}
	assert.False(t, b.available(), "no-backend host must report unavailable")
	assert.Equal(t, "none", b.name())

	store := newStore(b)
	ctx := context.Background()
	key := "cfgms/session/unavailable-" + randHex(t, 6)

	err := store.StoreSecret(ctx, &interfaces.SecretRequest{Key: key, Value: "tok"})
	require.Error(t, err, "StoreSecret must fail with no usable keychain")
	assert.Contains(t, err.Error(), "oskeychain")

	_, err = store.GetSecret(ctx, key)
	require.Error(t, err, "GetSecret must fail with no usable keychain")
	assert.NotErrorIs(t, err, interfaces.ErrSecretNotFound,
		"a missing backend is a failure, not a missing secret")

	require.Error(t, store.DeleteSecret(ctx, key), "DeleteSecret must fail with no usable keychain")
}

// TestLinuxKeyringFallback is the [REQUIRED TEST]: with the Secret Service
// unavailable, the provider must store/load via the kernel session keyring and
// still round-trip.
func TestLinuxKeyringFallback(t *testing.T) {
	// Force the Secret Service backend to report unavailable by removing the
	// session bus address. With no bus, libsecret/secret-tool cannot be used.
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
	require.False(t, newSecretServiceBackend().available(),
		"Secret Service must report unavailable without a session bus")

	kr := newKeyringBackend()
	if !kr.available() {
		// Justified skip: the kernel keyring (keyctl) is a host/kernel
		// capability, not something the test controls. GitHub-hosted Linux
		// runners support the session keyring; a kernel built without
		// CONFIG_KEYS (ENOSYS) cannot exercise this path.
		t.Skip("kernel session keyring unavailable (no CONFIG_KEYS); cannot exercise keyring fallback")
	}

	// With Secret Service unavailable, backend selection must fall through to
	// the kernel keyring.
	b, err := platformNewBackend()
	require.NoError(t, err)
	require.Equal(t, "linux-kernel-keyring", b.name(),
		"with Secret Service unavailable, the keyring must be selected")

	store := newStore(b)
	ctx := context.Background()
	key := "cfgms/session/keyring-fallback-" + randHex(t, 6)
	token := "keyring-tok-" + randHex(t, 16)

	t.Cleanup(func() { _ = store.DeleteSecret(ctx, key) })

	require.NoError(t, store.StoreSecret(ctx, &interfaces.SecretRequest{Key: key, Value: token}))

	got, err := store.GetSecret(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, token, got.Value, "keyring round-trip must preserve the token")

	require.NoError(t, store.DeleteSecret(ctx, key))
	_, err = store.GetSecret(ctx, key)
	assert.Error(t, err, "secret must be gone after delete")
}
