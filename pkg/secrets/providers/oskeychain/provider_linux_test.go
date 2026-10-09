// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package oskeychain

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

// helperEnv switches the re-executed test binary into the never-exiting
// secret-tool stand-in used by the timeout tests.
const helperEnv = "CFGMS_OSKEYCHAIN_HANG_HELPER"

// TestMain lets the test binary double as a secret-tool that never answers: the
// standard Go helper-process pattern. It is a real child process, so the
// timeout path really kills a real process.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		time.Sleep(time.Hour)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func shortTimeouts(t *testing.T) {
	t.Helper()
	oldProbe, oldTool := probeTimeout, toolTimeout
	probeTimeout, toolTimeout = 300*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { probeTimeout, toolTimeout = oldProbe, oldTool })
}

func hangingBackend(t *testing.T) *secretServiceBackend {
	t.Helper()
	t.Setenv(helperEnv, "1")
	exe, err := os.Executable()
	require.NoError(t, err)
	return &secretServiceBackend{bin: exe}
}

// TestSecretServiceAvailable_SilentBus: a bus socket that accepts connections
// and never replies must make available() return false within the probe
// timeout, not hang.
func TestSecretServiceAvailable_SilentBus(t *testing.T) {
	shortTimeouts(t)
	sock := filepath.Join(t.TempDir(), "bus.sock")
	l, err := net.Listen("unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+sock)

	b := &secretServiceBackend{bin: "/bin/true"}
	start := time.Now()
	assert.False(t, b.available())
	assert.Less(t, time.Since(start), probeTimeout+time.Second)
}

func TestSecretServiceAvailable_NothingListening(t *testing.T) {
	shortTimeouts(t)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(t.TempDir(), "absent.sock"))
	b := &secretServiceBackend{bin: "/bin/true"}
	assert.False(t, b.available())
}

// TestSecretToolTimeouts: a secret-tool that never exits is killed at the
// timeout; every call returns an error and get never reports "not found".
func TestSecretToolTimeouts(t *testing.T) {
	shortTimeouts(t)
	b := hangingBackend(t)

	start := time.Now()
	err := b.set("k", []byte("v"))
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)

	_, err = b.get("k")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.False(t, errors.Is(err, errSecretNotFound), "a timed-out lookup is not 'not found'")

	err = b.del("k")
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 3*toolTimeout+2*time.Second)
}

func TestSecretServiceGet_StartFailureIsNotNotFound(t *testing.T) {
	b := &secretServiceBackend{bin: filepath.Join(t.TempDir(), "missing")}
	_, err := b.get("k")
	require.Error(t, err)
	assert.False(t, errors.Is(err, errSecretNotFound))
}

func TestSecretServiceGet_CleanExitNoOutputIsNotFound(t *testing.T) {
	b := &secretServiceBackend{bin: "/bin/false"}
	_, err := b.get("k")
	assert.ErrorIs(t, err, errSecretNotFound)
}

// TestCompareAndSwap_TimedOutLookupIsNotVersionZero: a version lookup that
// timed out must fail the swap rather than be read as version 0.
func TestCompareAndSwap_TimedOutLookupIsNotVersionZero(t *testing.T) {
	shortTimeouts(t)
	store := newStore(hangingBackend(t))
	v, ok, err := store.CompareAndSwapSecret(context.Background(), "cfgms/session/cas-hang",
		0, &interfaces.SecretRequest{Key: "cfgms/session/cas-hang", Value: "v"})
	require.Error(t, err)
	assert.False(t, ok)
	assert.Equal(t, 0, v)
}
