// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package oskeychain

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// keyringType is the kernel keyring key type used for session tokens.
const keyringType = "user"

// platformNewBackend selects the Linux backend in fallback order: the Secret
// Service (libsecret) if a session bus exposes one, otherwise the kernel
// session keyring (headless-safe). Returns an unavailable backend if neither is
// usable, so Provider.Available reports (false, nil).
func platformNewBackend() (backend, error) {
	if ss := newSecretServiceBackend(); ss.available() {
		return ss, nil
	}
	if kr := newKeyringBackend(); kr.available() {
		return kr, nil
	}
	return unavailableBackend{}, nil
}

// unavailableBackend is returned on Linux hosts with no Secret Service and no
// usable kernel keyring (e.g. a minimal container). Its operations error; the
// provider reports it as unavailable so callers fall back to the --bundle path.
type unavailableBackend struct{}

func (unavailableBackend) name() string    { return "none" }
func (unavailableBackend) available() bool { return false }
func (unavailableBackend) set(string, []byte) error {
	return errors.New("no OS keychain backend available")
}
func (unavailableBackend) get(string) ([]byte, error) {
	return nil, errors.New("no OS keychain backend available")
}
func (unavailableBackend) del(string) error { return errors.New("no OS keychain backend available") }

// ---- Secret Service (libsecret via secret-tool) ----

// secretServiceBackend stores secrets in the freedesktop Secret Service
// (gnome-keyring, KWallet, etc.) via the libsecret `secret-tool` CLI.
type secretServiceBackend struct {
	bin string // resolved path to secret-tool, "" when unavailable
}

func newSecretServiceBackend() *secretServiceBackend {
	bin, err := exec.LookPath("secret-tool")
	if err != nil {
		return &secretServiceBackend{}
	}
	return &secretServiceBackend{bin: bin}
}

func (b *secretServiceBackend) name() string { return "linux-secret-service" }

// available reports the Secret Service usable: the secret-tool binary is present
// and a session bus exists for it to talk to. Headless hosts (no
// DBUS_SESSION_BUS_ADDRESS) report false so selection falls through to the
// kernel keyring.
func (b *secretServiceBackend) available() bool {
	return b.bin != "" && os.Getenv("DBUS_SESSION_BUS_ADDRESS") != ""
}

func (b *secretServiceBackend) set(key string, value []byte) error {
	// secret-tool store reads the secret from stdin; attributes come from argv.
	cmd := exec.Command(b.bin, "store", "--label=CFGMS session token", //nolint:gosec // fixed binary + discrete args, no shell
		"service", serviceName, "account", key)
	cmd.Stdin = bytes.NewReader(value)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("secret-tool store: %w: %s", err, stderr.String())
	}
	return nil
}

func (b *secretServiceBackend) get(key string) ([]byte, error) {
	cmd := exec.Command(b.bin, "lookup", "service", serviceName, "account", key) //nolint:gosec // fixed binary + discrete args, no shell
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// secret-tool exits non-zero with no output when the item is absent.
		if stdout.Len() == 0 {
			return nil, errSecretNotFound
		}
		return nil, fmt.Errorf("secret-tool lookup: %w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func (b *secretServiceBackend) del(key string) error {
	cmd := exec.Command(b.bin, "clear", "service", serviceName, "account", key) //nolint:gosec // fixed binary + discrete args, no shell
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("secret-tool clear: %w: %s", err, stderr.String())
	}
	return nil
}

// ---- Kernel session keyring (keyctl) ----

// keyringBackend stores secrets in the kernel session keyring. It is
// headless-safe and the token dies with the login session — acceptable for a
// short-lived session token.
type keyringBackend struct{}

func newKeyringBackend() *keyringBackend { return &keyringBackend{} }

func (b *keyringBackend) name() string { return "linux-kernel-keyring" }

// available probes whether the kernel keyring is usable by materializing the
// session keyring. Returns false on kernels without keyctl support (ENOSYS) or
// where access is denied.
func (b *keyringBackend) available() bool {
	_, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_SESSION_KEYRING, true)
	return err == nil
}

func (b *keyringBackend) set(key string, value []byte) error {
	// add_key updates the payload in place when a "user" key with this
	// description already exists in the session keyring.
	if _, err := unix.AddKey(keyringType, key, value, unix.KEY_SPEC_SESSION_KEYRING); err != nil {
		return fmt.Errorf("add_key: %w", err)
	}
	return nil
}

func (b *keyringBackend) get(key string) ([]byte, error) {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_SESSION_KEYRING, keyringType, key, 0)
	if err != nil {
		// ENOKEY (and friends) mean the key is absent.
		return nil, errSecretNotFound
	}

	// First call sizes the payload, second reads it.
	size, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("keyctl read (size): %w", err)
	}
	buf := make([]byte, size)
	n, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("keyctl read: %w", err)
	}
	if n > len(buf) {
		n = len(buf)
	}
	return buf[:n], nil
}

func (b *keyringBackend) del(key string) error {
	id, err := unix.KeyctlSearch(unix.KEY_SPEC_SESSION_KEYRING, keyringType, key, 0)
	if err != nil {
		// Absent key is not an error.
		return nil
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_UNLINK, id, unix.KEY_SPEC_SESSION_KEYRING, 0, 0); err != nil {
		return fmt.Errorf("keyctl unlink: %w", err)
	}
	return nil
}
