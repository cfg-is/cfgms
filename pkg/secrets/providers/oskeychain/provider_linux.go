// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package oskeychain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	// defaultProbeTimeout bounds the Secret Service availability probe.
	defaultProbeTimeout = 3 * time.Second
	// defaultToolTimeout bounds each secret-tool invocation. A locked keyring
	// makes secret-tool wait forever on a prompt a terminal session cannot show.
	defaultToolTimeout = 5 * time.Second
)

// Package variables so tests can shorten them.
var (
	probeTimeout = defaultProbeTimeout
	toolTimeout  = defaultToolTimeout
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

// available reports the Secret Service usable: the secret-tool binary is present,
// a session bus answers, and the default collection is unlocked. A locked
// collection needs a graphical prompt that would hang secret-tool, so it counts
// as unavailable and selection falls through to the kernel keyring. Any dial
// error, bus error or timeout also reports false.
func (b *secretServiceBackend) available() bool {
	if b.bin == "" || os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	return defaultCollectionUnlocked(ctx)
}

// defaultCollectionUnlocked reads the Locked property of the default collection
// over D-Bus. Reading the property never triggers an unlock prompt.
func defaultCollectionUnlocked(ctx context.Context) bool {
	conn, err := dbus.SessionBusPrivate(dbus.WithContext(ctx))
	if err != nil {
		return false
	}
	// Closing the connection also unblocks the goroutine below if the bus is silent.
	defer func() { _ = conn.Close() }()

	result := make(chan bool, 1)
	go func() {
		if err := conn.Auth(nil); err != nil {
			result <- false
			return
		}
		if err := conn.Hello(); err != nil {
			result <- false
			return
		}
		var alias dbus.ObjectPath
		svc := conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets")
		if err := svc.CallWithContext(ctx, "org.freedesktop.Secret.Service.ReadAlias", 0, "default").Store(&alias); err != nil {
			result <- false
			return
		}
		if alias == "/" || alias == "" {
			result <- false
			return
		}
		prop, err := conn.Object("org.freedesktop.secrets", alias).
			GetProperty("org.freedesktop.Secret.Collection.Locked")
		if err != nil {
			result <- false
			return
		}
		locked, ok := prop.Value().(bool)
		result <- ok && !locked
	}()

	select {
	case ok := <-result:
		return ok
	case <-ctx.Done():
		return false
	}
}

// runTool runs secret-tool under toolTimeout, killing the child on expiry. A
// timeout returns an error wrapping context.DeadlineExceeded.
func (b *secretServiceBackend) runTool(op string, stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	// #nosec G204 -- b.bin is resolved by LookPath for secret-tool, command
	// structure is fixed, the key is a discrete attribute value, and no shell runs.
	cmd := exec.CommandContext(ctx, b.bin, args...)
	cmd.WaitDelay = time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("secret-tool %s: timed out after %s: %w", op, toolTimeout, ctxErr)
		}
		return stdout.Bytes(), &toolError{op: op, err: err, stderr: stderr.String()}
	}
	return stdout.Bytes(), nil
}

// toolError is a secret-tool failure that is not a timeout.
type toolError struct {
	op     string
	err    error
	stderr string
}

func (e *toolError) Error() string {
	return fmt.Sprintf("secret-tool %s: %v: %s", e.op, e.err, e.stderr)
}
func (e *toolError) Unwrap() error { return e.err }

func (b *secretServiceBackend) set(key string, value []byte) error {
	// secret-tool store reads the secret from stdin; attributes come from argv.
	// Non-nil stdin even for an empty value so the child never inherits ours.
	if value == nil {
		value = []byte{}
	}
	_, err := b.runTool("store", value, "store", "--label=CFGMS session token",
		"service", serviceName, "account", key)
	return err
}

func (b *secretServiceBackend) get(key string) ([]byte, error) {
	out, err := b.runTool("lookup", nil, "lookup", "service", serviceName, "account", key)
	if err != nil {
		// secret-tool exits non-zero with no output when the item is absent. Only
		// that case is "not found"; a timeout or start failure is a real error.
		var te *toolError
		var ee *exec.ExitError
		if errors.As(err, &te) && errors.As(err, &ee) && len(out) == 0 {
			return nil, errSecretNotFound
		}
		return nil, err
	}
	return out, nil
}

func (b *secretServiceBackend) del(key string) error {
	_, err := b.runTool("clear", nil, "clear", "service", serviceName, "account", key)
	return err
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
