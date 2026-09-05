// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package testutil

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ProvisionSecretsEnv satisfies the same external-key and durable secret-data
// contracts the controller enforces in production: CFGMS_SECRETS_KEY_FILE must
// name a real key file, and secret data must live at an explicit path rather
// than a shared temporary directory.
//
// It is intended for TestMain, where no *testing.T exists yet. Tests that
// exercise path isolation can still override either variable with t.Setenv.
// The returned cleanup removes the generated key and secret directory.
//
// CFGMS_ALLOW_EPHEMERAL_SECRETS is set to "true" because tests necessarily
// use os.TempDir()-backed paths. Tests that specifically exercise the
// ephemeral-rejection guard must clear this variable with t.Setenv.
func ProvisionSecretsEnv(prefix string) (cleanup func(), err error) {
	base, err := os.MkdirTemp("", prefix)
	if err != nil {
		return nil, fmt.Errorf("create test secrets directory: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(base) }

	keyPath, err := resolveSecretsKeyFile(base)
	if err != nil {
		cleanup()
		return nil, err
	}
	if err := os.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath); err != nil {
		cleanup()
		return nil, fmt.Errorf("set test secrets key environment: %w", err)
	}
	if err := os.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(base, "secrets")); err != nil {
		cleanup()
		return nil, fmt.Errorf("set test secrets path environment: %w", err)
	}
	if err := os.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "true"); err != nil {
		cleanup()
		return nil, fmt.Errorf("set ephemeral secrets override environment: %w", err)
	}
	return cleanup, nil
}

// SetupSecretsEnvForTest is the single-test form of ProvisionSecretsEnv. It
// scopes all variables to t via t.Setenv and cleans up with the test.
// CFGMS_ALLOW_EPHEMERAL_SECRETS is set to "true" because tests use
// os.TempDir()-backed paths; tests that exercise the rejection guard must
// clear it with t.Setenv.
func SetupSecretsEnvForTest(t *testing.T) {
	t.Helper()

	base := t.TempDir()
	keyPath, err := resolveSecretsKeyFile(base)
	if err != nil {
		t.Fatalf("SetupSecretsEnvForTest: %v", err)
	}
	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(base, "secrets"))
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "true")
}

// resolveSecretsKeyFile returns the master key file the SOPS secret store should
// use: an already-provisioned CFGMS_SECRETS_KEY_FILE when the environment names
// a readable one, otherwise a fresh key written under base.
//
// Honouring an ambient key matters because the master key is process-scoped
// while some secret DATA is not. Tests that exercise the `database` storage
// provider share one PostgreSQL instance across every test binary in a run, and
// the audit chain persists its HMAC key there under a fixed name
// (`audit/hmac-key`, pkg/audit.WithSecretsStore). Minting a fresh random key per
// process meant the first binary to run wrote that row encrypted under its own
// key and every later binary failed to read it with
//
//	load audit HMAC key: failed to decrypt secret:
//	secret ciphertext authentication failed
//
// Which binaries failed depended on package scheduling, so the whole-repo `go
// test ./...` that `make test` runs failed while the same packages passed when
// run alone. `make test-integration-setup` exports CFGMS_SECRETS_KEY_FILE via
// .env.test precisely so one key spans the run; the integration suites already
// guard the mirror-image hazard by refusing to rotate that key out from under a
// running suite (test/integration/controller/docker_helper.go). This closes the
// unit-test half.
//
// Secret DATA paths stay per-test — only the key is shared, exactly as a single
// controller process holds one master key in production. A test that needs an
// isolated key still overrides CFGMS_SECRETS_KEY_FILE with t.Setenv, and when
// no ambient key exists the previous fresh-key-per-invocation behaviour is
// unchanged.
func resolveSecretsKeyFile(base string) (string, error) {
	if existing := strings.TrimSpace(os.Getenv("CFGMS_SECRETS_KEY_FILE")); existing != "" {
		// #nosec G703 -- reading this environment value is the whole point of the
		// function: CFGMS_SECRETS_KEY_FILE is the production contract for naming the
		// master key file (features/controller/api/server.go rejects startup without
		// it), and the test harness sets it deliberately via .env.test. The value is
		// supplied by the process launching the test run, not by any request or
		// stored data, and nothing here reads or writes the named file — os.Stat only
		// decides whether to reuse the path or mint a fresh key beside base.
		if info, err := os.Stat(existing); err == nil && !info.IsDir() && info.Size() > 0 {
			return existing, nil
		}
	}
	return writeSecretsKeyFile(base)
}

// writeSecretsKeyFile generates a fresh 256-bit key per invocation — never a
// fixed test key — and writes it owner-readable in the base64 form the SOPS
// provider expects.
func writeSecretsKeyFile(base string) (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generate test secrets key: %w", err)
	}
	keyPath := filepath.Join(base, "controller-secrets.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		return "", fmt.Errorf("write test secrets key: %w", err)
	}
	return keyPath, nil
}

// ReservePrivateListenerAddress returns a loopback host:port that is free right
// now. Private listeners are validated against a fixed numeric port, so ":0"
// cannot be handed to the server — a test has to name a concrete port. There is
// an unavoidable race between releasing this port and the server binding it;
// loopback ports on a test host are plentiful enough for that to be acceptable.
func ReservePrivateListenerAddress(t *testing.T) string {
	t.Helper()

	address, err := ReserveLoopbackAddress()
	if err != nil {
		t.Fatalf("ReservePrivateListenerAddress: %v", err)
	}
	return address
}

// Ports are drawn from [reservedPortMin, reservedPortMax], a band that sits
// below the ephemeral range on every platform CFGMS builds for — Linux starts
// its default range at 32768, macOS and Windows at 49152. Nothing in that band
// is handed out by a `:0` bind, which is what makes the reservation hold.
const (
	reservedPortMin = 20000
	reservedPortMax = 32767
	reserveAttempts = 64
)

var (
	reservedPortsMu sync.Mutex
	reservedPorts   = map[int]struct{}{}
)

// ReserveLoopbackAddress is ReservePrivateListenerAddress for harness code that
// builds a controller outside a *testing.T — the e2e framework constructs its
// controller config in a plain function.
//
// There is an unavoidable gap between releasing a port here and the server
// binding it, so the reservation has to make a collision in that gap
// vanishingly unlikely rather than merely unlikely. The original implementation
// bound "127.0.0.1:0", read the address and closed the listener, which handed
// back a port from the OS ephemeral range — precisely the range the OS draws
// from when any other process on the host binds :0. Under `make test`, where
// every package's test binary runs concurrently, that lost the race often
// enough to fail a merge-queue run:
//
//	bind private metrics listener: listen tcp 127.0.0.1:34941:
//	bind: address already in use
//
// Two changes close it. The port is drawn from a band below the ephemeral range
// (see the constants above), so no concurrent :0 bind can take it; and ports
// handed out by this process are remembered, so two tests in the same binary
// never receive the same one. Each candidate is still probed with a real bind,
// so a port held by an unrelated long-lived process is skipped rather than
// returned.
//
// The residual risk is two *separate* test binaries independently drawing the
// same port from a ~12k-wide band inside the same gap. That is not zero, but it
// is several orders of magnitude below the ephemeral-range collision it
// replaces.
func ReserveLoopbackAddress() (string, error) {
	for attempt := 0; attempt < reserveAttempts; attempt++ {
		port, err := candidatePort()
		if err != nil {
			return "", err
		}

		reservedPortsMu.Lock()
		if _, taken := reservedPorts[port]; taken {
			reservedPortsMu.Unlock()
			continue
		}
		reservedPorts[port] = struct{}{}
		reservedPortsMu.Unlock()

		address := fmt.Sprintf("127.0.0.1:%d", port)
		listener, err := net.Listen("tcp", address)
		if err != nil {
			// Held by something outside this process — leave it marked so this
			// process does not probe it again, and try another.
			continue
		}
		if err := listener.Close(); err != nil {
			return "", fmt.Errorf("release loopback port: %w", err)
		}
		return address, nil
	}
	return "", fmt.Errorf("reserve loopback port: no free port in [%d, %d] after %d attempts",
		reservedPortMin, reservedPortMax, reserveAttempts)
}

// candidatePort returns a uniformly random port in the reserved band. It draws
// from crypto/rand so parallel test binaries starting in the same instant do not
// share a seed and walk the same sequence.
func candidatePort() (int, error) {
	span := int64(reservedPortMax - reservedPortMin + 1)
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return 0, fmt.Errorf("reserve loopback port: %w", err)
	}
	return reservedPortMin + int(n.Int64()), nil
}
