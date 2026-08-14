// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package testutil

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

	keyPath, err := writeSecretsKeyFile(base)
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
	keyPath, err := writeSecretsKeyFile(base)
	if err != nil {
		t.Fatalf("SetupSecretsEnvForTest: %v", err)
	}
	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(base, "secrets"))
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "true")
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

// ReserveLoopbackAddress is ReservePrivateListenerAddress for harness code that
// builds a controller outside a *testing.T — the e2e framework constructs its
// controller config in a plain function.
func ReserveLoopbackAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("reserve loopback port: %w", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", fmt.Errorf("release loopback port: %w", err)
	}
	return address, nil
}
