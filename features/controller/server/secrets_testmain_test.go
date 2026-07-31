// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain provisions the same external-key and durable secret-data contracts
// required by production. Tests that exercise path isolation can still override
// CFGMS_SECRETS_REPO_PATH with t.Setenv.
func TestMain(m *testing.M) {
	base, err := os.MkdirTemp("", "cfgms-server-secrets-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create test secrets directory: %v\n", err)
		os.Exit(1)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Fprintf(os.Stderr, "generate test secrets key: %v\n", err)
		os.Exit(1)
	}
	keyPath := filepath.Join(base, "controller-secrets.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write test secrets key: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "set test secrets key environment: %v\n", err)
		os.Exit(1)
	}
	secretsPath := filepath.Join(base, "secrets")
	if err := os.Setenv("CFGMS_SECRETS_REPO_PATH", secretsPath); err != nil {
		fmt.Fprintf(os.Stderr, "set test secrets path environment: %v\n", err)
		os.Exit(1)
	}

	exitCode := m.Run()
	_ = os.RemoveAll(base)
	os.Exit(exitCode)
}
