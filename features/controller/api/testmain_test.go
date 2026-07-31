// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #2993: argon2id removed — passkey-only login. TestMain no longer needs
// to override cost parameters. The file is retained as the package-level test entry
// point in case future TestMain logic is needed.
package api

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	base, err := os.MkdirTemp("", "cfgms-api-test-secrets-")
	if err != nil {
		panic(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	keyPath := filepath.Join(base, "controller-secrets.key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		panic(err)
	}
	if err := os.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath); err != nil {
		panic(err)
	}
	if err := os.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(base, "data")); err != nil {
		panic(err)
	}

	code := m.Run()
	_ = os.RemoveAll(base)
	os.Exit(code)
}
