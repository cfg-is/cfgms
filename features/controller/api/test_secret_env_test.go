// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// setTestSecretsEnv provisions an ephemeral external encryption key separately
// from the test's secret-data root. Tests exercise the same fail-closed,
// encrypted-at-rest path as production.
func setTestSecretsEnv(t *testing.T) {
	t.Helper()

	base := t.TempDir()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	keyPath := filepath.Join(base, "controller-secrets.key")
	err = os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600)
	require.NoError(t, err)

	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(base, "data"))
}
