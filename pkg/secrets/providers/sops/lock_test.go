// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCASLockDir_DerivesFromPrivateStorageRoot proves the lock directory is placed
// inside the secret store's own data root — a directory the store creates 0700 and
// no other local user can write to — for both shapes of file-backed configuration.
func TestCASLockDir_DerivesFromPrivateStorageRoot(t *testing.T) {
	dir, err := casLockDir(&SOPSSecretStoreConfig{
		StorageConfig: map[string]interface{}{"root": "/var/lib/cfgms/secrets"},
	})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/var/lib/cfgms/secrets", casLockSubdir), dir)

	dir, err = casLockDir(&SOPSSecretStoreConfig{
		StorageConfig: map[string]interface{}{"path": "/var/lib/cfgms/secrets.db"},
	})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/var/lib/cfgms", casLockSubdir), dir)
}

// TestCASLockDir_FailsClosedWithoutPrivateRoot is the regression proof for the
// silent-degradation footgun: a backend that exposes no filesystem root — the
// database/cluster shape, whose storage_config carries only a dsn — must produce an
// error, never a path under a shared location such as os.TempDir().
//
// A lock directory under a world-writable path can be pre-created by any local
// unprivileged user, who can then delete the lock files at will and defeat mutual
// exclusion outright. That would silently re-enable the double-collect/double-mint
// race this lock exists to prevent, on a single node, with no warning anywhere.
func TestCASLockDir_FailsClosedWithoutPrivateRoot(t *testing.T) {
	cases := []struct {
		name string
		cfg  *SOPSSecretStoreConfig
	}{
		{"nil config", nil},
		{"nil storage config", &SOPSSecretStoreConfig{}},
		{"empty storage config", &SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{}}},
		{
			"database backend exposes only a dsn",
			&SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{
				"dsn": "postgres://cfgms@db.example.internal:5432/cfgms?sslmode=verify-full",
			}},
		},
		{
			"blank root",
			&SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{"root": "   "}},
		},
		{
			"non-string root",
			&SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{"root": 42}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := casLockDir(tc.cfg)
			require.ErrorIs(t, err, errNoCASLockRoot)
			assert.Empty(t, dir)
		})
	}
}

// TestCASLockDir_NeverReturnsSharedTempDir asserts the specific degraded path that
// used to exist can no longer be produced by any configuration shape, including one
// that names the temp directory only incidentally.
func TestCASLockDir_NeverReturnsSharedTempDir(t *testing.T) {
	_, err := casLockDir(&SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{"dsn": "postgres://x"}})
	require.Error(t, err)

	// A configuration that genuinely points at a directory under os.TempDir() is a
	// caller's explicit choice (the ephemeral-secrets dev override), not a silent
	// fallback: it yields that directory, not the shared, predictable
	// os.TempDir()/cfgms-sops.cas-locks any local user could pre-create.
	explicit := filepath.Join(t.TempDir(), "secrets")
	dir, err := casLockDir(&SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{"root": explicit}})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(explicit, casLockSubdir), dir)
	assert.NotEqual(t, filepath.Join(os.TempDir(), "cfgms-sops"+casLockSubdir), dir)
	assert.True(t, strings.HasPrefix(dir, explicit))
}
