// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
)

// setupKeyFileForGuardTest creates a real 32-byte AES key file under dir and
// returns its path. The key file is stored separately from the secrets root so
// that the SOPS provider's co-location check passes.
func setupKeyFileForGuardTest(t *testing.T, dir string) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "ctrl-secrets.key")
	err = os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600)
	require.NoError(t, err)
	return keyPath
}

// flatfileConfigForGuardTest returns a StorageConfig using the flatfile provider.
func flatfileConfigForGuardTest() *config.StorageConfig {
	return &config.StorageConfig{Provider: "flatfile"}
}

// persistentDirForGuardTest returns a directory the ephemeral guard classifies
// as persistent, without writing anything outside the test's own scratch space.
//
// The guard's ephemeral root is os.TempDir(), which Go derives from the
// environment ($TMPDIR on Unix, $TMP/$TEMP on Windows). The helper points those
// variables at a dedicated "ephemeral" subdirectory of the test's scratch space,
// which makes the sibling "persistent" subdirectory genuinely non-ephemeral by
// exactly the rule production uses. Nothing is written to the repository working
// tree, so key material and secret stores cannot survive into git, and the
// fixture is hermetic on any host or CI runner.
func persistentDirForGuardTest(t *testing.T) string {
	t.Helper()

	base := t.TempDir()
	ephemeral := filepath.Join(base, "ephemeral")
	require.NoError(t, os.MkdirAll(ephemeral, 0o700))
	persistent := filepath.Join(base, "persistent")
	require.NoError(t, os.MkdirAll(persistent, 0o700))

	// Redirect the temporary-directory lookup on every supported platform.
	t.Setenv("TMPDIR", ephemeral) // Unix
	t.Setenv("TMP", ephemeral)    // Windows
	t.Setenv("TEMP", ephemeral)   // Windows
	require.False(t, isEphemeralSecretsPath(persistent),
		"fixture directory must be outside the relocated ephemeral root")

	return persistent
}

// TestNewSecretStore_RejectsEphemeralPath verifies that NewSecretStore returns
// a clear error when CFGMS_SECRETS_REPO_PATH resolves to a path under
// os.TempDir() and the dev override is not set.
func TestNewSecretStore_RejectsEphemeralPath(t *testing.T) {
	keyDir := t.TempDir()
	keyPath := setupKeyFileForGuardTest(t, keyDir)

	secretsDir := filepath.Join(t.TempDir(), "secrets")

	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", secretsDir)
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "")

	cfg := config.DefaultConfig()
	cfg.Storage = flatfileConfigForGuardTest()

	_, err := NewSecretStore(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing ephemeral secret storage",
		"must name the ephemeral-storage rejection so operators understand why startup failed")
}

// TestNewSecretStore_AllowsEphemeralWithOverride verifies that
// CFGMS_ALLOW_EPHEMERAL_SECRETS=true downgrades the ephemeral-path hard fail
// to a WARN and allows the store to initialize. This is the dev/test escape
// hatch; it must not be set in production.
func TestNewSecretStore_AllowsEphemeralWithOverride(t *testing.T) {
	keyDir := t.TempDir()
	keyPath := setupKeyFileForGuardTest(t, keyDir)

	secretsDir := filepath.Join(t.TempDir(), "secrets")

	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", secretsDir)
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "true")

	cfg := config.DefaultConfig()
	cfg.Storage = flatfileConfigForGuardTest()

	store, err := NewSecretStore(cfg)
	require.NoError(t, err, "dev override must suppress the ephemeral-path error")
	require.NotNil(t, store)
	require.NoError(t, store.Close())
}

// TestNewSecretStore_AllowsPersistentPath verifies that a flatfile secrets path
// outside os.TempDir() passes the ephemeral guard and starts the store without
// requiring the dev override.
func TestNewSecretStore_AllowsPersistentPath(t *testing.T) {
	persistentBase := persistentDirForGuardTest(t)

	// Key file in t.TempDir() — the key may live anywhere, only the secrets
	// root is checked for ephemerality.
	keyPath := setupKeyFileForGuardTest(t, t.TempDir())
	secretsDir := filepath.Join(persistentBase, "secrets")

	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", secretsDir)
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "") // must NOT be needed for persistent path

	cfg := config.DefaultConfig()
	cfg.Storage = flatfileConfigForGuardTest()

	store, err := NewSecretStore(cfg)
	require.NoError(t, err, "persistent (non-tmp) path must not trigger ephemeral rejection")
	require.NotNil(t, store)
	require.NoError(t, store.Close())
}

// TestNewSecretStore_DatabaseProviderNotEphemeral verifies that the flatfile
// ephemeral-path check is not applied when cfg.Storage.Provider is "database".
// The error returned must be a store-creation error (provider not registered
// or DB unreachable), not an ephemeral-storage rejection.
func TestNewSecretStore_DatabaseProviderNotEphemeral(t *testing.T) {
	keyDir := t.TempDir()
	keyPath := setupKeyFileForGuardTest(t, keyDir)

	// CFGMS_SECRETS_REPO_PATH is still required by the path computation even
	// for the database provider, but its value must not trigger the ephemeral
	// guard because the path is unused for database-backed secrets.
	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(t.TempDir(), "secrets"))
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "") // override must not be needed

	cfg := config.DefaultConfig()
	cfg.Storage = &config.StorageConfig{
		Provider: "database",
		Config: map[string]interface{}{
			// Non-ephemeral DSN (no :memory:, not under /tmp). The connection
			// will fail because no Postgres is running in unit-test context, but
			// the failure must NOT be the ephemeral-storage guard.
			"dsn": "host=localhost port=5432 dbname=cfgms sslmode=disable",
		},
	}

	_, err := NewSecretStore(cfg)
	require.Error(t, err, "store creation with unreachable database must return an error")
	assert.NotContains(t, err.Error(), "refusing ephemeral secret storage",
		"database provider with non-ephemeral DSN must not be rejected by the ephemeral guard")
}

// TestNewSecretStore_DatabaseMemoryDSN_Rejected verifies that a database
// provider configured with an in-memory DSN (:memory:) is rejected by the
// ephemeral guard the same way a flatfile tmp path is.
func TestNewSecretStore_DatabaseMemoryDSN_Rejected(t *testing.T) {
	keyDir := t.TempDir()
	keyPath := setupKeyFileForGuardTest(t, keyDir)

	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(t.TempDir(), "secrets"))
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "")

	cfg := config.DefaultConfig()
	cfg.Storage = &config.StorageConfig{
		Provider: "database",
		Config: map[string]interface{}{
			"dsn": ":memory:",
		},
	}

	_, err := NewSecretStore(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing ephemeral secret storage",
		":memory: database DSN must be rejected as ephemeral")
}

// TestNewSecretStore_FailsOnUnhealthyStore_NoOverride verifies that a store
// initialization failure propagates as an error when CFGMS_ALLOW_EPHEMERAL_SECRETS
// is not set. This is the fail-closed behaviour for broken stores: the controller
// refuses to start rather than running with an unusable secret store.
//
// A persistent path is used so that the ephemeral guard does not fire first,
// isolating the test to the store-creation failure path. A missing key file
// forces a creation-time error (loadExternalKey fails), which is the primary
// source of "unhealthy store" errors with real components (the flatfile health
// check always passes for freshly-created directories).
func TestNewSecretStore_FailsOnUnhealthyStore_NoOverride(t *testing.T) {
	// Use a persistent (non-tmp) path so the ephemeral guard does not fire.
	persistentBase := persistentDirForGuardTest(t)

	// Missing key file forces a store creation failure.
	t.Setenv("CFGMS_SECRETS_KEY_FILE", filepath.Join(persistentBase, "nonexistent.key"))
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(persistentBase, "secrets"))
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "") // no override → error must propagate

	cfg := config.DefaultConfig()
	cfg.Storage = flatfileConfigForGuardTest()

	_, err := NewSecretStore(cfg)
	require.Error(t, err, "store initialization failure must propagate without the dev override")
	assert.Contains(t, err.Error(), "failed to create secret store",
		"error must name the store creation failure")
	assert.NotContains(t, err.Error(), "refusing ephemeral secret storage",
		"persistent path must not trigger the ephemeral guard")
}

// TestNewSecretStore_OverrideDoesNotSuppressStoreFailure verifies that
// CFGMS_ALLOW_EPHEMERAL_SECRETS governs the storage-location decision only. A
// broken store (missing key file) must still abort startup with the override
// set — one flag must not disable two independent fail-closed controls.
func TestNewSecretStore_OverrideDoesNotSuppressStoreFailure(t *testing.T) {
	base := t.TempDir()

	t.Setenv("CFGMS_SECRETS_KEY_FILE", filepath.Join(base, "nonexistent.key"))
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(base, "secrets"))
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "true") // covers the tmp path only

	cfg := config.DefaultConfig()
	cfg.Storage = flatfileConfigForGuardTest()

	_, err := NewSecretStore(cfg)
	require.Error(t, err, "the ephemeral override must not suppress a broken secret store")
	assert.NotContains(t, err.Error(), "refusing ephemeral secret storage",
		"the override must still cover the ephemeral path itself")
}

// TestNewSecretStore_SQLiteWithoutPath_Rejected verifies that storage.provider:
// sqlite with no configured database path is rejected. The sqlite backend keys
// off "path" and treats an absent value as ":memory:", so a persistent
// CFGMS_SECRETS_REPO_PATH must not be accepted as evidence of durability.
func TestNewSecretStore_SQLiteWithoutPath_Rejected(t *testing.T) {
	persistentBase := persistentDirForGuardTest(t)
	keyPath := setupKeyFileForGuardTest(t, t.TempDir())

	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(persistentBase, "secrets"))
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "")

	cfg := config.DefaultConfig()
	cfg.Storage = &config.StorageConfig{Provider: "sqlite"}

	_, err := NewSecretStore(cfg)
	require.Error(t, err, "sqlite without a database path resolves to an in-memory store")
	assert.Contains(t, err.Error(), "refusing ephemeral secret storage",
		"the ephemeral guard must reject a path-less sqlite secret store")
	assert.Contains(t, err.Error(), "storage.sqlite_path",
		"the error must name the setting that fixes it")
}

// TestNewSecretStore_SQLiteMemoryPath_Rejected verifies that an explicitly
// in-memory sqlite path is rejected the same way an absent one is.
func TestNewSecretStore_SQLiteMemoryPath_Rejected(t *testing.T) {
	persistentBase := persistentDirForGuardTest(t)
	keyPath := setupKeyFileForGuardTest(t, t.TempDir())

	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(persistentBase, "secrets"))
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "")

	cfg := config.DefaultConfig()
	cfg.Storage = &config.StorageConfig{
		Provider:   "sqlite",
		SQLitePath: ":memory:",
	}

	_, err := NewSecretStore(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing ephemeral secret storage",
		"in-memory sqlite path must be rejected")
}

// TestNewSecretStore_SQLitePersistentPath_PassesGuard verifies that a sqlite
// backend with a persistent database file is not rejected by the ephemeral
// guard. Store creation still fails (the sqlite provider has no config-store
// implementation), which must surface as a store-creation error rather than an
// ephemeral-storage rejection.
func TestNewSecretStore_SQLitePersistentPath_PassesGuard(t *testing.T) {
	persistentBase := persistentDirForGuardTest(t)
	keyPath := setupKeyFileForGuardTest(t, t.TempDir())

	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyPath)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", filepath.Join(persistentBase, "secrets"))
	t.Setenv("CFGMS_ALLOW_EPHEMERAL_SECRETS", "")

	cfg := config.DefaultConfig()
	cfg.Storage = &config.StorageConfig{
		Provider:   "sqlite",
		SQLitePath: filepath.Join(persistentBase, "secrets.db"),
	}

	_, err := NewSecretStore(cfg)
	require.Error(t, err, "the sqlite provider does not implement a config store")
	assert.NotContains(t, err.Error(), "refusing ephemeral secret storage",
		"a persistent sqlite database file must pass the ephemeral guard")
	assert.Contains(t, err.Error(), "failed to create secret store")
}

// TestResolveSecretsBackend_HandsSQLitePathToBackend verifies that the guard and
// the secrets backend read the same configuration: the map returned for the
// sqlite provider carries the resolved "path" key the backend consumes, not the
// flat-file "root" key it ignores.
func TestResolveSecretsBackend_HandsSQLitePathToBackend(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "secrets.db")

	backend, reason := resolveSecretsBackend(&config.StorageConfig{
		Provider:   "sqlite",
		SQLitePath: dbPath,
	}, "/var/lib/cfgms/secrets")

	assert.Equal(t, dbPath, backend["path"],
		"sqlite backend config must carry the resolved database path")
	assert.NotContains(t, backend, "root",
		"the flat-file root key is meaningless to the sqlite backend")
	assert.NotEmpty(t, reason,
		"a tmp-directory database file is ephemeral even when the secrets path is persistent")
}

// TestResolveSecretsBackend_ConfigPathWinsOverSQLitePath verifies precedence:
// storage.config.path is what the backend reads first, so the guard must judge
// that value rather than storage.sqlite_path.
func TestResolveSecretsBackend_ConfigPathWinsOverSQLitePath(t *testing.T) {
	backend, reason := resolveSecretsBackend(&config.StorageConfig{
		Provider:   "sqlite",
		SQLitePath: "/var/lib/cfgms/persistent.db",
		Config:     map[string]interface{}{"path": ":memory:"},
	}, "/var/lib/cfgms/secrets")

	assert.Equal(t, ":memory:", backend["path"])
	assert.NotEmpty(t, reason, "the in-memory config path must be judged, not the persistent fallback")
}

// TestIsEphemeralSQLitePath covers the sqlite path-detection helper.
func TestIsEphemeralSQLitePath(t *testing.T) {
	tmp := os.TempDir()

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"memory", ":memory:", true},
		{"named memory DSN", "file:secrets?mode=memory&cache=shared", true},
		{"tmp file", filepath.Join(tmp, "secrets.db"), true},
		{"tmp file URI", "file:" + filepath.Join(tmp, "secrets.db"), true},
		{"persistent file", "/var/lib/cfgms/secrets.db", false},
		{"persistent file URI", "file:/var/lib/cfgms/secrets.db", false},
		{"relative file", "data/secrets.db", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isEphemeralSQLitePath(tc.path))
		})
	}
}

// TestIsEphemeralSecretsPath covers the path-detection helper.
func TestIsEphemeralSecretsPath(t *testing.T) {
	tmp := os.TempDir()

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"under os.TempDir", filepath.Join(tmp, "secrets"), true},
		{"deep under os.TempDir", filepath.Join(tmp, "a", "b", "c"), true},
		{"os.TempDir itself", tmp, true},
		{"dev shm", "/dev/shm/cfgms", true},
		{"run user", "/run/user/1000/cfgms", true},
		{"var lib", "/var/lib/cfgms/secrets", false},
		{"workspace", "/workspace/data/secrets", false},
		{"root relative path", "data/secrets", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isEphemeralSecretsPath(tc.path)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestIsDatabaseDSNEphemeral covers the DSN-detection helper.
func TestIsDatabaseDSNEphemeral(t *testing.T) {
	tmp := os.TempDir()

	cases := []struct {
		name string
		dsn  string
		want bool
	}{
		{"empty DSN", "", false},
		{"memory DSN", ":memory:", true},
		{"file memory URI", "file::memory:", true},
		{"file memory URI with params", "file::memory:?cache=shared", true},
		{"file tmp path", "file:" + filepath.Join(tmp, "foo.db"), true},
		{"bare tmp path", filepath.Join(tmp, "foo.db"), true},
		{"postgres DSN", "host=pg.example.com port=5432 dbname=cfgms sslmode=require", false},
		{"persistent file path", "/var/lib/cfgms/cfgms.db", false},
		{"persistent file URI", "file:/var/lib/cfgms/cfgms.db", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isDatabaseDSNEphemeral(tc.dsn)
			assert.Equal(t, tc.want, got)
		})
	}
}
