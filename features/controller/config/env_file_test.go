// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeSecretFile creates a file holding secret material with the permissions a
// systemd credential would have (owner+group read, no world access).
func writeSecretFile(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o440); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// TestResolveEnvValueDirectVariableWins proves an explicitly exported variable
// takes precedence over its _FILE companion, so an operator can always override
// a credential-delivered value without editing the unit.
func TestResolveEnvValueDirectVariableWins(t *testing.T) {
	path := writeSecretFile(t, "db-password", "from-file")
	t.Setenv("CFGMS_TEST_SECRET", "from-env")
	t.Setenv("CFGMS_TEST_SECRET_FILE", path)

	value, found, err := resolveEnvValue("CFGMS_TEST_SECRET")
	if err != nil {
		t.Fatalf("resolveEnvValue returned error: %v", err)
	}
	if !found {
		t.Fatal("expected the variable to resolve")
	}
	if value != "from-env" {
		t.Fatalf("expected the direct variable to win, got %q", value)
	}
}

// TestResolveEnvValueFromFile is the core of the ADR-030 delivery path: the
// unit environment carries only a path, and the value arrives from the file.
func TestResolveEnvValueFromFile(t *testing.T) {
	path := writeSecretFile(t, "db-password", "s3cret-value")
	_ = os.Unsetenv("CFGMS_TEST_SECRET")
	t.Setenv("CFGMS_TEST_SECRET_FILE", path)

	value, found, err := resolveEnvValue("CFGMS_TEST_SECRET")
	if err != nil {
		t.Fatalf("resolveEnvValue returned error: %v", err)
	}
	if !found {
		t.Fatal("expected the _FILE companion to resolve the value")
	}
	if value != "s3cret-value" {
		t.Fatalf("expected %q, got %q", "s3cret-value", value)
	}
}

// TestResolveEnvValueStripsTrailingNewline covers the common case of a secret
// written with a shell redirect: the newline must not become part of the key.
func TestResolveEnvValueStripsTrailingNewline(t *testing.T) {
	path := writeSecretFile(t, "hmac-key", "hmac-key-value\n")
	_ = os.Unsetenv("CFGMS_TEST_SECRET")
	t.Setenv("CFGMS_TEST_SECRET_FILE", path)

	value, _, err := resolveEnvValue("CFGMS_TEST_SECRET")
	if err != nil {
		t.Fatalf("resolveEnvValue returned error: %v", err)
	}
	if value != "hmac-key-value" {
		t.Fatalf("expected the trailing newline stripped, got %q", value)
	}
}

// TestResolveEnvValueRejectsWorldReadableFile keeps the _FILE channel from
// becoming a weaker delivery path than the environment it replaces.
func TestResolveEnvValueRejectsWorldReadableFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced by the Windows file system layer")
	}

	path := filepath.Join(t.TempDir(), "db-password")
	if err := os.WriteFile(path, []byte("s3cret"), 0o444); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	_ = os.Unsetenv("CFGMS_TEST_SECRET")
	t.Setenv("CFGMS_TEST_SECRET_FILE", path)

	_, found, err := resolveEnvValue("CFGMS_TEST_SECRET")
	if err == nil {
		t.Fatal("expected a world-readable secret file to be rejected")
	}
	if found {
		t.Fatal("a rejected file must not resolve to a value")
	}
	if !strings.Contains(err.Error(), "world-accessible") {
		t.Fatalf("expected the error to name the permission problem, got: %v", err)
	}
}

// TestResolveEnvValueMissingFileIsAnError distinguishes "no credential was
// delivered" (unset) from "a credential was declared but cannot be read"
// (present but broken). The second must fail loudly rather than look absent.
func TestResolveEnvValueMissingFileIsAnError(t *testing.T) {
	_ = os.Unsetenv("CFGMS_TEST_SECRET")
	t.Setenv("CFGMS_TEST_SECRET_FILE", filepath.Join(t.TempDir(), "does-not-exist"))

	_, _, err := resolveEnvValue("CFGMS_TEST_SECRET")
	if err == nil {
		t.Fatal("expected an unreadable _FILE reference to be an error")
	}
}

// TestResolveEnvValueUnsetIsNotAnError keeps the ordinary "variable simply is
// not configured" case on the missing-variable path.
func TestResolveEnvValueUnsetIsNotAnError(t *testing.T) {
	_ = os.Unsetenv("CFGMS_TEST_SECRET")
	_ = os.Unsetenv("CFGMS_TEST_SECRET_FILE")

	value, found, err := resolveEnvValue("CFGMS_TEST_SECRET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found || value != "" {
		t.Fatalf("expected an unset variable to resolve to nothing, got %q (found=%v)", value, found)
	}
}

// TestValidateEnvVarsAcceptsFileDeliveredVariable proves a config referencing
// ${VAR} loads when only VAR_FILE is exported — the shape the HA cluster unit
// produces.
func TestValidateEnvVarsAcceptsFileDeliveredVariable(t *testing.T) {
	path := writeSecretFile(t, "db-password", "s3cret")
	_ = os.Unsetenv("CFGMS_TEST_SECRET")
	t.Setenv("CFGMS_TEST_SECRET_FILE", path)

	if err := validateEnvVars(`password: "${CFGMS_TEST_SECRET}"`); err != nil {
		t.Fatalf("expected a file-delivered variable to satisfy validation: %v", err)
	}
}

// TestValidateEnvVarsReportsBrokenFileReference proves a declared-but-unreadable
// credential surfaces as its own error rather than as "missing variable".
func TestValidateEnvVarsReportsBrokenFileReference(t *testing.T) {
	_ = os.Unsetenv("CFGMS_TEST_SECRET")
	t.Setenv("CFGMS_TEST_SECRET_FILE", filepath.Join(t.TempDir(), "absent"))

	err := validateEnvVars(`password: "${CFGMS_TEST_SECRET}"`)
	if err == nil {
		t.Fatal("expected a broken _FILE reference to fail validation")
	}
	if strings.Contains(err.Error(), "missing required environment variables") {
		t.Fatalf("a broken credential must not be reported as a missing variable: %v", err)
	}
}

// TestExpandEnvWithDefaultsUsesFileValue covers both expansion syntaxes the
// rendered controller.cfg uses.
func TestExpandEnvWithDefaultsUsesFileValue(t *testing.T) {
	path := writeSecretFile(t, "db-password", "pg-password")
	_ = os.Unsetenv("CFGMS_TEST_SECRET")
	t.Setenv("CFGMS_TEST_SECRET_FILE", path)

	expanded, err := expandEnvWithDefaults(
		"password: \"${CFGMS_TEST_SECRET}\"\ndsn: \"password=${CFGMS_TEST_SECRET} sslmode=disable\"\n")
	if err != nil {
		t.Fatalf("expandEnvWithDefaults returned error: %v", err)
	}
	if strings.Count(expanded, "pg-password") != 2 {
		t.Fatalf("expected both references expanded from the file, got: %q", expanded)
	}
}

// TestExpandEnvWithDefaultsFileBeatsDefault proves a file-delivered value is
// used in preference to a ${VAR:-default} fallback — otherwise a credential
// that failed to arrive would be silently replaced by the default.
func TestExpandEnvWithDefaultsFileBeatsDefault(t *testing.T) {
	path := writeSecretFile(t, "hmac-key", "real-key")
	_ = os.Unsetenv("CFGMS_TEST_SECRET")
	t.Setenv("CFGMS_TEST_SECRET_FILE", path)

	expanded, err := expandEnvWithDefaults(`session_hmac_key: "${CFGMS_TEST_SECRET:-fallback}"`)
	if err != nil {
		t.Fatalf("expandEnvWithDefaults returned error: %v", err)
	}
	if !strings.Contains(expanded, "real-key") {
		t.Fatalf("expected the file value to beat the default, got: %q", expanded)
	}
}

// TestExpandEnvWithDefaultsPropagatesFileError proves a broken credential
// reference inside a defaulted reference is not silently swallowed by the
// default.
func TestExpandEnvWithDefaultsPropagatesFileError(t *testing.T) {
	_ = os.Unsetenv("CFGMS_TEST_SECRET")
	t.Setenv("CFGMS_TEST_SECRET_FILE", filepath.Join(t.TempDir(), "absent"))

	if _, err := expandEnvWithDefaults(`key: "${CFGMS_TEST_SECRET:-fallback}"`); err == nil {
		t.Fatal("expected a broken _FILE reference to surface as an error, not fall back to the default")
	}
}

// TestLoadConfigResolvesSecretsFromCredentialFiles is the end-to-end proof for
// ADR-030: a controller config that references its DB password and session HMAC
// key as ${VAR} loads correctly when the values arrive only as files, with no
// secret in the environment.
func TestLoadConfigResolvesSecretsFromCredentialFiles(t *testing.T) {
	credDir := t.TempDir()
	dbPasswordPath := filepath.Join(credDir, "cfgms-db-password")
	hmacKeyPath := filepath.Join(credDir, "cfgms-session-hmac-key")
	if err := os.WriteFile(dbPasswordPath, []byte("pg-password-from-credential"), 0o440); err != nil {
		t.Fatalf("write db password: %v", err)
	}
	if err := os.WriteFile(hmacKeyPath, []byte("hmac-key-from-credential\n"), 0o440); err != nil {
		t.Fatalf("write hmac key: %v", err)
	}

	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "controller.cfg")
	configBody := `listen_addr: "127.0.0.1:9080"
data_dir: "` + filepath.ToSlash(configDir) + `"
storage:
  provider: database
  config:
    host: "db.example.test"
    password: "${CFGMS_STORAGE_DB_PASSWORD}"
  cluster:
    postgres_dsn: "host=db.example.test password=${CFGMS_STORAGE_DB_PASSWORD} sslmode=disable"
    session_hmac_key: "${CFGMS_SESSION_HMAC_KEY}"
`
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	_ = os.Unsetenv("CFGMS_STORAGE_DB_PASSWORD")
	_ = os.Unsetenv("CFGMS_SESSION_HMAC_KEY")
	t.Setenv("CFGMS_STORAGE_DB_PASSWORD_FILE", dbPasswordPath)
	t.Setenv("CFGMS_SESSION_HMAC_KEY_FILE", hmacKeyPath)

	cfg, err := LoadWithPath(configPath)
	if err != nil {
		t.Fatalf("LoadWithPath failed with file-delivered secrets: %v", err)
	}

	password, _ := cfg.Storage.Config["password"].(string)
	if password != "pg-password-from-credential" {
		t.Fatalf("storage.config.password did not resolve from the credential file, got %q", password)
	}
	if cfg.Storage.Cluster == nil {
		t.Fatal("storage.cluster was not parsed")
	}
	if !strings.Contains(cfg.Storage.Cluster.PostgresDSN, "password=pg-password-from-credential") {
		t.Fatalf("cluster DSN did not resolve from the credential file, got %q", cfg.Storage.Cluster.PostgresDSN)
	}
	if cfg.Storage.Cluster.SessionHMACKey != "hmac-key-from-credential" {
		t.Fatalf("session_hmac_key did not resolve from the credential file, got %q", cfg.Storage.Cluster.SessionHMACKey)
	}
}
