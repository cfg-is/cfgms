// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package script

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestSecretStore creates a StewardSecretStore in a temporary directory.
// Skips the test when /etc/machine-id is unavailable (containers without
// platform identity, matching the pattern in pkg/secrets/providers/steward).
func newTestSecretStore(t *testing.T) interfaces.SecretStore {
	t.Helper()
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		t.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}
	provider := &steward.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": t.TempDir(),
	})
	require.NoError(t, err, "failed to create test secret store")
	return store
}

// storeSecret is a test helper that stores a secret value and fails the test on error.
func storeSecret(t *testing.T, store interfaces.SecretStore, key, value string) {
	t.Helper()
	err := store.StoreSecret(context.Background(), &interfaces.SecretRequest{
		Key:   key,
		Value: value,
	})
	require.NoError(t, err, "failed to store test secret %q", key)
}

// TestResolveSecretBindings_SecretStore verifies that secret-store bindings are
// resolved by fetching from the real steward store.
func TestResolveSecretBindings_SecretStore(t *testing.T) {
	store := newTestSecretStore(t)
	storeSecret(t, store, "db/password", "s3cr3t-db-pass")

	bindings := []ParamBinding{
		{Name: "DbPassword", From: ParamSourceSecretStore, Key: "db/password"},
	}

	resolved, err := ResolveSecretBindings(context.Background(), store, bindings)
	require.NoError(t, err)
	require.Len(t, resolved, 1)

	param := resolved[0]
	assert.Equal(t, "DbPassword", param.Name)
	assert.Equal(t, "s3cr3t-db-pass", param.Value)
	assert.True(t, param.IsSecret)
}

// TestResolveSecretBindings_LiteralParam verifies that literal bindings are
// returned as-is without hitting the secret store.
// The store is not required for this test because the function never calls it.
func TestResolveSecretBindings_LiteralParam(t *testing.T) {
	bindings := []ParamBinding{
		{Name: "ApiUrl", From: ParamSourceLiteral, Value: "https://example.com"},
	}

	// Literal bindings don't touch the store; pass nil to confirm store is unreachable.
	resolved, err := ResolveSecretBindings(context.Background(), nil, bindings)
	require.NoError(t, err)
	require.Len(t, resolved, 1)

	param := resolved[0]
	assert.Equal(t, "ApiUrl", param.Name)
	assert.Equal(t, "https://example.com", param.Value)
	assert.False(t, param.IsSecret)
}

// TestResolveSecretBindings_MixedParams verifies that a mix of secret-store
// and literal bindings all resolve correctly in one call.
func TestResolveSecretBindings_MixedParams(t *testing.T) {
	store := newTestSecretStore(t)
	storeSecret(t, store, "api/key", "tok-abc123")

	bindings := []ParamBinding{
		{Name: "Token", From: ParamSourceSecretStore, Key: "api/key"},
		{Name: "Endpoint", From: ParamSourceLiteral, Value: "https://api.example.com"},
	}

	resolved, err := ResolveSecretBindings(context.Background(), store, bindings)
	require.NoError(t, err)
	require.Len(t, resolved, 2)

	byName := make(map[string]ResolvedParam, len(resolved))
	for _, p := range resolved {
		byName[p.Name] = p
	}

	token := byName["Token"]
	assert.Equal(t, "tok-abc123", token.Value)
	assert.True(t, token.IsSecret)

	endpoint := byName["Endpoint"]
	assert.Equal(t, "https://api.example.com", endpoint.Value)
	assert.False(t, endpoint.IsSecret)
}

// TestResolveSecretBindings_MissingKey verifies that resolution fails with a
// clear error when a referenced secret key does not exist in the store.
func TestResolveSecretBindings_MissingKey(t *testing.T) {
	store := newTestSecretStore(t)

	bindings := []ParamBinding{
		{Name: "Missing", From: ParamSourceSecretStore, Key: "does/not/exist"},
	}

	_, err := ResolveSecretBindings(context.Background(), store, bindings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Missing")
	assert.Contains(t, err.Error(), "does/not/exist")
}

// TestResolveSecretBindings_EmptyKey verifies that a secret-store binding
// with no key is rejected before hitting the store.
func TestResolveSecretBindings_EmptyKey(t *testing.T) {
	bindings := []ParamBinding{
		{Name: "DbPass", From: ParamSourceSecretStore, Key: ""},
	}

	// The key validation happens before any store call; nil store is safe here.
	_, err := ResolveSecretBindings(context.Background(), nil, bindings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key is required")
}

// TestResolveSecretBindings_UnknownSource verifies that an unrecognised From
// value produces a clear error without reaching the store.
func TestResolveSecretBindings_UnknownSource(t *testing.T) {
	bindings := []ParamBinding{
		{Name: "Param", From: "vault", Key: "some/key"},
	}

	// Unknown source is caught in the switch default; store is never called.
	_, err := ResolveSecretBindings(context.Background(), nil, bindings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown source")
}

// TestResolveSecretBindings_EmptyBindings verifies that an empty binding
// list returns an empty result without error.
func TestResolveSecretBindings_EmptyBindings(t *testing.T) {
	// Empty bindings: loop body never runs, store is never reached.
	resolved, err := ResolveSecretBindings(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Empty(t, resolved)
}

// TestSecretEnvVarName_PowerShell verifies the Windows-safe CFGMS_SECRET_ prefix.
func TestSecretEnvVarName_PowerShell(t *testing.T) {
	name := SecretEnvVarName(ShellPowerShell, "DbPassword")
	assert.Equal(t, "CFGMS_SECRET_DBPASSWORD", name)
}

// TestSecretEnvVarName_CMD verifies the Windows-safe prefix for CMD shell.
func TestSecretEnvVarName_CMD(t *testing.T) {
	name := SecretEnvVarName(ShellCmd, "ApiKey")
	assert.Equal(t, "CFGMS_SECRET_APIKEY", name)
}

// TestSecretEnvVarName_Bash verifies the 12-factor pattern for bash (no prefix).
func TestSecretEnvVarName_Bash(t *testing.T) {
	name := SecretEnvVarName(ShellBash, "Secret")
	assert.Equal(t, "SECRET", name)
}

// TestSecretEnvVarName_Python verifies the 12-factor pattern for python.
func TestSecretEnvVarName_Python(t *testing.T) {
	name := SecretEnvVarName(ShellPython3, "DatabaseUrl")
	assert.Equal(t, "DATABASEURL", name)
}

// TestSecretEnvVarName_CaseNormalization verifies that mixed-case param names
// are always uppercased in the env var name.
func TestSecretEnvVarName_CaseNormalization(t *testing.T) {
	cases := []struct {
		shell    ShellType
		input    string
		expected string
	}{
		{ShellBash, "mySecret", "MYSECRET"},
		{ShellPowerShell, "mySecret", "CFGMS_SECRET_MYSECRET"},
		{ShellSh, "api_key", "API_KEY"},
		{ShellZsh, "token", "TOKEN"},
	}

	for _, tc := range cases {
		got := SecretEnvVarName(tc.shell, tc.input)
		assert.Equal(t, tc.expected, got, "shell=%s param=%s", tc.shell, tc.input)
	}
}

// TestExecutorWithSecrets_InjectsEnvVar is an integration test that runs a real
// script, verifies the secret is accessible via env var, and confirms the env
// var is absent from the parent process after execution.
func TestExecutorWithSecrets_InjectsEnvVar(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping secret injection integration test in short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only test; Windows secret injection requires PowerShell runner")
	}

	store := newTestSecretStore(t)
	storeSecret(t, store, "test/secret", "super-secret-value")

	bindings := []ParamBinding{
		{Name: "TestSecret", From: ParamSourceSecretStore, Key: "test/secret"},
	}

	// The script echoes the env var — env var name is TestSecret → TESTSECRET (bash).
	config := &ScriptConfig{
		Content: "echo $TESTSECRET",
		Shell:   ShellBash,
		Timeout: 10 * time.Second,
	}

	executor := NewExecutorWithSecrets(config, store, bindings)
	result, err := executor.Execute(context.Background())
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 0, result.ExitCode, "script should exit 0; stderr: %s", result.Stderr)
	assert.Contains(t, strings.TrimSpace(result.Stdout), "super-secret-value",
		"script output should contain the resolved secret value")

	// Env var must be absent in the parent process after execution.
	assert.Empty(t, os.Getenv("TESTSECRET"),
		"TESTSECRET env var must be cleared from the parent process after execution")
}

// TestExecutorWithSecrets_BlocksOnMissingSecret verifies that execution is
// prevented when a referenced secret does not exist in the store.
func TestExecutorWithSecrets_BlocksOnMissingSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping secret injection integration test in short mode")
	}

	store := newTestSecretStore(t)
	// Deliberately do NOT store the secret.

	bindings := []ParamBinding{
		{Name: "Missing", From: ParamSourceSecretStore, Key: "no/such/key"},
	}

	config := &ScriptConfig{
		Content: "echo should-not-run",
		Shell:   ShellBash,
		Timeout: 10 * time.Second,
	}

	executor := NewExecutorWithSecrets(config, store, bindings)
	_, err := executor.Execute(context.Background())
	require.Error(t, err, "execution must be blocked when secret resolution fails")
	assert.Contains(t, err.Error(), "secret injection blocked")
}

// TestExecutorWithSecrets_CleansUpOnFailure verifies that secret env vars are
// never present in the parent process even when the script itself fails.
// Since secrets are injected only into cmd.Env (child process), they never
// appear in the parent — this test confirms the isolation holds post-execution.
func TestExecutorWithSecrets_CleansUpOnFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping secret injection integration test in short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("Unix-only test; Windows secret injection requires PowerShell runner")
	}

	store := newTestSecretStore(t)
	storeSecret(t, store, "cleanup/secret", "cleanup-value")

	bindings := []ParamBinding{
		{Name: "CleanupSecret", From: ParamSourceSecretStore, Key: "cleanup/secret"},
	}

	config := &ScriptConfig{
		Content: "exit 1", // Script fails deliberately.
		Shell:   ShellBash,
		Timeout: 10 * time.Second,
	}

	executor := NewExecutorWithSecrets(config, store, bindings)
	result, err := executor.Execute(context.Background())

	// The executor returns nil error for non-zero exit codes — the process ran
	// and completed; the exit code is surfaced in result.ExitCode.
	require.NoError(t, err, "executor must not return error for non-zero exit code")
	require.NotNil(t, result, "executor must return a result even on non-zero exit")
	assert.Equal(t, 1, result.ExitCode, "script should report exit code 1")

	// Secret env var must never appear in the parent process — injection is
	// child-process-scoped only, so there is nothing to "clean up" in the parent.
	assert.Empty(t, os.Getenv("CLEANUPSECRET"),
		"CLEANUPSECRET must not appear in the parent process (secrets are child-process-scoped)")
}
