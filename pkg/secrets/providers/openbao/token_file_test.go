// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package openbao

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// clearTokenEnv removes every token variable this package consults so a test
// starts from a known state regardless of the developer's shell.
func clearTokenEnv(t *testing.T) {
	t.Helper()
	for _, name := range tokenEnvVars {
		t.Setenv(name, "")
		t.Setenv(name+"_FILE", "")
	}
}

func writeTokenFile(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openbao-token")
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

// TestParseOpenBaoConfigReadsTokenFromCredentialFile is the ADR-030 delivery
// path: the unit environment names a file under /run/credentials/ and the token
// itself never enters the process environment.
func TestParseOpenBaoConfigReadsTokenFromCredentialFile(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("OPENBAO_TOKEN_FILE", writeTokenFile(t, "s.clustertoken", 0o440))

	cfg, err := parseOpenBaoConfig(map[string]interface{}{})
	if err != nil {
		t.Fatalf("parseOpenBaoConfig returned error: %v", err)
	}
	if cfg.Token != "s.clustertoken" {
		t.Fatalf("expected the token to resolve from the credential file, got %q", cfg.Token)
	}
}

// TestParseOpenBaoConfigPrefersDirectToken keeps the existing environment path
// authoritative so an operator override still works.
func TestParseOpenBaoConfigPrefersDirectToken(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("OPENBAO_TOKEN", "s.direct")
	t.Setenv("OPENBAO_TOKEN_FILE", writeTokenFile(t, "s.fromfile", 0o440))

	cfg, err := parseOpenBaoConfig(map[string]interface{}{})
	if err != nil {
		t.Fatalf("parseOpenBaoConfig returned error: %v", err)
	}
	if cfg.Token != "s.direct" {
		t.Fatalf("expected the direct variable to win, got %q", cfg.Token)
	}
}

// TestParseOpenBaoConfigFallsBackToBaoTokenFile proves the BAO_TOKEN alias has
// the same file-delivered form as OPENBAO_TOKEN.
func TestParseOpenBaoConfigFallsBackToBaoTokenFile(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("BAO_TOKEN_FILE", writeTokenFile(t, "s.baotoken\n", 0o440))

	cfg, err := parseOpenBaoConfig(map[string]interface{}{})
	if err != nil {
		t.Fatalf("parseOpenBaoConfig returned error: %v", err)
	}
	if cfg.Token != "s.baotoken" {
		t.Fatalf("expected BAO_TOKEN_FILE to resolve with the newline stripped, got %q", cfg.Token)
	}
}

// TestParseOpenBaoConfigRejectsUnreadableTokenFile proves a declared but broken
// credential fails loudly instead of silently producing an empty token, which
// would surface much later as an opaque vault permission error.
func TestParseOpenBaoConfigRejectsUnreadableTokenFile(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("OPENBAO_TOKEN_FILE", filepath.Join(t.TempDir(), "absent"))

	if _, err := parseOpenBaoConfig(map[string]interface{}{}); err == nil {
		t.Fatal("expected an unreadable OPENBAO_TOKEN_FILE to be an error")
	}
}

// TestParseOpenBaoConfigRejectsWorldReadableTokenFile keeps the file channel
// from being weaker than the environment it replaces.
func TestParseOpenBaoConfigRejectsWorldReadableTokenFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced by the Windows file system layer")
	}
	clearTokenEnv(t)
	t.Setenv("OPENBAO_TOKEN_FILE", writeTokenFile(t, "s.exposed", 0o444))

	_, err := parseOpenBaoConfig(map[string]interface{}{})
	if err == nil {
		t.Fatal("expected a world-readable token file to be rejected")
	}
	if !strings.Contains(err.Error(), "world-accessible") {
		t.Fatalf("expected the error to name the permission problem, got: %v", err)
	}
}

// TestParseOpenBaoConfigNoTokenIsNotAnError keeps deployments that authenticate
// by other means (or run without a vault) on the existing path.
func TestParseOpenBaoConfigNoTokenIsNotAnError(t *testing.T) {
	clearTokenEnv(t)

	cfg, err := parseOpenBaoConfig(map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error with no token configured: %v", err)
	}
	if cfg.Token != "" {
		t.Fatalf("expected an empty token, got %q", cfg.Token)
	}
}
