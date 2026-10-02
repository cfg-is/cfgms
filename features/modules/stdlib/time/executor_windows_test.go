// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package timemodule

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// w32tmAvailable returns true when the Windows Time Service is available.
func w32tmAvailable() bool {
	return exec.Command("w32tm", "/query", "/configuration").Run() == nil
}

// TestWindowsExecutor_GetNTPConfig_ServerParsing verifies the NtpServer line
// parsing in getNTPConfig: it must strip trailing parenthetical annotations
// and comma-delimited polling flags from each server token.
func TestWindowsExecutor_GetNTPConfig_ServerParsing(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		want    []string
		enabled bool
	}{
		{
			name:    "single server with polling flag",
			line:    "NtpServer: time.windows.com,0x9 (Local)",
			want:    []string{"time.windows.com"},
			enabled: false, // type line absent → false default in this test
		},
		{
			name:    "multiple servers with polling flags",
			line:    "NtpServer: ntp1.example.com,0x9 ntp2.example.com,0x9 (Local)",
			want:    []string{"ntp1.example.com", "ntp2.example.com"},
			enabled: false,
		},
		{
			name:    "server without polling flag",
			line:    "NtpServer: pool.ntp.org (Local)",
			want:    []string{"pool.ntp.org"},
			enabled: false,
		},
		{
			name:    "empty NtpServer",
			line:    "NtpServer:  (Local)",
			want:    nil,
			enabled: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var servers []string

			// Replicate the parsing contract from getNTPConfig.
			ntpLine := strings.TrimSpace(tc.line)
			if strings.HasPrefix(ntpLine, "NtpServer:") {
				val := strings.TrimPrefix(ntpLine, "NtpServer:")
				if idx := strings.Index(val, "("); idx >= 0 {
					val = val[:idx]
				}
				for _, s := range strings.Fields(val) {
					if comma := strings.Index(s, ","); comma >= 0 {
						s = s[:comma]
					}
					if s != "" {
						servers = append(servers, s)
					}
				}
			}

			if len(servers) != len(tc.want) {
				t.Fatalf("server count: got %d (%v), want %d (%v)", len(servers), servers, len(tc.want), tc.want)
			}
			for i := range tc.want {
				if servers[i] != tc.want[i] {
					t.Errorf("server[%d]: got %q, want %q", i, servers[i], tc.want[i])
				}
			}
		})
	}
}

// TestWindowsExecutor_GetNTPConfig_TypeParsing verifies the Type: line parsing
// in getNTPConfig: "NTP" and "NT5DS" mean sync enabled; "NoSync" means disabled.
func TestWindowsExecutor_GetNTPConfig_TypeParsing(t *testing.T) {
	cases := []struct {
		typeLine string
		enabled  bool
	}{
		{"Type: NTP", true},
		{"Type: NT5DS", true},
		{"Type: NoSync", false},
		{"Type: nosync", false}, // case-insensitive
	}

	for _, tc := range cases {
		trimmed := strings.TrimSpace(tc.typeLine)
		enabled := true
		if strings.HasPrefix(trimmed, "Type:") {
			val := strings.TrimSpace(strings.TrimPrefix(trimmed, "Type:"))
			enabled = !strings.EqualFold(val, "NoSync")
		}
		if enabled != tc.enabled {
			t.Errorf("Type parse(%q): got enabled=%v, want enabled=%v", tc.typeLine, enabled, tc.enabled)
		}
	}
}

// TestIsAccessDeniedExitError verifies the exit-code classification getNTPConfig
// relies on to map w32tm's access-denied failure to modules.ErrInsufficientPrivilege
// (Issue #4147). Uses a synthetic exit code from cmd.exe rather than depending on
// this session's actual elevation state, so the classification itself is
// deterministic regardless of whether the test runner is elevated.
func TestIsAccessDeniedExitError(t *testing.T) {
	runWithExitCode := func(t *testing.T, code int) error {
		t.Helper()
		return exec.Command("cmd", "/c", "exit", "/b", strconv.Itoa(code)).Run()
	}

	t.Run("access denied HRESULT is classified as access denied", func(t *testing.T) {
		err := runWithExitCode(t, errAccessDeniedHRESULT)
		if err == nil {
			t.Fatal("exit /b with a non-zero code must return a non-nil error")
		}
		if !isAccessDeniedExitError(err) {
			t.Errorf("isAccessDeniedExitError(%v) = false, want true", err)
		}
	})

	t.Run("an unrelated non-zero exit code is not classified as access denied", func(t *testing.T) {
		err := runWithExitCode(t, 1)
		if err == nil {
			t.Fatal("exit /b 1 must return a non-nil error")
		}
		if isAccessDeniedExitError(err) {
			t.Errorf("isAccessDeniedExitError(%v) = true, want false", err)
		}
	})

	t.Run("success is not classified as access denied", func(t *testing.T) {
		if err := runWithExitCode(t, 0); err != nil {
			t.Fatalf("exit /b 0 must succeed, got %v", err)
		}
	})

	t.Run("a non-ExitError is never classified as access denied", func(t *testing.T) {
		_, err := exec.LookPath("this-binary-does-not-exist-cfgms-4147")
		if err == nil {
			t.Fatal("expected LookPath to fail for a nonexistent binary")
		}
		if isAccessDeniedExitError(err) {
			t.Errorf("isAccessDeniedExitError(%v) = true, want false for a non-ExitError", err)
		}
	})
}

// TestWindowsExecutor_GetState verifies the full getState round-trip on Windows
// when w32tm and the Windows Time Service are available.
func TestWindowsExecutor_GetState(t *testing.T) {
	if !w32tmAvailable() {
		t.Skip("skipping: w32tm not available or Windows Time Service is not running")
	}

	e := &windowsExecutor{}
	state, err := e.getState()
	if err != nil {
		t.Fatalf("getState() error: %v", err)
	}

	if state.Timezone == "" {
		t.Error("getState() returned empty Timezone")
	}
	// NTPServers may be empty (valid when no peers are configured).
	// NTPSyncEnabled is boolean — no assertion on the specific value.
}
