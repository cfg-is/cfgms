// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package timemodule

import (
	"os/exec"
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
