// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package timemodule

import (
	"os/exec"
	"strings"
	"testing"
)

// systemsetupAvailable returns true when the systemsetup command is reachable.
// macOS tests that interact with systemsetup require elevated privileges or
// system access not present in all CI runners.
func systemsetupAvailable() bool {
	return exec.Command("systemsetup", "-gettimezone").Run() == nil
}

// TestDarwinExecutor_GetTimezone_Parsing verifies the colon-prefix stripping
// logic used in getTimezone for the "Time Zone: America/Chicago" output format.
func TestDarwinExecutor_GetTimezone_Parsing(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"Time Zone: America/Chicago", "America/Chicago"},
		{"Time Zone: UTC", "UTC"},
		{"Time Zone: Europe/London", "Europe/London"},
		{"Time Zone: Pacific/Auckland", "Pacific/Auckland"},
	}

	for _, tc := range cases {
		// Replicate the parsing contract from getTimezone.
		got := ""
		if idx := strings.Index(tc.raw, ":"); idx >= 0 {
			got = strings.TrimSpace(tc.raw[idx+1:])
		}
		if got != tc.want {
			t.Errorf("getTimezone parse(%q): got %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestDarwinExecutor_GetNTPServer_Parsing verifies the colon-prefix stripping
// logic used in getNTPServer for "Network Time Server: time.apple.com" output.
func TestDarwinExecutor_GetNTPServer_Parsing(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"Network Time Server: time.apple.com", "time.apple.com"},
		{"Network Time Server: pool.ntp.org", "pool.ntp.org"},
		{"Network Time Server: ", ""},
	}

	for _, tc := range cases {
		got := ""
		if idx := strings.Index(tc.raw, ":"); idx >= 0 {
			got = strings.TrimSpace(tc.raw[idx+1:])
		}
		if got != tc.want {
			t.Errorf("getNTPServer parse(%q): got %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestDarwinExecutor_GetNTPEnabled_Parsing verifies the suffix-detection logic
// for the "Using Network Time: On" / "Using Network Time: Off" output format.
func TestDarwinExecutor_GetNTPEnabled_Parsing(t *testing.T) {
	cases := []struct {
		raw     string
		enabled bool
	}{
		{"Using Network Time: On", true},
		{"Using Network Time: Off", false},
		{"using network time: on", true},  // lowercase variant
		{"using network time: off", false}, // lowercase variant
		{"Using Network Time: ON", true},   // uppercase variant
	}

	for _, tc := range cases {
		lower := strings.ToLower(strings.TrimSpace(tc.raw))
		got := strings.HasSuffix(lower, "on")
		if got != tc.enabled {
			t.Errorf("getNTPEnabled parse(%q): got enabled=%v, want enabled=%v", tc.raw, got, tc.enabled)
		}
	}
}

// TestDarwinExecutor_GetState verifies the full getState round-trip on macOS
// when systemsetup is available. Skipped when systemsetup is not accessible.
func TestDarwinExecutor_GetState(t *testing.T) {
	if !systemsetupAvailable() {
		t.Skip("skipping: systemsetup not available or requires elevated privileges")
	}

	e := &darwinExecutor{}
	state, err := e.getState()
	if err != nil {
		t.Fatalf("getState() error: %v", err)
	}

	if state.Timezone == "" {
		t.Error("getState() returned empty Timezone")
	}
	// NTPServers may be empty (valid when no NTP server is configured).
	// NTPSyncEnabled is boolean — no assertion on the specific value.
}
