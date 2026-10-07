// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package timemodule

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// newFixtureExecutor creates a linuxExecutor pointed at temp files inside
// tmpDir. None of the CI host's real system files are touched.
func newFixtureExecutor(t *testing.T) (*linuxExecutor, string) {
	t.Helper()
	dir := t.TempDir()
	return &linuxExecutor{
		timezoneFile:    filepath.Join(dir, "timezone"),
		timesyncdConfig: filepath.Join(dir, "timesyncd.conf"),
	}, dir
}

// TestLinuxExecutor_TimezoneRoundTrip verifies Get/Set round-trip for timezone
// against fixture-isolated config paths (ADR-016 acceptance criterion).
func TestLinuxExecutor_TimezoneRoundTrip(t *testing.T) {
	e, _ := newFixtureExecutor(t)

	desired := timeState{
		Timezone:       "America/Chicago",
		NTPServers:     []string{"time1.example.com", "time2.example.com"},
		NTPSyncEnabled: true,
	}

	if err := e.setState(desired); err != nil {
		// timedatectl may fail in CI (no systemd). Skip when the error is from
		// timedatectl (not a file write problem); fatal when it's a genuine
		// file write error since those indicate a broken test fixture.
		if !isFileWriteError(err) {
			t.Skipf("setState: timedatectl failed (expected in CI without systemd): %v", err)
		}
		t.Fatalf("setState file write failed: %v", err)
	}

	got, err := e.getState()
	if err != nil {
		t.Fatalf("getState() error: %v", err)
	}

	if got.Timezone != desired.Timezone {
		t.Errorf("Timezone: got %q, want %q", got.Timezone, desired.Timezone)
	}
}

// TestLinuxExecutor_NTPServerListRoundTrip verifies Get/Set round-trip for
// the NTP server list against fixture-isolated config paths.
func TestLinuxExecutor_NTPServerListRoundTrip(t *testing.T) {
	e, _ := newFixtureExecutor(t)

	servers := []string{"time2.example.com", "time1.example.com", "time3.example.com"}
	desired := timeState{
		Timezone:       "UTC",
		NTPServers:     servers,
		NTPSyncEnabled: true,
	}

	if err := e.setState(desired); err != nil {
		if !isFileWriteError(err) {
			t.Skipf("setState: timedatectl failed (expected in CI without systemd): %v", err)
		}
		t.Fatalf("setState file write failed: %v", err)
	}

	got, err := e.getState()
	if err != nil {
		t.Fatalf("getState() error: %v", err)
	}

	wantServers := make([]string, len(servers))
	copy(wantServers, servers)
	sort.Strings(wantServers)

	if len(got.NTPServers) != len(wantServers) {
		t.Fatalf("NTPServers length: got %d, want %d — got=%v", len(got.NTPServers), len(wantServers), got.NTPServers)
	}
	for i := range wantServers {
		if got.NTPServers[i] != wantServers[i] {
			t.Errorf("NTPServers[%d]: got %q, want %q", i, got.NTPServers[i], wantServers[i])
		}
	}
}

// TestLinuxExecutor_NTPServersSorted verifies that getState always returns a
// sorted NTP server list regardless of the order stored in the config file.
func TestLinuxExecutor_NTPServersSorted(t *testing.T) {
	e, dir := newFixtureExecutor(t)

	// Write a timesyncd.conf with servers in reverse alphabetical order.
	content := "# cfgms:ntp_sync_enabled=true\n[Time]\nNTP=z.pool.ntp.org a.pool.ntp.org m.pool.ntp.org\nFallbackNTP=\n"
	if err := os.WriteFile(filepath.Join(dir, "timesyncd.conf"), []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "timezone"), []byte("UTC\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := e.getState()
	if err != nil {
		t.Fatalf("getState() error: %v", err)
	}

	// Verify the returned list is sorted.
	for i := 1; i < len(got.NTPServers); i++ {
		if got.NTPServers[i] < got.NTPServers[i-1] {
			t.Errorf("NTPServers not sorted at index %d: %q < %q", i, got.NTPServers[i], got.NTPServers[i-1])
		}
	}
}

// TestLinuxExecutor_NTPSyncEnabledRoundTrip verifies that the NTP sync enabled
// flag survives a Set → Get round-trip via the cfgms marker in timesyncd.conf.
func TestLinuxExecutor_NTPSyncEnabledRoundTrip(t *testing.T) {
	e, _ := newFixtureExecutor(t)

	for _, wantEnabled := range []bool{true, false} {
		desired := timeState{
			Timezone:       "UTC",
			NTPServers:     []string{"pool.ntp.org"},
			NTPSyncEnabled: wantEnabled,
		}

		if err := e.setState(desired); err != nil {
			if !isFileWriteError(err) {
				t.Skipf("setState: timedatectl failed (expected in CI without systemd): %v", err)
			}
			t.Fatalf("setState file write failed: %v", err)
		}

		got, err := e.getState()
		if err != nil {
			t.Fatalf("getState() error after setState(enabled=%v): %v", wantEnabled, err)
		}

		if got.NTPSyncEnabled != wantEnabled {
			t.Errorf("NTPSyncEnabled: got %v, want %v", got.NTPSyncEnabled, wantEnabled)
		}
	}
}

// TestLinuxExecutor_MissingFiles verifies getState returns sensible defaults
// when the timezone and timesyncd config files do not exist.
func TestLinuxExecutor_MissingFiles(t *testing.T) {
	e, _ := newFixtureExecutor(t)
	// Files don't exist — newFixtureExecutor only creates the dir, not files.

	got, err := e.getState()
	if err != nil {
		t.Fatalf("getState() with missing files returned error: %v", err)
	}

	if got.Timezone == "" {
		t.Error("getState() with missing timezone file must return a non-empty default timezone")
	}
}

// TestLinuxExecutor_GetIsIdempotent verifies two consecutive getState calls
// return identical results (ADR-016 clause 4 determinism contract).
func TestLinuxExecutor_GetIsIdempotent(t *testing.T) {
	e, _ := newFixtureExecutor(t)

	desired := timeState{
		Timezone:       "Europe/Berlin",
		NTPServers:     []string{"ntp1.example.com", "ntp2.example.com"},
		NTPSyncEnabled: true,
	}

	if err := e.setState(desired); err != nil {
		if !isFileWriteError(err) {
			t.Skipf("setState: timedatectl failed (expected in CI without systemd): %v", err)
		}
		t.Fatalf("setState file write failed: %v", err)
	}

	got1, err := e.getState()
	if err != nil {
		t.Fatalf("first getState() error: %v", err)
	}
	got2, err := e.getState()
	if err != nil {
		t.Fatalf("second getState() error: %v", err)
	}

	if got1.Timezone != got2.Timezone {
		t.Errorf("Timezone not idempotent: %q vs %q", got1.Timezone, got2.Timezone)
	}
	if got1.NTPSyncEnabled != got2.NTPSyncEnabled {
		t.Errorf("NTPSyncEnabled not idempotent: %v vs %v", got1.NTPSyncEnabled, got2.NTPSyncEnabled)
	}
	if len(got1.NTPServers) != len(got2.NTPServers) {
		t.Errorf("NTPServers length not idempotent: %d vs %d", len(got1.NTPServers), len(got2.NTPServers))
	}
	for i := range got1.NTPServers {
		if got1.NTPServers[i] != got2.NTPServers[i] {
			t.Errorf("NTPServers[%d] not idempotent: %q vs %q", i, got1.NTPServers[i], got2.NTPServers[i])
		}
	}
}

// isFileWriteError returns true when the error originates from a file write
// operation (i.e., a genuine failure unrelated to systemd unavailability).
// Used to distinguish fixture-test-relevant failures from expected CI skips.
func isFileWriteError(err error) bool {
	if err == nil {
		return false
	}
	// If the error message mentions timedatectl, it's a runtime-apply failure,
	// not a file write failure.
	return !strings.Contains(err.Error(), "timedatectl")
}
