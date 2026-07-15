// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package hostname

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// newFixtureExecutor creates a linuxExecutor with:
//   - hostnameFile pointing at a temp file (never /etc/hostname)
//   - setHostname wired to a no-op that captures the value written
//
// Tests can manipulate the temp file and captured value directly, without
// requiring root or touching the CI runner's actual kernel hostname.
func newFixtureExecutor(t *testing.T) (*linuxExecutor, *string) {
	t.Helper()
	dir := t.TempDir()
	var captured string
	e := &linuxExecutor{
		hostnameFile: filepath.Join(dir, "hostname"),
		setHostname:  func(name string) error { captured = name; return nil },
	}
	return e, &captured
}

// TestLinuxExecutor_GetDefaultsWhenFileAbsent verifies getState returns a
// non-empty hostname (from os.Hostname fallback) when /etc/hostname is missing.
func TestLinuxExecutor_GetDefaultsWhenFileAbsent(t *testing.T) {
	e, _ := newFixtureExecutor(t)
	// hostnameFile does not exist yet; getState must fall back to os.Hostname.
	state, err := e.getState()
	if err != nil {
		t.Fatalf("getState() with missing file returned error: %v", err)
	}
	if state.Hostname == "" {
		t.Error("getState() with missing file must return a non-empty hostname")
	}
}

// TestLinuxExecutor_HostnameRoundTrip verifies Set→Get round-trip via fixture
// paths. The injected no-op setHostname never calls syscall.Sethostname, so
// the CI runner's kernel hostname is never modified.
func TestLinuxExecutor_HostnameRoundTrip(t *testing.T) {
	e, captured := newFixtureExecutor(t)

	desired := hostnameState{Hostname: "fixture-host"}

	if err := e.setState(desired); err != nil {
		t.Fatalf("setState() error: %v", err)
	}

	// The injected setHostname should have been called with the desired name.
	if *captured != "fixture-host" {
		t.Errorf("setHostname was called with %q, want %q", *captured, "fixture-host")
	}

	got, err := e.getState()
	if err != nil {
		t.Fatalf("getState() after setState error: %v", err)
	}

	if got.Hostname != desired.Hostname {
		t.Errorf("Hostname: got %q, want %q", got.Hostname, desired.Hostname)
	}
}

// TestLinuxExecutor_WorkgroupAbsent verifies that getState never returns a
// non-empty Workgroup on Linux (Workgroup is Windows-only).
func TestLinuxExecutor_WorkgroupAbsent(t *testing.T) {
	e, _ := newFixtureExecutor(t)

	if err := e.setState(hostnameState{Hostname: "linux-host"}); err != nil {
		t.Fatalf("setState() error: %v", err)
	}

	state, err := e.getState()
	if err != nil {
		t.Fatalf("getState() error: %v", err)
	}

	if state.Workgroup != "" {
		t.Errorf("getState() on Linux must not return a workgroup; got %q", state.Workgroup)
	}
}

// TestLinuxExecutor_HostnameFileContent verifies that setState writes the
// hostname to hostnameFile with a trailing newline (POSIX line-ending convention).
func TestLinuxExecutor_HostnameFileContent(t *testing.T) {
	e, _ := newFixtureExecutor(t)

	if err := e.setState(hostnameState{Hostname: "test-node"}); err != nil {
		t.Fatalf("setState() error: %v", err)
	}

	data, err := os.ReadFile(e.hostnameFile)
	if err != nil {
		t.Fatalf("ReadFile(%q) error: %v", e.hostnameFile, err)
	}

	want := "test-node\n"
	if string(data) != want {
		t.Errorf("hostnameFile content = %q, want %q", string(data), want)
	}
}

// TestLinuxExecutor_GetIsIdempotent verifies two consecutive getState calls
// return identical results (ADR-016 clause 4 determinism contract).
func TestLinuxExecutor_GetIsIdempotent(t *testing.T) {
	e, _ := newFixtureExecutor(t)

	if err := e.setState(hostnameState{Hostname: "idempotent-host"}); err != nil {
		t.Fatalf("setState() error: %v", err)
	}

	got1, err := e.getState()
	if err != nil {
		t.Fatalf("first getState() error: %v", err)
	}
	got2, err := e.getState()
	if err != nil {
		t.Fatalf("second getState() error: %v", err)
	}

	if got1.Hostname != got2.Hostname {
		t.Errorf("Hostname not idempotent: %q vs %q", got1.Hostname, got2.Hostname)
	}
}

// TestLinuxExecutor_SetIsIdempotentNoOp verifies that the hostnameModule's
// Set method skips the write when the host is already in the desired state —
// the injected setHostname is not called a second time (ADR-016 clause 1,
// declare-once identity semantics).
func TestLinuxExecutor_SetIsIdempotentNoOp(t *testing.T) {
	dir := t.TempDir()
	callCount := 0
	e := &linuxExecutor{
		hostnameFile: filepath.Join(dir, "hostname"),
		setHostname:  func(_ string) error { callCount++; return nil },
	}

	m := &hostnameModule{executor: e}
	ctx := context.Background()

	cfg := &HostnameConfig{Hostname: "stable-host"}

	// First Set: the file doesn't exist yet so getState falls back to os.Hostname
	// (which is NOT "stable-host"), causing setState to execute.
	if err := m.Set(ctx, "system", cfg); err != nil {
		t.Fatalf("first Set() error: %v", err)
	}
	afterFirst := callCount

	// Second Set: the file now contains "stable-host" so getState returns the
	// same value as desired; the module must return early without calling setState.
	if err := m.Set(ctx, "system", cfg); err != nil {
		t.Fatalf("second Set() error: %v", err)
	}

	if callCount != afterFirst {
		t.Errorf("setHostname called %d additional time(s) on idempotent Set; want 0", callCount-afterFirst)
	}
}
