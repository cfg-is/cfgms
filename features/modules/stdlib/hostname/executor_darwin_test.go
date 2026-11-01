// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package hostname

import (
	"os/exec"
	"testing"
)

// scutilAvailable returns true when the scutil command is reachable on this runner.
func scutilAvailable() bool {
	return exec.Command("scutil", "--get", "HostName").Run() == nil
}

// newDarwinFixtureExecutor creates a darwinExecutor with injectable functions
// pointed at fixture values. Tests never call real scutil commands or require
// macOS admin privileges.
func newDarwinFixtureExecutor(initialHostname string) (*darwinExecutor, *string) {
	current := initialHostname
	e := &darwinExecutor{
		getHostNameFn:  func() (string, error) { return current, nil },
		setHostNamesFn: func(name string) error { current = name; return nil },
	}
	return e, &current
}

// TestDarwinExecutor_HostnameRoundTrip verifies Set→Get round-trip using
// fixture-injected functions. Real scutil is never called.
func TestDarwinExecutor_HostnameRoundTrip(t *testing.T) {
	e, current := newDarwinFixtureExecutor("initial-host")

	if err := e.setState(hostnameState{Hostname: "new-host"}); err != nil {
		t.Fatalf("setState() error: %v", err)
	}

	if *current != "new-host" {
		t.Errorf("setHostNamesFn captured %q, want %q", *current, "new-host")
	}

	state, err := e.getState()
	if err != nil {
		t.Fatalf("getState() after setState error: %v", err)
	}

	if state.Hostname != "new-host" {
		t.Errorf("Hostname: got %q, want %q", state.Hostname, "new-host")
	}
}

// TestDarwinExecutor_WorkgroupAbsent verifies that getState never returns a
// non-empty Workgroup on macOS (Workgroup is Windows-only).
func TestDarwinExecutor_WorkgroupAbsent(t *testing.T) {
	e, _ := newDarwinFixtureExecutor("mac-host")

	state, err := e.getState()
	if err != nil {
		t.Fatalf("getState() error: %v", err)
	}

	if state.Workgroup != "" {
		t.Errorf("getState() on macOS must not return a workgroup; got %q", state.Workgroup)
	}
}

// TestDarwinExecutor_GetIsIdempotent verifies two consecutive getState calls
// return identical results (ADR-016 clause 4 determinism contract).
func TestDarwinExecutor_GetIsIdempotent(t *testing.T) {
	e, _ := newDarwinFixtureExecutor("idempotent-host")

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

// TestDarwinExecutor_GetState_Integration verifies the full getState round-trip
// on macOS when scutil is available. Skipped when scutil is not accessible or
// requires elevated privileges not present on the runner.
func TestDarwinExecutor_GetState_Integration(t *testing.T) {
	if !scutilAvailable() {
		t.Skip("skipping: scutil not available or requires elevated privileges")
	}

	e := &darwinExecutor{
		getHostNameFn:  scutilGetHostName,
		setHostNamesFn: scutilSetHostNames,
	}
	state, err := e.getState()
	if err != nil {
		t.Fatalf("getState() error: %v", err)
	}

	if state.Hostname == "" {
		t.Error("getState() returned empty Hostname")
	}
}
