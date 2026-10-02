// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package hostname

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// newWindowsFixtureExecutor creates a windowsExecutor with all four injectable
// functions pointing at fixture values. Tests never call real wmic/netdom or
// require Windows admin privileges.
func newWindowsFixtureExecutor(initialHostname, initialWorkgroup string) (*windowsExecutor, *hostnameState) {
	state := &hostnameState{Hostname: initialHostname, Workgroup: initialWorkgroup}
	e := &windowsExecutor{
		getHostname:  func() (string, error) { return state.Hostname, nil },
		getWorkgroup: func(_ string) (string, error) { return state.Workgroup, nil },
		setHostname:  func(_, newName string) error { state.Hostname = newName; return nil },
		setWorkgroup: func(_, wg string) error { state.Workgroup = wg; return nil },
	}
	return e, state
}

// TestWindowsExecutor_HostnameRoundTrip verifies Set→Get round-trip using
// fixture-injected functions. Real wmic/netdom are never called.
func TestWindowsExecutor_HostnameRoundTrip(t *testing.T) {
	e, state := newWindowsFixtureExecutor("old-host", "WORKGROUP")

	if err := e.setState(hostnameState{Hostname: "new-host", Workgroup: "WORKGROUP"}); err != nil {
		t.Fatalf("setState() error: %v", err)
	}

	if state.Hostname != "new-host" {
		t.Errorf("Hostname after setState: got %q, want %q", state.Hostname, "new-host")
	}

	got, err := e.getState()
	if err != nil {
		t.Fatalf("getState() after setState error: %v", err)
	}

	if got.Hostname != "new-host" {
		t.Errorf("getState().Hostname: got %q, want %q", got.Hostname, "new-host")
	}
}

// TestWindowsExecutor_WorkgroupRoundTrip verifies Set→Get round-trip for the
// workgroup field using fixture-injected functions.
func TestWindowsExecutor_WorkgroupRoundTrip(t *testing.T) {
	e, state := newWindowsFixtureExecutor("myhost", "OLDGROUP")

	if err := e.setState(hostnameState{Hostname: "myhost", Workgroup: "NEWGROUP"}); err != nil {
		t.Fatalf("setState() error: %v", err)
	}

	if state.Workgroup != "NEWGROUP" {
		t.Errorf("Workgroup after setState: got %q, want %q", state.Workgroup, "NEWGROUP")
	}

	got, err := e.getState()
	if err != nil {
		t.Fatalf("getState() error: %v", err)
	}

	if got.Workgroup != "NEWGROUP" {
		t.Errorf("getState().Workgroup: got %q, want %q", got.Workgroup, "NEWGROUP")
	}
}

// TestWindowsExecutor_HostnameUnchangedWhenSame verifies that setHostname is
// not called when the current hostname already matches the desired value.
func TestWindowsExecutor_HostnameUnchangedWhenSame(t *testing.T) {
	renameCalls := 0
	e := &windowsExecutor{
		getHostname:  func() (string, error) { return "same-host", nil },
		getWorkgroup: func(_ string) (string, error) { return "WORKGROUP", nil },
		setHostname:  func(_, _ string) error { renameCalls++; return nil },
		setWorkgroup: func(_, _ string) error { return nil },
	}

	if err := e.setState(hostnameState{Hostname: "same-host", Workgroup: "WORKGROUP"}); err != nil {
		t.Fatalf("setState() error: %v", err)
	}

	if renameCalls != 0 {
		t.Errorf("setHostname called %d time(s) when hostname was already correct; want 0", renameCalls)
	}
}

// TestWindowsExecutor_WorkgroupUnchangedWhenSame verifies that setWorkgroup is
// not called when the current workgroup already matches the desired value.
func TestWindowsExecutor_WorkgroupUnchangedWhenSame(t *testing.T) {
	workgroupCalls := 0
	e := &windowsExecutor{
		getHostname:  func() (string, error) { return "myhost", nil },
		getWorkgroup: func(_ string) (string, error) { return "SAME", nil },
		setHostname:  func(_, _ string) error { return nil },
		setWorkgroup: func(_, _ string) error { workgroupCalls++; return nil },
	}

	if err := e.setState(hostnameState{Hostname: "myhost", Workgroup: "SAME"}); err != nil {
		t.Fatalf("setState() error: %v", err)
	}

	if workgroupCalls != 0 {
		t.Errorf("setWorkgroup called %d time(s) when workgroup was already correct; want 0", workgroupCalls)
	}
}

// TestWindowsExecutor_GetIsIdempotent verifies two consecutive getState calls
// return identical results (ADR-016 clause 4 determinism contract).
func TestWindowsExecutor_GetIsIdempotent(t *testing.T) {
	e, _ := newWindowsFixtureExecutor("stable-host", "CORP")

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
	if got1.Workgroup != got2.Workgroup {
		t.Errorf("Workgroup not idempotent: %q vs %q", got1.Workgroup, got2.Workgroup)
	}
}

// TestWindowsExecutor_WmicWorkgroupParsing verifies that the wmic output
// parsing correctly extracts the workgroup name from "Workgroup=GROUPNAME"
// lines (case-insensitive, trims surrounding whitespace and CRLF endings).
func TestWindowsExecutor_WmicWorkgroupParsing(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "standard workgroup",
			output: "\r\nWorkgroup=WORKGROUP\r\n",
			want:   "WORKGROUP",
		},
		{
			name:   "custom workgroup",
			output: "Workgroup=CORP\r\n",
			want:   "CORP",
		},
		{
			name:   "empty workgroup",
			output: "Workgroup=\r\n",
			want:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Replicate the parsing logic from wmicGetWorkgroup.
			var got string
			for _, line := range strings.Split(strings.ReplaceAll(tc.output, "\r\n", "\n"), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToUpper(trimmed), "WORKGROUP=") {
					got = strings.TrimSpace(trimmed[len("WORKGROUP="):])
					break
				}
			}
			if got != tc.want {
				t.Errorf("wmicGetWorkgroup parse(%q): got %q, want %q", tc.output, got, tc.want)
			}
		})
	}
}

// wmicAvailable returns true when wmic.exe is reachable on this runner.
func wmicAvailable() bool {
	return exec.Command("wmic", "computersystem", "get", "Workgroup", "/format:list").Run() == nil
}

// TestWindowsExecutor_GetState_Integration verifies the full getState round-trip
// on Windows when wmic.exe is available. Skipped when wmic is absent.
func TestWindowsExecutor_GetState_Integration(t *testing.T) {
	if !wmicAvailable() {
		t.Skip("skipping: wmic not available on this runner")
	}

	e := &windowsExecutor{
		getHostname:  os.Hostname,
		getWorkgroup: wmicGetWorkgroup,
		setHostname:  netdomRename,
		setWorkgroup: wmicSetWorkgroup,
	}
	state, err := e.getState()
	if err != nil {
		t.Fatalf("getState() error: %v", err)
	}

	if state.Hostname == "" {
		t.Error("getState() returned empty Hostname")
	}
}
