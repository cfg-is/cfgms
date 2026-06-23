//go:build linux || windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package integration

import (
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/logging"
)

// This is the automated verification gate for the DNA-collection-audit epic
// (#1932): it spawns a real steward DNA Collector, waits for the first full
// snapshot (background collection completed), and asserts every Must-Collect
// attribute from docs/architecture/dna-collection.md is present and non-empty on
// the corresponding platform.
//
// Tiers, per the must-collect spec:
//   - must-collect (no privilege): asserted unconditionally.
//   - must-collect-privileged: validated when present; when absent and the
//     runner is not elevated, a WARN is logged and the assertion is skipped
//     (an unprivileged runner cannot read e.g. encryption state).
//   - #2147 carve-out: on a Windows host where wmic has been removed, the memory
//     collector's CIM fallback does not yet populate memory_total_gb; that gap is
//     tracked by #2147, so its absence there is a WARN, not a failure. The carve-
//     out auto-tightens once memory_total_gb is collected.

// collectFullSnapshot spawns a real Collector, triggers and waits for background
// collection, then returns the merged full-snapshot attributes. Real components
// only (no mocks), per CLAUDE.md testing standards.
func collectFullSnapshot(t *testing.T) map[string]string {
	t.Helper()
	c := dna.NewCollector(logging.NewLogger("error"))
	ctx := t.Context()
	if _, err := c.Collect(ctx); err != nil {
		t.Fatalf("first Collect (kicks off background collection): %v", err)
	}
	c.WaitForBackground(ctx)
	snap, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("second Collect (merged full snapshot): %v", err)
	}
	if snap == nil || snap.Attributes == nil {
		t.Fatal("nil snapshot or attributes")
	}
	return snap.Attributes
}

// dumpKeysOnFailure logs the collected attribute KEYS only — never values, which
// may contain hostnames, IP addresses, or usernames — so CI can inspect coverage
// when an assertion fails.
func dumpKeysOnFailure(t *testing.T, attrs map[string]string) {
	t.Helper()
	if !t.Failed() {
		return
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("collected %d attribute keys (values omitted — may be tenant-sensitive): %s",
		len(keys), strings.Join(keys, ", "))
}

func requireNonEmpty(t *testing.T, attrs map[string]string, key string) {
	t.Helper()
	if v, ok := attrs[key]; !ok || strings.TrimSpace(v) == "" {
		t.Errorf("must-collect attribute %q is missing or empty", key)
	}
}

// requireOneOf asserts that at least one of keys is present and non-empty.
func requireOneOf(t *testing.T, attrs map[string]string, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if v, ok := attrs[k]; ok && strings.TrimSpace(v) != "" {
			return
		}
	}
	t.Errorf("at least one of must-collect attributes %v must be present and non-empty", keys)
}

// checkPrivileged validates a must-collect-privileged attribute: present and
// non-empty is always good; absent fails only on an elevated runner, otherwise it
// is a WARN+skip (an unprivileged runner legitimately cannot read it).
func checkPrivileged(t *testing.T, attrs map[string]string, key string, elevated bool) {
	t.Helper()
	v, ok := attrs[key]
	switch {
	case ok && strings.TrimSpace(v) != "":
		return
	case elevated:
		t.Errorf("privileged must-collect attribute %q missing or empty despite elevated privileges", key)
	default:
		t.Logf("WARN: privileged attribute %q not collected (requires elevation); skipping assertion", key)
	}
}

// assertMemoryTotalGB asserts memory_total_gb with the #2147 carve-out: absence
// is tolerated (WARN) only on a Windows host where wmic has been removed and the
// CIM-fallback parser gap (#2147) is responsible; present values are always
// validated, and absence for any other reason is a hard failure.
func assertMemoryTotalGB(t *testing.T, attrs map[string]string) {
	t.Helper()
	if v, ok := attrs["memory_total_gb"]; ok && strings.TrimSpace(v) != "" {
		return
	}
	if runtime.GOOS == "windows" && !wmicAvailable() {
		t.Logf("WARN: memory_total_gb absent on a wmic-less Windows host; the memory CIM-fallback parser gap is tracked by #2147 — skipping (enforced once #2147 lands)")
		return
	}
	t.Errorf("must-collect attribute %q is missing or empty", "memory_total_gb")
}

// runnerIsElevated reports whether the test runner has elevated privileges.
// os.Geteuid() returns 0 for root on Linux; on Windows it returns -1, so Windows
// runs are treated as unprivileged here (privileged attrs are validated when
// present and WARN-skipped when absent). Detecting Windows token elevation needs
// platform-specific code outside this integration test's scope.
func runnerIsElevated() bool {
	return os.Geteuid() == 0
}

func wmicAvailable() bool {
	_, err := exec.LookPath("wmic")
	return err == nil
}

// assertAllPlatformMustCollect asserts the cross-platform must-collect set
// (docs/architecture/dna-collection.md "All platforms").
func assertAllPlatformMustCollect(t *testing.T, attrs map[string]string) {
	t.Helper()
	for _, k := range []string{
		"timestamp", "runtime_os", "runtime_arch", "hostname", "num_cpu",
		"primary_mac", "ip_addresses", "network_interface_count",
		"default_gateway", "os",
	} {
		requireNonEmpty(t, attrs, k)
	}
}

func TestDNASnapshotLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		// The file builds on linux||windows; this test asserts the Linux
		// must-collect set, so it is a no-op on a Windows runner.
		t.Skipf("Linux-only DNA must-collect gate; running on %s", runtime.GOOS)
	}
	attrs := collectFullSnapshot(t)
	defer dumpKeysOnFailure(t, attrs)
	elevated := runnerIsElevated()

	assertAllPlatformMustCollect(t, attrs)
	requireOneOf(t, attrs, "os_name", "os_pretty_name")
	requireNonEmpty(t, attrs, "kernel_version")
	assertMemoryTotalGB(t, attrs)
	requireNonEmpty(t, attrs, "local_user_count")
	requireNonEmpty(t, attrs, "domain_joined")
	requireNonEmpty(t, attrs, "av_products_detected")
	requireOneOf(t, attrs, "ufw_firewall_state", "iptables_rule_count", "firewall_state")
	checkPrivileged(t, attrs, "luks_encrypted_devices", elevated)
}

func TestDNASnapshotWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		// The file builds on linux||windows; this test asserts the Windows
		// must-collect set, so it is a no-op on a Linux runner.
		t.Skipf("Windows-only DNA must-collect gate; running on %s", runtime.GOOS)
	}
	attrs := collectFullSnapshot(t)
	defer dumpKeysOnFailure(t, attrs)
	elevated := runnerIsElevated()

	assertAllPlatformMustCollect(t, attrs)
	requireOneOf(t, attrs, "windows_caption", "windows_version")
	requireNonEmpty(t, attrs, "windows_build_number")
	assertMemoryTotalGB(t, attrs)
	requireNonEmpty(t, attrs, "local_user_count")
	requireNonEmpty(t, attrs, "domain_joined")
	requireNonEmpty(t, attrs, "av_products_detected")
	requireNonEmpty(t, attrs, "windows_firewall_domain_profile")
	checkPrivileged(t, attrs, "bitlocker_enabled", elevated)
}
