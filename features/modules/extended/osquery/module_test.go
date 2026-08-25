// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package osquery

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
)

// Compile-time assertion: osqueryModule satisfies modules.Module.
var _ modules.Module = (*osqueryModule)(nil)

// TestGet_ReturnsErrNotImplemented pins the S1 scaffold contract for Get():
// fact-mapping logic lands in S4 of epic #2855, and until then Get() must return
// modules.ErrNotImplemented with a nil state rather than a partial result.
func TestGet_ReturnsErrNotImplemented(t *testing.T) {
	m := New()
	state, err := m.Get(context.Background(), "host:cpu")
	if !errors.Is(err, modules.ErrNotImplemented) {
		t.Errorf("Get() error = %v, want modules.ErrNotImplemented until S4 of epic #2855 implements fact mapping", err)
	}
	if state != nil {
		t.Errorf("Get() state = %v, want nil — an unimplemented Get must not return partial facts", state)
	}
}

func TestGet_ReturnsErrNotImplemented_AllResourceIDs(t *testing.T) {
	m := New()
	ctx := context.Background()
	resourceIDs := []string{"host:cpu", "host:memory", "host:os", "host:bios", "", "arbitrary"}
	for _, rid := range resourceIDs {
		state, err := m.Get(ctx, rid)
		if !errors.Is(err, modules.ErrNotImplemented) {
			t.Errorf("Get(%q) error = %v, want modules.ErrNotImplemented unconditionally", rid, err)
		}
		if state != nil {
			t.Errorf("Get(%q) state = %v, want nil", rid, state)
		}
	}
}

func TestSet_ReturnsErrNotImplemented(t *testing.T) {
	m := New()
	err := m.Set(context.Background(), "host:cpu", nil)
	if !errors.Is(err, modules.ErrNotImplemented) {
		t.Errorf("Set() = %v, want modules.ErrNotImplemented — osquery is read-only and Set must never converge state", err)
	}
}

func TestSet_ReturnsErrNotImplemented_AllResourceIDs(t *testing.T) {
	m := New()
	ctx := context.Background()
	resourceIDs := []string{"host:cpu", "host:memory", "host:os", "host:bios", "", "arbitrary"}
	for _, rid := range resourceIDs {
		err := m.Set(ctx, rid, nil)
		if !errors.Is(err, modules.ErrNotImplemented) {
			t.Errorf("Set(%q) = %v, want modules.ErrNotImplemented unconditionally", rid, err)
		}
	}
}

// TestModuleYAML_ParsesViaParseModuleMetadata verifies that module.yaml is
// valid per modules.ParseModuleMetadata and declares steward executor.
func TestModuleYAML_ParsesViaParseModuleMetadata(t *testing.T) {
	f, err := os.Open("module.yaml")
	if err != nil {
		t.Fatalf("open module.yaml: %v", err)
	}
	defer func() { _ = f.Close() }()

	meta, err := modules.ParseModuleMetadata(f)
	if err != nil {
		t.Fatalf("ParseModuleMetadata(module.yaml): %v", err)
	}

	if meta.Name != "osquery" {
		t.Errorf("name = %q, want %q", meta.Name, "osquery")
	}
	if len(meta.Executors) != 1 || meta.Executors[0] != "steward" {
		t.Errorf("executors = %v, want [steward]", meta.Executors)
	}
	if meta.Kind != "steward" {
		t.Errorf("kind = %q, want %q", meta.Kind, "steward")
	}
	if meta.Publisher != "cfgms" {
		t.Errorf("publisher = %q, want %q", meta.Publisher, "cfgms")
	}
}

// TestModuleYAML_NoBehavioralEnvelopeWritesPaths verifies that the manifest
// declares no writes_paths — osquery is read-only and never writes files during
// fact collection.
func TestModuleYAML_NoBehavioralEnvelopeWritesPaths(t *testing.T) {
	f, err := os.Open("module.yaml")
	if err != nil {
		t.Fatalf("open module.yaml: %v", err)
	}
	defer func() { _ = f.Close() }()

	meta, err := modules.ParseModuleMetadata(f)
	if err != nil {
		t.Fatalf("ParseModuleMetadata: %v", err)
	}

	if meta.BehavioralEnvelope == nil {
		t.Fatal("module.yaml has no behavioral_envelope — required for security auditing")
	}
	if len(meta.BehavioralEnvelope.WritesPaths) != 0 {
		t.Errorf("behavioral_envelope.writes_paths = %v, want empty — osquery must not write files",
			meta.BehavioralEnvelope.WritesPaths)
	}
}

// TestBehavioralEnvelope_ReadScopeMatchesCuratedFacts is the required test from
// issue #3561 AC: the behavioral envelope's declared read scope must match only
// the four curated host:* kinds' actual requirements, not osquery's full table surface.
//
// The curated kinds and their fact sources:
//   - host:cpu  → /proc/cpuinfo, /sys/devices/system/cpu (world-readable on Linux)
//   - host:memory → /proc/meminfo (world-readable on Linux)
//   - host:os  → /etc/os-release, /proc/version (world-readable on Linux)
//   - host:bios → /sys/class/dmi/id (world-readable on Linux)
//
// The following paths are explicitly forbidden — they correspond to osquery tables
// outside the four curated fact domains:
//   - /etc/passwd, /etc/shadow  → users/groups table (out of scope)
//   - /var/log                  → logged_in_users / processes / shell history (out of scope)
//   - /proc/net                 → network interface tables (out of scope)
//   - /etc/hosts                → hosts table (out of scope)
func TestBehavioralEnvelope_ReadScopeMatchesCuratedFacts(t *testing.T) {
	f, err := os.Open("module.yaml")
	if err != nil {
		t.Fatalf("open module.yaml: %v", err)
	}
	defer func() { _ = f.Close() }()

	meta, err := modules.ParseModuleMetadata(f)
	if err != nil {
		t.Fatalf("ParseModuleMetadata: %v", err)
	}

	if meta.BehavioralEnvelope == nil {
		t.Fatal("module.yaml has no behavioral_envelope")
	}

	reads := meta.BehavioralEnvelope.ReadsPaths

	// Paths associated with osquery tables outside the four curated fact domains.
	// If any of these appear, the behavioral envelope is wider than the curated scope.
	forbiddenPaths := []string{
		"/etc/passwd",    // users table
		"/etc/shadow",    // shadow passwords
		"/var/log",       // logged_in_users, shell_history, etc.
		"/proc/net",      // interface_details, arp_cache, etc.
		"/etc/hosts",     // hosts table
		"/etc/crontab",   // crontab table
		"/home",          // user home directories
		"/tmp",           // process open files
		"/usr/local/etc", // brew package receipts
	}

	for _, forbidden := range forbiddenPaths {
		for _, declared := range reads {
			if declared == forbidden {
				t.Errorf("reads_paths contains %q — this path is associated with osquery tables "+
					"outside the four curated host:* fact domains (host:cpu/memory/os/bios). "+
					"The behavioral envelope must be scoped to the curated fact list only.", forbidden)
			}
		}
	}

	// Verify that reads_paths is not trivially empty — the module must declare
	// the paths it actually reads so the security envelope is auditable.
	if len(reads) == 0 {
		t.Error("reads_paths is empty — the behavioral envelope must declare the paths " +
			"that osquery reads for the four curated host:* fact domains")
	}
}

func TestPinnedVersion_IsNonEmpty(t *testing.T) {
	if pinnedVersion == "" {
		t.Error("pinnedVersion is empty — a named constant is required for version auditability (S9 wires it into refresh-pins)")
	}
}
