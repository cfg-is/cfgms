// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
)

// DefaultBannedEphemeralFields is the conservative list of field names that
// must not appear in ConfigState.AsMap() output per ADR-016 clause 4, which
// prohibits ephemeral runtime values: live PIDs, current CPU/memory statistics,
// timestamps, and uptime counters.
var DefaultBannedEphemeralFields = []string{
	"pid",
	"timestamp",
	"uptime_seconds",
	"cpu_percent",
	"memory_bytes",
}

// AssertDeterministicGet calls m.Get(ctx, resourceID) twice against unchanged
// state and asserts that the canonical JSON-encoded AsMap() output is
// byte-for-byte identical across both calls.
//
// Use this in a module's own test file to verify ADR-016 clause 4 compliance.
// Determinism is proved empirically — two actual Get calls are compared — rather
// than by asserting an encoding invariant. encoding/json is used for canonical
// serialisation (it sorts map keys); the test does NOT rely on yaml.v3 ordering.
//
// If the module's Get is non-deterministic the test fails with the differing
// encoded outputs so the caller can identify which field varies.
func AssertDeterministicGet(t *testing.T, m modules.Module, resourceID string) {
	t.Helper()

	ctx := context.Background()

	state1, err := m.Get(ctx, resourceID)
	if err != nil {
		t.Fatalf("AssertDeterministicGet: first Get(%q) returned error: %v", resourceID, err)
	}
	if state1 == nil {
		t.Fatalf("AssertDeterministicGet: first Get(%q) returned nil state", resourceID)
	}

	state2, err := m.Get(ctx, resourceID)
	if err != nil {
		t.Fatalf("AssertDeterministicGet: second Get(%q) returned error: %v", resourceID, err)
	}
	if state2 == nil {
		t.Fatalf("AssertDeterministicGet: second Get(%q) returned nil state", resourceID)
	}

	enc1, err := json.Marshal(state1.AsMap())
	if err != nil {
		t.Fatalf("AssertDeterministicGet: json.Marshal(state1.AsMap()) error: %v", err)
	}

	enc2, err := json.Marshal(state2.AsMap())
	if err != nil {
		t.Fatalf("AssertDeterministicGet: json.Marshal(state2.AsMap()) error: %v", err)
	}

	if !bytes.Equal(enc1, enc2) {
		t.Errorf("AssertDeterministicGet: Get(%q) is not deterministic\nfirst:  %s\nsecond: %s",
			resourceID, enc1, enc2)
	}
}

// AssertNoEphemeralFields checks that state.AsMap() contains none of the
// banned field names.
//
// Use this in a module's own test file to verify that ADR-016 clause 4's
// prohibition on ephemeral fields is respected. Pass DefaultBannedEphemeralFields
// or a module-specific extension of it as banned. Banned field examples from
// ADR-016 clause 4: live PIDs, current CPU/memory, timestamps, uptime counters.
func AssertNoEphemeralFields(t *testing.T, state modules.ConfigState, banned []string) {
	t.Helper()

	m := state.AsMap()
	for _, field := range banned {
		if _, ok := m[field]; ok {
			t.Errorf("AssertNoEphemeralFields: AsMap() contains banned ephemeral field %q (ADR-016 clause 4)", field)
		}
	}
}

// DefaultBannedMutatingVerbPrefixes is the set of PowerShell verb prefixes that
// indicate a mutating cmdlet invocation, used by AssertObserveReadOnly's
// command-verb layer check (ADR-024 §4). Covers the four standard PowerShell
// CRUD verb groups that modify system state.
var DefaultBannedMutatingVerbPrefixes = []string{
	"New-", "Set-", "Remove-", "Add-",
}

// checkObserveReadOnly implements the two-layer read-only check and returns a
// list of violation messages (empty = pass). Kept unexported so callers use
// AssertObserveReadOnly; the unexported form enables unit testing of the check
// logic via package-internal tests without requiring a *testing.T mock.
func checkObserveReadOnly(envelope *modules.BehavioralEnvelope, commands []string) []string {
	var violations []string

	// Layer 1: writes_paths must be empty at the envelope level.
	if envelope != nil && len(envelope.WritesPaths) > 0 {
		violations = append(violations, fmt.Sprintf(
			"BehavioralEnvelope.writes_paths is non-empty %v; observe path must declare no writes (ADR-024 §4)",
			envelope.WritesPaths,
		))
	}

	// Layer 2: scan caller-supplied command strings for banned mutating-verb prefixes.
	for _, cmd := range commands {
		for _, prefix := range DefaultBannedMutatingVerbPrefixes {
			if strings.Contains(cmd, prefix) {
				violations = append(violations, fmt.Sprintf(
					"command contains banned mutating verb prefix %q (ADR-024 §4):\n%s",
					prefix, cmd,
				))
			}
		}
	}

	return violations
}

// AssertObserveReadOnly asserts that an observe path is provably read-only per
// ADR-024 §4. Call it in a module's own _test.go alongside AssertDeterministicGet
// and AssertNoEphemeralFields to cover the full observe-mode conformance surface.
//
// Two independent checks form a two-layer defence:
//
// Layer 1 (envelope-level): envelope.WritesPaths must be empty. A non-empty
// WritesPaths list proves the module's behavioural envelope declares a write,
// violating the "no mutations" requirement for observe-eligible paths.
//
// Layer 2 (command-verb-level): each string in commands is scanned for banned
// PowerShell mutating-verb prefixes (New-*, Set-*, Remove-*, Add-*) drawn from
// DefaultBannedMutatingVerbPrefixes. This catches modules that correctly declare
// an empty writes_paths in their manifest but whose observe path still invokes a
// mutating cmdlet internally. Callers supply the PowerShell script blocks or
// command strings executed during the observe path.
//
// The two-layer design is intentional: the envelope check is necessary but not
// sufficient — a module could declare no writes_paths in its manifest while its
// Get still calls a mutating command. The command-verb check closes that gap;
// document this two-layer requirement in any module's test so a future reader
// does not assume the envelope check alone is sufficient (ADR-024 §4).
//
// This helper generalises the inline assertNoWriteCmdlets pattern from
// features/modules/hyperv/observe_test.go; pass the same kind of PowerShell
// script-block strings the caller records for each executed command.
func AssertObserveReadOnly(t *testing.T, envelope *modules.BehavioralEnvelope, commands []string) {
	t.Helper()
	for _, msg := range checkObserveReadOnly(envelope, commands) {
		t.Errorf("AssertObserveReadOnly: %s", msg)
	}
}
