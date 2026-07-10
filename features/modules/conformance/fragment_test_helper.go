// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package conformance

import (
	"bytes"
	"context"
	"encoding/json"
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
