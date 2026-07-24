// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"bytes"
	"testing"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testConfigState is a minimal ConfigState fixture for canonical encoding tests.
// It is not a mock — it is a deterministic test double that directly implements
// the ConfigState interface contract (ADR-016 clause 4).
type testConfigState struct {
	data map[string]interface{}
}

func (s *testConfigState) AsMap() map[string]interface{} { return s.data }
func (s *testConfigState) ToYAML() ([]byte, error)       { return []byte(""), nil }
func (s *testConfigState) FromYAML([]byte) error         { return nil }
func (s *testConfigState) Validate() error               { return nil }
func (s *testConfigState) GetManagedFields() []string    { return nil }

var _ modules.ConfigState = (*testConfigState)(nil)

// stateFrom builds a testConfigState from a literal map.
func stateFrom(m map[string]interface{}) *testConfigState {
	return &testConfigState{data: m}
}

// TestCanonicalizeFragment_Deterministic asserts that calling CanonicalizeFragment
// twice with the same ConfigState fixture (same object) produces identical bytes.
func TestCanonicalizeFragment_Deterministic(t *testing.T) {
	state := stateFrom(map[string]interface{}{
		"name":    "sshd",
		"enabled": true,
		"port":    int64(22),
	})

	out1, err := CanonicalizeFragment("service:sshd", "service", state)
	require.NoError(t, err)
	out2, err := CanonicalizeFragment("service:sshd", "service", state)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(out1, out2), "two calls with the same input must produce identical bytes")
	assert.NotEmpty(t, out1, "output must not be empty")
}

// TestCanonicalizeFragment_IndependentFixtures asserts that two independently-built
// ConfigState objects with the same key/value pairs produce identical canonical bytes
// (cross-invocation determinism — the primary AC).
func TestCanonicalizeFragment_IndependentFixtures(t *testing.T) {
	// Build two independent objects — distinct map allocations, same content.
	stateA := stateFrom(map[string]interface{}{
		"name":    "sshd",
		"enabled": true,
		"port":    int64(22),
	})
	stateB := stateFrom(map[string]interface{}{
		"name":    "sshd",
		"enabled": true,
		"port":    int64(22),
	})

	outA, err := CanonicalizeFragment("service:sshd", "service", stateA)
	require.NoError(t, err)
	outB, err := CanonicalizeFragment("service:sshd", "service", stateB)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(outA, outB),
		"independently-built identical ConfigState fixtures must produce identical canonical_bytes")
}

// TestCanonicalizeFragment_MapKeyOrderIndependent asserts that reordering the
// keys in the input map (same key/value pairs, different Go map insertion order)
// does not change the output. [REQUIRED TEST per AC]
func TestCanonicalizeFragment_MapKeyOrderIndependent(t *testing.T) {
	// Go maps do not preserve insertion order, but we build each map explicitly
	// to document the intent: the pairs are identical, the order is "different"
	// in the sense that the map runtime may traverse them differently.
	state1 := stateFrom(map[string]interface{}{
		"alpha": "one",
		"beta":  "two",
		"gamma": "three",
	})
	state2 := stateFrom(map[string]interface{}{
		"gamma": "three",
		"alpha": "one",
		"beta":  "two",
	})

	out1, err := CanonicalizeFragment("service:sshd", "service", state1)
	require.NoError(t, err)
	out2, err := CanonicalizeFragment("service:sshd", "service", state2)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(out1, out2),
		"map-key reordering in input ConfigState.AsMap() must produce identical canonical_bytes")
}

// TestCanonicalizeFragment_DifferentStatesProduceDifferentBytes asserts that two
// structurally different states produce different canonical bytes. [REQUIRED TEST per AC]
func TestCanonicalizeFragment_DifferentStatesProduceDifferentBytes(t *testing.T) {
	stateA := stateFrom(map[string]interface{}{
		"name":    "sshd",
		"enabled": true,
	})
	stateB := stateFrom(map[string]interface{}{
		"name":    "sshd",
		"enabled": false,
	})
	stateC := stateFrom(map[string]interface{}{
		"name": "nginx",
	})

	outA, err := CanonicalizeFragment("service:sshd", "service", stateA)
	require.NoError(t, err)
	outB, err := CanonicalizeFragment("service:sshd", "service", stateB)
	require.NoError(t, err)
	outC, err := CanonicalizeFragment("service:nginx", "service", stateC)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(outA, outB), "different boolean value must produce different bytes")
	assert.False(t, bytes.Equal(outA, outC), "different state content must produce different bytes")
	assert.False(t, bytes.Equal(outB, outC), "different state content must produce different bytes")
}

// TestCanonicalizeFragment_CollisionClosure is the SECURITY test verifying that
// the specific collision class present in dna.go's ComputeHash (separator-only
// encoding: `fmt.Fprintf(h, "%s=%s\n", k, v)`) does NOT apply to
// CanonicalizeFragment. [REQUIRED TEST — SECURITY per AC]
//
// Collision pair: {"a": "b\nc=d"} and {"a":"b","c":"d"} both serialize to
// "a=b\nc=d\n" under the old separator-only scheme. The length-prefix encoding
// used here closes this class because the field-count header differs (1 vs 2).
func TestCanonicalizeFragment_CollisionClosure(t *testing.T) {
	// One key whose value contains a newline and an equals sign — exactly the
	// string that an unescaped separator scheme would fold into a second pair.
	stateOne := stateFrom(map[string]interface{}{
		"a": "b\nc=d",
	})
	// Two distinct keys — structurally different from stateOne.
	stateTwo := stateFrom(map[string]interface{}{
		"a": "b",
		"c": "d",
	})

	outOne, err := CanonicalizeFragment("fragment:x", "module", stateOne)
	require.NoError(t, err)
	outTwo, err := CanonicalizeFragment("fragment:x", "module", stateTwo)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(outOne, outTwo),
		"length-prefix encoding must distinguish {\"a\":\"b\\nc=d\"} from {\"a\":\"b\",\"c\":\"d\"}: "+
			"these are the exact inputs that ComputeHash's separator scheme collapses to the same bytes")
}

// TestCanonicalizeFragment_SliceCollisionClosure is the SECURITY test for the
// slice analogue of the ComputeHash collision class. The canonTagOther fallback
// used fmt.Sprintf("%v") on slices, which uses a space separator inside brackets:
// []interface{}{"libcurl nss"} and []interface{}{"libcurl","nss"} both render as
// "[libcurl nss]". The dedicated []interface{} path with length-prefix per element
// closes this class.
func TestCanonicalizeFragment_SliceCollisionClosure(t *testing.T) {
	// One element containing a space — the string that a %v scheme folds into two.
	stateOne := stateFrom(map[string]interface{}{
		"dependencies": []interface{}{"libcurl nss"},
	})
	// Two elements — structurally different from stateOne.
	stateTwo := stateFrom(map[string]interface{}{
		"dependencies": []interface{}{"libcurl", "nss"},
	})

	outOne, err := CanonicalizeFragment("pkg:curl", "package", stateOne)
	require.NoError(t, err)
	outTwo, err := CanonicalizeFragment("pkg:curl", "package", stateTwo)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(outOne, outTwo),
		"slice collision closure: [\"libcurl nss\"] (one element with space) must produce "+
			"different bytes than [\"libcurl\",\"nss\"] (two elements)")
}

// TestCanonicalizeFragment_SliceDeterministic asserts that []interface{} slices
// produce identical bytes on repeated calls.
func TestCanonicalizeFragment_SliceDeterministic(t *testing.T) {
	state := stateFrom(map[string]interface{}{
		"providers": []interface{}{"apt", "snap"},
	})

	out1, err := CanonicalizeFragment("pkg:curl", "package", state)
	require.NoError(t, err)
	out2, err := CanonicalizeFragment("pkg:curl", "package", state)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(out1, out2),
		"[]interface{} slice values must produce identical bytes on repeated calls")
}

// TestCanonicalizeFragment_TypeRoundTrips asserts that numeric, boolean, string,
// nested-map, and slice values all round-trip through the encoder with a fixed
// format: two calls with the same typed value always produce the same bytes, and
// different types / values produce different bytes. [REQUIRED TEST per AC]
func TestCanonicalizeFragment_TypeRoundTrips(t *testing.T) {
	cases := []struct {
		name  string
		state *testConfigState
	}{
		{"string", stateFrom(map[string]interface{}{"v": "hello"})},
		{"empty_string", stateFrom(map[string]interface{}{"v": ""})},
		{"bool_true", stateFrom(map[string]interface{}{"v": true})},
		{"bool_false", stateFrom(map[string]interface{}{"v": false})},
		{"int64", stateFrom(map[string]interface{}{"v": int64(42)})},
		{"int64_zero", stateFrom(map[string]interface{}{"v": int64(0)})},
		{"int64_negative", stateFrom(map[string]interface{}{"v": int64(-1)})},
		{"float64", stateFrom(map[string]interface{}{"v": float64(3.14)})},
		{"float64_zero", stateFrom(map[string]interface{}{"v": float64(0.0)})},
		{"nil", stateFrom(map[string]interface{}{"v": nil})},
		{"nested_map", stateFrom(map[string]interface{}{
			"v": map[string]interface{}{"inner": "val", "count": int64(1)},
		})},
		{"slice_strings", stateFrom(map[string]interface{}{
			"v": []interface{}{"wget", "curl"},
		})},
		{"slice_empty", stateFrom(map[string]interface{}{
			"v": []interface{}{},
		})},
		{"slice_mixed", stateFrom(map[string]interface{}{
			"v": []interface{}{"svc", true, int64(22)},
		})},
	}

	// Each case must be deterministic.
	for _, tc := range cases {
		t.Run(tc.name+"_deterministic", func(t *testing.T) {
			out1, err := CanonicalizeFragment("frag:test", "module", tc.state)
			require.NoError(t, err)
			out2, err := CanonicalizeFragment("frag:test", "module", tc.state)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(out1, out2),
				"type %s: two calls must produce identical bytes", tc.name)
		})
	}

	// Collect all outputs; no two distinct types should collide.
	outputs := make([][]byte, len(cases))
	for i, tc := range cases {
		out, err := CanonicalizeFragment("frag:test", "module", tc.state)
		require.NoError(t, err, "case %s", tc.name)
		outputs[i] = out
	}
	for i := range outputs {
		for j := i + 1; j < len(outputs); j++ {
			assert.False(t, bytes.Equal(outputs[i], outputs[j]),
				"cases %q and %q must produce different bytes (no accidental collision)",
				cases[i].name, cases[j].name)
		}
	}
}

// TestCanonicalizeFragment_EphemeralKeysStripped asserts that keys with
// timestamp-like names are excluded from the output. Two states that differ only
// in an ephemeral key must produce identical canonical bytes.
func TestCanonicalizeFragment_EphemeralKeysStripped(t *testing.T) {
	stateA := stateFrom(map[string]interface{}{
		"name":       "sshd",
		"enabled":    true,
		"created_at": "2026-01-01T00:00:00Z", // ephemeral: _at suffix
		"updated_at": "2026-07-24T12:00:00Z", // ephemeral: _at suffix
		"timestamp":  "2026-07-24T12:00:00Z", // ephemeral: exact match
	})
	stateB := stateFrom(map[string]interface{}{
		"name":       "sshd",
		"enabled":    true,
		"created_at": "1970-01-01T00:00:00Z", // different value — must not matter
		"updated_at": "1970-01-01T00:00:00Z", // different value — must not matter
		"timestamp":  "1970-01-01T00:00:00Z", // different value — must not matter
	})
	stateC := stateFrom(map[string]interface{}{
		"name":    "sshd",
		"enabled": true,
		// No ephemeral keys at all.
	})

	outA, err := CanonicalizeFragment("service:sshd", "service", stateA)
	require.NoError(t, err)
	outB, err := CanonicalizeFragment("service:sshd", "service", stateB)
	require.NoError(t, err)
	outC, err := CanonicalizeFragment("service:sshd", "service", stateC)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(outA, outB),
		"states that differ only in ephemeral keys must produce identical canonical_bytes")
	assert.True(t, bytes.Equal(outA, outC),
		"states with and without ephemeral keys (same stable content) must produce identical canonical_bytes")
}

// TestCanonicalizeFragment_EmptyState asserts that an empty ConfigState is handled
// gracefully and produces a non-nil byte slice.
func TestCanonicalizeFragment_EmptyState(t *testing.T) {
	state := stateFrom(map[string]interface{}{})
	out, err := CanonicalizeFragment("frag:empty", "module", state)
	require.NoError(t, err)
	assert.NotNil(t, out, "empty state must return a non-nil byte slice")
}

// TestCanonicalizeFragment_NestedMapKeyOrder asserts that nested maps are also
// sorted by key, so {inner:{b:2,a:1}} == {inner:{a:1,b:2}}.
func TestCanonicalizeFragment_NestedMapKeyOrder(t *testing.T) {
	state1 := stateFrom(map[string]interface{}{
		"cfg": map[string]interface{}{"b": "two", "a": "one"},
	})
	state2 := stateFrom(map[string]interface{}{
		"cfg": map[string]interface{}{"a": "one", "b": "two"},
	})

	out1, err := CanonicalizeFragment("frag:x", "module", state1)
	require.NoError(t, err)
	out2, err := CanonicalizeFragment("frag:x", "module", state2)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(out1, out2),
		"nested map key order must not affect canonical bytes")
}

// TestCanonicalizeFragment_BoolVsInt asserts that true and int64(1) produce
// different bytes (type tag differentiates them).
func TestCanonicalizeFragment_BoolVsInt(t *testing.T) {
	stateBool := stateFrom(map[string]interface{}{"v": true})
	stateInt := stateFrom(map[string]interface{}{"v": int64(1)})

	outBool, err := CanonicalizeFragment("frag:x", "module", stateBool)
	require.NoError(t, err)
	outInt, err := CanonicalizeFragment("frag:x", "module", stateInt)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(outBool, outInt),
		"bool(true) and int64(1) must produce different canonical bytes (type tag differentiates them)")
}

// TestCanonicalizeFragment_StringVsNestedMap asserts that a string value and a
// nested map value at the same key produce different bytes.
func TestCanonicalizeFragment_StringVsNestedMap(t *testing.T) {
	stateStr := stateFrom(map[string]interface{}{"v": "hello"})
	stateMap := stateFrom(map[string]interface{}{"v": map[string]interface{}{"inner": "hello"}})

	outStr, err := CanonicalizeFragment("frag:x", "module", stateStr)
	require.NoError(t, err)
	outMap, err := CanonicalizeFragment("frag:x", "module", stateMap)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(outStr, outMap),
		"string value and nested-map value at the same key must produce different bytes")
}
