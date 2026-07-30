// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"bytes"
	"encoding/binary"
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

// ─── DecodeCanonicalFragment (Issue #2908) ────────────────────────────────────

// TestDecodeCanonicalFragment_RoundTrips verifies that every supported type
// survives a CanonicalizeFragment → DecodeCanonicalFragment round-trip.
func TestDecodeCanonicalFragment_RoundTrips(t *testing.T) {
	cases := []struct {
		name    string
		in      map[string]interface{}
		wantOut map[string]interface{} // expected decoded form (may differ in exact numeric type)
	}{
		{
			name:    "string",
			in:      map[string]interface{}{"v": "hello"},
			wantOut: map[string]interface{}{"v": "hello"},
		},
		{
			name:    "bool_true",
			in:      map[string]interface{}{"v": true},
			wantOut: map[string]interface{}{"v": true},
		},
		{
			name:    "bool_false",
			in:      map[string]interface{}{"v": false},
			wantOut: map[string]interface{}{"v": false},
		},
		{
			name:    "int64",
			in:      map[string]interface{}{"v": int64(42)},
			wantOut: map[string]interface{}{"v": int64(42)},
		},
		{
			name:    "nil",
			in:      map[string]interface{}{"v": nil},
			wantOut: map[string]interface{}{"v": nil},
		},
		{
			name: "nested_map_interface",
			in:   map[string]interface{}{"owners": map[string]interface{}{"csv": "node-a"}},
			wantOut: map[string]interface{}{
				"owners": map[string]interface{}{"csv": "node-a"},
			},
		},
		{
			name: "slice_strings",
			in:   map[string]interface{}{"members": []interface{}{"node-a", "node-b"}},
			wantOut: map[string]interface{}{
				"members": []interface{}{"node-a", "node-b"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := stateFrom(tc.in)
			b, err := CanonicalizeFragment("frag:test", "module", state)
			require.NoError(t, err)

			got, err := DecodeCanonicalFragment(b)
			require.NoError(t, err)
			assert.Equal(t, tc.wantOut, got)
		})
	}
}

// TestDecodeCanonicalFragment_MapStringString verifies that map[string]string
// values (used by ClusterStatus.AsMap for resource_owner) encode as proper maps
// and decode back to map[string]interface{} — not as an opaque Go format string.
func TestDecodeCanonicalFragment_MapStringString(t *testing.T) {
	state := stateFrom(map[string]interface{}{
		"resource_owner": map[string]string{
			"web-01": "CFG-70-02",
			"csv":    "CFG-AB-02",
		},
	})

	b, err := CanonicalizeFragment("cluster:cfg-lab", "hyperv", state)
	require.NoError(t, err)

	got, err := DecodeCanonicalFragment(b)
	require.NoError(t, err)

	owners, ok := got["resource_owner"].(map[string]interface{})
	require.True(t, ok, "resource_owner must decode as map[string]interface{}, got %T", got["resource_owner"])
	assert.Equal(t, "CFG-70-02", owners["web-01"])
	assert.Equal(t, "CFG-AB-02", owners["csv"])
}

// TestDecodeCanonicalFragment_ClusterStatusShape is the concrete end-to-end
// round-trip for the full ClusterStatus.AsMap() payload (Issue #2908 AC).
func TestDecodeCanonicalFragment_ClusterStatusShape(t *testing.T) {
	// Simulate exactly what ClusterStatus.AsMap() returns.
	in := map[string]interface{}{
		"name":                       "cfg-lab",
		"cno_owner_node":             "CFG-70-02",
		"member_nodes":               []string{"CFG-70-02", "CFG-AB-02"},
		"resource_owner":             map[string]string{"web-01": "CFG-70-02"},
		"csv_paths":                  []string{"/ClusterStorage/Volume1"},
		"found":                      true,
		"cluster_access_ok":          true,
		"cluster_access_remediation": "",
	}

	b, err := CanonicalizeFragment("cluster:cfg-lab", "hyperv", stateFrom(in))
	require.NoError(t, err)

	got, err := DecodeCanonicalFragment(b)
	require.NoError(t, err)

	// resource_owner must be a proper map, not the Go fmt.Sprintf("%v") string.
	owners, ok := got["resource_owner"].(map[string]interface{})
	require.True(t, ok, "resource_owner must decode as map[string]interface{}, got %T", got["resource_owner"])
	assert.Equal(t, "CFG-70-02", owners["web-01"])

	// name and cno_owner_node must survive round-trip as strings.
	assert.Equal(t, "cfg-lab", got["name"])
	assert.Equal(t, "CFG-70-02", got["cno_owner_node"])

	// found must survive as bool.
	assert.Equal(t, true, got["found"])

	// member_nodes must survive as []interface{} of strings.
	members, ok := got["member_nodes"].([]interface{})
	require.True(t, ok, "member_nodes must decode as []interface{}, got %T", got["member_nodes"])
	assert.ElementsMatch(t, []interface{}{"CFG-70-02", "CFG-AB-02"}, members)
}

// TestDecodeCanonicalFragment_TrailingBytesError verifies that trailing bytes
// after a valid payload return an error rather than silently succeeding.
func TestDecodeCanonicalFragment_TrailingBytesError(t *testing.T) {
	state := stateFrom(map[string]interface{}{"v": "hello"})
	b, err := CanonicalizeFragment("frag:x", "module", state)
	require.NoError(t, err)

	// Append a garbage byte.
	corrupted := append(b, 0xFF)
	_, err = DecodeCanonicalFragment(corrupted)
	assert.Error(t, err, "trailing bytes must return an error")
}

// TestDecodeCanonicalFragment_TruncatedError verifies that a truncated payload
// returns an error.
func TestDecodeCanonicalFragment_TruncatedError(t *testing.T) {
	state := stateFrom(map[string]interface{}{"v": "hello"})
	b, err := CanonicalizeFragment("frag:x", "module", state)
	require.NoError(t, err)

	// Truncate to the first 3 bytes.
	_, err = DecodeCanonicalFragment(b[:3])
	assert.Error(t, err, "truncated payload must return an error")
}

// TestDecodeCanonicalFragment_EmptyState verifies that an empty map encodes and
// decodes as an empty map.
func TestDecodeCanonicalFragment_EmptyState(t *testing.T) {
	state := stateFrom(map[string]interface{}{})
	b, err := CanonicalizeFragment("frag:empty", "module", state)
	require.NoError(t, err)

	got, err := DecodeCanonicalFragment(b)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// ─── Hostile canonical_bytes (steward-supplied, threat-model hardening) ───────

// be32 returns the big-endian encoding of v, matching the wire format's
// length/count header shape.
func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

// TestDecodeCanonicalFragment_HostileSliceCount verifies that a declared slice
// element count larger than the remaining buffer is rejected before any
// allocation is made from it. Every element consumes at least one type-tag byte,
// so such a count is structurally impossible.
//
// Before the count was validated, a 14-byte payload declaring 50 000 000 elements
// allocated 762 MB and a payload declaring 4 294 967 295 elements ended in
// "fatal error: out of memory" — a Go runtime fatal error that recover() cannot
// catch, so no gRPC/HTTP recovery interceptor would have contained it.
func TestDecodeCanonicalFragment_HostileSliceCount(t *testing.T) {
	for _, count := range []uint32{50_000_000, 4_294_967_295, 1} {
		// One map entry: zero-length key, value = slice with a hostile element count.
		var b []byte
		b = append(b, be32(1)...)     // map entry count = 1
		b = append(b, be32(0)...)     // key length = 0
		b = append(b, canonTagSlice)  // value tag: slice
		b = append(b, be32(count)...) // hostile element count
		require.Len(t, b, 13, "fixture must stay small enough to prove the count is not trusted")

		_, err := DecodeCanonicalFragment(b)
		require.Error(t, err, "slice count %d must be rejected", count)
		assert.Contains(t, err.Error(), "slice elements",
			"error must name the impossible slice count, got: %v", err)
	}
}

// TestDecodeCanonicalFragment_HostileMapCount verifies that a declared map entry
// count larger than the remaining buffer can hold is rejected before the map is
// allocated. A 4-byte payload of FF FF FF FF previously drove allocation to
// multi-GB and ended in an unrecoverable "fatal error: out of memory".
func TestDecodeCanonicalFragment_HostileMapCount(t *testing.T) {
	for _, count := range []uint32{4_294_967_295, 50_000_000, 1} {
		_, err := DecodeCanonicalFragment(be32(count))
		require.Error(t, err, "map entry count %d must be rejected", count)
		assert.Contains(t, err.Error(), "entries exceeds",
			"error must name the impossible entry count, got: %v", err)
	}
}

// TestDecodeCanonicalFragment_HostileNestingDepth verifies that unbounded nesting
// is rejected by the maxCanonDecodeDepth ceiling. 45 MB of nested 'M' tags
// previously produced "fatal error: stack overflow", which is also unrecoverable.
func TestDecodeCanonicalFragment_HostileNestingDepth(t *testing.T) {
	// Build maxCanonDecodeDepth+5 levels of {"": {"": ... }}.
	depth := maxCanonDecodeDepth + 5
	var b []byte
	for i := 0; i < depth; i++ {
		b = append(b, be32(1)...) // one entry at this level
		b = append(b, be32(0)...) // zero-length key
		b = append(b, canonTagMap)
	}
	b = append(b, be32(0)...) // innermost map: zero entries

	_, err := DecodeCanonicalFragment(b)
	require.Error(t, err, "nesting beyond the depth ceiling must be rejected")
	assert.Contains(t, err.Error(), "nesting depth exceeds",
		"error must name the depth ceiling, got: %v", err)
}

// TestDecodeCanonicalFragment_LegitimateNestingStillDecodes guards the depth
// ceiling against being set so low that real fragment shapes break: the deepest
// payload in the codebase is a map of maps (ClusterStatus.resource_owner).
func TestDecodeCanonicalFragment_LegitimateNestingStillDecodes(t *testing.T) {
	// Three levels of nesting — well within the ceiling, well beyond real use.
	b, err := CanonicalizeFragment("cluster:cfg-lab", "hyperv", stateFrom(map[string]interface{}{
		"l1": map[string]interface{}{
			"l2": map[string]interface{}{
				"l3": map[string]interface{}{"owner": "CFG-70-02"},
			},
		},
	}))
	require.NoError(t, err)

	got, err := DecodeCanonicalFragment(b)
	require.NoError(t, err, "legitimately nested fragments must still decode")
	l1 := got["l1"].(map[string]interface{})
	l2 := l1["l2"].(map[string]interface{})
	l3 := l2["l3"].(map[string]interface{})
	assert.Equal(t, "CFG-70-02", l3["owner"])
}

// TestDecodeCanonicalFragment_HostileStringLength verifies that a declared string
// length exceeding the remaining buffer is rejected rather than indexed. The
// uint64 comparison in the decoder also keeps the guard sound on 32-bit GOARCH,
// where int(uint32(0xFFFFFFFF)) is negative and would make a len() check a no-op.
func TestDecodeCanonicalFragment_HostileStringLength(t *testing.T) {
	for _, tag := range []byte{canonTagString, canonTagOther, canonTagFloat} {
		var b []byte
		b = append(b, be32(1)...)             // map entry count = 1
		b = append(b, be32(0)...)             // key length = 0
		b = append(b, tag)                    // value tag
		b = append(b, be32(4_294_967_295)...) // hostile declared length
		b = append(b, 'x')                    // one real byte

		_, err := DecodeCanonicalFragment(b)
		require.Error(t, err, "hostile length for tag %q must be rejected", string(tag))
		assert.Contains(t, err.Error(), "truncated",
			"error must report truncation for tag %q, got: %v", string(tag), err)
	}
}

// TestDecodeCanonicalFragment_HostileKeyLength verifies the map key-length guard.
func TestDecodeCanonicalFragment_HostileKeyLength(t *testing.T) {
	var b []byte
	b = append(b, be32(1)...)             // map entry count = 1
	b = append(b, be32(4_294_967_295)...) // hostile key length
	b = append(b, 'k', canonTagNull)      // one real key byte + a value tag

	_, err := DecodeCanonicalFragment(b)
	require.Error(t, err, "hostile key length must be rejected")
	assert.Contains(t, err.Error(), "key bytes truncated")
}

// TestDecodeCanonicalFragment_OversizedInputRejected verifies the total-size cap,
// which bounds heap amplification for any in-process caller that is not behind the
// gRPC maxRecvMsgSize limit.
func TestDecodeCanonicalFragment_OversizedInputRejected(t *testing.T) {
	_, err := DecodeCanonicalFragment(make([]byte, MaxCanonicalFragmentSize+1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}
