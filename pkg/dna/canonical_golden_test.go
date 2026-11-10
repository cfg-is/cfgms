// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// The expected values in this file were generated from the implementation that
// lived in features/steward/dna before it moved to pkg/dna, and have not been
// edited since. Canonical bytes feed FragmentHash and the aggregate root that
// stewards and the controller compare, so any change to a value here is a wire
// format break, not a test update.

// goldenState covers every wire tag: N (nil), B (bool), I (int64), U (uint64),
// F (float), S (string), M (nested map), L (slice) and O (other). The width
// variants (int, uint8, float32) and the normalised containers (map[string]string,
// []string, []map[string]interface{}) must encode identically to their canonical
// counterparts, and created_at is an ephemeral key that must not appear.
func goldenState() MapState {
	return MapState{
		"k_nil":        nil,
		"k_bool_true":  true,
		"k_bool_false": false,
		"k_int":        int(-42),
		"k_int64":      int64(1 << 40),
		"k_uint64":     uint64(1<<63 + 5),
		"k_uint8":      uint8(200),
		"k_float":      3.14159,
		"k_float_int":  float64(2),
		"k_float32":    float32(0.5),
		"k_string":     "héllo wörld",
		"k_empty":      "",
		"k_map":        map[string]interface{}{"a": "b", "n": int64(1), "deep": map[string]interface{}{"x": true}},
		"k_mapstr":     map[string]string{"k": "v"},
		"k_slice":      []interface{}{"x", int64(2), nil, true, []interface{}{"inner"}},
		"k_strslice":   []string{"p", "q"},
		"k_mapslice":   []map[string]interface{}{{"id": "1"}},
		"k_other":      5 * time.Second,
		"created_at":   "2026-01-01T00:00:00Z",
	}
}

const (
	goldenCanonicalHex  = "000000120000000c6b5f626f6f6c5f66616c736542000000000b6b5f626f6f6c5f747275654201000000076b5f656d7074795300000000000000076b5f666c6f61744600000007332e3134313539000000096b5f666c6f617433324600000003302e350000000b6b5f666c6f61745f696e74460000000132000000056b5f696e7449ffffffffffffffd6000000076b5f696e743634490000010000000000000000056b5f6d61704d00000003000000016153000000016200000004646565704d0000000100000001784201000000016e4900000000000000010000000a6b5f6d6170736c6963654c000000014d00000001000000026964530000000131000000086b5f6d61707374724d00000001000000016b530000000176000000056b5f6e696c4e000000076b5f6f746865724f000000023573000000076b5f736c6963654c000000055300000001784900000000000000024e42014c000000015300000005696e6e6572000000086b5f737472696e67530000000d68c3a96c6c6f2077c3b6726c640000000a6b5f737472736c6963654c00000002530000000170530000000171000000086b5f75696e743634558000000000000005000000076b5f75696e74385500000000000000c8"
	goldenFragmentHash  = "3db660fd98de1545a9ab741c71dbea842b04071ed05de16c03a4c421fb9581d5"
	goldenAggregateRoot = "90635d3232b49454e17066e0043a8b1a4c8122d431a8ee89016b079cd9d7977d"
	goldenBulkRoot      = "1c21cfee0acfb5515bddb40a8d1a857f6aa92a1ecdca8264d7839ecfa0a53e89"
)

// goldenManifest is a fixed manifest: two fragments hashed from fixed bytes and
// the golden fragment.
func goldenManifest() []*commonpb.ManifestEntry {
	return []*commonpb.ManifestEntry{
		{FragmentId: "host:os", FragmentHash: "840a8dcfeae95966a870b0b5257997ce94cbc19dd979409d1671d2e93a9e0de6"},
		{FragmentId: "cluster:a", FragmentHash: goldenFragmentHash},
		{FragmentId: "host:cpu", FragmentHash: "68ab84f7c6d0f5781585eb1b5289499fb29081b918f71ebddb5f72021c9ef9c5"},
	}
}

// TestCanonicalGolden_AllWireTags pins the exact canonical bytes and FragmentHash
// of a state covering every wire tag, plus the AggregateRoot and BulkRoot of a
// fixed manifest.
func TestCanonicalGolden_AllWireTags(t *testing.T) {
	canonical, err := CanonicalizeFragment("cluster:a", "golden", goldenState())
	require.NoError(t, err)
	assert.Equal(t, goldenCanonicalHex, hex.EncodeToString(canonical), "canonical bytes must not change")
	assert.Equal(t, goldenFragmentHash, FragmentHash(canonical), "fragment hash must not change")

	// Every wire tag must actually be present in the pinned bytes.
	for _, tag := range []byte{canonTagNull, canonTagBool, canonTagInt, canonTagUint,
		canonTagFloat, canonTagString, canonTagMap, canonTagSlice, canonTagOther} {
		assert.Contains(t, string(canonical), string(tag), "fixture must exercise tag %q", string(tag))
	}
	assert.NotContains(t, string(canonical), "created_at", "ephemeral keys must be stripped")

	manifest := goldenManifest()
	root, err := AggregateRoot(manifest)
	require.NoError(t, err)
	assert.Equal(t, goldenAggregateRoot, root, "aggregate root must not change")
	assert.Equal(t, goldenBulkRoot, BulkRoot(manifest), "bulk root must not change")

	// NewFragment is the same canonicalize-and-hash step.
	frag, err := NewFragment("cluster:a", "golden", goldenState())
	require.NoError(t, err)
	assert.Equal(t, canonical, frag.GetCanonicalBytes())
	assert.Equal(t, goldenFragmentHash, frag.GetFragmentHash())
}

// TestCanonicalGolden_Decode feeds the golden bytes back through the decoder and
// checks every wire tag decodes to the documented Go type.
func TestCanonicalGolden_Decode(t *testing.T) {
	raw, err := hex.DecodeString(goldenCanonicalHex)
	require.NoError(t, err)

	got, err := DecodeCanonicalFragment(raw)
	require.NoError(t, err)

	want := map[string]interface{}{
		"k_nil":        nil,
		"k_bool_true":  true,
		"k_bool_false": false,
		"k_int":        int64(-42),
		"k_int64":      int64(1 << 40),
		"k_uint64":     uint64(1<<63 + 5),
		"k_uint8":      uint64(200),
		"k_float":      3.14159,
		"k_float_int":  float64(2),
		"k_float32":    float64(0.5),
		"k_string":     "héllo wörld",
		"k_empty":      "",
		"k_map":        map[string]interface{}{"a": "b", "n": int64(1), "deep": map[string]interface{}{"x": true}},
		"k_mapstr":     map[string]interface{}{"k": "v"},
		"k_slice":      []interface{}{"x", int64(2), nil, true, []interface{}{"inner"}},
		"k_strslice":   []interface{}{"p", "q"},
		"k_mapslice":   []interface{}{map[string]interface{}{"id": "1"}},
		"k_other":      "5s",
	}
	assert.Equal(t, want, got)

	// Re-encoding the decoded map and decoding it again is a fixed point. The bytes
	// differ from the golden ones only because the O-tagged value decodes to a
	// plain string and so re-encodes under the S tag.
	again, err := CanonicalizeFragment("cluster:a", "golden", MapState(got))
	require.NoError(t, err)
	regot, err := DecodeCanonicalFragment(again)
	require.NoError(t, err)
	assert.Equal(t, got, regot)
}

// hostileEntry builds a one-entry map with a zero-length key whose value starts
// with tag followed by tail.
func hostileEntry(tag byte, tail ...[]byte) []byte {
	b := append(be32(1), be32(0)...)
	b = append(b, tag)
	for _, t := range tail {
		b = append(b, t...)
	}
	return b
}

// hostileNesting builds levels nested single-entry maps with a zero-length key,
// ending in an empty map.
func hostileNesting(levels int) []byte {
	var b []byte
	for i := 0; i < levels; i++ {
		b = append(b, be32(1)...)
		b = append(b, be32(0)...)
		b = append(b, canonTagMap)
	}
	return append(b, be32(0)...)
}

// TestDecodeCanonicalFragment_HostileInputs asserts the exact error for every
// hostile or malformed input. The messages are the ones the decoder in
// features/steward/dna returned before the move.
func TestDecodeCanonicalFragment_HostileInputs(t *testing.T) {
	const nested = `decodeCanonMap: entry "": decodeCanonValue: nested map: `
	cases := []struct {
		name  string
		input []byte
		want  string
	}{
		{name: "empty buffer", input: []byte{}, want: "DecodeCanonicalFragment: decodeCanonMap: need 4 bytes for count, have 0"},
		{name: "truncated header", input: []byte{0, 0}, want: "DecodeCanonicalFragment: decodeCanonMap: need 4 bytes for count, have 2"},
		{name: "declared 2^32-1 map entries", input: be32(4294967295), want: "DecodeCanonicalFragment: decodeCanonMap: declared 4294967295 entries exceeds 0 possible in 0 remaining bytes"},
		{name: "declared 2^32-1 slice elements", input: hostileEntry(canonTagSlice, be32(4294967295)), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: declared 4294967295 slice elements exceeds 0 remaining bytes"},
		{name: "declared 50M slice elements", input: hostileEntry(canonTagSlice, be32(50000000)), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: declared 50000000 slice elements exceeds 0 remaining bytes"},
		{name: "slice count truncated", input: hostileEntry(canonTagSlice, []byte{0}), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: slice count truncated"},
		{name: "slice count exceeds remaining", input: hostileEntry(canonTagSlice, []byte{0, 0, 0, 1}), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: declared 1 slice elements exceeds 0 remaining bytes"},
		{name: "hostile string length", input: hostileEntry(canonTagString, be32(4294967295), []byte("x")), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: string/other bytes truncated"},
		{name: "hostile other length", input: hostileEntry(canonTagOther, be32(4294967295), []byte("x")), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: string/other bytes truncated"},
		{name: "hostile float length", input: hostileEntry(canonTagFloat, be32(4294967295), []byte("x")), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: float string truncated"},
		{name: "hostile key length", input: append(append(be32(1), be32(4294967295)...), 'k', canonTagNull), want: "DecodeCanonicalFragment: decodeCanonMap: key bytes truncated at entry 0"},
		{name: "entry count with no entries", input: append(be32(2), be32(0)...), want: "DecodeCanonicalFragment: decodeCanonMap: declared 2 entries exceeds 0 possible in 4 remaining bytes"},
		{name: "entry count with no value", input: append(be32(1), be32(0)...), want: "DecodeCanonicalFragment: decodeCanonMap: declared 1 entries exceeds 0 possible in 4 remaining bytes"},
		{name: "trailing bytes", input: append(be32(0), 0xff), want: "DecodeCanonicalFragment: 4 bytes consumed, 5 total"},
		{name: "unknown tag", input: hostileEntry('Z'), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: unknown tag 0x5a"},
		{name: "unparseable float", input: hostileEntry(canonTagFloat, be32(1), []byte("x")), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: parse float \"x\": strconv.ParseFloat: parsing \"x\": invalid syntax"},
		{name: "bool truncated", input: hostileEntry(canonTagBool), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: bool truncated"},
		{name: "int64 truncated", input: hostileEntry(canonTagInt, []byte{1, 2}), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: int64 truncated"},
		{name: "uint64 truncated", input: hostileEntry(canonTagUint, []byte{1, 2}), want: "DecodeCanonicalFragment: decodeCanonMap: entry \"\": decodeCanonValue: uint64 truncated"},
		{name: "nesting beyond the depth ceiling", input: hostileNesting(37),
			want: "DecodeCanonicalFragment: " + strings.Repeat(nested, 33) + "decodeCanonMap: nesting depth exceeds 32"},
		{name: "oversized input", input: make([]byte, MaxCanonicalFragmentSize+1), want: "DecodeCanonicalFragment: 8388609 bytes exceeds maximum 8388608"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeCanonicalFragment(tc.input)
			require.Error(t, err)
			assert.Nil(t, got)
			assert.Equal(t, tc.want, err.Error())
		})
	}
}

// TestDecodeCanonicalFragment_GoldenBytesAccepted is the positive half of the
// hostile-input table: the golden bytes decode without error.
func TestDecodeCanonicalFragment_GoldenBytesAccepted(t *testing.T) {
	raw, err := hex.DecodeString(goldenCanonicalHex)
	require.NoError(t, err)
	_, err = DecodeCanonicalFragment(raw)
	require.NoError(t, err)
}
