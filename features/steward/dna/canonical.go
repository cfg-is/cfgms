// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/cfgis/cfgms/features/modules"
)

// Wire-format type tags for CanonicalizeFragment's length-prefix encoding.
// Each value field is preceded by one of these bytes to distinguish types that
// share a textual representation (e.g. bool(true) vs int64(1) vs string("1")).
const (
	canonTagNull   = byte('N') // nil: no further bytes
	canonTagBool   = byte('B') // 1 byte: 0x00 or 0x01
	canonTagInt    = byte('I') // 8 bytes big-endian int64
	canonTagUint   = byte('U') // 8 bytes big-endian uint64
	canonTagFloat  = byte('F') // uint32 length + shortest-round-trip decimal string
	canonTagString = byte('S') // uint32 length + UTF-8 bytes
	canonTagMap    = byte('M') // uint32 entry-count + sorted key-value pairs (recursive)
	canonTagSlice  = byte('L') // uint32 element-count + recursively encoded elements (ordered)
	canonTagOther  = byte('O') // uint32 length + fmt.Sprintf("%v", value) bytes
)

// ephemeralKeySuffixes are lowercase snake_case suffix patterns that indicate
// run-local values forbidden by ADR-016 clause 4. We strip them defensively;
// the primary enforcement point is ConfigState.AsMap() itself.
// CamelCase variants (e.g. "createdAt") are not matched here because bare
// suffixes would be too greedy ("format" ends in "at"). The ADR-016 clause 4
// contract requires ConfigState implementations to use snake_case for map keys,
// which this list covers.
var ephemeralKeySuffixes = []string{
	"_at", "_time", "_timestamp", "_ts", "_since", "_ago", "_when",
}

// ephemeralKeyExact is the set of exact lowercase key names that are always
// run-local (e.g. "pid", "uptime") and must not enter canonical bytes.
var ephemeralKeyExact = map[string]bool{
	"timestamp":    true,
	"pid":          true,
	"uptime":       true,
	"elapsed":      true,
	"last_updated": true,
}

// CanonicalizeFragment produces a deterministic, collision-resistant byte encoding
// of fragment state for use as Fragment.canonical_bytes (ADR-017 §S2).
//
// # Wire format
//
//	[uint32 BE: stable-field count]
//	For each field, sorted ascending by key:
//	  [uint32 BE: key byte-length] [key bytes]
//	  [1 byte: type tag]
//	  [type-specific value bytes — see canonTag* constants]
//
// Length-prefixing every key and value closes the collision class present in
// ComputeHash (separator-only scheme): {"a":"b\nc=d"} and {"a":"b","c":"d"}
// serialize differently because their field-count headers differ (1 vs 2).
//
// Ephemeral keys (timestamp-like suffixes or exact names in ephemeralKeyExact)
// are stripped before encoding as a belt-and-suspenders defensive measure;
// ConfigState.AsMap() must already exclude them per ADR-016 clause 4.
//
// The fragmentID and authority parameters are currently accepted for future use
// by S3 (hash chaining) but are not included in the byte output — canonical_bytes
// represents state only, not provenance metadata (provenance lives in
// FragmentEnvelope per ADR-017 A1.1).
func CanonicalizeFragment(_, _ string, state modules.ConfigState) ([]byte, error) {
	return encodeTopLevel(state.AsMap())
}

// encodeTopLevel encodes the top-level map from ConfigState.AsMap(), stripping
// ephemeral keys before producing the sorted length-prefix byte stream.
func encodeTopLevel(m map[string]interface{}) ([]byte, error) {
	// Filter ephemeral keys first so the field count reflects only stable fields.
	stable := make(map[string]interface{}, len(m))
	for k, v := range m {
		if !isEphemeralKey(k) {
			stable[k] = v
		}
	}
	return canonEncodeMap(stable)
}

// canonEncodeMap encodes a map[string]interface{} as sorted length-prefix entries.
// Used for both the top-level state and nested map values.
func canonEncodeMap(m map[string]interface{}) ([]byte, error) {
	if len(m) > math.MaxUint32 {
		return nil, fmt.Errorf("canonical map has too many entries")
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := make([]byte, 4)
	// #nosec G115 -- map length is explicitly bounded by MaxUint32 above.
	binary.BigEndian.PutUint32(buf, uint32(len(keys)))

	for _, k := range keys {
		// Key: uint32 length + bytes.
		kb := []byte(k)
		if len(kb) > math.MaxUint32 {
			return nil, fmt.Errorf("canonical map key exceeds uint32 length")
		}
		var klen [4]byte
		// #nosec G115 -- key length is explicitly bounded by MaxUint32 above.
		binary.BigEndian.PutUint32(klen[:], uint32(len(kb)))
		buf = append(buf, klen[:]...)
		buf = append(buf, kb...)

		// Value: type tag + type-specific encoding.
		vb, err := canonEncodeValue(m[k])
		if err != nil {
			return nil, fmt.Errorf("canonical encode key %q: %w", k, err)
		}
		buf = append(buf, vb...)
	}
	return buf, nil
}

// canonEncodeValue encodes a single value with its type tag.
func canonEncodeValue(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case nil:
		return []byte{canonTagNull}, nil

	case bool:
		b := byte(0x00)
		if val {
			b = 0x01
		}
		return []byte{canonTagBool, b}, nil

	case int:
		return canonEncodeInt64(int64(val)), nil
	case int8:
		return canonEncodeInt64(int64(val)), nil
	case int16:
		return canonEncodeInt64(int64(val)), nil
	case int32:
		return canonEncodeInt64(int64(val)), nil
	case int64:
		return canonEncodeInt64(val), nil

	case uint:
		return canonEncodeUint64(uint64(val)), nil
	case uint8:
		return canonEncodeUint64(uint64(val)), nil
	case uint16:
		return canonEncodeUint64(uint64(val)), nil
	case uint32:
		return canonEncodeUint64(uint64(val)), nil
	case uint64:
		return canonEncodeUint64(val), nil

	case float32:
		return canonEncodeFloat(float64(val))
	case float64:
		return canonEncodeFloat(val)

	case string:
		return canonEncodeStringTag(canonTagString, []byte(val))

	case map[string]interface{}:
		inner, err := canonEncodeMap(val)
		if err != nil {
			return nil, err
		}
		return append([]byte{canonTagMap}, inner...), nil

	case []interface{}:
		return canonEncodeSlice(val)

	case []string:
		// Normalise to []interface{} so element encoding is identical to the
		// []interface{} path — same type tag, same byte layout.
		elems := make([]interface{}, len(val))
		for i, s := range val {
			elems[i] = s
		}
		return canonEncodeSlice(elems)

	case []map[string]interface{}:
		// ADQueryResult.GenericObjects uses this type; %v on a slice of maps is
		// collision-prone (space separator), so encode explicitly.
		elems := make([]interface{}, len(val))
		for i, m := range val {
			elems[i] = m
		}
		return canonEncodeSlice(elems)

	default:
		// Fallback for any unexpected concrete type: encode as its %v string with
		// a distinct tag so it cannot collide with a real string value.
		// Known slice types that land here: []DirectoryUser, []DirectoryGroup,
		// []OrganizationalUnit — struct %v wraps each element in {}, providing
		// a higher collision bar than plain string slices, but new slice-of-struct
		// types appearing in AsMap() implementations should be given explicit cases.
		return canonEncodeStringTag(canonTagOther, []byte(fmt.Sprintf("%v", val)))
	}
}

// canonEncodeSlice encodes a []interface{} as [canonTagSlice][uint32 count][elements...].
// Element order is preserved (slices are ordered, unlike maps); each element is
// encoded recursively via canonEncodeValue so the full type-tag machinery applies.
func canonEncodeSlice(elems []interface{}) ([]byte, error) {
	if len(elems) > math.MaxUint32 {
		return nil, fmt.Errorf("canonical slice has too many elements")
	}
	var count [4]byte
	// #nosec G115 -- element count is explicitly bounded by MaxUint32 above.
	binary.BigEndian.PutUint32(count[:], uint32(len(elems)))
	buf := append([]byte{canonTagSlice}, count[:]...)
	for i, elem := range elems {
		eb, err := canonEncodeValue(elem)
		if err != nil {
			return nil, fmt.Errorf("slice element %d: %w", i, err)
		}
		buf = append(buf, eb...)
	}
	return buf, nil
}

// canonEncodeInt64 encodes an int64 as tag + 8 big-endian bytes.
func canonEncodeInt64(v int64) []byte {
	buf := make([]byte, 9)
	buf[0] = canonTagInt
	// #nosec G115 -- this is the specified two's-complement bit encoding of
	// the signed int64, not a numeric narrowing or range conversion.
	binary.BigEndian.PutUint64(buf[1:], uint64(v))
	return buf
}

// canonEncodeUint64 encodes a uint64 as tag + 8 big-endian bytes.
func canonEncodeUint64(v uint64) []byte {
	buf := make([]byte, 9)
	buf[0] = canonTagUint
	binary.BigEndian.PutUint64(buf[1:], v)
	return buf
}

// canonEncodeFloat encodes a float64 as tag + uint32-prefixed decimal string.
// We use strconv.FormatFloat with format 'g' and precision -1 (shortest
// round-trip representation) rather than stdlib JSON to avoid depending on
// float-formatting behaviour that has shifted across Go patch releases.
func canonEncodeFloat(v float64) ([]byte, error) {
	s := strconv.FormatFloat(v, 'g', -1, 64)
	return canonEncodeStringTag(canonTagFloat, []byte(s))
}

// canonEncodeStringTag encodes a byte slice as [tag][uint32 length][bytes].
func canonEncodeStringTag(tag byte, s []byte) ([]byte, error) {
	if len(s) > math.MaxUint32 {
		return nil, fmt.Errorf("canonical value exceeds uint32 length")
	}
	buf := make([]byte, 1+4+len(s))
	buf[0] = tag
	// #nosec G115 -- byte length is explicitly bounded by MaxUint32 above.
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(s)))
	copy(buf[5:], s)
	return buf, nil
}

// isEphemeralKey reports whether a map key represents a run-local value that
// must be excluded from canonical bytes (ADR-016 clause 4).
func isEphemeralKey(k string) bool {
	lower := strings.ToLower(k)
	if ephemeralKeyExact[lower] {
		return true
	}
	for _, suffix := range ephemeralKeySuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}
