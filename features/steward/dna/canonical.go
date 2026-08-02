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

// DecodeCanonicalFragment reverses CanonicalizeFragment, recovering the stable
// key-value pairs from canonical bytes. Ephemeral keys were stripped at encode
// time and are absent from the result. The returned map uses Go native types:
//   - bool for B-tagged values
//   - int64 for I-tagged values
//   - uint64 for U-tagged values
//   - float64 for F-tagged values
//   - string for S- and O-tagged values
//   - map[string]interface{} for M-tagged nested maps
//   - []interface{} for L-tagged slices
//   - nil for N-tagged null values
//
// Used by the cluster registry to extract resource_owner from cluster:* fragments.
//
// # Hostile-input handling
//
// canonical_bytes arrive from stewards, which per the threat model run on hosts
// that may be compromised. Every declared length and count in the header is
// therefore validated against the bytes actually remaining in the buffer before
// any allocation, and nesting depth is capped at maxCanonDecodeDepth. Without
// those checks a 14-byte payload declaring a 2^32-element slice drives the Go
// runtime into an unrecoverable "out of memory" fatal error (not a panic, so no
// recovery interceptor can contain it), and deeply nested map tags drive it into
// an equally unrecoverable "stack overflow".
func DecodeCanonicalFragment(b []byte) (map[string]interface{}, error) {
	if len(b) > MaxCanonicalFragmentSize {
		return nil, fmt.Errorf("DecodeCanonicalFragment: %d bytes exceeds maximum %d",
			len(b), MaxCanonicalFragmentSize)
	}
	m, n, err := decodeCanonMap(b, 0)
	if err != nil {
		return nil, fmt.Errorf("DecodeCanonicalFragment: %w", err)
	}
	if n != len(b) {
		return nil, fmt.Errorf("DecodeCanonicalFragment: %d bytes consumed, %d total", n, len(b))
	}
	return m, nil
}

// MaxCanonicalFragmentSize bounds the canonical_bytes payload DecodeCanonicalFragment
// will accept. It matches the gRPC maxRecvMsgSize in
// pkg/dataplane/providers/grpc/limits.go. Real fragments are curated key subsets
// (see PartitionHostFacts) and are orders of magnitude smaller.
//
// This is a decoder-local backstop, NOT the wire bound. maxRecvMsgSize caps a single
// gRPC message, and the sync_dna path reassembles many ≤64 KB DNAChunk messages into
// one snapshot, so the wire itself does not bound a fragment. Ingest-side bounds on
// fragment count and per-fragment size are enforced where the snapshot is
// reassembled (features/controller/transport/dna_handler.go: maxDNATransferFragments,
// maxReassembledDNABytes) — this constant must not be relied on as the only limit
// standing between a hostile steward and the decoder.
const MaxCanonicalFragmentSize = 8 * 1024 * 1024

// maxCanonDecodeDepth bounds map/slice nesting during decode. decodeCanonValue and
// decodeCanonMap are mutually recursive, so without a ceiling a stream of nested 'M'
// tags (9 input bytes per level) overflows the goroutine stack — a fatal, unrecoverable
// runtime error. Real fragment payloads are flat maps of scalars; the deepest shape in
// the codebase is a map of maps (depth 2), so 32 is far above any legitimate use.
const maxCanonDecodeDepth = 32

// minCanonMapEntrySize is the smallest number of bytes a single map entry can occupy:
// 4 bytes of key length (a zero-length key is legal) plus a 1-byte type tag. Used to
// reject an entry count that is structurally impossible for the remaining buffer
// before any allocation is made from it.
const minCanonMapEntrySize = 5

// decodeCanonMap decodes [uint32 count][entries...] from b at the given nesting depth.
// Returns the map, bytes consumed, and any error.
//
// The declared entry count is validated against the remaining buffer before the map is
// built, and the map grows incrementally rather than being pre-sized from the header,
// so a hostile count cannot drive an allocation larger than the input itself.
func decodeCanonMap(b []byte, depth int) (map[string]interface{}, int, error) {
	if depth > maxCanonDecodeDepth {
		return nil, 0, fmt.Errorf("decodeCanonMap: nesting depth exceeds %d", maxCanonDecodeDepth)
	}
	if len(b) < 4 {
		return nil, 0, fmt.Errorf("decodeCanonMap: need 4 bytes for count, have %d", len(b))
	}
	count := uint64(binary.BigEndian.Uint32(b[:4]))
	pos := 4
	if maxEntries := uint64(len(b)-pos) / minCanonMapEntrySize; count > maxEntries {
		return nil, 0, fmt.Errorf("decodeCanonMap: declared %d entries exceeds %d possible in %d remaining bytes",
			count, maxEntries, len(b)-pos)
	}
	m := make(map[string]interface{})
	for i := uint64(0); i < count; i++ {
		if pos+4 > len(b) {
			return nil, 0, fmt.Errorf("decodeCanonMap: key length truncated at entry %d", i)
		}
		klen := uint64(binary.BigEndian.Uint32(b[pos : pos+4]))
		pos += 4
		if klen > uint64(len(b)-pos) {
			return nil, 0, fmt.Errorf("decodeCanonMap: key bytes truncated at entry %d", i)
		}
		key := string(b[pos : pos+int(klen)])
		pos += int(klen)
		v, n, err := decodeCanonValue(b[pos:], depth)
		if err != nil {
			return nil, 0, fmt.Errorf("decodeCanonMap: entry %q: %w", key, err)
		}
		pos += n
		m[key] = v
	}
	return m, pos, nil
}

// decodeCanonValue decodes one type-tagged value from b at the given nesting depth.
// Returns the value, bytes consumed, and any error.
func decodeCanonValue(b []byte, depth int) (interface{}, int, error) {
	if depth > maxCanonDecodeDepth {
		return nil, 0, fmt.Errorf("decodeCanonValue: nesting depth exceeds %d", maxCanonDecodeDepth)
	}
	if len(b) == 0 {
		return nil, 0, fmt.Errorf("decodeCanonValue: empty buffer")
	}
	switch b[0] {
	case canonTagNull:
		return nil, 1, nil

	case canonTagBool:
		if len(b) < 2 {
			return nil, 0, fmt.Errorf("decodeCanonValue: bool truncated")
		}
		return b[1] != 0x00, 2, nil

	case canonTagInt:
		if len(b) < 9 {
			return nil, 0, fmt.Errorf("decodeCanonValue: int64 truncated")
		}
		return int64(binary.BigEndian.Uint64(b[1:9])), 9, nil

	case canonTagUint:
		if len(b) < 9 {
			return nil, 0, fmt.Errorf("decodeCanonValue: uint64 truncated")
		}
		return binary.BigEndian.Uint64(b[1:9]), 9, nil

	case canonTagFloat:
		if len(b) < 5 {
			return nil, 0, fmt.Errorf("decodeCanonValue: float length truncated")
		}
		// Compared in uint64 (not int) so the guard holds on 32-bit GOARCH, where
		// int(uint32) can go negative and make "len(b) < 5+slen" trivially false.
		slen := uint64(binary.BigEndian.Uint32(b[1:5]))
		if slen > uint64(len(b)-5) {
			return nil, 0, fmt.Errorf("decodeCanonValue: float string truncated")
		}
		s := string(b[5 : 5+int(slen)])
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("decodeCanonValue: parse float %q: %w", s, err)
		}
		return v, 5 + int(slen), nil

	case canonTagString, canonTagOther:
		if len(b) < 5 {
			return nil, 0, fmt.Errorf("decodeCanonValue: string/other length truncated")
		}
		// uint64 comparison for the same 32-bit-safety reason as canonTagFloat.
		slen := uint64(binary.BigEndian.Uint32(b[1:5]))
		if slen > uint64(len(b)-5) {
			return nil, 0, fmt.Errorf("decodeCanonValue: string/other bytes truncated")
		}
		return string(b[5 : 5+int(slen)]), 5 + int(slen), nil

	case canonTagMap:
		m, n, err := decodeCanonMap(b[1:], depth+1)
		if err != nil {
			return nil, 0, fmt.Errorf("decodeCanonValue: nested map: %w", err)
		}
		return m, 1 + n, nil

	case canonTagSlice:
		if len(b) < 5 {
			return nil, 0, fmt.Errorf("decodeCanonValue: slice count truncated")
		}
		count := uint64(binary.BigEndian.Uint32(b[1:5]))
		pos := 5
		// Every element consumes at least one type-tag byte, so a count larger than
		// the remaining buffer is structurally impossible. Rejecting it here (rather
		// than discovering the truncation mid-loop) keeps a hostile header from
		// driving an allocation before a single element has been read.
		if count > uint64(len(b)-pos) {
			return nil, 0, fmt.Errorf("decodeCanonValue: declared %d slice elements exceeds %d remaining bytes",
				count, len(b)-pos)
		}
		// Grown incrementally rather than pre-sized from the declared count, so the
		// allocation tracks elements actually decoded instead of the declared header.
		elems := make([]interface{}, 0)
		for i := uint64(0); i < count; i++ {
			v, n, err := decodeCanonValue(b[pos:], depth+1)
			if err != nil {
				return nil, 0, fmt.Errorf("decodeCanonValue: slice element %d: %w", i, err)
			}
			elems = append(elems, v)
			pos += n
		}
		return elems, pos, nil

	default:
		return nil, 0, fmt.Errorf("decodeCanonValue: unknown tag 0x%02x", b[0])
	}
}

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

	case map[string]string:
		// Normalise to map[string]interface{} so the encoding is identical to the
		// map[string]interface{} path (sorted keys, length-prefix entries, decodable).
		// Without this case, map[string]string falls to the default/O path which
		// produces Go's fmt.Sprintf("%v") string — opaque and not decodable.
		converted := make(map[string]interface{}, len(val))
		for k, v := range val {
			converted[k] = v
		}
		inner, err := canonEncodeMap(converted)
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
