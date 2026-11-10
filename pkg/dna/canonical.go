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
// Used by the cluster registry to extract resource_owner from cluster:* fragments,
// and by the DNA entity-graph writer to project fragment fields.
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

// canonSpan converts a wire-declared length into an int offset, but only after
// proving it addresses bytes that are actually present.
//
// Every length and count in the canonical encoding arrives as an attacker-chosen
// uint32, so each one needs the same two-sided argument before it can be used as
// an index. Routing them all through one function means that argument is made
// once, in a place that can be audited, instead of being restated at each site.
//
// The comparison runs in uint64 deliberately: on a 32-bit GOARCH a direct
// int(uint32) can go negative, which would make a "remaining < declared" guard
// trivially false and defeat the check. remaining is a slice length and so is
// never negative, making the widening lossless; declared is then bounded by
// remaining, so narrowing it to int is lossless too.
//
// #nosec G115 -- both conversions are bounded by the guards in this function:
// remaining is a non-negative slice length, and declared is rejected unless it
// is <= remaining, so neither widening nor narrowing can lose information.
func canonSpan(declared uint32, remaining int) (int, bool) {
	if remaining < 0 {
		return 0, false
	}
	if uint64(declared) > uint64(remaining) {
		return 0, false
	}
	return int(declared), true
}

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
	declaredCount := binary.BigEndian.Uint32(b[:4])
	pos := 4
	// Each entry needs at least minCanonMapEntrySize bytes, so a count larger than
	// the remaining buffer can hold is structurally impossible. canonSpan bounds the
	// count by the remaining bytes; the divisor tightens that to what can actually fit.
	count, ok := canonSpan(declaredCount, len(b)-pos)
	if !ok || count > (len(b)-pos)/minCanonMapEntrySize {
		return nil, 0, fmt.Errorf("decodeCanonMap: declared %d entries exceeds %d possible in %d remaining bytes",
			declaredCount, (len(b)-pos)/minCanonMapEntrySize, len(b)-pos)
	}
	m := make(map[string]interface{})
	for i := 0; i < count; i++ {
		if pos+4 > len(b) {
			return nil, 0, fmt.Errorf("decodeCanonMap: key length truncated at entry %d", i)
		}
		declaredKeyLen := binary.BigEndian.Uint32(b[pos : pos+4])
		pos += 4
		klen, ok := canonSpan(declaredKeyLen, len(b)-pos)
		if !ok {
			return nil, 0, fmt.Errorf("decodeCanonMap: key bytes truncated at entry %d", i)
		}
		key := string(b[pos : pos+klen])
		pos += klen
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
// Returns the value, bytes consumed, and any error. It dispatches on the wire tag;
// each tag's layout lives in its own helper.
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
	case canonTagBool, canonTagInt, canonTagUint:
		return decodeCanonFixed(b)
	case canonTagFloat:
		return decodeCanonFloat(b)
	case canonTagString, canonTagOther:
		return decodeCanonString(b)
	case canonTagMap:
		return decodeCanonNestedMap(b, depth)
	case canonTagSlice:
		return decodeCanonSlice(b, depth)
	default:
		return nil, 0, fmt.Errorf("decodeCanonValue: unknown tag 0x%02x", b[0])
	}
}

// decodeCanonFixed decodes the fixed-width scalar tags: a bool (tag + 1 byte), an
// int64 or a uint64 (tag + 8 big-endian bytes). b[0] must be one of those tags.
func decodeCanonFixed(b []byte) (interface{}, int, error) {
	switch b[0] {
	case canonTagBool:
		if len(b) < 2 {
			return nil, 0, fmt.Errorf("decodeCanonValue: bool truncated")
		}
		return b[1] != 0x00, 2, nil
	case canonTagInt:
		if len(b) < 9 {
			return nil, 0, fmt.Errorf("decodeCanonValue: int64 truncated")
		}
		// #nosec G115 -- the inverse of the encoder's uint64(v) at appendCanonInt:
		// it reads back the same two's-complement bit pattern that was written, so
		// all 64 bits are preserved. This is a reinterpretation, not a narrowing.
		return int64(binary.BigEndian.Uint64(b[1:9])), 9, nil
	default:
		if len(b) < 9 {
			return nil, 0, fmt.Errorf("decodeCanonValue: uint64 truncated")
		}
		return binary.BigEndian.Uint64(b[1:9]), 9, nil
	}
}

// decodeCanonFloat decodes [F][uint32 length][shortest-round-trip decimal string].
func decodeCanonFloat(b []byte) (interface{}, int, error) {
	if len(b) < 5 {
		return nil, 0, fmt.Errorf("decodeCanonValue: float length truncated")
	}
	slen, ok := canonSpan(binary.BigEndian.Uint32(b[1:5]), len(b)-5)
	if !ok {
		return nil, 0, fmt.Errorf("decodeCanonValue: float string truncated")
	}
	s := string(b[5 : 5+slen])
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, 0, fmt.Errorf("decodeCanonValue: parse float %q: %w", s, err)
	}
	return v, 5 + slen, nil
}

// decodeCanonString decodes [S or O][uint32 length][bytes]; both tags decode to a
// Go string.
func decodeCanonString(b []byte) (interface{}, int, error) {
	if len(b) < 5 {
		return nil, 0, fmt.Errorf("decodeCanonValue: string/other length truncated")
	}
	slen, ok := canonSpan(binary.BigEndian.Uint32(b[1:5]), len(b)-5)
	if !ok {
		return nil, 0, fmt.Errorf("decodeCanonValue: string/other bytes truncated")
	}
	return string(b[5 : 5+slen]), 5 + slen, nil
}

// decodeCanonNestedMap decodes an M-tagged value: the tag byte followed by a map
// one nesting level deeper than the value that holds it.
func decodeCanonNestedMap(b []byte, depth int) (interface{}, int, error) {
	m, n, err := decodeCanonMap(b[1:], depth+1)
	if err != nil {
		return nil, 0, fmt.Errorf("decodeCanonValue: nested map: %w", err)
	}
	return m, 1 + n, nil
}

// decodeCanonSlice decodes [L][uint32 count][elements...], one nesting level
// deeper than the value that holds it.
func decodeCanonSlice(b []byte, depth int) (interface{}, int, error) {
	if len(b) < 5 {
		return nil, 0, fmt.Errorf("decodeCanonValue: slice count truncated")
	}
	declaredCount := binary.BigEndian.Uint32(b[1:5])
	pos := 5
	// Every element consumes at least one type-tag byte, so a count larger than
	// the remaining buffer is structurally impossible. Rejecting it here (rather
	// than discovering the truncation mid-loop) keeps a hostile header from
	// driving an allocation before a single element has been read.
	count, ok := canonSpan(declaredCount, len(b)-pos)
	if !ok {
		return nil, 0, fmt.Errorf("decodeCanonValue: declared %d slice elements exceeds %d remaining bytes",
			declaredCount, len(b)-pos)
	}
	// Grown incrementally rather than pre-sized from the declared count, so the
	// allocation tracks elements actually decoded instead of the declared header.
	elems := make([]interface{}, 0)
	for i := 0; i < count; i++ {
		v, n, err := decodeCanonValue(b[pos:], depth+1)
		if err != nil {
			return nil, 0, fmt.Errorf("decodeCanonValue: slice element %d: %w", i, err)
		}
		elems = append(elems, v)
		pos += n
	}
	return elems, pos, nil
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

// canonEncodeValue encodes a single value with its type tag. Scalars are routed to
// the width-specific helpers below; containers are normalised to the
// map[string]interface{} / []interface{} encodings so equivalent Go types produce
// identical bytes.
func canonEncodeValue(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case nil:
		return []byte{canonTagNull}, nil
	case bool:
		return canonEncodeBool(val), nil
	case string:
		return canonEncodeStringTag(canonTagString, []byte(val))
	case map[string]interface{}:
		return canonEncodeMapValue(val)
	case map[string]string:
		return canonEncodeStringMap(val)
	case []interface{}:
		return canonEncodeSlice(val)
	case []string:
		return canonEncodeStringSlice(val)
	case []map[string]interface{}:
		return canonEncodeMapSlice(val)
	}
	return canonEncodeNumberOrOther(v)
}

// canonEncodeStringMap normalises a map[string]string to map[string]interface{}
// so the encoding is identical to the map[string]interface{} path (sorted keys,
// length-prefix entries, decodable). Without it, map[string]string would fall to
// the O path, which produces Go's fmt.Sprintf("%v") string — opaque and not
// decodable.
func canonEncodeStringMap(m map[string]string) ([]byte, error) {
	converted := make(map[string]interface{}, len(m))
	for k, e := range m {
		converted[k] = e
	}
	return canonEncodeMapValue(converted)
}

// canonEncodeStringSlice normalises a []string to []interface{} so element
// encoding is identical to the []interface{} path — same type tag, same byte
// layout.
func canonEncodeStringSlice(v []string) ([]byte, error) {
	elems := make([]interface{}, len(v))
	for i, e := range v {
		elems[i] = e
	}
	return canonEncodeSlice(elems)
}

// canonEncodeMapSlice encodes a []map[string]interface{} explicitly.
// ADQueryResult.GenericObjects uses this type; %v on a slice of maps is
// collision-prone (space separator).
func canonEncodeMapSlice(v []map[string]interface{}) ([]byte, error) {
	elems := make([]interface{}, len(v))
	for i, e := range v {
		elems[i] = e
	}
	return canonEncodeSlice(elems)
}

// canonEncodeNumberOrOther encodes the numeric kinds, and falls back to the O tag
// for any other concrete type.
func canonEncodeNumberOrOther(v interface{}) ([]byte, error) {
	if n, ok := canonSignedInt(v); ok {
		return canonEncodeInt64(n), nil
	}
	if n, ok := canonUnsignedInt(v); ok {
		return canonEncodeUint64(n), nil
	}
	if f, ok := canonFloatValue(v); ok {
		return canonEncodeFloat(f)
	}
	// Fallback for any unexpected concrete type: encode as its %v string with
	// a distinct tag so it cannot collide with a real string value.
	// Known slice types that land here: []DirectoryUser, []DirectoryGroup,
	// []OrganizationalUnit — struct %v wraps each element in {}, providing
	// a higher collision bar than plain string slices, but new slice-of-struct
	// types appearing in AsMap() implementations should be given explicit cases.
	return canonEncodeStringTag(canonTagOther, []byte(fmt.Sprintf("%v", v)))
}

// canonSignedInt widens the built-in signed integer types to int64.
func canonSignedInt(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

// canonUnsignedInt widens the built-in unsigned integer types to uint64.
func canonUnsignedInt(v interface{}) (uint64, bool) {
	switch n := v.(type) {
	case uint:
		return uint64(n), true
	case uint8:
		return uint64(n), true
	case uint16:
		return uint64(n), true
	case uint32:
		return uint64(n), true
	case uint64:
		return n, true
	}
	return 0, false
}

// canonFloatValue widens the built-in float types to float64.
func canonFloatValue(v interface{}) (float64, bool) {
	switch f := v.(type) {
	case float32:
		return float64(f), true
	case float64:
		return f, true
	}
	return 0, false
}

// canonEncodeBool encodes a bool as [B][0x00|0x01].
func canonEncodeBool(v bool) []byte {
	b := byte(0x00)
	if v {
		b = 0x01
	}
	return []byte{canonTagBool, b}
}

// canonEncodeMapValue encodes a nested map as [canonTagMap] + its sorted entries.
func canonEncodeMapValue(m map[string]interface{}) ([]byte, error) {
	inner, err := canonEncodeMap(m)
	if err != nil {
		return nil, err
	}
	return append([]byte{canonTagMap}, inner...), nil
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
