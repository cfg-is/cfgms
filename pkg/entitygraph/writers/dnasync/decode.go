// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dnasync

// This file contains a self-contained decoder for the ADR-017 canonical fragment
// byte encoding. The encoding is defined in features/steward/dna/canonical.go and
// reproduced here because pkg/ must never import features/ (import direction rule).
// The algorithm is identical; only the package-private helper names differ.
//
// Format (from CanonicalizeFragment):
//
//	[uint32 BE: stable-field count]
//	For each field, sorted ascending by key:
//	  [uint32 BE: key byte-length] [key bytes]
//	  [1 byte: type tag]
//	  [type-specific value bytes]

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

// decodeCanonicalFragment reverses the canonical encoding, recovering the
// stable key-value pairs from canonical bytes.
//
// Returns an error when bytes are malformed or exceed maxDecodePayloadSize.
// On error callers should fall back to a minimal payload rather than failing
// the entire delta ingest.
func decodeCanonicalFragment(b []byte) (map[string]interface{}, error) {
	if len(b) > maxDecodePayloadSize {
		return nil, fmt.Errorf("dnasync/decode: %d bytes exceeds maximum %d", len(b), maxDecodePayloadSize)
	}
	m, n, err := decodeMap(b, 0)
	if err != nil {
		return nil, fmt.Errorf("dnasync/decode: %w", err)
	}
	if n != len(b) {
		return nil, fmt.Errorf("dnasync/decode: %d bytes consumed, %d total", n, len(b))
	}
	return m, nil
}

// maxDecodePayloadSize matches features/steward/dna.MaxCanonicalFragmentSize.
const maxDecodePayloadSize = 8 * 1024 * 1024

// maxDecodeDepth prevents stack overflow from adversarially nested maps.
const maxDecodeDepth = 32

// minMapEntrySize is the smallest number of bytes one map entry can occupy
// (4-byte key length + 1-byte type tag), used to bound declared counts.
const minMapEntrySize = 5

// canonTag* are the wire-format type tags matching CanonicalizeFragment's encoding.
const (
	canonTagNull   = byte('N')
	canonTagBool   = byte('B')
	canonTagInt    = byte('I')
	canonTagUint   = byte('U')
	canonTagFloat  = byte('F')
	canonTagString = byte('S')
	canonTagMap    = byte('M')
	canonTagSlice  = byte('L')
	canonTagOther  = byte('O')
)

// canonSpan converts a declared uint32 length to an int, validating it fits
// within the remaining buffer. Running in uint64 prevents signed overflow on
// 32-bit platforms.
//
// #nosec G115 -- conversions are safe: remaining is a non-negative slice length
// and declared is bounded by remaining before narrowing to int.
func canonSpan(declared uint32, remaining int) (int, bool) {
	if remaining < 0 {
		return 0, false
	}
	if uint64(declared) > uint64(remaining) {
		return 0, false
	}
	return int(declared), true
}

// decodeMap decodes [uint32 count][entries...] from b at the given nesting depth.
func decodeMap(b []byte, depth int) (map[string]interface{}, int, error) {
	if depth > maxDecodeDepth {
		return nil, 0, fmt.Errorf("decodeMap: nesting depth exceeds %d", maxDecodeDepth)
	}
	if len(b) < 4 {
		return nil, 0, fmt.Errorf("decodeMap: need 4 bytes for count, have %d", len(b))
	}
	declaredCount := binary.BigEndian.Uint32(b[:4])
	pos := 4
	count, ok := canonSpan(declaredCount, len(b)-pos)
	if !ok || count > (len(b)-pos)/minMapEntrySize {
		return nil, 0, fmt.Errorf("decodeMap: declared %d entries exceeds %d possible in %d remaining bytes",
			declaredCount, (len(b)-pos)/minMapEntrySize, len(b)-pos)
	}
	m := make(map[string]interface{})
	for i := 0; i < count; i++ {
		if pos+4 > len(b) {
			return nil, 0, fmt.Errorf("decodeMap: key length truncated at entry %d", i)
		}
		klen, ok := canonSpan(binary.BigEndian.Uint32(b[pos:pos+4]), len(b)-pos-4)
		if !ok {
			return nil, 0, fmt.Errorf("decodeMap: key bytes truncated at entry %d", i)
		}
		pos += 4
		key := string(b[pos : pos+klen])
		pos += klen
		v, n, err := decodeValue(b[pos:], depth)
		if err != nil {
			return nil, 0, fmt.Errorf("decodeMap: entry %q: %w", key, err)
		}
		m[key] = v
		pos += n
	}
	return m, pos, nil
}

// decodeValue decodes one type-tagged value from b at the given nesting depth.
func decodeValue(b []byte, depth int) (interface{}, int, error) {
	if depth > maxDecodeDepth {
		return nil, 0, fmt.Errorf("decodeValue: nesting depth exceeds %d", maxDecodeDepth)
	}
	if len(b) == 0 {
		return nil, 0, fmt.Errorf("decodeValue: empty buffer")
	}
	switch b[0] {
	case canonTagNull:
		return nil, 1, nil

	case canonTagBool:
		if len(b) < 2 {
			return nil, 0, fmt.Errorf("decodeValue: bool truncated")
		}
		return b[1] != 0x00, 2, nil

	case canonTagInt:
		if len(b) < 9 {
			return nil, 0, fmt.Errorf("decodeValue: int64 truncated")
		}
		// #nosec G115 -- reinterprets the same two's-complement bits written by the encoder.
		return int64(binary.BigEndian.Uint64(b[1:9])), 9, nil

	case canonTagUint:
		if len(b) < 9 {
			return nil, 0, fmt.Errorf("decodeValue: uint64 truncated")
		}
		return binary.BigEndian.Uint64(b[1:9]), 9, nil

	case canonTagFloat:
		if len(b) < 5 {
			return nil, 0, fmt.Errorf("decodeValue: float length truncated")
		}
		slen, ok := canonSpan(binary.BigEndian.Uint32(b[1:5]), len(b)-5)
		if !ok {
			return nil, 0, fmt.Errorf("decodeValue: float string truncated")
		}
		s := string(b[5 : 5+slen])
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, 0, fmt.Errorf("decodeValue: parse float %q: %w", s, err)
		}
		return v, 5 + slen, nil

	case canonTagString, canonTagOther:
		if len(b) < 5 {
			return nil, 0, fmt.Errorf("decodeValue: string/other length truncated")
		}
		slen, ok := canonSpan(binary.BigEndian.Uint32(b[1:5]), len(b)-5)
		if !ok {
			return nil, 0, fmt.Errorf("decodeValue: string/other bytes truncated")
		}
		return string(b[5 : 5+slen]), 5 + slen, nil

	case canonTagMap:
		m, n, err := decodeMap(b[1:], depth+1)
		if err != nil {
			return nil, 0, fmt.Errorf("decodeValue: nested map: %w", err)
		}
		return m, 1 + n, nil

	case canonTagSlice:
		if len(b) < 5 {
			return nil, 0, fmt.Errorf("decodeValue: slice count truncated")
		}
		declaredCount := binary.BigEndian.Uint32(b[1:5])
		pos := 5
		count, ok := canonSpan(declaredCount, len(b)-pos)
		if !ok {
			return nil, 0, fmt.Errorf("decodeValue: declared %d slice elements exceeds %d remaining bytes",
				declaredCount, len(b)-pos)
		}
		elems := make([]interface{}, 0)
		for i := 0; i < count; i++ {
			v, n, err := decodeValue(b[pos:], depth+1)
			if err != nil {
				return nil, 0, fmt.Errorf("decodeValue: slice element %d: %w", i, err)
			}
			elems = append(elems, v)
			pos += n
		}
		return elems, pos, nil

	default:
		return nil, 0, fmt.Errorf("decodeValue: unknown tag 0x%02x", b[0])
	}
}
