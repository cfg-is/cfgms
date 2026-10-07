// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package dnasync

import "fmt"

// osqueryDefaultMaxFieldBytes is the default per-field byte limit for
// string values in osquery-authority host:* fragments.
const osqueryDefaultMaxFieldBytes = 512

// osqueryFragmentBounds declares the validation rules for one curated
// osquery host:* fragment kind.
type osqueryFragmentBounds struct {
	// defaultMaxBytes caps every string field in this kind.
	defaultMaxBytes int
	// fieldOverrides maps specific field names to a different byte cap.
	// nil or empty → use defaultMaxBytes for all fields.
	fieldOverrides map[string]int
}

// osqueryBoundsTable maps fragment_id to its declared bounds.
// Only the four curated host:* kinds are present; any other fragment_id
// resolves to no bounds and passes validation unchanged.
//
// Field names mirror features/steward/dna/fragments.go hostFactFragmentSpecs.
var osqueryBoundsTable = map[string]osqueryFragmentBounds{
	"host:cpu": {
		defaultMaxBytes: osqueryDefaultMaxFieldBytes,
		// cpu_flags is a space-separated list of all CPU feature flags; a
		// server CPU can have 100+ flags of 3–15 chars each, reaching ~2 KB.
		fieldOverrides: map[string]int{"cpu_flags": 4096},
	},
	"host:memory": {
		// Every host:memory field is a short numeric or enum string, so this
		// kind is capped tighter than the package default.
		defaultMaxBytes: 256,
	},
	"host:os": {
		defaultMaxBytes: osqueryDefaultMaxFieldBytes,
	},
	"host:bios": {
		defaultMaxBytes: osqueryDefaultMaxFieldBytes,
	},
}

// validateOsqueryCanonicalBytes decodes the canonical bytes of an
// osquery-authority host:* fragment and checks every string field against
// the declared bounds for that fragment_id:
//
//   - byte length ≤ declared cap for that field (or the kind default)
//   - printable ASCII only (0x20–0x7E); no control characters, no null bytes
//
// Returns nil when fragID has no entry in osqueryBoundsTable (unknown kinds
// pass through unchanged) or when canonBytes is empty.
// Returns a non-nil error naming the offending field on first violation.
func validateOsqueryCanonicalBytes(fragID string, canonBytes []byte) error {
	bounds, ok := osqueryBoundsTable[fragID]
	if !ok {
		return nil
	}
	if len(canonBytes) == 0 {
		return nil
	}

	fields, err := decodeCanonicalFragment(canonBytes)
	if err != nil {
		return fmt.Errorf("osquery fragment %q: malformed canonical bytes: %w", fragID, err)
	}

	return validateOsqueryFields(fragID, bounds, fields)
}

// validateOsqueryFields checks a decoded map[string]interface{} payload against
// the declared bounds. Recursion into nested maps is not performed — only top-level
// string values are validated (nested maps are opaque hardware-detail sub-objects
// with no declared field schema at this validation layer).
func validateOsqueryFields(fragID string, bounds osqueryFragmentBounds, fields map[string]interface{}) error {
	for k, v := range fields {
		s, ok := v.(string)
		if !ok {
			continue
		}

		maxBytes := bounds.defaultMaxBytes
		if override, ok := bounds.fieldOverrides[k]; ok {
			maxBytes = override
		}

		if len(s) > maxBytes {
			return fmt.Errorf("osquery fragment %q: field %q byte length %d exceeds %d-byte limit",
				fragID, k, len(s), maxBytes)
		}

		if !isPrintableASCII(s) {
			return fmt.Errorf("osquery fragment %q: field %q contains non-printable or non-ASCII characters",
				fragID, k)
		}
	}
	return nil
}

// isPrintableASCII reports whether every byte of s is a printable ASCII
// character (0x20 space through 0x7E tilde). Returns true for the empty string.
func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
}
