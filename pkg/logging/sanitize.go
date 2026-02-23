// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package logging

import (
	"strings"
	"unicode"
)

// maxLogValueLength is the maximum length for a sanitized log value.
// Values exceeding this length are truncated with a [truncated] suffix.
const maxLogValueLength = 1024

// SanitizeLogValue sanitizes a string for safe inclusion in log output.
// It replaces all Unicode control characters (C0: U+0000-U+001F, C1: U+007F-U+009F)
// with underscores and truncates values exceeding 1024 characters.
//
// This function uses strings.Builder to construct a new string, which breaks
// CodeQL taint tracking (CWE-117) when used at log call sites.
//
// Usage:
//
//	logger.Info("request received", "steward_id", logging.SanitizeLogValue(stewardID))
func SanitizeLogValue(s string) string {
	if s == "" {
		return s
	}

	// Truncate long values to prevent log flooding
	truncated := false
	if len(s) > maxLogValueLength {
		s = s[:maxLogValueLength]
		truncated = true
	}

	// Use strings.Builder to construct a new string (breaks CodeQL taint tracking)
	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		if unicode.IsControl(r) {
			b.WriteByte('_')
		} else {
			b.WriteRune(r)
		}
	}

	if truncated {
		b.WriteString("[truncated]")
	}

	return b.String()
}

// sanitizeMapValues sanitizes all string values in a map for safe logging.
// Non-string values are left unchanged.
func sanitizeMapValues(fields map[string]any) {
	for k, v := range fields {
		if str, ok := v.(string); ok {
			fields[k] = SanitizeLogValue(str)
		}
	}
}

// sanitizeKeysAndValues sanitizes string values in a variadic key-value slice.
// Only values at odd indices (the "value" positions) that are strings are sanitized.
// Returns a new slice with sanitized values.
func sanitizeKeysAndValues(keysAndValues []any) []any {
	if len(keysAndValues) == 0 {
		return keysAndValues
	}

	result := make([]any, len(keysAndValues))
	copy(result, keysAndValues)

	for i := 1; i < len(result); i += 2 {
		if str, ok := result[i].(string); ok {
			result[i] = SanitizeLogValue(str)
		}
	}

	return result
}
