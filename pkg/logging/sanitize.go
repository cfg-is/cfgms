// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package logging

import (
	"fmt"
	"strings"
)

// maxLogValueLength is the maximum length for a sanitized log value.
// Values exceeding this length are truncated with a [truncated] suffix.
const maxLogValueLength = 1024

// logSanitizer replaces all Unicode control characters with underscores.
// Built once at package init using a trie-based replacer for single-pass performance.
//
// Coverage: C0 (U+0000-U+001F), DEL (U+007F), C1 (U+0080-U+009F) — 65 characters total.
// CodeQL recognizes strings.NewReplacer as a sanitizer when \n and \r are explicitly listed,
// which resolves go/log-injection (CWE-117) taint tracking through the logging infrastructure.
var logSanitizer = strings.NewReplacer(
	// C0 control characters (U+0000 - U+001F)
	"\x00", "_", // NUL
	"\x01", "_", // SOH
	"\x02", "_", // STX
	"\x03", "_", // ETX
	"\x04", "_", // EOT
	"\x05", "_", // ENQ
	"\x06", "_", // ACK
	"\x07", "_", // BEL
	"\x08", "_", // BS
	"\x09", "_", // HT (tab)
	"\x0a", "_", // LF (newline) — CWE-117 log line forgery
	"\x0b", "_", // VT
	"\x0c", "_", // FF
	"\x0d", "_", // CR (carriage return) — CWE-117 log line forgery
	"\x0e", "_", // SO
	"\x0f", "_", // SI
	"\x10", "_", // DLE
	"\x11", "_", // DC1
	"\x12", "_", // DC2
	"\x13", "_", // DC3
	"\x14", "_", // DC4
	"\x15", "_", // NAK
	"\x16", "_", // SYN
	"\x17", "_", // ETB
	"\x18", "_", // CAN
	"\x19", "_", // EM
	"\x1a", "_", // SUB
	"\x1b", "_", // ESC — ANSI escape sequences
	"\x1c", "_", // FS
	"\x1d", "_", // GS
	"\x1e", "_", // RS
	"\x1f", "_", // US
	// DEL (U+007F)
	"\x7f", "_",
	// C1 control characters (U+0080 - U+009F)
	"\u0080", "_", // PAD
	"\u0081", "_", // HOP
	"\u0082", "_", // BPH
	"\u0083", "_", // NBH
	"\u0084", "_", // IND
	"\u0085", "_", // NEL
	"\u0086", "_", // SSA
	"\u0087", "_", // ESA
	"\u0088", "_", // HTS
	"\u0089", "_", // HTJ
	"\u008a", "_", // VTS
	"\u008b", "_", // PLD
	"\u008c", "_", // PLU
	"\u008d", "_", // RI
	"\u008e", "_", // SS2
	"\u008f", "_", // SS3
	"\u0090", "_", // DCS
	"\u0091", "_", // PU1
	"\u0092", "_", // PU2
	"\u0093", "_", // STS
	"\u0094", "_", // CCH
	"\u0095", "_", // MW
	"\u0096", "_", // SPA
	"\u0097", "_", // EPA
	"\u0098", "_", // SOS
	"\u0099", "_", // SGCI
	"\u009a", "_", // SCI
	"\u009b", "_", // CSI
	"\u009c", "_", // ST
	"\u009d", "_", // OSC
	"\u009e", "_", // PM
	"\u009f", "_", // APC
)

// SanitizeLogValue sanitizes a string for safe inclusion in log output.
// It replaces all Unicode control characters (C0: U+0000-U+001F, DEL: U+007F,
// C1: U+0080-U+009F) with underscores and truncates values exceeding 1024 characters.
//
// Uses strings.NewReplacer for single-pass trie-based replacement. CodeQL recognizes
// this pattern as a log injection sanitizer (CWE-117), resolving taint tracking alerts
// at both call sites and within the logging infrastructure.
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

	s = logSanitizer.Replace(s)

	if truncated {
		return s + "[truncated]"
	}

	return s
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

// formatKeysAndValues formats key-value pairs into a sanitized string.
// Returns an empty string if no key-value pairs are provided, otherwise returns
// a space-prefixed formatted string like " [key1=value1 key2=value2]".
func formatKeysAndValues(keysAndValues []any) string {
	if len(keysAndValues) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString(" [")

	for i := 0; i < len(keysAndValues)-1; i += 2 {
		if i > 0 {
			b.WriteByte(' ')
		}

		// Keys are internal constants, not user input — format directly
		key := fmt.Sprintf("%v", keysAndValues[i])
		b.WriteString(key)
		b.WriteByte('=')

		// Values may contain user input — sanitize strings through SanitizeLogValue
		val := keysAndValues[i+1]
		if str, ok := val.(string); ok {
			b.WriteString(SanitizeLogValue(str))
		} else {
			fmt.Fprintf(&b, "%v", val)
		}
	}

	b.WriteByte(']')
	return b.String()
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
