// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package audit

// RedactString replaces the value portion of key=value pairs in s where the key
// matches a sensitive substring from RedactedKeys. Use this on free-form text
// (e.g. stdout/stderr) to catch patterns like password=... or token=... that appear
// inline in script output. This is distinct from RedactMap: RedactString is pattern-
// based over free-form text; RedactMap is key-based over a structured map.
func RedactString(s string) string {
	return redactErrorMessage(s)
}

// RedactMap returns a copy of m with string values replaced by [REDACTED] when the
// lowercased key contains any substring from RedactedKeys. Non-string values are
// copied as-is. Returns nil when m is nil.
func RedactMap(m map[string]interface{}) map[string]interface{} {
	return redactMap(m)
}
