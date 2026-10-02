// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package interfaces

import "strings"

// EscapeLikePattern escapes the SQL LIKE metacharacters '%', '_', and the
// escape character '\' itself, so s is matched as a literal substring rather
// than a wildcard pattern when concatenated into a LIKE clause. Callers must
// pair this with "ESCAPE '\'" on the LIKE clause; PostgreSQL and SQLite both
// support it.
//
// Both entity graph providers build LIKE patterns from subject strings
// (arbitrary EID local-ids) — this is the one place that escaping lives so
// database and sqlite do not carry two copies of the same logic.
func EscapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}
