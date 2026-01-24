// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package security

import (
	"regexp"
)

// identifierPattern matches valid identifiers (alphanumeric + dash/underscore)
var identifierPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// SanitizeIdentifier validates and returns an identifier safe for logging.
// Returns the identifier if valid, or "[INVALID]" if validation fails.
// This acts as a sanitization barrier for CodeQL taint tracking.
func SanitizeIdentifier(id string) string {
	if id == "" {
		return "[EMPTY]"
	}

	if len(id) > 256 {
		return "[TOO_LONG]"
	}

	if identifierPattern.MatchString(id) {
		return id
	}

	return "[INVALID]"
}

// IsValidIdentifier checks if an identifier is safe for logging
func IsValidIdentifier(id string) bool {
	if id == "" || len(id) > 256 {
		return false
	}
	return identifierPattern.MatchString(id)
}
