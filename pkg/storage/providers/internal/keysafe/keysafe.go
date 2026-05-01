// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package keysafe provides path-safety validators for storage key fields.
// It uses only the standard library to avoid import cycles with other CFGMS packages.
package keysafe

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// windowsDriveRE matches Windows drive letter prefixes like "C:" or "c:".
var windowsDriveRE = regexp.MustCompile(`^[A-Za-z]:`)

// ValidateLeafField validates a single path component that must not contain
// any directory separators or traversal sequences.
//
// Rejects: "/", "\", "..", "." (single dot), null bytes, leading/trailing
// whitespace, leading dot, trailing dot or space, absolute paths, and
// Windows drive letters. Empty string is allowed — callers enforce non-emptiness
// when required.
func ValidateLeafField(fieldName, value string) error {
	if value == "" {
		return nil
	}
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("invalid %s %q: must not contain null bytes", fieldName, sanitize(value))
	}
	if value != strings.TrimFunc(value, unicode.IsSpace) {
		return fmt.Errorf("invalid %s %q: must not have leading or trailing whitespace", fieldName, sanitize(value))
	}
	if strings.HasSuffix(value, ".") {
		return fmt.Errorf("invalid %s %q: must not end with '.'", fieldName, sanitize(value))
	}
	if strings.HasPrefix(value, ".") {
		return fmt.Errorf("invalid %s %q: must not start with '.'", fieldName, sanitize(value))
	}
	if strings.ContainsAny(value, `/\`) {
		return fmt.Errorf("invalid %s %q: must not contain path separators", fieldName, sanitize(value))
	}
	if filepath.IsAbs(value) {
		return fmt.Errorf("invalid %s %q: must not be an absolute path", fieldName, sanitize(value))
	}
	if windowsDriveRE.MatchString(value) {
		return fmt.Errorf("invalid %s %q: must not contain a Windows drive letter", fieldName, sanitize(value))
	}
	return nil
}

// ValidateTenantID validates a hierarchical tenant ID where internal "/" separators
// are legitimate (e.g. "root/msp-a/client-1") but traversal sequences and
// structural anomalies are not.
//
// Rejects: empty string, null bytes, backslash, leading/trailing "/", "//" runs,
// and any segment equal to ".." or ".".
func ValidateTenantID(value string) error {
	if value == "" {
		return fmt.Errorf("tenant ID must not be empty")
	}
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("invalid tenant ID %q: must not contain null bytes", sanitize(value))
	}
	if strings.ContainsRune(value, '\\') {
		return fmt.Errorf("invalid tenant ID %q: must not contain backslash", sanitize(value))
	}
	if strings.HasPrefix(value, "/") {
		return fmt.Errorf("invalid tenant ID %q: must not start with '/'", sanitize(value))
	}
	if strings.HasSuffix(value, "/") {
		return fmt.Errorf("invalid tenant ID %q: must not end with '/'", sanitize(value))
	}
	if strings.Contains(value, "//") {
		return fmt.Errorf("invalid tenant ID %q: must not contain '//'", sanitize(value))
	}
	for _, seg := range strings.Split(value, "/") {
		if seg == ".." {
			return fmt.Errorf("invalid tenant ID %q: must not contain '..' segments", sanitize(value))
		}
		if seg == "." {
			return fmt.Errorf("invalid tenant ID %q: must not contain '.' segments", sanitize(value))
		}
	}
	return nil
}

// sanitize strips control characters and limits length to prevent log injection
// when the value is included in error messages.
func sanitize(value string) string {
	const maxLen = 100
	var sb strings.Builder
	count := 0
	for _, r := range value {
		if count >= maxLen {
			sb.WriteString("...")
			break
		}
		if r < 0x20 || r == 0x7f {
			sb.WriteRune('?')
		} else {
			sb.WriteRune(r)
		}
		count++
	}
	return sb.String()
}
