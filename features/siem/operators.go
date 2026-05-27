// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package siem

import (
	"regexp"
	"strings"
)

// applyOperator evaluates a single SIEM operator against two string values.
// caseSensitive applies only to string comparison operators (equals, not_equals,
// contains, not_contains, starts_with, ends_with). The regex, exists, not_exists,
// greater_than, and less_than operators ignore caseSensitive.
func applyOperator(operator, fieldValue, conditionValue string, caseSensitive bool) bool {
	switch operator {
	case "exists":
		return fieldValue != ""
	case "not_exists":
		return fieldValue == ""
	case "regex":
		matched, err := regexp.MatchString(conditionValue, fieldValue)
		return err == nil && matched
	case "greater_than":
		// numeric comparison not yet supported
		return false
	case "less_than":
		// numeric comparison not yet supported
		return false
	}

	fv := fieldValue
	cv := conditionValue
	if !caseSensitive {
		fv = strings.ToLower(fieldValue)
		cv = strings.ToLower(conditionValue)
	}

	switch operator {
	case "equals":
		return fv == cv
	case "not_equals":
		return fv != cv
	case "contains":
		return strings.Contains(fv, cv)
	case "not_contains":
		return !strings.Contains(fv, cv)
	case "starts_with":
		return strings.HasPrefix(fv, cv)
	case "ends_with":
		return strings.HasSuffix(fv, cv)
	default:
		return false
	}
}
