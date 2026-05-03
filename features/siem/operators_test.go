// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package siem

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyOperator(t *testing.T) {
	tests := []struct {
		name           string
		operator       string
		fieldValue     string
		conditionValue string
		caseSensitive  bool
		want           bool
	}{
		// equals
		{name: "equals/match", operator: "equals", fieldValue: "foo", conditionValue: "foo", caseSensitive: true, want: true},
		{name: "equals/no-match", operator: "equals", fieldValue: "foo", conditionValue: "bar", caseSensitive: true, want: false},
		{name: "equals/case-insensitive-match", operator: "equals", fieldValue: "FOO", conditionValue: "foo", caseSensitive: false, want: true},
		{name: "equals/case-sensitive-no-match", operator: "equals", fieldValue: "FOO", conditionValue: "foo", caseSensitive: true, want: false},

		// not_equals
		{name: "not_equals/no-match", operator: "not_equals", fieldValue: "foo", conditionValue: "foo", caseSensitive: true, want: false},
		{name: "not_equals/match", operator: "not_equals", fieldValue: "foo", conditionValue: "bar", caseSensitive: true, want: true},
		{name: "not_equals/case-insensitive-no-match", operator: "not_equals", fieldValue: "FOO", conditionValue: "foo", caseSensitive: false, want: false},
		{name: "not_equals/case-sensitive-match", operator: "not_equals", fieldValue: "FOO", conditionValue: "foo", caseSensitive: true, want: true},

		// contains
		{name: "contains/match", operator: "contains", fieldValue: "foobar", conditionValue: "oba", caseSensitive: true, want: true},
		{name: "contains/no-match", operator: "contains", fieldValue: "foobar", conditionValue: "xyz", caseSensitive: true, want: false},
		{name: "contains/case-insensitive-match", operator: "contains", fieldValue: "FOOBAR", conditionValue: "oba", caseSensitive: false, want: true},
		{name: "contains/case-sensitive-no-match", operator: "contains", fieldValue: "FOOBAR", conditionValue: "oba", caseSensitive: true, want: false},

		// not_contains
		{name: "not_contains/match", operator: "not_contains", fieldValue: "foobar", conditionValue: "xyz", caseSensitive: true, want: true},
		{name: "not_contains/no-match", operator: "not_contains", fieldValue: "foobar", conditionValue: "oba", caseSensitive: true, want: false},
		{name: "not_contains/case-insensitive-no-match", operator: "not_contains", fieldValue: "FOOBAR", conditionValue: "oba", caseSensitive: false, want: false},
		{name: "not_contains/case-sensitive-match", operator: "not_contains", fieldValue: "FOOBAR", conditionValue: "oba", caseSensitive: true, want: true},

		// starts_with
		{name: "starts_with/match", operator: "starts_with", fieldValue: "foobar", conditionValue: "foo", caseSensitive: true, want: true},
		{name: "starts_with/no-match", operator: "starts_with", fieldValue: "foobar", conditionValue: "bar", caseSensitive: true, want: false},
		{name: "starts_with/case-insensitive-match", operator: "starts_with", fieldValue: "FOOBAR", conditionValue: "foo", caseSensitive: false, want: true},
		{name: "starts_with/case-sensitive-no-match", operator: "starts_with", fieldValue: "FOOBAR", conditionValue: "foo", caseSensitive: true, want: false},

		// ends_with
		{name: "ends_with/match", operator: "ends_with", fieldValue: "foobar", conditionValue: "bar", caseSensitive: true, want: true},
		{name: "ends_with/no-match", operator: "ends_with", fieldValue: "foobar", conditionValue: "foo", caseSensitive: true, want: false},
		{name: "ends_with/case-insensitive-match", operator: "ends_with", fieldValue: "FOOBAR", conditionValue: "bar", caseSensitive: false, want: true},
		{name: "ends_with/case-sensitive-no-match", operator: "ends_with", fieldValue: "FOOBAR", conditionValue: "bar", caseSensitive: true, want: false},

		// exists
		{name: "exists/non-empty", operator: "exists", fieldValue: "something", conditionValue: "", caseSensitive: true, want: true},
		{name: "exists/empty", operator: "exists", fieldValue: "", conditionValue: "", caseSensitive: true, want: false},
		{name: "exists/caseSensitive-ignored", operator: "exists", fieldValue: "x", conditionValue: "", caseSensitive: false, want: true},

		// not_exists
		{name: "not_exists/empty", operator: "not_exists", fieldValue: "", conditionValue: "", caseSensitive: true, want: true},
		{name: "not_exists/non-empty", operator: "not_exists", fieldValue: "something", conditionValue: "", caseSensitive: true, want: false},
		{name: "not_exists/caseSensitive-ignored", operator: "not_exists", fieldValue: "", conditionValue: "", caseSensitive: false, want: true},

		// regex
		{name: "regex/match", operator: "regex", fieldValue: "error code 404", conditionValue: `code \d+`, caseSensitive: true, want: true},
		{name: "regex/no-match", operator: "regex", fieldValue: "everything is fine", conditionValue: `code \d+`, caseSensitive: true, want: false},
		{name: "regex/invalid-pattern", operator: "regex", fieldValue: "anything", conditionValue: `[invalid`, caseSensitive: true, want: false},
		{name: "regex/caseSensitive-ignored", operator: "regex", fieldValue: "FOO", conditionValue: `foo`, caseSensitive: false, want: false},

		// greater_than (not yet supported)
		{name: "greater_than/returns-false", operator: "greater_than", fieldValue: "100", conditionValue: "50", caseSensitive: true, want: false},

		// less_than (not yet supported)
		{name: "less_than/returns-false", operator: "less_than", fieldValue: "10", conditionValue: "50", caseSensitive: true, want: false},

		// unknown operator
		{name: "unknown/returns-false", operator: "unknown_op", fieldValue: "foo", conditionValue: "foo", caseSensitive: true, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := applyOperator(tc.operator, tc.fieldValue, tc.conditionValue, tc.caseSensitive)
			require.Equal(t, tc.want, got)
		})
	}
}
