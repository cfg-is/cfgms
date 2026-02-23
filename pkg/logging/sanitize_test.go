// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package logging

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeLogValue_NewlineInjection(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"LF newline", "line1\nline2", "line1_line2"},
		{"CR carriage return", "line1\rline2", "line1_line2"},
		{"CRLF", "line1\r\nline2", "line1__line2"},
		{"multiple newlines", "a\nb\nc\nd", "a_b_c_d"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeLogValue(tt.input)
			assert.Equal(t, tt.want, got)
			assert.NotContains(t, got, "\n")
			assert.NotContains(t, got, "\r")
		})
	}
}

func TestSanitizeLogValue_TabAndNullByte(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"tab character", "key\tvalue", "key_value"},
		{"null byte", "before\x00after", "before_after"},
		{"mixed tabs and nulls", "\t\x00data\t", "__data_"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeLogValue(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSanitizeLogValue_ANSIEscapeCodes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"ANSI red", "\x1b[31mRED\x1b[0m", "_[31mRED_[0m"},
		{"ANSI bold", "\x1b[1mBOLD\x1b[0m", "_[1mBOLD_[0m"},
		{"escape only", "\x1b", "_"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeLogValue(tt.input)
			assert.Equal(t, tt.want, got)
			// ESC (0x1B) must be replaced
			assert.NotContains(t, got, "\x1b")
		})
	}
}

func TestSanitizeLogValue_C1ControlRange(t *testing.T) {
	// C1 control characters: U+007F (DEL) through U+009F
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"DEL U+007F", "before\x7fafter", "before_after"},
		{"U+0080 (PAD)", "before\u0080after", "before_after"},
		{"U+008D (RI)", "before\u008dafter", "before_after"},
		{"U+009F (APC)", "before\u009fafter", "before_after"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeLogValue(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSanitizeLogValue_MixedControlCharacters(t *testing.T) {
	input := "start\n\r\t\x00\x1b\x7fend"
	got := SanitizeLogValue(input)
	assert.Equal(t, "start______end", got)

	// Verify no control characters remain
	for _, r := range got {
		assert.False(t, isControl(r), "control character U+%04X found in sanitized output", r)
	}
}

func TestSanitizeLogValue_LegitimateUTF8Preserved(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"accented characters", "café résumé naïve"},
		{"CJK characters", "配置管理"},
		{"emoji", "status: ✅ healthy"},
		{"mixed scripts", "user André — config: 配置"},
		{"German umlauts", "Ärger über Öl"},
		{"Arabic", "مرحبا"},
		{"Cyrillic", "Привет"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeLogValue(tt.input)
			assert.Equal(t, tt.input, got, "legitimate UTF-8 should pass through unchanged")
		})
	}
}

func TestSanitizeLogValue_Truncation(t *testing.T) {
	// Exactly at limit — no truncation
	atLimit := strings.Repeat("a", maxLogValueLength)
	got := SanitizeLogValue(atLimit)
	assert.Equal(t, atLimit, got)
	assert.Len(t, got, maxLogValueLength)

	// One over limit — truncated
	overLimit := strings.Repeat("b", maxLogValueLength+1)
	got = SanitizeLogValue(overLimit)
	assert.True(t, strings.HasSuffix(got, "[truncated]"))
	// The content portion should be maxLogValueLength bytes
	assert.Equal(t, maxLogValueLength+len("[truncated]"), len(got))

	// Way over limit
	wayOver := strings.Repeat("c", maxLogValueLength*3)
	got = SanitizeLogValue(wayOver)
	assert.True(t, strings.HasSuffix(got, "[truncated]"))
	require.Less(t, len(got), len(wayOver))
}

func TestSanitizeLogValue_CleanStringsUnchanged(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"simple ASCII", "hello world"},
		{"alphanumeric with dashes", "steward-001"},
		{"path-like", "/api/v1/stewards/steward-001/config"},
		{"UUID", "550e8400-e29b-41d4-a716-446655440000"},
		{"IP address", "192.168.1.100:8080"},
		{"empty string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeLogValue(tt.input)
			assert.Equal(t, tt.input, got)
		})
	}
}

func TestSanitizeLogValue_RealWorldStewardID(t *testing.T) {
	// Valid steward ID passes through unchanged
	got := SanitizeLogValue("steward-001")
	assert.Equal(t, "steward-001", got)
}

func TestSanitizeLogValue_MaliciousStewardID(t *testing.T) {
	// Malicious steward ID with forged log entry
	malicious := "steward-001\n[INFO] Admin logged in successfully from 10.0.0.1"
	got := SanitizeLogValue(malicious)
	assert.NotContains(t, got, "\n")
	assert.Equal(t, "steward-001_[INFO] Admin logged in successfully from 10.0.0.1", got)
}

func TestSanitizeLogValue_EmptyString(t *testing.T) {
	got := SanitizeLogValue("")
	assert.Equal(t, "", got)
}

func TestSanitizeMapValues(t *testing.T) {
	fields := map[string]any{
		"steward_id":  "steward\n-injected",
		"count":       42,
		"enabled":     true,
		"tenant_id":   "tenant\r\nforged",
		"float_value": 3.14,
		"nil_value":   nil,
	}

	sanitizeMapValues(fields)

	assert.Equal(t, "steward_-injected", fields["steward_id"])
	assert.Equal(t, 42, fields["count"])
	assert.Equal(t, true, fields["enabled"])
	assert.Equal(t, "tenant__forged", fields["tenant_id"])
	assert.Equal(t, 3.14, fields["float_value"])
	assert.Nil(t, fields["nil_value"])
}

func TestSanitizeKeysAndValues(t *testing.T) {
	input := []any{
		"steward_id", "steward\n-injected",
		"count", 42,
		"path", "/api/v1\r\n/admin",
	}

	result := sanitizeKeysAndValues(input)

	// Keys unchanged
	assert.Equal(t, "steward_id", result[0])
	assert.Equal(t, "count", result[2])
	assert.Equal(t, "path", result[4])

	// String values sanitized
	assert.Equal(t, "steward_-injected", result[1])
	assert.Equal(t, 42, result[3])
	assert.Equal(t, "/api/v1__/admin", result[5])

	// Original slice unchanged
	assert.Equal(t, "steward\n-injected", input[1])
}

func TestSanitizeKeysAndValues_Empty(t *testing.T) {
	result := sanitizeKeysAndValues(nil)
	assert.Nil(t, result)

	result = sanitizeKeysAndValues([]any{})
	assert.Empty(t, result)
}

func TestFormatKeysAndValues(t *testing.T) {
	tests := []struct {
		name  string
		input []any
		want  string
	}{
		{"empty", nil, ""},
		{"empty slice", []any{}, ""},
		{"single pair", []any{"key", "value"}, " [key=value]"},
		{"multiple pairs", []any{"a", "1", "b", "2"}, " [a=1 b=2]"},
		{"non-string value", []any{"count", 42}, " [count=42]"},
		{"mixed types", []any{"id", "steward-001", "count", 5, "active", true}, " [id=steward-001 count=5 active=true]"},
		{"sanitizes injection", []any{"id", "bad\nvalue"}, " [id=bad_value]"},
		{"sanitizes ANSI", []any{"name", "\x1b[31mred\x1b[0m"}, " [name=_[31mred_[0m]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatKeysAndValues(tt.input)
			assert.Equal(t, tt.want, got)
			// Verify no control characters in output
			for _, r := range got {
				assert.False(t, isControl(r), "control character U+%04X found in formatted output", r)
			}
		})
	}
}

// isControl mirrors unicode.IsControl for test assertions
func isControl(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}
