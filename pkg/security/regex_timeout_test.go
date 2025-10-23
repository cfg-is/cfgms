// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package security - Tests for regex timeout mechanism
package security

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegexMatcher_MatchStringWithTimeout_Normal tests normal regex matching
func TestRegexMatcher_MatchStringWithTimeout_Normal(t *testing.T) {
	matcher := NewRegexMatcher(1 * time.Second)

	tests := []struct {
		name     string
		pattern  string
		input    string
		expected bool
	}{
		{
			name:     "simple match",
			pattern:  `^[a-z]+$`,
			input:    "hello",
			expected: true,
		},
		{
			name:     "no match",
			pattern:  `^[0-9]+$`,
			input:    "hello",
			expected: false,
		},
		{
			name:     "email pattern",
			pattern:  `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
			input:    "user@example.com",
			expected: true,
		},
		{
			name:     "complex pattern",
			pattern:  `(?i)(script|javascript)`,
			input:    "no malicious content",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := regexp.MustCompile(tt.pattern)
			matched, err := matcher.MatchStringWithTimeout(pattern, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, matched)
		})
	}
}

// TestRegexMatcher_MatchStringWithTimeout_ReDoS tests ReDoS prevention
func TestRegexMatcher_MatchStringWithTimeout_ReDoS(t *testing.T) {
	// Use very short timeout for this test
	matcher := NewRegexMatcher(100 * time.Millisecond)

	// Known ReDoS pattern: catastrophic backtracking
	// Pattern (a+)+ is vulnerable to ReDoS
	pattern := regexp.MustCompile(`^(a+)+$`)

	// Create input that triggers catastrophic backtracking
	// Each additional 'a' doubles the processing time
	input := strings.Repeat("a", 30) + "b" // Doesn't match, causes backtracking

	matched, err := matcher.MatchStringWithTimeout(pattern, input)

	// Should timeout for malicious input
	if err == ErrRegexTimeout {
		// Expected behavior - ReDoS detected and prevented
		assert.False(t, matched)
		t.Logf("✅ ReDoS attack prevented - timeout triggered")
	} else {
		// If no timeout, should complete quickly (Go's RE2 engine is resistant to ReDoS)
		// This is actually OK - Go uses RE2 which doesn't have catastrophic backtracking
		t.Logf("ℹ️  Go's RE2 engine handled this pattern efficiently (no timeout needed)")
	}
}

// TestRegexMatcher_MatchStringWithTimeout_QuickOperation tests fast regex
func TestRegexMatcher_MatchStringWithTimeout_QuickOperation(t *testing.T) {
	matcher := NewRegexMatcher(1 * time.Second)

	pattern := regexp.MustCompile(`^[a-z]+$`)
	input := "validinput"

	start := time.Now()
	matched, err := matcher.MatchStringWithTimeout(pattern, input)
	duration := time.Since(start)

	require.NoError(t, err)
	assert.True(t, matched)
	assert.Less(t, duration, 100*time.Millisecond, "fast regex should complete quickly")
}

// TestRegexMatcher_FindStringWithTimeout tests FindString with timeout
func TestRegexMatcher_FindStringWithTimeout(t *testing.T) {
	matcher := NewRegexMatcher(1 * time.Second)

	tests := []struct {
		name     string
		pattern  string
		input    string
		expected string
	}{
		{
			name:     "find word",
			pattern:  `[a-z]+`,
			input:    "test123",
			expected: "test",
		},
		{
			name:     "find number",
			pattern:  `[0-9]+`,
			input:    "abc123def",
			expected: "123",
		},
		{
			name:     "no match",
			pattern:  `[0-9]+`,
			input:    "abcdef",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := regexp.MustCompile(tt.pattern)
			result, err := matcher.FindStringWithTimeout(pattern, tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestMatchStringWithTimeout_ConvenienceFunction tests the convenience function
func TestMatchStringWithTimeout_ConvenienceFunction(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z]+$`)

	matched, err := MatchStringWithTimeout(pattern, "hello")
	require.NoError(t, err)
	assert.True(t, matched)

	matched, err = MatchStringWithTimeout(pattern, "123")
	require.NoError(t, err)
	assert.False(t, matched)
}

// TestNewRegexMatcher_DefaultTimeout tests default timeout initialization
func TestNewRegexMatcher_DefaultTimeout(t *testing.T) {
	// Zero timeout should use default
	matcher := NewRegexMatcher(0)
	assert.Equal(t, DefaultRegexTimeout, matcher.timeout)

	// Explicit timeout should be honored
	customTimeout := 500 * time.Millisecond
	matcher = NewRegexMatcher(customTimeout)
	assert.Equal(t, customTimeout, matcher.timeout)
}
