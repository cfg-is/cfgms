// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AssertTimeApprox asserts that two times are approximately equal
func AssertTimeApprox(t *testing.T, expected, actual time.Time, delta time.Duration) {
	diff := expected.Sub(actual)
	if diff < 0 {
		diff = -diff
	}
	assert.True(t, diff <= delta, "Times should be within %v of each other, got %v", delta, diff)
}

// RequireTimeApprox requires that two times are approximately equal
func RequireTimeApprox(t *testing.T, expected, actual time.Time, delta time.Duration) {
	diff := expected.Sub(actual)
	if diff < 0 {
		diff = -diff
	}
	require.True(t, diff <= delta, "Times should be within %v of each other, got %v", delta, diff)
}

// AssertErrorIs asserts that an error is of a specific type
func AssertErrorIs(t *testing.T, expected, actual error) {
	assert.ErrorIs(t, actual, expected)
}

// RequireErrorIs requires that an error is of a specific type
func RequireErrorIs(t *testing.T, expected, actual error) {
	require.ErrorIs(t, actual, expected)
}

// AssertErrorContains asserts that an error message contains a specific string
func AssertErrorContains(t *testing.T, err error, contains string) {
	assert.Error(t, err)
	assert.Contains(t, err.Error(), contains)
}

// RequireErrorContains requires that an error message contains a specific string
func RequireErrorContains(t *testing.T, err error, contains string) {
	require.Error(t, err)
	require.Contains(t, err.Error(), contains)
}

// AssertPanics asserts that a function panics
func AssertPanics(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r == nil {
			assert.Fail(t, "Expected function to panic")
		}
	}()
	f()
}

// RequirePanics requires that a function panics
func RequirePanics(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r == nil {
			require.Fail(t, "Expected function to panic")
		}
	}()
	f()
}

// AssertNotPanics asserts that a function does not panic
func AssertNotPanics(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r != nil {
			assert.Fail(t, "Expected function not to panic, got: %v", r)
		}
	}()
	f()
}

// RequireNotPanics requires that a function does not panic
func RequireNotPanics(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r != nil {
			require.Fail(t, "Expected function not to panic, got: %v", r)
		}
	}()
	f()
}
