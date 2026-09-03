// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package modules_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/modules"
)

func TestRetryExhaustedError_Is(t *testing.T) {
	err := modules.NewRetryExhaustedError("boom", "creating")

	assert.True(t, errors.Is(err, modules.ErrRetryExhausted),
		"errors.Is must return true for a *RetryExhaustedError against ErrRetryExhausted")

	wrapped := errors.Join(errors.New("outer"), err)
	assert.True(t, errors.Is(wrapped, modules.ErrRetryExhausted),
		"errors.Is must return true when the RetryExhaustedError is wrapped")
}

func TestRetryExhaustedError_As(t *testing.T) {
	orig := modules.NewRetryExhaustedError("exit status 1", "creating")

	var extracted *modules.RetryExhaustedError
	assert.True(t, errors.As(orig, &extracted),
		"errors.As must succeed for *RetryExhaustedError")
	assert.Equal(t, "exit status 1", extracted.LastError)
	assert.Equal(t, "creating", extracted.FailedFrom)
}

func TestRetryExhaustedError_ErrorString_WithFailedFrom(t *testing.T) {
	err := modules.NewRetryExhaustedError("exit status 1", "creating")

	msg := err.Error()
	assert.True(t, strings.Contains(msg, "retry budget exhausted"),
		"error message must contain 'retry budget exhausted'")
	assert.True(t, strings.Contains(msg, "creating"),
		"error message must contain the failed-from phase")
	assert.True(t, strings.Contains(msg, "exit status 1"),
		"error message must contain the last-error detail")
}

func TestRetryExhaustedError_ErrorString_NoFailedFrom(t *testing.T) {
	err := modules.NewRetryExhaustedError("some failure", "")

	msg := err.Error()
	assert.True(t, strings.Contains(msg, "retry budget exhausted"),
		"error message must contain 'retry budget exhausted'")
	assert.True(t, strings.Contains(msg, "some failure"),
		"error message must contain the last-error detail")
}

func TestErrRetryExhausted_IsNotMatchedByOtherErrors(t *testing.T) {
	plain := errors.New("some other error")
	assert.False(t, errors.Is(plain, modules.ErrRetryExhausted),
		"a plain error must not match ErrRetryExhausted")
}
