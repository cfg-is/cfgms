// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package modules_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/modules"
)

func TestRebootDeferredError_Is(t *testing.T) {
	nextWindow := time.Date(2026, time.January, 12, 2, 0, 0, 0, time.UTC)
	err := modules.NewRebootDeferredError(nextWindow)

	assert.True(t, errors.Is(err, modules.ErrRebootDeferred),
		"errors.Is must return true for a *RebootDeferredError against ErrRebootDeferred")

	// Wrapping must still match.
	wrapped := errors.Join(errors.New("outer"), err)
	assert.True(t, errors.Is(wrapped, modules.ErrRebootDeferred),
		"errors.Is must return true when the RebootDeferredError is wrapped")
}

func TestRebootDeferredError_As(t *testing.T) {
	nextWindow := time.Date(2026, time.January, 12, 2, 0, 0, 0, time.UTC)
	orig := modules.NewRebootDeferredError(nextWindow)

	var extracted *modules.RebootDeferredError
	assert.True(t, errors.As(orig, &extracted),
		"errors.As must succeed for *RebootDeferredError")
	assert.Equal(t, nextWindow, extracted.NextWindow)
}

func TestRebootDeferredError_ErrorString_WithNextWindow(t *testing.T) {
	nextWindow := time.Date(2026, time.January, 12, 2, 0, 0, 0, time.UTC)
	err := modules.NewRebootDeferredError(nextWindow)

	msg := err.Error()
	assert.True(t, strings.Contains(msg, "reboot deferred"),
		"error message must contain 'reboot deferred'")
	assert.True(t, strings.Contains(msg, "2026-01-12"),
		"error message must contain the next-window date")
}

func TestRebootDeferredError_ErrorString_ZeroNextWindow(t *testing.T) {
	err := modules.NewRebootDeferredError(time.Time{})

	msg := err.Error()
	assert.Contains(t, msg, "no upcoming window",
		"zero NextWindow must produce 'no upcoming window' message")
}

func TestErrRebootDeferred_IsNotMatchedByOtherErrors(t *testing.T) {
	plain := errors.New("some other error")
	assert.False(t, errors.Is(plain, modules.ErrRebootDeferred),
		"a plain error must not match ErrRebootDeferred")
}
