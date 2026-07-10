// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package dex

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// assertStubOrSkip verifies the !windows stub's sole behavioral contract:
// Collector.Run must return ErrPlatformNotSupported.
func assertStubOrSkip(t *testing.T, col *Collector) {
	t.Helper()
	_, err := col.Run(context.Background())
	assert.ErrorIs(t, err, ErrPlatformNotSupported,
		"non-Windows stub must return ErrPlatformNotSupported from Run")
}
