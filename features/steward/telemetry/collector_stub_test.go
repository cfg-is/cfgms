// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows && !linux

package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStubCollector_ReturnsErrPlatformNotSupported pins the AC1 contract for
// unsupported platforms (currently macOS and any other non-Linux/non-Windows
// target): the collector compiles and every Snapshot returns
// ErrPlatformNotSupported with an empty result. There is no macOS CI runner
// today, so this only runs where GOOS is neither windows nor linux, but it keeps
// the stub honest the moment such a runner exists.
func TestStubCollector_ReturnsErrPlatformNotSupported(t *testing.T) {
	tel, err := NewCollector().Snapshot(context.Background())
	require.ErrorIs(t, err, ErrPlatformNotSupported)
	assert.Empty(t, tel.Processes)
	assert.Empty(t, tel.Services)
}
