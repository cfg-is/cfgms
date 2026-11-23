// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//go:build windows

package package_module

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBrewUnavailableOnWindows(t *testing.T) {
	cmd, err := newBrewCmd(context.Background(), "--version")
	require.ErrorIs(t, err, errBrewUnsupported)
	assert.Nil(t, cmd)
	assert.ErrorIs(t, brewCheck(context.Background()), errBrewUnsupported)
	assert.False(t, brewProbe(context.Background()))
}
