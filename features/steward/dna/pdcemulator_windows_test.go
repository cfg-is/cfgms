//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package dna

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWindowsPDCEmulatorResolver_RealHost runs the real resolver against this
// host. On a non-DC it must skip the directory lookup and report no role holder;
// on a DC it must resolve the role holder by DNS name.
func TestWindowsPDCEmulatorResolver_RealHost(t *testing.T) {
	isDC, err := isDomainController()
	require.NoError(t, err)

	localHost, pdcHost, gotDC, err := newPlatformPDCEmulatorResolver().ResolvePDCEmulator(context.Background())
	assert.Equal(t, isDC, gotDC)
	if !isDC {
		require.NoError(t, err)
		assert.Empty(t, pdcHost, "a non-DC must not look up the PDC emulator")
		return
	}
	require.NoError(t, err, "a domain controller must resolve its PDC emulator")
	assert.NotEmpty(t, localHost)
	assert.NotEmpty(t, pdcHost)
}

func TestLocalDNSHostName(t *testing.T) {
	name, err := localDNSHostName()
	require.NoError(t, err)
	assert.NotEmpty(t, name)
}
