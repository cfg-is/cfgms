// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package hyperv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestModule_Configure_PSHostStartFailureIsReturned verifies there is no silent
// fallback: when the local PowerShell host cannot start, Configure returns that
// error and sets no transport, even with winrm_* keys absent. On a non-Windows
// build the error is the unsupported-platform error naming the Hyper-V module.
func TestModule_Configure_PSHostStartFailureIsReturned(t *testing.T) {
	m := &hypervModule{executor: &stubHypervExecutor{}}
	require.NoError(t, m.SetSecretStore(newInlineStore()))
	err := m.Configure(mapConfigState{})
	require.Error(t, err)
	assert.ErrorIs(t, err, errPSHostUnsupported)
	assert.Contains(t, err.Error(), "Hyper-V module")
	assert.Contains(t, err.Error(), "unsupported")
	assert.Nil(t, m.transport)

	err = m.Configure(mapConfigState{"transport": "ps-host"})
	assert.ErrorIs(t, err, errPSHostUnsupported)
	assert.Nil(t, m.transport)
}
