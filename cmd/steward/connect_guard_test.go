// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/client"
	"github.com/cfgis/cfgms/pkg/logging"
)

// A panicking connect attempt becomes an ordinary connect failure with a fixed
// reason; a later successful attempt (markHealthy) clears it.
func TestConnectGuarded_PanicBecomesFailureWithFixedReason(t *testing.T) {
	s := newSubsystemState()
	s.markDegraded("controller")

	tc, err := connectGuarded(s, logging.NewNoopLogger(), func() (*client.TransportClient, error) {
		panic("connect exploded")
	})
	require.ErrorIs(t, err, errConnectPanicked)
	assert.Nil(t, tc)
	assert.NotContains(t, err.Error(), "connect exploded")

	reasons := s.reasons.List()
	require.Len(t, reasons, 1)
	assert.Equal(t, "panic", reasons[0].Code)
	assert.Equal(t, "controller recovered from a panic", reasons[0].Message)

	s.markHealthy("controller")
	assert.Empty(t, s.reasons.List())
}
