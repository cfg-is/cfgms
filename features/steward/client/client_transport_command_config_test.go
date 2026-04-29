// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client exercises command-authentication config wiring in TransportClient.
package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewTransportClient_StoresCommandAuthFields verifies that
// SignedCommandReplayWindow and SignedCommandMaxParamsBytes from TransportConfig
// are stored on the TransportClient so that setupCommandHandler can pass them
// to commands.New (Story #919 fix for PR #927).
func TestNewTransportClient_StoresCommandAuthFields(t *testing.T) {
	replayWindow := 10 * time.Minute
	maxParams := 128 * 1024

	c, err := NewTransportClient(&TransportConfig{
		ControllerURL:               "localhost:4433",
		SignedCommandReplayWindow:   replayWindow,
		SignedCommandMaxParamsBytes: maxParams,
		Logger:                      newTestLogger(t),
	})
	require.NoError(t, err)
	assert.Equal(t, replayWindow, c.commandReplayWindow,
		"commandReplayWindow must be stored from TransportConfig.SignedCommandReplayWindow")
	assert.Equal(t, maxParams, c.commandMaxParamsBytes,
		"commandMaxParamsBytes must be stored from TransportConfig.SignedCommandMaxParamsBytes")
}

// TestNewTransportClient_ZeroCommandAuthFieldsArePreserved verifies that when
// SignedCommandReplayWindow and SignedCommandMaxParamsBytes are zero (unset),
// those zero values are stored unchanged so that commands.New can apply its own
// defaults (5 min / 64 KiB) rather than having the caller silently override them.
func TestNewTransportClient_ZeroCommandAuthFieldsArePreserved(t *testing.T) {
	c, err := NewTransportClient(&TransportConfig{
		ControllerURL: "localhost:4433",
		Logger:        newTestLogger(t),
	})
	require.NoError(t, err)
	assert.Equal(t, time.Duration(0), c.commandReplayWindow,
		"zero SignedCommandReplayWindow must be stored as-is so commands.Handler applies its default")
	assert.Equal(t, 0, c.commandMaxParamsBytes,
		"zero SignedCommandMaxParamsBytes must be stored as-is so commands.Handler applies its default")
}
