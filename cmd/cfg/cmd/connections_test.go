// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectionsList_Empty(t *testing.T) {
	withTempConfigDir(t)

	orig := connectionsListJSON
	t.Cleanup(func() { connectionsListJSON = orig })
	connectionsListJSON = false

	output := captureStdout(t, func() {
		err := runConnectionsList(connectionsListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "No connections configured.")
}

func TestConnectionsList_Table(t *testing.T) {
	withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	require.NoError(t, reg.Register(ConnectionEntry{
		Name:          "prod",
		ControllerURL: "https://ctrl.example.com:9090",
		AdminIdentity: "admin@example.com",
		LastUsed:      ts,
	}))

	orig := connectionsListJSON
	t.Cleanup(func() { connectionsListJSON = orig })
	connectionsListJSON = false

	output := captureStdout(t, func() {
		err := runConnectionsList(connectionsListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "prod")
	assert.Contains(t, output, "https://ctrl.example.com:9090")
	assert.Contains(t, output, "admin@example.com")
	assert.Contains(t, output, "2026-06-01T12:00:00Z")
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "URL")
	assert.Contains(t, output, "IDENTITY")
	assert.Contains(t, output, "LAST USED")
}

func TestConnectionsList_JSON(t *testing.T) {
	withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	require.NoError(t, reg.Register(ConnectionEntry{
		Name:          "staging",
		ControllerURL: "https://staging.example.com:9090",
		AdminIdentity: "staging-admin",
	}))

	orig := connectionsListJSON
	t.Cleanup(func() { connectionsListJSON = orig })
	connectionsListJSON = true

	output := captureStdout(t, func() {
		err := runConnectionsList(connectionsListCmd, []string{})
		require.NoError(t, err)
	})

	var entries []ConnectionEntry
	require.NoError(t, json.Unmarshal([]byte(output), &entries))
	require.Len(t, entries, 1)
	assert.Equal(t, "staging", entries[0].Name)
	assert.Equal(t, "https://staging.example.com:9090", entries[0].ControllerURL)
}

func TestConnectionsList_NoLastUsed(t *testing.T) {
	withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	require.NoError(t, reg.Register(ConnectionEntry{
		Name:          "dev",
		ControllerURL: "https://dev.example.com:9090",
		AdminIdentity: "dev-admin",
	}))

	orig := connectionsListJSON
	t.Cleanup(func() { connectionsListJSON = orig })
	connectionsListJSON = false

	output := captureStdout(t, func() {
		err := runConnectionsList(connectionsListCmd, []string{})
		require.NoError(t, err)
	})

	assert.Contains(t, output, "dev")
	assert.Contains(t, output, "-")
}
