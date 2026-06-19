// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/controller/cutover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCutoverHistoryPath_ReturnsNonEmpty(t *testing.T) {
	p := defaultCutoverHistoryPath()
	assert.NotEmpty(t, p)
	assert.Contains(t, p, "cutover.history.jsonl")
}

func TestRunControllerUpgradeHistory_EmptyFile_PrintsMessage(t *testing.T) {
	dir := t.TempDir()
	historyPath = filepath.Join(dir, "no-events.jsonl")
	historyLimit = 10
	historyJSONMode = false
	t.Cleanup(func() {
		historyPath = defaultCutoverHistoryPath()
		historyLimit = 10
		historyJSONMode = false
	})

	out := captureStdout(t, func() {
		err := runControllerUpgradeHistory(nil, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No upgrade events recorded", "empty history must print a helpful message")
}

func TestRunControllerUpgradeHistory_HumanReadable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "history.jsonl")
	historyPath = p
	historyLimit = 10
	historyJSONMode = false
	t.Cleanup(func() {
		historyPath = defaultCutoverHistoryPath()
		historyLimit = 10
		historyJSONMode = false
	})

	h := cutover.NewHistory(p)
	ts := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	require.NoError(t, h.Append(cutover.UpgradeEvent{
		EventType:  cutover.EventCommitted,
		Timestamp:  ts,
		BinaryPath: "/opt/cfgms/cfgms-v2",
	}))

	out := captureStdout(t, func() {
		err := runControllerUpgradeHistory(nil, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, cutover.EventCommitted, "human-readable output must show event type")
	assert.Contains(t, out, "/opt/cfgms/cfgms-v2", "human-readable output must show binary path")
}

func TestRunControllerUpgradeHistory_JSONMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "history.jsonl")
	historyPath = p
	historyLimit = 10
	historyJSONMode = true
	t.Cleanup(func() {
		historyPath = defaultCutoverHistoryPath()
		historyJSONMode = false
	})

	h := cutover.NewHistory(p)
	require.NoError(t, h.Append(cutover.UpgradeEvent{
		EventType:  cutover.EventStaged,
		BinaryPath: "/opt/cfgms/cfgms-v3",
	}))

	out := captureStdout(t, func() {
		err := runControllerUpgradeHistory(nil, nil)
		require.NoError(t, err)
	})

	var events []cutover.UpgradeEvent
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &events),
		"--json output must be valid JSON array; got: %s", out)
	require.Len(t, events, 1)
	assert.Equal(t, cutover.EventStaged, events[0].EventType)
	assert.Equal(t, "/opt/cfgms/cfgms-v3", events[0].BinaryPath)
}

func TestRunControllerUpgradeHistory_LimitEnforced(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "history.jsonl")
	historyPath = p
	historyLimit = 3
	historyJSONMode = true
	t.Cleanup(func() {
		historyPath = defaultCutoverHistoryPath()
		historyJSONMode = false
		historyLimit = 10
	})

	h := cutover.NewHistory(p)
	ts0 := time.Now().UTC()
	for i := 0; i < 10; i++ {
		require.NoError(t, h.Append(cutover.UpgradeEvent{
			EventType:  cutover.EventStaged,
			Timestamp:  ts0.Add(time.Duration(i) * time.Second),
			BinaryPath: "v",
		}))
	}

	out := captureStdout(t, func() {
		err := runControllerUpgradeHistory(nil, nil)
		require.NoError(t, err)
	})

	var events []cutover.UpgradeEvent
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &events))
	assert.Len(t, events, 3, "--limit=3 must return at most 3 events")
}

func TestRunControllerUpgradeHistory_MissingFile_NoError(t *testing.T) {
	historyPath = filepath.Join(t.TempDir(), "nonexistent.jsonl")
	historyLimit = 10
	historyJSONMode = false
	t.Cleanup(func() { historyPath = defaultCutoverHistoryPath() })

	err := runControllerUpgradeHistory(nil, nil)
	require.NoError(t, err, "missing history file must not return an error — fresh install path")
}

