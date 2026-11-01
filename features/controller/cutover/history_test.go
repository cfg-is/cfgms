// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistory_AppendAndRecent_NewestFirst(t *testing.T) {
	dir := t.TempDir()
	h := NewHistory(filepath.Join(dir, "history.jsonl"))

	t0 := time.Now().UTC().Truncate(time.Second)
	events := []UpgradeEvent{
		{EventType: EventStaged, Timestamp: t0, BinaryPath: "v1"},
		{EventType: EventSmoketestPassed, Timestamp: t0.Add(1 * time.Second), BinaryPath: "v1"},
		{EventType: EventCommitted, Timestamp: t0.Add(2 * time.Second), BinaryPath: "v1", PreviousBinary: "v0"},
	}
	for _, e := range events {
		require.NoError(t, h.Append(e))
	}

	got, err := h.Recent(0) // all
	require.NoError(t, err)
	require.Len(t, got, 3)
	// Newest first.
	assert.Equal(t, EventCommitted, got[0].EventType)
	assert.Equal(t, EventSmoketestPassed, got[1].EventType)
	assert.Equal(t, EventStaged, got[2].EventType)
}

func TestHistory_Recent_RespectsLimit(t *testing.T) {
	dir := t.TempDir()
	h := NewHistory(filepath.Join(dir, "history.jsonl"))
	t0 := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 20; i++ {
		require.NoError(t, h.Append(UpgradeEvent{
			EventType:  EventStaged,
			Timestamp:  t0.Add(time.Duration(i) * time.Second),
			BinaryPath: "vN",
		}))
	}
	got, err := h.Recent(5)
	require.NoError(t, err)
	assert.Len(t, got, 5, "Recent(5) returns the 5 newest events")
}

func TestHistory_Recent_MissingFile_ReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	h := NewHistory(filepath.Join(dir, "no-such-file.jsonl"))
	got, err := h.Recent(10)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestHistory_Append_AutoTimestampOnZero(t *testing.T) {
	dir := t.TempDir()
	h := NewHistory(filepath.Join(dir, "history.jsonl"))
	before := time.Now().UTC().Add(-time.Second)
	require.NoError(t, h.Append(UpgradeEvent{EventType: EventStaged}))
	after := time.Now().UTC().Add(time.Second)
	got, err := h.Recent(1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.True(t, got[0].Timestamp.After(before) && got[0].Timestamp.Before(after),
		"Append must fill in Timestamp when zero; got %s", got[0].Timestamp)
}

// TestHistory_ConcurrentAppend_NoTornRecords verifies the mutex-
// serialized append actually serialises — running 100 concurrent
// Appends from 10 goroutines must produce 100 well-formed events.
func TestHistory_ConcurrentAppend_NoTornRecords(t *testing.T) {
	dir := t.TempDir()
	h := NewHistory(filepath.Join(dir, "history.jsonl"))

	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		appendErrs []error
	)
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if err := h.Append(UpgradeEvent{
					EventType:  EventStaged,
					BinaryPath: "v",
				}); err != nil {
					mu.Lock()
					appendErrs = append(appendErrs, err)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	require.Empty(t, appendErrs, "concurrent Append calls must not produce errors; got: %v", appendErrs)

	got, err := h.Recent(0)
	require.NoError(t, err)
	assert.Len(t, got, 100, "all 100 concurrent appends must produce parseable events")
}
