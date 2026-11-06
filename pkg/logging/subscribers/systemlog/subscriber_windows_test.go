//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package systemlog

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/eventlog"
)

// TestEventLogLevels writes under a throwaway source and reads each event
// back with wevtutil (requires an elevated native Windows runner).
func TestEventLogLevels(t *testing.T) {
	source := fmt.Sprintf("cfgms-systemlog-test-%d", time.Now().UnixNano())
	t.Cleanup(func() { _ = eventlog.Remove(source) })

	s := NewSubscriber()
	if err := s.Initialize(map[string]interface{}{"tag": source}); err != nil {
		if _, kerr := registry.OpenKey(registry.LOCAL_MACHINE, eventLogKeyPrefix, registry.SET_VALUE); kerr != nil {
			t.Fatalf("event source install requires elevation: %v", err)
		}
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	cases := []struct {
		level Level
		name  string // wevtutil LevelDisplayName
		msg   string
	}{
		{LevelInfo, "Information", "systemlog info probe"},
		{LevelWarning, "Warning", "systemlog warning probe"},
		{LevelError, "Error", "systemlog error probe"},
	}
	for _, c := range cases {
		require.NoError(t, s.WriteOnce(LevelInfo+c.level, c.msg, c.msg))
		query := fmt.Sprintf("*[System[Provider[@Name='%s']]] and *[EventData[Data='%s']]", source, c.msg)
		var out []byte
		for i := 0; i < 20; i++ {
			out, _ = exec.Command("wevtutil", "qe", "Application", "/q:"+query, "/c:1", "/f:text").CombinedOutput()
			if len(out) > 0 {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
		assert.Contains(t, string(out), "Level:", c.msg)
		assert.Contains(t, string(out), c.name, c.msg)
	}
}

func TestEventLogInitializeFailureNoPanic(t *testing.T) {
	s := NewSubscriber()
	err := s.Initialize(map[string]interface{}{"collapse_window": "nope"})
	require.Error(t, err)
	ok, why := s.Available()
	assert.False(t, ok)
	assert.Error(t, why)
}

func TestOpenSourceWithRetryRecoversFromAccessDenied(t *testing.T) {
	const denied = 3
	calls := 0
	open := func(string) (*eventlog.Log, error) {
		calls++
		if calls <= denied {
			return nil, windows.ERROR_ACCESS_DENIED
		}
		return &eventlog.Log{}, nil
	}
	l, err := openSourceWithRetry(open, "src", 5*time.Second, time.Millisecond)
	require.NoError(t, err)
	assert.NotNil(t, l)
	assert.Equal(t, denied+1, calls)
}

func TestOpenSourceWithRetryDoesNotRetryOtherErrors(t *testing.T) {
	calls := 0
	boom := errors.New("boom")
	open := func(string) (*eventlog.Log, error) {
		calls++
		return nil, boom
	}
	_, err := openSourceWithRetry(open, "src", 5*time.Second, time.Millisecond)
	require.ErrorIs(t, err, boom)
	assert.Equal(t, 1, calls)
}

func TestOpenSourceWithRetryHonoursDeadline(t *testing.T) {
	open := func(string) (*eventlog.Log, error) { return nil, windows.ERROR_ACCESS_DENIED }
	deadline := 200 * time.Millisecond
	start := time.Now()
	_, err := openSourceWithRetry(open, "src", deadline, 10*time.Millisecond)
	elapsed := time.Since(start)
	require.ErrorIs(t, err, windows.ERROR_ACCESS_DENIED)
	assert.GreaterOrEqual(t, elapsed, deadline)
	assert.Less(t, elapsed, deadline+2*time.Second)
}
