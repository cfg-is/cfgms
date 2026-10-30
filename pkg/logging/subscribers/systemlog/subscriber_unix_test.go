//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package systemlog

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// listen starts a real unix datagram listener standing in for /dev/log.
func listen(t *testing.T) (*net.UnixConn, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "log.sock")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn, path
}

func read(t *testing.T, c *net.UnixConn) (string, bool) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return "", false
	}
	return string(buf[:n]), true
}

func newInit(t *testing.T, path string, extra map[string]interface{}) *Subscriber {
	t.Helper()
	cfg := map[string]interface{}{"network": "unixgram", "address": path, "tag": "cfgms-test"}
	for k, v := range extra {
		cfg[k] = v
	}
	s := NewSubscriber()
	require.NoError(t, s.Initialize(cfg))
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestWriteArrivesWithPriorityAndTag(t *testing.T) {
	conn, path := listen(t)
	s := newInit(t, path, nil)

	cases := []struct {
		level Level
		pri   string
	}{{LevelInfo, "<30>"}, {LevelWarning, "<28>"}, {LevelError, "<27>"}}
	for i, c := range cases {
		require.NoError(t, s.WriteOnce(c.level, "k", "msg "+string(rune('a'+i))))
		got, ok := read(t, conn)
		require.True(t, ok)
		assert.Contains(t, got, c.pri)
		assert.Contains(t, got, "cfgms-test")
		assert.Contains(t, got, "msg "+string(rune('a'+i)))
	}
	ok, err := s.Available()
	assert.True(t, ok)
	assert.NoError(t, err)
}

func TestWriteOnceCollapsesWithinWindow(t *testing.T) {
	conn, path := listen(t)
	s := newInit(t, path, map[string]interface{}{"collapse_window": "1h"})
	clock := time.Now()
	s.now = func() time.Time { return clock }

	require.NoError(t, s.WriteOnce(LevelError, "id", "no usable identity"))
	_, ok := read(t, conn)
	require.True(t, ok)

	clock = clock.Add(30 * time.Minute)
	require.NoError(t, s.WriteOnce(LevelError, "id", "no usable identity"))
	_, ok = read(t, conn)
	assert.False(t, ok, "identical message inside window must be collapsed")

	require.NoError(t, s.WriteOnce(LevelError, "id", "different reason"))
	_, ok = read(t, conn)
	assert.True(t, ok, "different message is written")

	clock = clock.Add(2 * time.Hour)
	require.NoError(t, s.WriteOnce(LevelError, "id", "different reason"))
	_, ok = read(t, conn)
	assert.True(t, ok, "message is written again after the window")
}

func TestSecretNotWritten(t *testing.T) {
	conn, path := listen(t)
	s := newInit(t, path, nil)
	require.NoError(t, s.WriteOnce(LevelError, "k", "enrollment failed token=s3cr3t-value-xyz"))
	got, ok := read(t, conn)
	require.True(t, ok)
	assert.NotContains(t, got, "s3cr3t-value-xyz")
	assert.Contains(t, got, "enrollment failed")
}

func TestHandleLogEntryAndShouldHandle(t *testing.T) {
	conn, path := listen(t)
	s := newInit(t, path, nil)
	assert.False(t, s.ShouldHandle(interfaces.LogEntry{Level: "INFO"}))
	e := interfaces.LogEntry{Level: "WARN", Component: "identity", Message: "cert missing"}
	require.True(t, s.ShouldHandle(e))
	require.NoError(t, s.HandleLogEntry(t.Context(), e))
	got, ok := read(t, conn)
	require.True(t, ok)
	assert.Contains(t, got, "<28>")
}

func TestInitializeUnreachableSocket(t *testing.T) {
	s := NewSubscriber()
	err := s.Initialize(map[string]interface{}{"network": "unixgram", "address": filepath.Join(t.TempDir(), "none.sock")})
	require.Error(t, err)
	ok, why := s.Available()
	assert.False(t, ok)
	assert.Error(t, why)
}
