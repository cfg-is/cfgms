// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"

	// Auto-register the file provider so NewLoggingManager("file") works.
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
)

// testSubscriber is a test-local implementation of LoggingSubscriber.
// It is entirely self-contained — no production code hooks are used.
type testSubscriber struct {
	mu           sync.Mutex
	name         string
	received     []interfaces.LogEntry
	err          error
	filterFn     func(interfaces.LogEntry) bool
	closed       bool
	handleDelay  time.Duration
	handleCalled int
}

func newTestSubscriber(name string) *testSubscriber {
	return &testSubscriber{
		name:     name,
		filterFn: func(interfaces.LogEntry) bool { return true },
	}
}

func (s *testSubscriber) Name() string        { return s.name }
func (s *testSubscriber) Description() string { return "test subscriber" }
func (s *testSubscriber) Initialize(_ map[string]interface{}) error {
	return nil
}
func (s *testSubscriber) Available() (bool, error) { return true, nil }

func (s *testSubscriber) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

func (s *testSubscriber) ShouldHandle(e interfaces.LogEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.filterFn(e)
}

func (s *testSubscriber) HandleLogEntry(_ context.Context, e interfaces.LogEntry) error {
	if s.handleDelay > 0 {
		time.Sleep(s.handleDelay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handleCalled++
	if s.err != nil {
		return s.err
	}
	s.received = append(s.received, e)
	return nil
}

func (s *testSubscriber) Entries() []interfaces.LogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]interfaces.LogEntry, len(s.received))
	copy(out, s.received)
	return out
}

func (s *testSubscriber) IsClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// fileLoggingConfig returns a minimal file-provider LoggingConfig using t.TempDir().
func fileLoggingConfig(t *testing.T) *LoggingConfig {
	t.Helper()
	return &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":   t.TempDir(),
			"file_prefix": "test",
		},
		Level:       "INFO",
		ServiceName: "test-service",
		Component:   "test-component",
		AsyncWrites: false,
		BufferSize:  100,
	}
}

func TestLoggingManager_WithSubscribers(t *testing.T) {
	cfg := fileLoggingConfig(t)

	manager, err := NewLoggingManager(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, manager.Close()) }()

	sub1 := newTestSubscriber("sub1")
	sub2 := newTestSubscriber("sub2")
	manager.AddSubscriber(sub1)
	manager.AddSubscriber(sub2)

	ctx := context.Background()
	entry := interfaces.LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   "Test message",
	}

	require.NoError(t, manager.WriteEntry(ctx, entry))

	require.Eventually(t, func() bool {
		return len(sub1.Entries()) == 1 && len(sub2.Entries()) == 1
	}, time.Second, 10*time.Millisecond)

	assert.Equal(t, "Test message", sub1.Entries()[0].Message)
	assert.Equal(t, "Test message", sub2.Entries()[0].Message)
}

func TestLoggingManager_SubscriberFiltering(t *testing.T) {
	cfg := fileLoggingConfig(t)

	manager, err := NewLoggingManager(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, manager.Close()) }()

	sub := newTestSubscriber("filtered")
	sub.filterFn = func(e interfaces.LogEntry) bool { return e.Level == "ERROR" }
	manager.AddSubscriber(sub)

	ctx := context.Background()

	require.NoError(t, manager.WriteEntry(ctx, interfaces.LogEntry{
		Timestamp: time.Now(), Level: "INFO", Message: "ignored",
	}))
	require.NoError(t, manager.WriteEntry(ctx, interfaces.LogEntry{
		Timestamp: time.Now(), Level: "ERROR", Message: "Error message",
	}))

	require.Eventually(t, func() bool {
		return len(sub.Entries()) == 1
	}, time.Second, 10*time.Millisecond)

	assert.Equal(t, "ERROR", sub.Entries()[0].Level)
	assert.Equal(t, "Error message", sub.Entries()[0].Message)
}

func TestLoggingManager_SubscriberError(t *testing.T) {
	cfg := fileLoggingConfig(t)

	manager, err := NewLoggingManager(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, manager.Close()) }()

	errSub := newTestSubscriber("error-sub")
	errSub.err = assert.AnError
	manager.AddSubscriber(errSub)

	ctx := context.Background()
	entry := interfaces.LogEntry{
		Timestamp: time.Now(), Level: "INFO", Message: "Test message",
	}

	// Primary logging must succeed even when the subscriber returns an error.
	require.NoError(t, manager.WriteEntry(ctx, entry))

	require.Eventually(t, func() bool {
		errSub.mu.Lock()
		called := errSub.handleCalled
		errSub.mu.Unlock()
		return called == 1
	}, time.Second, 10*time.Millisecond)

	// No successful handling due to error return.
	assert.Empty(t, errSub.Entries())
}

func TestLoggingManager_EventChannelOverflow(t *testing.T) {
	cfg := fileLoggingConfig(t)
	cfg.BufferSize = 1 // tiny buffer to force drops

	manager, err := NewLoggingManager(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, manager.Close()) }()

	// Add a subscriber with a small delay so the loop goroutine is held per
	// entry, ensuring 100 rapid publishes overflow the buffer=1 bus.
	sub := newTestSubscriber("overflow-sub")
	sub.handleDelay = time.Millisecond
	manager.AddSubscriber(sub)

	// Flood the bus directly (bypassing WriteEntry's file-I/O) so the publish
	// loop runs faster than the event loop can drain with bufSize=1.
	floodEntry := interfaces.LogEntry{Timestamp: time.Now(), Level: "INFO", Message: "flood"}
	for i := 0; i < 100; i++ {
		manager.eventBus.Publish(floodEntry)
	}

	// The bus must have dropped at least one entry.
	chanBus, ok := manager.eventBus.(interface{ DroppedCount() int64 })
	require.True(t, ok, "eventBus must expose DroppedCount for overflow verification")
	assert.Greater(t, chanBus.DroppedCount(), int64(0), "expected at least one dropped entry")

	// Primary WriteEntry persistence must still succeed even when the bus is overflowing.
	require.NoError(t, manager.WriteEntry(context.Background(), interfaces.LogEntry{
		Timestamp: time.Now(), Level: "INFO", Message: "persistence check",
	}))
}

func TestLoggingManager_NoSubscribers(t *testing.T) {
	cfg := fileLoggingConfig(t)

	manager, err := NewLoggingManager(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, manager.Close()) }()

	// Should work normally without subscribers.
	ctx := context.Background()
	require.NoError(t, manager.WriteEntry(ctx, interfaces.LogEntry{
		Timestamp: time.Now(), Level: "INFO", Message: "no subscribers",
	}))
}

func TestLoggingManager_Close_WithSubscribers(t *testing.T) {
	cfg := fileLoggingConfig(t)

	manager, err := NewLoggingManager(cfg)
	require.NoError(t, err)

	sub := newTestSubscriber("close-test")
	manager.AddSubscriber(sub)
	assert.False(t, sub.IsClosed())

	require.NoError(t, manager.Close())
	assert.True(t, sub.IsClosed())
}

// TestLoggingManager_RuntimeAddSubscriber_ReceivesEntries is an ACCEPTANCE
// CRITERIA required test. It verifies that a subscriber added at runtime via
// AddSubscriber receives subsequent WriteEntry entries.
func TestLoggingManager_RuntimeAddSubscriber_ReceivesEntries(t *testing.T) {
	cfg := fileLoggingConfig(t)

	manager, err := NewLoggingManager(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, manager.Close()) }()

	ctx := context.Background()

	// Add a drain subscriber to confirm the bus has dispatched the pre-subscribe
	// entry before registering the subscriber-under-test. This is race-free:
	// once drain receives the entry the bus has consumed it from the channel, so
	// a subscriber added after this point will never see it.
	drain := newTestSubscriber("drain-confirm")
	manager.AddSubscriber(drain)

	// Publish before subscribing — these must NOT be delivered to runtime-sub.
	require.NoError(t, manager.WriteEntry(ctx, interfaces.LogEntry{
		Timestamp: time.Now(), Level: "INFO", Message: "pre-subscribe entry",
	}))
	require.Eventually(t, func() bool {
		return len(drain.Entries()) >= 1
	}, time.Second, 5*time.Millisecond, "drain subscriber must confirm pre-subscribe entry dispatched")

	// Add subscriber at runtime.
	sub := newTestSubscriber("runtime-sub")
	manager.AddSubscriber(sub)

	// Publish after subscribing — MUST be delivered.
	require.NoError(t, manager.WriteEntry(ctx, interfaces.LogEntry{
		Timestamp: time.Now(), Level: "INFO", Message: "post-subscribe entry",
	}))

	require.Eventually(t, func() bool {
		return len(sub.Entries()) == 1
	}, time.Second, 10*time.Millisecond, "runtime subscriber must receive post-subscribe entry")

	assert.Equal(t, "post-subscribe entry", sub.Entries()[0].Message)
	// The pre-subscribe entry must NOT have been delivered.
	assert.Len(t, sub.Entries(), 1)
}
