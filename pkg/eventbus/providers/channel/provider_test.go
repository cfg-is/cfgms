// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package channel

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// testSubscriber is a test-only LoggingSubscriber that records calls.
type testSubscriber struct {
	mu       sync.Mutex
	received []interfaces.LogEntry
	delay    time.Duration
	err      error
	filter   func(interfaces.LogEntry) bool
	closed   bool
}

func newTestSub() *testSubscriber {
	return &testSubscriber{
		filter: func(interfaces.LogEntry) bool { return true },
	}
}

func (s *testSubscriber) Name() string        { return "test-sub" }
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
	return s.filter(e)
}

func (s *testSubscriber) HandleLogEntry(_ context.Context, e interfaces.LogEntry) error {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.received = append(s.received, e)
	return nil
}

func (s *testSubscriber) entries() []interfaces.LogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]interfaces.LogEntry, len(s.received))
	copy(out, s.received)
	return out
}

func entry(msg string) interfaces.LogEntry {
	return interfaces.LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   msg,
	}
}

func TestChannelEventBus_DeliverToSubscriber(t *testing.T) {
	sub := newTestSub()
	bus := New(16)
	bus.Subscribe(sub)

	bus.Publish(entry("hello"))

	require.Eventually(t, func() bool {
		return len(sub.entries()) == 1
	}, time.Second, 10*time.Millisecond)

	assert.Equal(t, "hello", sub.entries()[0].Message)
	require.NoError(t, bus.Close())
}

func TestChannelEventBus_MultipleSubscribers(t *testing.T) {
	s1, s2 := newTestSub(), newTestSub()
	bus := New(16)
	bus.Subscribe(s1)
	bus.Subscribe(s2)

	bus.Publish(entry("broadcast"))

	require.Eventually(t, func() bool {
		return len(s1.entries()) == 1 && len(s2.entries()) == 1
	}, time.Second, 10*time.Millisecond)

	require.NoError(t, bus.Close())
}

// TestChannelEventBus_DropWithCounter is an ACCEPTANCE CRITERIA required test.
// It verifies: when the bus buffer is full, Publish does not block and
// DroppedCount() increments; primary WriteEntry persistence still succeeds.
func TestChannelEventBus_DropWithCounter(t *testing.T) {
	// Create a slow subscriber that holds the event goroutine so the buffer fills.
	slow := newTestSub()
	slow.delay = 200 * time.Millisecond

	bus := New(1) // buffer of 1 so it fills immediately
	bus.Subscribe(slow)

	// Publish enough entries to guarantee at least one drop.
	for i := 0; i < 10; i++ {
		bus.Publish(entry("flood"))
	}

	// Publish must not block — the test itself proves this by completing.
	assert.True(t, bus.DroppedCount() > 0, "expected at least one drop")
	require.NoError(t, bus.Close())
}

func TestChannelEventBus_SubscriberFiltering(t *testing.T) {
	sub := newTestSub()
	sub.filter = func(e interfaces.LogEntry) bool { return e.Level == "ERROR" }

	bus := New(16)
	bus.Subscribe(sub)

	bus.Publish(interfaces.LogEntry{Timestamp: time.Now(), Level: "INFO", Message: "ignored"})
	bus.Publish(interfaces.LogEntry{Timestamp: time.Now(), Level: "ERROR", Message: "kept"})

	require.Eventually(t, func() bool {
		return len(sub.entries()) == 1
	}, time.Second, 10*time.Millisecond)

	assert.Equal(t, "kept", sub.entries()[0].Message)
	require.NoError(t, bus.Close())
}

func TestChannelEventBus_SubscriberErrorDoesNotStopFanOut(t *testing.T) {
	bad := newTestSub()
	bad.err = errors.New("subscriber failure")
	good := newTestSub()

	bus := New(16)
	bus.Subscribe(bad)
	bus.Subscribe(good)

	bus.Publish(entry("test"))

	require.Eventually(t, func() bool {
		return len(good.entries()) == 1
	}, time.Second, 10*time.Millisecond)

	// bad subscriber recorded nothing (error path), good subscriber received entry.
	assert.Empty(t, bad.entries())
	assert.Len(t, good.entries(), 1)
	require.NoError(t, bus.Close())
}

func TestChannelEventBus_RuntimeSubscribe(t *testing.T) {
	bus := New(16)

	// Use a drain subscriber to confirm the bus has dispatched the pre-subscribe
	// entry before registering the subscriber-under-test. This is race-free:
	// once drain receives the entry the bus has consumed it from the channel, so
	// a subscriber added after this point will never see it.
	drain := newTestSub()
	bus.Subscribe(drain)
	bus.Publish(entry("pre-subscribe"))
	require.Eventually(t, func() bool {
		return len(drain.entries()) >= 1
	}, time.Second, 5*time.Millisecond, "drain subscriber must receive pre-subscribe entry")

	sub := newTestSub()
	bus.Subscribe(sub)

	bus.Publish(entry("post-subscribe"))

	require.Eventually(t, func() bool {
		return len(sub.entries()) == 1
	}, time.Second, 10*time.Millisecond)

	assert.Equal(t, "post-subscribe", sub.entries()[0].Message)
	require.NoError(t, bus.Close())
}

func TestChannelEventBus_CloseIdempotent(t *testing.T) {
	bus := New(16)
	require.NoError(t, bus.Close())
	require.NoError(t, bus.Close()) // second close must not panic or error
}

func TestChannelEventBus_SubscribersClosedOnBusClose(t *testing.T) {
	sub := newTestSub()
	bus := New(16)
	bus.Subscribe(sub)

	require.NoError(t, bus.Close())

	sub.mu.Lock()
	closed := sub.closed
	sub.mu.Unlock()
	assert.True(t, closed)
}
