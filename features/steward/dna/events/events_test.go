// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package events provides tests for the DNA change event system.

package events

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

// mockSubscriber implements EventSubscriber for testing.
type mockSubscriber struct {
	name      string
	priority  int
	async     bool
	events    []*DNAChangeEvent
	errors    []error
	callCount int
	mu        sync.Mutex
}

func (m *mockSubscriber) OnEvent(ctx context.Context, event *DNAChangeEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callCount++
	m.events = append(m.events, event)

	if len(m.errors) > 0 {
		err := m.errors[0]
		m.errors = m.errors[1:]
		return err
	}

	return nil
}

func (m *mockSubscriber) GetSubscriberInfo() *SubscriberInfo {
	return &SubscriberInfo{
		Name:        m.name,
		Description: "Mock subscriber for testing",
		EventTypes:  []string{EventTypeDNAWrite},
		Priority:    m.priority,
		Async:       m.async,
		Timeout:     5 * time.Second,
	}
}

func (m *mockSubscriber) Close() error {
	return nil
}

func (m *mockSubscriber) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func (m *mockSubscriber) getEvents() []*DNAChangeEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy to avoid race conditions
	events := make([]*DNAChangeEvent, len(m.events))
	copy(events, m.events)
	return events
}

func TestEventPublisher_PublishAndSubscribe(t *testing.T) {
	logger := logging.Logger(nil)
	publisher := NewPublisher(logger, DefaultPublisherConfig())

	// Create mock subscriber
	subscriber := &mockSubscriber{
		name:     "test_subscriber",
		priority: 10,
		async:    false,
	}

	// Subscribe to events
	err := publisher.Subscribe(EventTypeDNAWrite, subscriber)
	require.NoError(t, err)

	// Start publisher
	ctx := context.Background()
	err = publisher.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := publisher.Stop(ctx); err != nil {
			t.Logf("Failed to stop publisher: %v", err)
		}
	}()

	// Create test event
	event := &DNAChangeEvent{
		DeviceID:    "test-device",
		Timestamp:   time.Now(),
		DNA:         &commonpb.DNA{Id: "test-dna"},
		ContentHash: "abc123",
		ShardID:     "shard-0",
		Version:     1,
	}

	// Publish event
	err = publisher.Publish(ctx, EventTypeDNAWrite, event)
	require.NoError(t, err)

	// Give some time for processing
	time.Sleep(100 * time.Millisecond)

	// Verify subscriber was called
	assert.Equal(t, 1, subscriber.getCallCount())
	events := subscriber.getEvents()
	assert.Len(t, events, 1)
	assert.Equal(t, "test-device", events[0].DeviceID)
}

func TestEventPublisher_PriorityOrdering(t *testing.T) {
	logger := logging.Logger(nil)
	publisher := NewPublisher(logger, DefaultPublisherConfig())

	// Create subscribers with different priorities
	sub1 := &mockSubscriber{name: "low", priority: 1}
	sub2 := &mockSubscriber{name: "high", priority: 100}
	sub3 := &mockSubscriber{name: "medium", priority: 50}

	// Subscribe in random order
	err := publisher.Subscribe(EventTypeDNAWrite, sub1)
	require.NoError(t, err)
	err = publisher.Subscribe(EventTypeDNAWrite, sub2)
	require.NoError(t, err)
	err = publisher.Subscribe(EventTypeDNAWrite, sub3)
	require.NoError(t, err)

	// Start publisher
	ctx := context.Background()
	err = publisher.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := publisher.Stop(ctx); err != nil {
			t.Logf("Failed to stop publisher: %v", err)
		}
	}()

	// Create test event
	event := &DNAChangeEvent{
		DeviceID:    "test-device",
		Timestamp:   time.Now(),
		DNA:         &commonpb.DNA{Id: "test-dna"},
		ContentHash: "abc123",
	}

	// Publish event
	err = publisher.Publish(ctx, EventTypeDNAWrite, event)
	require.NoError(t, err)

	// Give some time for processing
	time.Sleep(100 * time.Millisecond)

	// Verify all subscribers were called
	assert.Equal(t, 1, sub1.getCallCount())
	assert.Equal(t, 1, sub2.getCallCount())
	assert.Equal(t, 1, sub3.getCallCount())
}

func TestEventPublisher_MultipleEvents(t *testing.T) {
	config := DefaultPublisherConfig()
	config.WorkerCount = 2
	config.QueueSize = 10

	logger := logging.Logger(nil)
	publisher := NewPublisher(logger, config)

	subscriber := &mockSubscriber{
		name:     "multi_subscriber",
		priority: 10,
		async:    true,
	}

	err := publisher.Subscribe(EventTypeDNAWrite, subscriber)
	require.NoError(t, err)

	// Start publisher
	ctx := context.Background()
	err = publisher.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := publisher.Stop(ctx); err != nil {
			t.Logf("Failed to stop publisher: %v", err)
		}
	}()

	// Publish multiple events
	numEvents := 5
	for i := 0; i < numEvents; i++ {
		event := &DNAChangeEvent{
			DeviceID:    "test-device",
			Timestamp:   time.Now(),
			DNA:         &commonpb.DNA{Id: "test-dna"},
			ContentHash: "abc123",
		}

		err = publisher.Publish(ctx, EventTypeDNAWrite, event)
		require.NoError(t, err)
	}

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Verify all events were processed
	assert.Equal(t, numEvents, subscriber.getCallCount())
	assert.Len(t, subscriber.getEvents(), numEvents)
}

func TestEventPublisher_Stats(t *testing.T) {
	logger := logging.Logger(nil)
	publisher := NewPublisher(logger, DefaultPublisherConfig())

	subscriber := &mockSubscriber{name: "test", priority: 10}
	err := publisher.Subscribe(EventTypeDNAWrite, subscriber)
	require.NoError(t, err)

	ctx := context.Background()
	err = publisher.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := publisher.Stop(ctx); err != nil {
			t.Logf("Failed to stop publisher: %v", err)
		}
	}()

	// Get initial stats
	stats := publisher.GetStats()
	assert.Equal(t, 1, stats.RegisteredSubscribers)
	assert.Equal(t, int64(0), stats.EventsPublished)

	// Publish event
	event := &DNAChangeEvent{
		DeviceID: "test-device",
		DNA:      &commonpb.DNA{Id: "test"},
	}

	err = publisher.Publish(ctx, EventTypeDNAWrite, event)
	require.NoError(t, err)

	// Wait and check stats
	time.Sleep(100 * time.Millisecond)
	stats = publisher.GetStats()
	assert.Equal(t, int64(1), stats.EventsPublished)
}

func TestEventPublisher_ErrorHandling(t *testing.T) {
	logger := logging.Logger(nil)
	publisher := NewPublisher(logger, DefaultPublisherConfig())

	// Create subscriber that returns an error
	subscriber := &mockSubscriber{
		name:     "error_subscriber",
		priority: 10,
		errors:   []error{assert.AnError},
	}

	err := publisher.Subscribe(EventTypeDNAWrite, subscriber)
	require.NoError(t, err)

	ctx := context.Background()
	err = publisher.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := publisher.Stop(ctx); err != nil {
			t.Logf("Failed to stop publisher: %v", err)
		}
	}()

	// Publish event
	event := &DNAChangeEvent{
		DeviceID: "test-device",
		DNA:      &commonpb.DNA{Id: "test"},
	}

	err = publisher.Publish(ctx, EventTypeDNAWrite, event)
	require.NoError(t, err) // Publisher shouldn't fail due to subscriber errors

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Check stats show the failure
	stats := publisher.GetStats()
	assert.Equal(t, int64(1), stats.EventsFailed)
	assert.Equal(t, int64(1), stats.SubscriberFailures["error_subscriber"])
}

func TestEventPublisher_Unsubscribe(t *testing.T) {
	logger := logging.Logger(nil)
	publisher := NewPublisher(logger, DefaultPublisherConfig())

	subscriber := &mockSubscriber{name: "test", priority: 10}

	// Subscribe
	err := publisher.Subscribe(EventTypeDNAWrite, subscriber)
	require.NoError(t, err)

	// Verify subscription
	stats := publisher.GetStats()
	assert.Equal(t, 1, stats.RegisteredSubscribers)

	// Unsubscribe
	err = publisher.Unsubscribe(EventTypeDNAWrite, "test")
	require.NoError(t, err)

	// Verify unsubscription
	stats = publisher.GetStats()
	assert.Equal(t, 0, stats.RegisteredSubscribers)
}

func TestDriftSubscriber_Creation(t *testing.T) {
	config := DefaultDriftSubscriberConfig()
	logger := logging.Logger(nil)

	subscriber := NewDriftSubscriber(nil, nil, config, logger)
	require.NotNil(t, subscriber)

	info := subscriber.GetSubscriberInfo()
	assert.Equal(t, "drift_detection", info.Name)
	assert.Contains(t, info.EventTypes, EventTypeDNAWrite)
	assert.Equal(t, 100, info.Priority)
}

func TestDriftSubscriber_EventProcessing(t *testing.T) {
	config := DefaultDriftSubscriberConfig()
	logger := logging.Logger(nil)

	subscriber := NewDriftSubscriber(nil, nil, config, logger)

	// Create test event
	event := &DNAChangeEvent{
		DeviceID:    "test-device",
		Timestamp:   time.Now(),
		DNA:         &commonpb.DNA{Id: "test-dna"},
		ContentHash: "abc123",
	}

	// Process event
	ctx := context.Background()
	err := subscriber.OnEvent(ctx, event)
	require.NoError(t, err)

	// Verify subscriber processed the event
	driftSub := subscriber.(*driftSubscriber)
	assert.Equal(t, int64(1), driftSub.stats.EventsReceived)
}

func TestDefaultConfigs(t *testing.T) {
	// Test default publisher config
	config := DefaultPublisherConfig()
	assert.Greater(t, config.WorkerCount, 0)
	assert.Greater(t, config.QueueSize, 0)
	assert.Greater(t, config.WorkerTimeout, time.Duration(0))

	// Test default drift subscriber config
	driftConfig := DefaultDriftSubscriberConfig()
	assert.True(t, driftConfig.EnableRealTimeDetection)
	assert.Greater(t, driftConfig.ComparisonWindow, time.Duration(0))
	assert.Greater(t, driftConfig.MaxDetectionTime, time.Duration(0))
}
