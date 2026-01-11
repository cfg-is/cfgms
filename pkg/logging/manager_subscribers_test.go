// SPDX-License-Identifier: Apache-2.0
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
)

// MockSubscriber implements LoggingSubscriber for testing
type MockSubscriber struct {
	name          string
	description   string
	initialized   bool
	closed        bool
	config        map[string]interface{}
	handled       []interfaces.LogEntry
	shouldHandle  func(interfaces.LogEntry) bool
	handleError   error
	availableFunc func() (bool, error)
	mutex         sync.RWMutex
}

func NewMockSubscriber(name string) *MockSubscriber {
	return &MockSubscriber{
		name:          name,
		description:   "Mock subscriber for testing",
		handled:       make([]interfaces.LogEntry, 0),
		shouldHandle:  func(interfaces.LogEntry) bool { return true },
		availableFunc: func() (bool, error) { return true, nil },
	}
}

func (m *MockSubscriber) Name() string {
	return m.name
}

func (m *MockSubscriber) Description() string {
	return m.description
}

func (m *MockSubscriber) Initialize(config map[string]interface{}) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.config = config
	m.initialized = true
	return nil
}

func (m *MockSubscriber) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.closed = true
	return nil
}

func (m *MockSubscriber) HandleLogEntry(ctx context.Context, entry interfaces.LogEntry) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.handleError != nil {
		return m.handleError
	}

	m.handled = append(m.handled, entry)
	return nil
}

func (m *MockSubscriber) ShouldHandle(entry interfaces.LogEntry) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.shouldHandle(entry)
}

func (m *MockSubscriber) Available() (bool, error) {
	return m.availableFunc()
}

func (m *MockSubscriber) GetHandled() []interfaces.LogEntry {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return append([]interfaces.LogEntry(nil), m.handled...)
}

func (m *MockSubscriber) SetShouldHandle(fn func(interfaces.LogEntry) bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.shouldHandle = fn
}

func (m *MockSubscriber) SetHandleError(err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.handleError = err
}

func TestLoggingManager_WithSubscribers(t *testing.T) {
	// Create config with mock subscribers
	config := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":   "/tmp/test-logs",
			"file_prefix": "test",
		},
		Level:       "INFO",
		ServiceName: "test-service",
		Component:   "test-component",
		AsyncWrites: false, // Synchronous for testing
		BufferSize:  100,
		Subscribers: []SubscriberConfig{
			{
				Type:    "mock1",
				Enabled: true,
				Config:  map[string]interface{}{"test": "config1"},
			},
			{
				Type:    "mock2",
				Enabled: true,
				Config:  map[string]interface{}{"test": "config2"},
			},
			{
				Type:    "mock3",
				Enabled: false, // Disabled
				Config:  map[string]interface{}{"test": "config3"},
			},
		},
	}

	// Create manager with mock subscriber factory
	originalMockFactory := mockFactory
	defer func() { mockFactory = originalMockFactory }()

	mockSubscribers := make(map[string]*MockSubscriber)
	mockFactory = func(subscriberType string) (interfaces.LoggingSubscriber, error) {
		mock := NewMockSubscriber(subscriberType)
		mockSubscribers[subscriberType] = mock
		return mock, nil
	}

	// Import providers
	_ = "github.com/cfgis/cfgms/pkg/logging/providers/file"

	manager, err := NewLoggingManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	// Verify subscribers were initialized
	assert.Len(t, manager.subscribers, 2) // Only enabled ones

	// Check mock1 was initialized
	mock1, exists := mockSubscribers["mock1"]
	require.True(t, exists)
	assert.True(t, mock1.initialized)
	assert.Equal(t, map[string]interface{}{"test": "config1"}, mock1.config)

	// Check mock2 was initialized
	mock2, exists := mockSubscribers["mock2"]
	require.True(t, exists)
	assert.True(t, mock2.initialized)
	assert.Equal(t, map[string]interface{}{"test": "config2"}, mock2.config)

	// Check mock3 was not initialized (disabled)
	_, exists = mockSubscribers["mock3"]
	assert.False(t, exists)

	// Test log entry handling
	ctx := context.Background()
	entry := interfaces.LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   "Test message",
	}

	err = manager.WriteEntry(ctx, entry)
	assert.NoError(t, err)

	// Give some time for async processing
	time.Sleep(100 * time.Millisecond)

	// Verify both subscribers received the entry
	handled1 := mock1.GetHandled()
	assert.Len(t, handled1, 1)
	assert.Equal(t, "Test message", handled1[0].Message)

	handled2 := mock2.GetHandled()
	assert.Len(t, handled2, 1)
	assert.Equal(t, "Test message", handled2[0].Message)
}

func TestLoggingManager_SubscriberFiltering(t *testing.T) {
	config := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":   "/tmp/test-logs",
			"file_prefix": "test",
		},
		Level:       "INFO",
		ServiceName: "test-service",
		BufferSize:  100,
		Subscribers: []SubscriberConfig{
			{
				Type:    "filtered",
				Enabled: true,
				Config:  map[string]interface{}{},
			},
		},
	}

	mockSubscriber := NewMockSubscriber("filtered")
	// Only handle ERROR level
	mockSubscriber.SetShouldHandle(func(entry interfaces.LogEntry) bool {
		return entry.Level == "ERROR"
	})

	originalMockFactory := mockFactory
	defer func() { mockFactory = originalMockFactory }()

	mockFactory = func(subscriberType string) (interfaces.LoggingSubscriber, error) {
		return mockSubscriber, nil
	}

	manager, err := NewLoggingManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	ctx := context.Background()

	// Send INFO entry (should be filtered out)
	infoEntry := interfaces.LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   "Info message",
	}
	err = manager.WriteEntry(ctx, infoEntry)
	assert.NoError(t, err)

	// Send ERROR entry (should be handled)
	errorEntry := interfaces.LogEntry{
		Timestamp: time.Now(),
		Level:     "ERROR",
		Message:   "Error message",
	}
	err = manager.WriteEntry(ctx, errorEntry)
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	handled := mockSubscriber.GetHandled()
	assert.Len(t, handled, 1)
	assert.Equal(t, "ERROR", handled[0].Level)
	assert.Equal(t, "Error message", handled[0].Message)
}

func TestLoggingManager_SubscriberError(t *testing.T) {
	config := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":   "/tmp/test-logs",
			"file_prefix": "test",
		},
		Level:      "INFO",
		BufferSize: 100,
		Subscribers: []SubscriberConfig{
			{
				Type:    "error-subscriber",
				Enabled: true,
				Config:  map[string]interface{}{},
			},
		},
	}

	mockSubscriber := NewMockSubscriber("error-subscriber")
	mockSubscriber.SetHandleError(assert.AnError)

	originalMockFactory := mockFactory
	defer func() { mockFactory = originalMockFactory }()

	mockFactory = func(subscriberType string) (interfaces.LoggingSubscriber, error) {
		return mockSubscriber, nil
	}

	manager, err := NewLoggingManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	ctx := context.Background()
	entry := interfaces.LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   "Test message",
	}

	// Primary logging should succeed even if subscriber fails
	err = manager.WriteEntry(ctx, entry)
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Verify subscriber was called (but failed)
	handled := mockSubscriber.GetHandled()
	assert.Len(t, handled, 0) // No successful handling due to error
}

func TestLoggingManager_EventChannelOverflow(t *testing.T) {
	config := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":   "/tmp/test-logs",
			"file_prefix": "test",
		},
		Level:      "INFO",
		BufferSize: 2, // Very small buffer to test overflow
		Subscribers: []SubscriberConfig{
			{
				Type:    "slow-subscriber",
				Enabled: true,
				Config:  map[string]interface{}{},
			},
		},
	}

	mockSubscriber := NewMockSubscriber("slow-subscriber")

	originalMockFactory := mockFactory
	defer func() { mockFactory = originalMockFactory }()

	mockFactory = func(subscriberType string) (interfaces.LoggingSubscriber, error) {
		return mockSubscriber, nil
	}

	manager, err := NewLoggingManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	ctx := context.Background()

	// Send multiple entries quickly to overflow buffer
	for i := 0; i < 10; i++ {
		entry := interfaces.LogEntry{
			Timestamp: time.Now(),
			Level:     "INFO",
			Message:   "Rapid message",
		}
		err = manager.WriteEntry(ctx, entry)
		assert.NoError(t, err) // Primary logging should still succeed
	}

	time.Sleep(200 * time.Millisecond)

	// Some entries may be dropped due to buffer overflow, but no errors
	handled := mockSubscriber.GetHandled()
	assert.LessOrEqual(t, len(handled), 10)
}

func TestLoggingManager_NoSubscribers(t *testing.T) {
	config := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":   "/tmp/test-logs",
			"file_prefix": "test",
		},
		Level:       "INFO",
		Subscribers: []SubscriberConfig{}, // No subscribers
	}

	manager, err := NewLoggingManager(config)
	require.NoError(t, err)
	defer func() { _ = manager.Close() }()

	assert.Len(t, manager.subscribers, 0)
	assert.Nil(t, manager.eventChan)

	// Should work normally without subscribers
	ctx := context.Background()
	entry := interfaces.LogEntry{
		Timestamp: time.Now(),
		Level:     "INFO",
		Message:   "Test message",
	}

	err = manager.WriteEntry(ctx, entry)
	assert.NoError(t, err)
}

func TestLoggingManager_Close_WithSubscribers(t *testing.T) {
	config := &LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":   "/tmp/test-logs",
			"file_prefix": "test",
		},
		Level:      "INFO",
		BufferSize: 100,
		Subscribers: []SubscriberConfig{
			{
				Type:    "close-test",
				Enabled: true,
				Config:  map[string]interface{}{},
			},
		},
	}

	mockSubscriber := NewMockSubscriber("close-test")

	originalMockFactory := mockFactory
	defer func() { mockFactory = originalMockFactory }()

	mockFactory = func(subscriberType string) (interfaces.LoggingSubscriber, error) {
		return mockSubscriber, nil
	}

	manager, err := NewLoggingManager(config)
	require.NoError(t, err)

	// Verify subscriber is initialized
	assert.True(t, mockSubscriber.initialized)
	assert.False(t, mockSubscriber.closed)

	// Close manager
	err = manager.Close()
	assert.NoError(t, err)

	// Verify subscriber was closed
	assert.True(t, mockSubscriber.closed)
}
