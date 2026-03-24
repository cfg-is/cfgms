// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package health

import (
	"context"
	"sync"
	"time"
)

// TransportProviderStats defines the interface for accessing transport provider statistics.
// This interface allows the collector to gather metrics from different transport implementations.
type TransportProviderStats interface {
	// GetConnectedStewards returns the number of connected stewards
	GetConnectedStewards() int

	// GetStreamErrors returns the total number of stream/delivery errors
	GetStreamErrors() int64

	// GetMessagesSent returns the total number of messages sent
	GetMessagesSent() int64

	// GetMessagesReceived returns the total number of messages received
	GetMessagesReceived() int64

	// GetReconnectionAttempts returns the total number of reconnection attempts
	GetReconnectionAttempts() int64

	// GetAvgLatency returns the average message latency
	GetAvgLatency() time.Duration
}

// TransportCollector collects transport provider metrics
type TransportCollector interface {
	ComponentCollector
	GetMetrics() *TransportMetrics
}

// DefaultTransportCollector implements TransportCollector
type DefaultTransportCollector struct {
	mu            sync.RWMutex
	metrics       *TransportMetrics
	providerStats TransportProviderStats
}

// NewDefaultTransportCollector creates a new transport metrics collector.
// providerStats may be nil when the transport has not yet started —
// CollectMetrics handles this gracefully by returning nil without updating metrics.
func NewDefaultTransportCollector(providerStats TransportProviderStats) *DefaultTransportCollector {
	return &DefaultTransportCollector{
		metrics:       &TransportMetrics{},
		providerStats: providerStats,
	}
}

// CollectMetrics gathers transport provider metrics.
// Returns nil without updating metrics if providerStats is nil (transport not yet started).
func (c *DefaultTransportCollector) CollectMetrics(ctx context.Context) error {
	if c.providerStats == nil {
		return nil
	}

	timestamp := time.Now()

	metrics := &TransportMetrics{
		ConnectedStewards:    c.providerStats.GetConnectedStewards(),
		StreamErrors:         c.providerStats.GetStreamErrors(),
		MessagesSent:         c.providerStats.GetMessagesSent(),
		MessagesReceived:     c.providerStats.GetMessagesReceived(),
		ReconnectionAttempts: c.providerStats.GetReconnectionAttempts(),
		AvgLatency:           c.providerStats.GetAvgLatency(),
		CollectedAt:          timestamp,
	}

	c.mu.Lock()
	c.metrics = metrics
	c.mu.Unlock()

	return nil
}

// GetMetrics returns the current transport metrics
func (c *DefaultTransportCollector) GetMetrics() *TransportMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}

// MockTransportProviderStats implements TransportProviderStats for testing
type MockTransportProviderStats struct {
	ConnectedStewardsVal    int
	StreamErrorsVal         int64
	MessagesSentVal         int64
	MessagesReceivedVal     int64
	ReconnectionAttemptsVal int64
	AvgLatencyVal           time.Duration
}

// GetConnectedStewards returns the number of connected stewards
func (m *MockTransportProviderStats) GetConnectedStewards() int {
	return m.ConnectedStewardsVal
}

// GetStreamErrors returns the total stream errors
func (m *MockTransportProviderStats) GetStreamErrors() int64 {
	return m.StreamErrorsVal
}

// GetMessagesSent returns total messages sent
func (m *MockTransportProviderStats) GetMessagesSent() int64 {
	return m.MessagesSentVal
}

// GetMessagesReceived returns total messages received
func (m *MockTransportProviderStats) GetMessagesReceived() int64 {
	return m.MessagesReceivedVal
}

// GetReconnectionAttempts returns total reconnection attempts
func (m *MockTransportProviderStats) GetReconnectionAttempts() int64 {
	return m.ReconnectionAttemptsVal
}

// GetAvgLatency returns average message latency
func (m *MockTransportProviderStats) GetAvgLatency() time.Duration {
	return m.AvgLatencyVal
}
