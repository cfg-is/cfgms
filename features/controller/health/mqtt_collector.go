// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package health

import (
	"context"
	"sync"
	"time"
)

// MQTTBrokerStats defines the interface for accessing MQTT broker statistics
// This interface allows the collector to gather metrics from different MQTT implementations
type MQTTBrokerStats interface {
	// GetActiveConnections returns the number of active steward connections
	GetActiveConnections() int64

	// GetMessageQueueDepth returns the current message queue depth
	GetMessageQueueDepth() int64

	// GetTotalMessagesSent returns the total number of messages sent
	GetTotalMessagesSent() int64

	// GetTotalMessagesReceived returns the total number of messages received
	GetTotalMessagesReceived() int64

	// GetConnectionErrors returns the total number of connection errors
	GetConnectionErrors() int64
}

// DefaultMQTTCollector implements MQTTCollector
type DefaultMQTTCollector struct {
	mu          sync.RWMutex
	metrics     *MQTTMetrics
	brokerStats MQTTBrokerStats

	// For calculating throughput
	lastMessagesSent     int64
	lastMessagesReceived int64
	lastCollectionTime   time.Time
}

// NewDefaultMQTTCollector creates a new MQTT metrics collector
func NewDefaultMQTTCollector(brokerStats MQTTBrokerStats) *DefaultMQTTCollector {
	return &DefaultMQTTCollector{
		metrics:     &MQTTMetrics{},
		brokerStats: brokerStats,
		// lastCollectionTime is zero initially, so first collection won't calculate throughput
	}
}

// CollectMetrics gathers MQTT broker metrics
func (c *DefaultMQTTCollector) CollectMetrics(ctx context.Context) error {
	timestamp := time.Now()

	// Get current stats from broker
	activeConnections := c.brokerStats.GetActiveConnections()
	queueDepth := c.brokerStats.GetMessageQueueDepth()
	totalSent := c.brokerStats.GetTotalMessagesSent()
	totalReceived := c.brokerStats.GetTotalMessagesReceived()
	connectionErrors := c.brokerStats.GetConnectionErrors()

	// Calculate throughput (messages per second)
	var throughput float64
	if !c.lastCollectionTime.IsZero() {
		duration := timestamp.Sub(c.lastCollectionTime).Seconds()
		if duration > 0 {
			sentDelta := totalSent - c.lastMessagesSent
			receivedDelta := totalReceived - c.lastMessagesReceived
			throughput = float64(sentDelta+receivedDelta) / duration
		}
	}

	// Build metrics
	metrics := &MQTTMetrics{
		ActiveConnections:     activeConnections,
		MessageQueueDepth:     queueDepth,
		MessageThroughput:     throughput,
		TotalMessagesSent:     totalSent,
		TotalMessagesReceived: totalReceived,
		ConnectionErrors:      connectionErrors,
		CollectedAt:           timestamp,
	}

	// Store for next calculation
	c.lastMessagesSent = totalSent
	c.lastMessagesReceived = totalReceived
	c.lastCollectionTime = timestamp

	c.mu.Lock()
	c.metrics = metrics
	c.mu.Unlock()

	return nil
}

// GetMetrics returns the current MQTT metrics
func (c *DefaultMQTTCollector) GetMetrics() *MQTTMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}

// MockMQTTBrokerStats implements MQTTBrokerStats for testing
type MockMQTTBrokerStats struct {
	ActiveConnections     int64
	MessageQueueDepth     int64
	TotalMessagesSent     int64
	TotalMessagesReceived int64
	ConnectionErrors      int64
}

// GetActiveConnections returns the number of active connections
func (m *MockMQTTBrokerStats) GetActiveConnections() int64 {
	return m.ActiveConnections
}

// GetMessageQueueDepth returns the message queue depth
func (m *MockMQTTBrokerStats) GetMessageQueueDepth() int64 {
	return m.MessageQueueDepth
}

// GetTotalMessagesSent returns total messages sent
func (m *MockMQTTBrokerStats) GetTotalMessagesSent() int64 {
	return m.TotalMessagesSent
}

// GetTotalMessagesReceived returns total messages received
func (m *MockMQTTBrokerStats) GetTotalMessagesReceived() int64 {
	return m.TotalMessagesReceived
}

// GetConnectionErrors returns connection error count
func (m *MockMQTTBrokerStats) GetConnectionErrors() int64 {
	return m.ConnectionErrors
}
