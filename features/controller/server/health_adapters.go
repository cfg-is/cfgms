// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"

	mqttInterfaces "github.com/cfgis/cfgms/pkg/mqtt/interfaces"
)

// MochiBrokerStatsAdapter adapts the MQTT broker's GetStats() to the
// health.MQTTBrokerStats interface used by the health collector.
type MochiBrokerStatsAdapter struct {
	broker mqttInterfaces.Broker
}

// NewMochiBrokerStatsAdapter creates an adapter wrapping an MQTT broker.
func NewMochiBrokerStatsAdapter(broker mqttInterfaces.Broker) *MochiBrokerStatsAdapter {
	return &MochiBrokerStatsAdapter{broker: broker}
}

// GetActiveConnections returns the number of connected MQTT clients.
func (a *MochiBrokerStatsAdapter) GetActiveConnections() int64 {
	stats, err := a.broker.GetStats(context.Background())
	if err != nil {
		return 0
	}
	return stats.ClientsConnected
}

// GetMessageQueueDepth returns messages dropped as a proxy for queue pressure.
func (a *MochiBrokerStatsAdapter) GetMessageQueueDepth() int64 {
	stats, err := a.broker.GetStats(context.Background())
	if err != nil {
		return 0
	}
	return stats.MessagesDropped
}

// GetTotalMessagesSent returns the total messages sent by the broker.
func (a *MochiBrokerStatsAdapter) GetTotalMessagesSent() int64 {
	stats, err := a.broker.GetStats(context.Background())
	if err != nil {
		return 0
	}
	return stats.MessagesSent
}

// GetTotalMessagesReceived returns the total messages received by the broker.
func (a *MochiBrokerStatsAdapter) GetTotalMessagesReceived() int64 {
	stats, err := a.broker.GetStats(context.Background())
	if err != nil {
		return 0
	}
	return stats.MessagesReceived
}

// GetConnectionErrors returns messages dropped as a proxy for connection errors.
func (a *MochiBrokerStatsAdapter) GetConnectionErrors() int64 {
	stats, err := a.broker.GetStats(context.Background())
	if err != nil {
		return 0
	}
	return stats.MessagesDropped
}

// BasicStorageStats implements health.StorageProviderStats with the provider
// name and zero metrics. Real latency instrumentation is a follow-up.
type BasicStorageStats struct {
	providerName string
}

// NewBasicStorageStats creates a BasicStorageStats for the given provider.
func NewBasicStorageStats(providerName string) *BasicStorageStats {
	return &BasicStorageStats{providerName: providerName}
}

// GetProviderName returns the storage provider name.
func (s *BasicStorageStats) GetProviderName() string {
	return s.providerName
}

// GetPoolUtilization returns 0 (not instrumented yet).
func (s *BasicStorageStats) GetPoolUtilization() float64 {
	return 0
}

// GetQueryMetrics returns zeros (not instrumented yet).
func (s *BasicStorageStats) GetQueryMetrics() (avgLatencyMs, p95LatencyMs float64, totalQueries, slowQueries, queryErrors int64) {
	return 0, 0, 0, 0, 0
}

// NoOpApplicationQueueStats implements health.ApplicationQueueStats returning
// zeros. The workflow engine doesn't exist yet.
type NoOpApplicationQueueStats struct{}

// GetWorkflowStats returns zeros.
func (n *NoOpApplicationQueueStats) GetWorkflowStats() (queueDepth int64, maxWaitTime float64, activeWorkflows int64) {
	return 0, 0, 0
}

// GetScriptStats returns zeros.
func (n *NoOpApplicationQueueStats) GetScriptStats() (queueDepth int64, maxWaitTime float64, activeScripts int64) {
	return 0, 0, 0
}

// GetConfigQueueDepth returns 0.
func (n *NoOpApplicationQueueStats) GetConfigQueueDepth() int64 {
	return 0
}
