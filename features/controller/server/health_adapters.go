// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"time"

	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
)

// GRPCTransportStatsAdapter adapts the gRPC ControlPlaneProvider's GetStats() to
// the health.TransportProviderStats interface used by the health collector.
type GRPCTransportStatsAdapter struct {
	provider controlplaneInterfaces.ControlPlaneProvider
}

// NewGRPCTransportStatsAdapter creates an adapter wrapping a ControlPlaneProvider.
func NewGRPCTransportStatsAdapter(provider controlplaneInterfaces.ControlPlaneProvider) *GRPCTransportStatsAdapter {
	return &GRPCTransportStatsAdapter{provider: provider}
}

// GetConnectedStewards returns the number of connected stewards from the gRPC provider.
func (a *GRPCTransportStatsAdapter) GetConnectedStewards() int {
	stats, err := a.provider.GetStats(context.Background())
	if err != nil {
		return 0
	}
	return int(stats.ConnectedStewards) // #nosec G115 -- steward count will never exceed int max
}

// GetStreamErrors returns delivery failures as a proxy for stream errors.
func (a *GRPCTransportStatsAdapter) GetStreamErrors() int64 {
	stats, err := a.provider.GetStats(context.Background())
	if err != nil {
		return 0
	}
	return stats.DeliveryFailures
}

// GetMessagesSent returns the total messages sent (commands + responses + heartbeats + events).
func (a *GRPCTransportStatsAdapter) GetMessagesSent() int64 {
	stats, err := a.provider.GetStats(context.Background())
	if err != nil {
		return 0
	}
	return stats.CommandsSent + stats.ResponsesSent + stats.HeartbeatsSent + stats.EventsPublished
}

// GetMessagesReceived returns the total messages received (commands + responses + heartbeats + events).
func (a *GRPCTransportStatsAdapter) GetMessagesReceived() int64 {
	stats, err := a.provider.GetStats(context.Background())
	if err != nil {
		return 0
	}
	return stats.CommandsReceived + stats.ResponsesReceived + stats.HeartbeatsReceived + stats.EventsReceived
}

// GetReconnectionAttempts returns the reconnection attempts from provider metrics.
// Returns 0 if the provider does not expose reconnection metrics (server mode).
func (a *GRPCTransportStatsAdapter) GetReconnectionAttempts() int64 {
	stats, err := a.provider.GetStats(context.Background())
	if err != nil {
		return 0
	}
	if stats.ProviderMetrics == nil {
		return 0
	}
	if v, ok := stats.ProviderMetrics["reconnect_attempts"]; ok {
		if attempts, ok := v.(int64); ok {
			return attempts
		}
	}
	return 0
}

// GetAvgLatency returns the average message latency.
func (a *GRPCTransportStatsAdapter) GetAvgLatency() time.Duration {
	stats, err := a.provider.GetStats(context.Background())
	if err != nil {
		return 0
	}
	return stats.AvgLatency
}

// UnimplementedStorageStats implements health.StorageProviderStats with sentinel
// values (-1) that are distinguishable from real zero measurements. Implemented()
// returns false so callers can skip or annotate these metrics accordingly.
type UnimplementedStorageStats struct {
	providerName string
}

// NewUnimplementedStorageStats creates an UnimplementedStorageStats for the given provider.
func NewUnimplementedStorageStats(providerName string) *UnimplementedStorageStats {
	return &UnimplementedStorageStats{providerName: providerName}
}

// Implemented returns false — storage metrics are not yet instrumented.
func (s *UnimplementedStorageStats) Implemented() bool {
	return false
}

// GetProviderName returns the storage provider name.
func (s *UnimplementedStorageStats) GetProviderName() string {
	return s.providerName
}

// GetPoolUtilization returns -1.0 (sentinel: not instrumented).
func (s *UnimplementedStorageStats) GetPoolUtilization() float64 {
	return -1.0
}

// GetQueryMetrics returns -1 for all values (sentinel: not instrumented).
func (s *UnimplementedStorageStats) GetQueryMetrics() (avgLatencyMs, p95LatencyMs float64, totalQueries, slowQueries, queryErrors int64) {
	return -1, -1, -1, -1, -1
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
