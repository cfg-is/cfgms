// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// stubControlPlaneProvider implements controlplaneInterfaces.ControlPlaneProvider for testing.
// Only GetStats is used by the adapter; other methods are no-ops.
type stubControlPlaneProvider struct {
	controlplaneInterfaces.ControlPlaneProvider // embed interface to satisfy unused methods
	stats                                       *controlplaneTypes.ControlPlaneStats
	err                                         error
}

func (s *stubControlPlaneProvider) GetStats(_ context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	return s.stats, s.err
}

func TestGRPCTransportStatsAdapter_MapsStatsCorrectly(t *testing.T) {
	provider := &stubControlPlaneProvider{
		stats: &controlplaneTypes.ControlPlaneStats{
			ConnectedStewards:  7,
			CommandsSent:       10,
			ResponsesSent:      5,
			HeartbeatsSent:     20,
			EventsPublished:    3,
			CommandsReceived:   8,
			ResponsesReceived:  4,
			HeartbeatsReceived: 18,
			EventsReceived:     6,
			DeliveryFailures:   2,
			AvgLatency:         3 * time.Millisecond,
			ProviderMetrics: map[string]interface{}{
				"reconnect_attempts": int64(4),
			},
		},
	}

	adapter := NewGRPCTransportStatsAdapter(provider)

	assert.Equal(t, 7, adapter.GetConnectedStewards())
	assert.Equal(t, int64(2), adapter.GetStreamErrors())
	// MessagesSent = CommandsSent + ResponsesSent + HeartbeatsSent + EventsPublished = 10+5+20+3 = 38
	assert.Equal(t, int64(38), adapter.GetMessagesSent())
	// MessagesReceived = CommandsReceived + ResponsesReceived + HeartbeatsReceived + EventsReceived = 8+4+18+6 = 36
	assert.Equal(t, int64(36), adapter.GetMessagesReceived())
	assert.Equal(t, int64(4), adapter.GetReconnectionAttempts())
	assert.Equal(t, 3*time.Millisecond, adapter.GetAvgLatency())
}

func TestGRPCTransportStatsAdapter_ReturnsZerosOnError(t *testing.T) {
	provider := &stubControlPlaneProvider{
		err: assert.AnError,
	}

	adapter := NewGRPCTransportStatsAdapter(provider)

	assert.Equal(t, 0, adapter.GetConnectedStewards())
	assert.Equal(t, int64(0), adapter.GetStreamErrors())
	assert.Equal(t, int64(0), adapter.GetMessagesSent())
	assert.Equal(t, int64(0), adapter.GetMessagesReceived())
	assert.Equal(t, int64(0), adapter.GetReconnectionAttempts())
	assert.Equal(t, time.Duration(0), adapter.GetAvgLatency())
}

func TestGRPCTransportStatsAdapter_NilProviderMetrics(t *testing.T) {
	provider := &stubControlPlaneProvider{
		stats: &controlplaneTypes.ControlPlaneStats{
			ConnectedStewards: 3,
			ProviderMetrics:   nil, // server mode — no reconnect_attempts
		},
	}

	adapter := NewGRPCTransportStatsAdapter(provider)

	assert.Equal(t, 3, adapter.GetConnectedStewards())
	assert.Equal(t, int64(0), adapter.GetReconnectionAttempts())
}

func TestGRPCTransportStatsAdapter_NoReconnectAttemptsKey(t *testing.T) {
	provider := &stubControlPlaneProvider{
		stats: &controlplaneTypes.ControlPlaneStats{
			ProviderMetrics: map[string]interface{}{
				"connection_state": "connected",
				// No reconnect_attempts key
			},
		},
	}

	adapter := NewGRPCTransportStatsAdapter(provider)

	assert.Equal(t, int64(0), adapter.GetReconnectionAttempts())
}

func TestBasicStorageStats_ReturnsProviderName(t *testing.T) {
	stats := NewBasicStorageStats("git")

	require.Equal(t, "git", stats.GetProviderName())
	assert.Equal(t, float64(0), stats.GetPoolUtilization())

	avg, p95, total, slow, errors := stats.GetQueryMetrics()
	assert.Equal(t, float64(0), avg)
	assert.Equal(t, float64(0), p95)
	assert.Equal(t, int64(0), total)
	assert.Equal(t, int64(0), slow)
	assert.Equal(t, int64(0), errors)
}

func TestNoOpApplicationQueueStats_ReturnsZeros(t *testing.T) {
	stats := &NoOpApplicationQueueStats{}

	depth, wait, active := stats.GetWorkflowStats()
	assert.Equal(t, int64(0), depth)
	assert.Equal(t, float64(0), wait)
	assert.Equal(t, int64(0), active)

	depth, wait, active = stats.GetScriptStats()
	assert.Equal(t, int64(0), depth)
	assert.Equal(t, float64(0), wait)
	assert.Equal(t, int64(0), active)

	assert.Equal(t, int64(0), stats.GetConfigQueueDepth())
}
