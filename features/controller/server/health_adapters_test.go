// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mqttInterfaces "github.com/cfgis/cfgms/pkg/mqtt/interfaces"
)

// stubBroker implements mqttInterfaces.Broker for testing the adapter.
// Only GetStats is used by the adapter; other methods are no-ops.
type stubBroker struct {
	mqttInterfaces.Broker // embed interface to satisfy unused methods
	stats                 mqttInterfaces.BrokerStats
	err                   error
}

func (b *stubBroker) GetStats(_ context.Context) (mqttInterfaces.BrokerStats, error) {
	return b.stats, b.err
}

func TestMochiBrokerStatsAdapter_MapsStatsCorrectly(t *testing.T) {
	broker := &stubBroker{
		stats: mqttInterfaces.BrokerStats{
			ClientsConnected: 5,
			MessagesSent:     100,
			MessagesReceived: 200,
			MessagesDropped:  3,
		},
	}

	adapter := NewMochiBrokerStatsAdapter(broker)

	assert.Equal(t, int64(5), adapter.GetActiveConnections())
	assert.Equal(t, int64(3), adapter.GetMessageQueueDepth())
	assert.Equal(t, int64(100), adapter.GetTotalMessagesSent())
	assert.Equal(t, int64(200), adapter.GetTotalMessagesReceived())
	assert.Equal(t, int64(3), adapter.GetConnectionErrors())
}

func TestMochiBrokerStatsAdapter_ReturnsZerosOnError(t *testing.T) {
	broker := &stubBroker{
		err: assert.AnError,
	}

	adapter := NewMochiBrokerStatsAdapter(broker)

	assert.Equal(t, int64(0), adapter.GetActiveConnections())
	assert.Equal(t, int64(0), adapter.GetMessageQueueDepth())
	assert.Equal(t, int64(0), adapter.GetTotalMessagesSent())
	assert.Equal(t, int64(0), adapter.GetTotalMessagesReceived())
	assert.Equal(t, int64(0), adapter.GetConnectionErrors())
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
