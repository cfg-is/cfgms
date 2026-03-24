// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package health_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/health"
)

func TestDefaultTransportCollector_CollectsMetrics(t *testing.T) {
	stats := &health.MockTransportProviderStats{
		ConnectedStewardsVal:    10,
		StreamErrorsVal:         3,
		MessagesSentVal:         500,
		MessagesReceivedVal:     750,
		ReconnectionAttemptsVal: 2,
		AvgLatencyVal:           5 * time.Millisecond,
	}

	collector := health.NewDefaultTransportCollector(stats)
	ctx := context.Background()

	err := collector.CollectMetrics(ctx)
	require.NoError(t, err)

	metrics := collector.GetMetrics()
	require.NotNil(t, metrics)

	assert.Equal(t, 10, metrics.ConnectedStewards)
	assert.Equal(t, int64(3), metrics.StreamErrors)
	assert.Equal(t, int64(500), metrics.MessagesSent)
	assert.Equal(t, int64(750), metrics.MessagesReceived)
	assert.Equal(t, int64(2), metrics.ReconnectionAttempts)
	assert.Equal(t, 5*time.Millisecond, metrics.AvgLatency)
	assert.False(t, metrics.CollectedAt.IsZero(), "CollectedAt should be set")
}

func TestDefaultTransportCollector_NilStatsHandledGracefully(t *testing.T) {
	// nil providerStats simulates transport not yet started
	collector := health.NewDefaultTransportCollector(nil)
	ctx := context.Background()

	// Should return nil without error
	err := collector.CollectMetrics(ctx)
	assert.NoError(t, err)

	// GetMetrics returns the initial empty struct (not nil)
	metrics := collector.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, 0, metrics.ConnectedStewards)
	assert.Equal(t, int64(0), metrics.StreamErrors)
}

func TestDefaultTransportCollector_ZeroValues(t *testing.T) {
	stats := &health.MockTransportProviderStats{}

	collector := health.NewDefaultTransportCollector(stats)
	ctx := context.Background()

	err := collector.CollectMetrics(ctx)
	require.NoError(t, err)

	metrics := collector.GetMetrics()
	require.NotNil(t, metrics)

	assert.Equal(t, 0, metrics.ConnectedStewards)
	assert.Equal(t, int64(0), metrics.StreamErrors)
	assert.Equal(t, int64(0), metrics.MessagesSent)
	assert.Equal(t, int64(0), metrics.MessagesReceived)
	assert.Equal(t, int64(0), metrics.ReconnectionAttempts)
	assert.Equal(t, time.Duration(0), metrics.AvgLatency)
}

func TestDefaultTransportCollector_UpdatesMetricsOnSubsequentCollections(t *testing.T) {
	stats := &health.MockTransportProviderStats{
		ConnectedStewardsVal: 5,
		MessagesSentVal:      100,
	}

	collector := health.NewDefaultTransportCollector(stats)
	ctx := context.Background()

	err := collector.CollectMetrics(ctx)
	require.NoError(t, err)

	first := collector.GetMetrics()
	assert.Equal(t, 5, first.ConnectedStewards)
	assert.Equal(t, int64(100), first.MessagesSent)

	// Update the mock stats
	stats.ConnectedStewardsVal = 15
	stats.MessagesSentVal = 200

	err = collector.CollectMetrics(ctx)
	require.NoError(t, err)

	second := collector.GetMetrics()
	assert.Equal(t, 15, second.ConnectedStewards)
	assert.Equal(t, int64(200), second.MessagesSent)
}
