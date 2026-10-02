// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerRegistration "github.com/cfgis/cfgms/features/controller/registration"
	cpmemory "github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// --- GRPCTransportStatsAdapter tests ---
//
// These tests drive a real in-process control plane (the memory
// ControlPlaneProvider) over a shared bus: a server-mode provider plus one
// client-mode provider per steward. Every counter the adapter reports is
// produced by real traffic through the provider — commands delivered, events
// published, heartbeats sent, deliveries that failed because the target steward
// was not connected. Nothing about the provider is substituted.

// controlPlaneStats starts a server-mode memory provider and one client-mode
// provider per steward ID, all attached to the same bus. It returns the server
// provider and the clients keyed by steward ID.
func controlPlaneStats(t *testing.T, stewardIDs ...string) (*cpmemory.Provider, map[string]*cpmemory.Provider) {
	t.Helper()
	ctx := context.Background()

	bus := cpmemory.NewBus()
	server := cpmemory.New(cpmemory.ModeServer)
	require.NoError(t, server.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, server.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, server.Stop(stopCtx))
	})

	clients := make(map[string]*cpmemory.Provider, len(stewardIDs))
	for _, id := range stewardIDs {
		client := cpmemory.New(cpmemory.ModeClient)
		require.NoError(t, client.Initialize(ctx, map[string]interface{}{
			"bus":        bus,
			"steward_id": id,
		}))
		require.NoError(t, client.Start(ctx))
		clients[id] = client
		t.Cleanup(func() {
			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, client.Stop(stopCtx))
		})
	}

	return server, clients
}

// sendCommand addresses a signed command at stewardID and sends it from the
// server-mode provider.
func sendCommand(server *cpmemory.Provider, stewardID string) error {
	return server.SendCommand(context.Background(), &controlplaneTypes.SignedCommand{
		Command: controlplaneTypes.Command{
			ID:        "cmd-" + stewardID,
			Type:      controlplaneTypes.CommandSyncConfig,
			StewardID: stewardID,
			Timestamp: time.Now().UTC(),
		},
	})
}

// TestGRPCTransportStatsAdapter_MapsServerStats drives real controller-side
// traffic and asserts the adapter reports the provider's actual counters, with
// messages-sent and messages-received aggregated per the adapter's contract.
func TestGRPCTransportStatsAdapter_MapsServerStats(t *testing.T) {
	ctx := context.Background()
	server, clients := controlPlaneStats(t, "steward-1", "steward-2")

	// 3 commands delivered to a connected steward.
	for i := 0; i < 3; i++ {
		require.NoError(t, sendCommand(server, "steward-1"))
	}
	// 1 command addressed at a steward that is not connected — a real delivery failure.
	require.Error(t, sendCommand(server, "steward-offline"),
		"sending to a disconnected steward must fail")

	// 4 heartbeats and 2 events travel steward → controller.
	for i := 0; i < 4; i++ {
		require.NoError(t, clients["steward-1"].SendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
			StewardID: "steward-1",
			Status:    controlplaneTypes.StatusHealthy,
			Timestamp: time.Now().UTC(),
		}))
	}
	for i := 0; i < 2; i++ {
		require.NoError(t, clients["steward-1"].PublishEvent(ctx, &controlplaneTypes.Event{
			ID:        fmt.Sprintf("evt-%d", i),
			Type:      controlplaneTypes.EventConfigApplied,
			StewardID: "steward-1",
			Timestamp: time.Now().UTC(),
		}))
	}

	adapter := NewGRPCTransportStatsAdapter(server)

	assert.Equal(t, 2, adapter.GetConnectedStewards(), "both stewards are attached to the bus")
	assert.Equal(t, int64(1), adapter.GetStreamErrors(), "one delivery failure was recorded")
	// MessagesSent = CommandsSent + ResponsesSent + HeartbeatsSent + EventsPublished
	assert.Equal(t, int64(3), adapter.GetMessagesSent())
	// MessagesReceived = CommandsReceived + ResponsesReceived + HeartbeatsReceived + EventsReceived
	assert.Equal(t, int64(6), adapter.GetMessagesReceived())
	// Server mode publishes no reconnection metric.
	assert.Equal(t, int64(0), adapter.GetReconnectionAttempts())
	// The in-process control plane does not instrument latency; the adapter must
	// report the provider's value rather than synthesising one.
	assert.Equal(t, time.Duration(0), adapter.GetAvgLatency())
}

// TestGRPCTransportStatsAdapter_MapsClientStats asserts the same aggregation
// from the steward side, where the counters that move are the mirror image of
// the controller side: heartbeats and events sent, commands received.
func TestGRPCTransportStatsAdapter_MapsClientStats(t *testing.T) {
	ctx := context.Background()
	server, clients := controlPlaneStats(t, "steward-1")
	client := clients["steward-1"]

	for i := 0; i < 3; i++ {
		require.NoError(t, sendCommand(server, "steward-1"))
	}
	for i := 0; i < 4; i++ {
		require.NoError(t, client.SendHeartbeat(ctx, &controlplaneTypes.Heartbeat{
			StewardID: "steward-1",
			Status:    controlplaneTypes.StatusHealthy,
			Timestamp: time.Now().UTC(),
		}))
	}
	for i := 0; i < 2; i++ {
		require.NoError(t, client.PublishEvent(ctx, &controlplaneTypes.Event{
			ID:        fmt.Sprintf("evt-%d", i),
			Type:      controlplaneTypes.EventConfigApplied,
			StewardID: "steward-1",
			Timestamp: time.Now().UTC(),
		}))
	}

	adapter := NewGRPCTransportStatsAdapter(client)

	assert.Equal(t, int64(6), adapter.GetMessagesSent(), "4 heartbeats + 2 events")
	assert.Equal(t, int64(3), adapter.GetMessagesReceived(), "3 commands received")
	assert.Equal(t, 0, adapter.GetConnectedStewards(), "client mode tracks no connected stewards")
	assert.Equal(t, int64(0), adapter.GetStreamErrors())
	// The client publishes connection_state but no reconnect_attempts, so the
	// adapter must fall back to 0 rather than mis-reading another metric.
	stats, err := client.GetStats(ctx)
	require.NoError(t, err)
	require.NotContains(t, stats.ProviderMetrics, "reconnect_attempts")
	require.Contains(t, stats.ProviderMetrics, "connection_state")
	assert.Equal(t, int64(0), adapter.GetReconnectionAttempts())
}

// TestGRPCTransportStatsAdapter_ZerosForIdleProvider asserts that a started
// provider that has carried no traffic reports zeros through every getter —
// the adapter must not invent values for an idle control plane.
func TestGRPCTransportStatsAdapter_ZerosForIdleProvider(t *testing.T) {
	server, _ := controlPlaneStats(t)

	adapter := NewGRPCTransportStatsAdapter(server)

	assert.Equal(t, 0, adapter.GetConnectedStewards())
	assert.Equal(t, int64(0), adapter.GetStreamErrors())
	assert.Equal(t, int64(0), adapter.GetMessagesSent())
	assert.Equal(t, int64(0), adapter.GetMessagesReceived())
	assert.Equal(t, int64(0), adapter.GetReconnectionAttempts())
	assert.Equal(t, time.Duration(0), adapter.GetAvgLatency())
}

func TestUnimplementedStorageStats_ReportsUnimplemented(t *testing.T) {
	stats := NewUnimplementedStorageStats("git")

	require.Equal(t, "git", stats.GetProviderName())
	assert.False(t, stats.Implemented())
	assert.Equal(t, -1.0, stats.GetPoolUtilization())

	avg, p95, total, slow, errors := stats.GetQueryMetrics()
	assert.Equal(t, -1.0, avg)
	assert.Equal(t, -1.0, p95)
	assert.Equal(t, int64(-1), total)
	assert.Equal(t, int64(-1), slow)
	assert.Equal(t, int64(-1), errors)
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

// --- stewardIPTrustAdapter tests ---
//
// Both stores below are real storage-provider implementations rooted at a
// t.TempDir(): the flat-file StewardStore and the flat-file IPTrustStore.

// newAdapterStewardStore returns a real flat-file StewardStore pre-populated
// with the given records.
func newAdapterStewardStore(t *testing.T, records ...*business.StewardRecord) business.StewardStore {
	t.Helper()
	store := newFlatFileStewardStore(t)
	for _, r := range records {
		require.NoError(t, store.RegisterSteward(context.Background(), r))
	}
	return store
}

// trustedCIDRs returns the CIDRs recorded for tenantID in the trust store.
func trustedCIDRs(t *testing.T, store business.IPTrustStore, tenantID string) []string {
	t.Helper()
	entries, err := store.ListTrustedRanges(context.Background(), tenantID)
	require.NoError(t, err)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.TenantID+"/"+e.CIDR)
	}
	return out
}

// normaliseCIDRForAdapter returns the network address form of a CIDR.
func normaliseCIDRForAdapter(cidr string) string {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return cidr
	}
	return ipNet.String()
}

func newTestAdapter(stewardStore business.StewardStore, trustStore business.IPTrustStore) *stewardIPTrustAdapter {
	evaluator := controllerRegistration.NewIPTrustEvaluator(controllerRegistration.IPTrustEvaluatorConfig{
		Store:     trustStore,
		Threshold: time.Millisecond, // tiny threshold so tests tip it instantly
		Logger:    logging.NewLogger("debug"),
	})
	return newStewardIPTrustAdapter(evaluator, stewardStore, logging.NewLogger("debug"))
}

// TestStewardIPTrustAdapter_ResolvesIPFromStewardStore verifies that the adapter
// looks up the steward's IP from the fleet registry and passes it to the
// IPTrustEvaluator (Issue #1694).
func TestStewardIPTrustAdapter_ResolvesIPFromStewardStore(t *testing.T) {
	stewardStore := newAdapterStewardStore(t, &business.StewardRecord{
		ID:        "steward-1",
		TenantID:  "tenant-1",
		IPAddress: "10.0.0.1",
		Status:    business.StewardStatusActive,
	})
	trustStore := newFlatFileIPTrustStore(t, t.TempDir())
	adapter := newTestAdapter(stewardStore, trustStore)
	ctx := context.Background()

	// Send first healthy call to start the timer.
	require.NoError(t, adapter.RecordLiveness(ctx, "steward-1", true))

	// Manually advance the evaluator's timer past the threshold.
	adapter.evaluator.ForceTimerExpiry("tenant-1", "10.0.0.1")

	// Second call tips over threshold — the resolved IP must be persisted as trusted.
	require.NoError(t, adapter.RecordLiveness(ctx, "steward-1", true))

	trusted := trustedCIDRs(t, trustStore, "tenant-1")
	require.Len(t, trusted, 1, "the resolved IP must be recorded as a trusted range")
	assert.Equal(t, fmt.Sprintf("tenant-1/%s", normaliseCIDRForAdapter("10.0.0.1/32")), trusted[0])
}

// TestStewardIPTrustAdapter_StewardNotFound_IsNoop verifies that a missing steward
// record is silently ignored without returning an error (best-effort).
func TestStewardIPTrustAdapter_StewardNotFound_IsNoop(t *testing.T) {
	stewardStore := newAdapterStewardStore(t) // empty
	trustStore := newFlatFileIPTrustStore(t, t.TempDir())
	adapter := newTestAdapter(stewardStore, trustStore)
	ctx := context.Background()

	err := adapter.RecordLiveness(ctx, "unknown-steward", true)
	assert.NoError(t, err, "missing steward must not return an error")
	assert.Empty(t, trustedCIDRs(t, trustStore, "tenant-1"))
}

// TestStewardIPTrustAdapter_NilStewardStore_IsNoop verifies that a nil steward
// store does not cause a panic.
func TestStewardIPTrustAdapter_NilStewardStore_IsNoop(t *testing.T) {
	trustStore := newFlatFileIPTrustStore(t, t.TempDir())
	evaluator := controllerRegistration.NewIPTrustEvaluator(controllerRegistration.IPTrustEvaluatorConfig{
		Store:     trustStore,
		Threshold: time.Millisecond,
		Logger:    logging.NewLogger("debug"),
	})
	adapter := newStewardIPTrustAdapter(evaluator, nil, logging.NewLogger("debug"))

	err := adapter.RecordLiveness(context.Background(), "steward-1", true)
	assert.NoError(t, err)
	assert.Empty(t, trustedCIDRs(t, trustStore, "tenant-1"))
}

// TestStewardIPTrustAdapter_EmptyIP_IsNoop verifies that a steward with no IP
// address stored is silently skipped.
func TestStewardIPTrustAdapter_EmptyIP_IsNoop(t *testing.T) {
	stewardStore := newAdapterStewardStore(t, &business.StewardRecord{
		ID:        "steward-noip",
		TenantID:  "tenant-1",
		IPAddress: "", // no IP stored yet
	})
	trustStore := newFlatFileIPTrustStore(t, t.TempDir())
	adapter := newTestAdapter(stewardStore, trustStore)

	err := adapter.RecordLiveness(context.Background(), "steward-noip", true)
	assert.NoError(t, err)
	assert.Empty(t, trustedCIDRs(t, trustStore, "tenant-1"))
}

// TestStewardIPTrustAdapter_OfflineCall_ResetsTimer verifies that a healthy=false
// call resets the trust timer for the steward's IP.
func TestStewardIPTrustAdapter_OfflineCall_ResetsTimer(t *testing.T) {
	stewardStore := newAdapterStewardStore(t, &business.StewardRecord{
		ID:        "steward-1",
		TenantID:  "tenant-1",
		IPAddress: "10.0.0.1",
	})
	trustStore := newFlatFileIPTrustStore(t, t.TempDir())
	evaluator := controllerRegistration.NewIPTrustEvaluator(controllerRegistration.IPTrustEvaluatorConfig{
		Store:     trustStore,
		Threshold: time.Hour, // long threshold to prevent accidental promotion
		Logger:    logging.NewLogger("debug"),
	})
	adapter := newStewardIPTrustAdapter(evaluator, stewardStore, logging.NewLogger("debug"))
	ctx := context.Background()

	// Start timer.
	require.NoError(t, adapter.RecordLiveness(ctx, "steward-1", true))

	// Timer entry must exist.
	assert.True(t, evaluator.HasTimer("tenant-1", "10.0.0.1"), "timer must exist after healthy call")

	// Go offline — timer must be cleared.
	require.NoError(t, adapter.RecordLiveness(ctx, "steward-1", false))
	assert.False(t, evaluator.HasTimer("tenant-1", "10.0.0.1"), "timer must be cleared after offline call")

	assert.Empty(t, trustedCIDRs(t, trustStore, "tenant-1"), "no trust must be granted after offline reset")
}

// TestStewardIPTrustAdapter_EvaluatorError_IsPropagated verifies that a genuine
// store failure surfaces to the caller instead of being swallowed. The failure is
// real: the flat-file IP trust store's backing JSON file is corrupted on disk, so
// the store cannot load its existing entries and refuses the write.
func TestStewardIPTrustAdapter_EvaluatorError_IsPropagated(t *testing.T) {
	stewardStore := newAdapterStewardStore(t, &business.StewardRecord{
		ID:        "steward-1",
		TenantID:  "tenant-1",
		IPAddress: "10.0.0.1",
	})

	trustRoot := t.TempDir()
	trustStore := newFlatFileIPTrustStore(t, trustRoot)
	// Corrupt the store's on-disk state — the file exists but is not valid JSON.
	corrupt := filepath.Join(trustRoot, "ip-trust", "ip_trust.json")
	require.NoError(t, os.WriteFile(corrupt, []byte("{ not json"), 0600))
	require.Error(t, trustStore.AddTrustedRange(context.Background(), "tenant-1", "10.0.0.1/32", false),
		"a corrupted store must reject writes — precondition for this test")

	evaluator := controllerRegistration.NewIPTrustEvaluator(controllerRegistration.IPTrustEvaluatorConfig{
		Store:     trustStore,
		Threshold: time.Millisecond,
		Logger:    logging.NewLogger("debug"),
	})
	adapter := newStewardIPTrustAdapter(evaluator, stewardStore, logging.NewLogger("debug"))
	ctx := context.Background()

	// First call starts the timer — no error expected.
	require.NoError(t, adapter.RecordLiveness(ctx, "steward-1", true))

	// Tip the timer.
	evaluator.ForceTimerExpiry("tenant-1", "10.0.0.1")

	// Second call should propagate the store error.
	err := adapter.RecordLiveness(ctx, "steward-1", true)
	require.Error(t, err, "store error must be propagated")
}
