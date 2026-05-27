// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controllerRegistration "github.com/cfgis/cfgms/features/controller/registration"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
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

// testStewardStore is a real in-memory StewardStore used for adapter testing.
// It is NOT a mock — it holds actual StewardRecord data and satisfies the
// StewardStore contract for the GetSteward lookup path.
type testStewardStore struct {
	mu       sync.RWMutex
	stewards map[string]*business.StewardRecord
}

func newTestStewardStore(records ...*business.StewardRecord) *testStewardStore {
	s := &testStewardStore{stewards: make(map[string]*business.StewardRecord)}
	for _, r := range records {
		s.stewards[r.ID] = r
	}
	return s
}

func (s *testStewardStore) RegisterSteward(_ context.Context, record *business.StewardRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stewards[record.ID] = record
	return nil
}

func (s *testStewardStore) GetSteward(_ context.Context, id string) (*business.StewardRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.stewards[id]
	if !ok {
		return nil, business.ErrStewardNotFound
	}
	cp := *r
	return &cp, nil
}

func (s *testStewardStore) UpdateHeartbeat(_ context.Context, _ string) error { return nil }
func (s *testStewardStore) ListStewards(_ context.Context) ([]*business.StewardRecord, error) {
	return nil, nil
}
func (s *testStewardStore) ListStewardsByStatus(_ context.Context, _ business.StewardStatus) ([]*business.StewardRecord, error) {
	return nil, nil
}
func (s *testStewardStore) UpdateStewardStatus(_ context.Context, _ string, _ business.StewardStatus) error {
	return nil
}
func (s *testStewardStore) DeregisterSteward(_ context.Context, _ string) error { return nil }
func (s *testStewardStore) GetStewardsSeen(_ context.Context, _ time.Time) ([]*business.StewardRecord, error) {
	return nil, nil
}
func (s *testStewardStore) HealthCheck(_ context.Context) error { return nil }
func (s *testStewardStore) Initialize(_ context.Context) error  { return nil }
func (s *testStewardStore) Close() error                        { return nil }

var _ business.StewardStore = (*testStewardStore)(nil)

// testIPTrustStoreForAdapter is a minimal in-memory IPTrustStore for adapter tests.
type testIPTrustStoreForAdapter struct {
	mu    sync.Mutex
	calls []string
}

func (s *testIPTrustStoreForAdapter) AddTrustedRange(_ context.Context, tenantID, cidr string, _ bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, tenantID+"/"+cidr)
	return nil
}
func (s *testIPTrustStoreForAdapter) IsTrusted(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
func (s *testIPTrustStoreForAdapter) ListTrustedRanges(_ context.Context, _ string) ([]*business.IPTrustEntry, error) {
	return nil, nil
}
func (s *testIPTrustStoreForAdapter) RevokeTrustedRange(_ context.Context, _, _ string) error {
	return business.ErrIPTrustEntryNotFound
}
func (s *testIPTrustStoreForAdapter) RecordHealthySteward(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}
func (s *testIPTrustStoreForAdapter) GetLastActivity(_ context.Context, _, _ string) (*business.IPTrustActivity, error) {
	return nil, nil
}
func (s *testIPTrustStoreForAdapter) addTrustedRangeCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.calls))
	copy(out, s.calls)
	return out
}

var _ business.IPTrustStore = (*testIPTrustStoreForAdapter)(nil)

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
	stewardStore := newTestStewardStore(&business.StewardRecord{
		ID:        "steward-1",
		TenantID:  "tenant-1",
		IPAddress: "10.0.0.1",
		Status:    business.StewardStatusActive,
	})
	trustStore := &testIPTrustStoreForAdapter{}
	adapter := newTestAdapter(stewardStore, trustStore)
	ctx := context.Background()

	// Send first healthy call to start the timer.
	require.NoError(t, adapter.RecordLiveness(ctx, "steward-1", true))

	// Manually advance the evaluator's timer past the threshold.
	adapter.evaluator.ForceTimerExpiry("tenant-1", "10.0.0.1")

	// Second call tips over threshold — must call AddTrustedRange with the resolved IP.
	require.NoError(t, adapter.RecordLiveness(ctx, "steward-1", true))

	calls := trustStore.addTrustedRangeCalls()
	require.Len(t, calls, 1, "AddTrustedRange must be called with the correct IP")
	assert.Equal(t, fmt.Sprintf("tenant-1/%s", normaliseCIDRForAdapter("10.0.0.1/32")), calls[0])
}

// TestStewardIPTrustAdapter_StewardNotFound_IsNoop verifies that a missing steward
// record is silently ignored without returning an error (best-effort).
func TestStewardIPTrustAdapter_StewardNotFound_IsNoop(t *testing.T) {
	stewardStore := newTestStewardStore() // empty
	trustStore := &testIPTrustStoreForAdapter{}
	adapter := newTestAdapter(stewardStore, trustStore)
	ctx := context.Background()

	err := adapter.RecordLiveness(ctx, "unknown-steward", true)
	assert.NoError(t, err, "missing steward must not return an error")
	assert.Empty(t, trustStore.addTrustedRangeCalls())
}

// TestStewardIPTrustAdapter_NilStewardStore_IsNoop verifies that a nil steward
// store does not cause a panic.
func TestStewardIPTrustAdapter_NilStewardStore_IsNoop(t *testing.T) {
	trustStore := &testIPTrustStoreForAdapter{}
	evaluator := controllerRegistration.NewIPTrustEvaluator(controllerRegistration.IPTrustEvaluatorConfig{
		Store:     trustStore,
		Threshold: time.Millisecond,
		Logger:    logging.NewLogger("debug"),
	})
	adapter := newStewardIPTrustAdapter(evaluator, nil, logging.NewLogger("debug"))

	err := adapter.RecordLiveness(context.Background(), "steward-1", true)
	assert.NoError(t, err)
	assert.Empty(t, trustStore.addTrustedRangeCalls())
}

// TestStewardIPTrustAdapter_EmptyIP_IsNoop verifies that a steward with no IP
// address stored is silently skipped.
func TestStewardIPTrustAdapter_EmptyIP_IsNoop(t *testing.T) {
	stewardStore := newTestStewardStore(&business.StewardRecord{
		ID:        "steward-noip",
		TenantID:  "tenant-1",
		IPAddress: "", // no IP stored yet
	})
	trustStore := &testIPTrustStoreForAdapter{}
	adapter := newTestAdapter(stewardStore, trustStore)

	err := adapter.RecordLiveness(context.Background(), "steward-noip", true)
	assert.NoError(t, err)
	assert.Empty(t, trustStore.addTrustedRangeCalls())
}

// TestStewardIPTrustAdapter_OfflineCall_ResetsTimer verifies that a healthy=false
// call resets the trust timer for the steward's IP.
func TestStewardIPTrustAdapter_OfflineCall_ResetsTimer(t *testing.T) {
	stewardStore := newTestStewardStore(&business.StewardRecord{
		ID:        "steward-1",
		TenantID:  "tenant-1",
		IPAddress: "10.0.0.1",
	})
	trustStore := &testIPTrustStoreForAdapter{}
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

	assert.Empty(t, trustStore.addTrustedRangeCalls(), "no trust must be granted after offline reset")
}

// TestStewardIPTrustAdapter_EvaluatorError_IsPropagated verifies that an error
// returned by IPTrustEvaluator (e.g. store failure) is returned to the caller.
func TestStewardIPTrustAdapter_EvaluatorError_IsPropagated(t *testing.T) {
	stewardStore := newTestStewardStore(&business.StewardRecord{
		ID:        "steward-1",
		TenantID:  "tenant-1",
		IPAddress: "10.0.0.1",
	})
	failStore := &failingIPTrustStore{err: errors.New("storage unavailable")}
	evaluator := controllerRegistration.NewIPTrustEvaluator(controllerRegistration.IPTrustEvaluatorConfig{
		Store:     failStore,
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

// failingIPTrustStore always returns an error from AddTrustedRange.
type failingIPTrustStore struct{ err error }

func (f *failingIPTrustStore) AddTrustedRange(_ context.Context, _, _ string, _ bool) error {
	return f.err
}
func (f *failingIPTrustStore) IsTrusted(_ context.Context, _, _ string) (bool, error) {
	return false, nil
}
func (f *failingIPTrustStore) ListTrustedRanges(_ context.Context, _ string) ([]*business.IPTrustEntry, error) {
	return nil, nil
}
func (f *failingIPTrustStore) RevokeTrustedRange(_ context.Context, _, _ string) error {
	return nil
}
func (f *failingIPTrustStore) RecordHealthySteward(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}
func (f *failingIPTrustStore) GetLastActivity(_ context.Context, _, _ string) (*business.IPTrustActivity, error) {
	return nil, nil
}

var _ business.IPTrustStore = (*failingIPTrustStore)(nil)
