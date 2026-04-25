// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client provides tests for offline report queueing.
// Issue #419: steward queues reports locally when controller is unreachable.
package client

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func makeTestEvent(id string, eventType cpTypes.EventType) *cpTypes.Event {
	return &cpTypes.Event{
		ID:        id,
		Type:      eventType,
		StewardID: "test-steward-001",
		TenantID:  "test-tenant",
		Timestamp: time.Now(),
		Details:   map[string]interface{}{"test": "data"},
	}
}

// noopControlPlane is a minimal real implementation of ControlPlaneProvider
// that satisfies the interface without performing any network operations.
// Embed in test-specific providers to override only the methods you need.
type noopControlPlane struct{}

func (n *noopControlPlane) Name() string        { return "noop" }
func (n *noopControlPlane) Description() string { return "noop test provider" }
func (n *noopControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (n *noopControlPlane) Start(_ context.Context) error                           { return nil }
func (n *noopControlPlane) Stop(_ context.Context) error                            { return nil }
func (n *noopControlPlane) SendCommand(_ context.Context, _ *cpTypes.Command) error { return nil }
func (n *noopControlPlane) FanOutCommand(_ context.Context, _ *cpTypes.Command, ids []string) (*cpTypes.FanOutResult, error) {
	return &cpTypes.FanOutResult{Succeeded: ids, Failed: make(map[string]error)}, nil
}
func (n *noopControlPlane) SubscribeCommands(_ context.Context, _ string, _ controlplaneInterfaces.CommandHandler) error {
	return nil
}
func (n *noopControlPlane) PublishEvent(_ context.Context, _ *cpTypes.Event) error { return nil }
func (n *noopControlPlane) SubscribeEvents(_ context.Context, _ *cpTypes.EventFilter, _ controlplaneInterfaces.EventHandler) error {
	return nil
}
func (n *noopControlPlane) SendHeartbeat(_ context.Context, _ *cpTypes.Heartbeat) error { return nil }
func (n *noopControlPlane) SubscribeHeartbeats(_ context.Context, _ controlplaneInterfaces.HeartbeatHandler) error {
	return nil
}
func (n *noopControlPlane) GetStats(_ context.Context) (*cpTypes.ControlPlaneStats, error) {
	return &cpTypes.ControlPlaneStats{}, nil
}
func (n *noopControlPlane) Available() (bool, error) { return true, nil }
func (n *noopControlPlane) IsConnected() bool        { return false }

// failingControlPlane always returns publishErr from PublishEvent.
type failingControlPlane struct {
	noopControlPlane
	publishErr error
}

func (f *failingControlPlane) PublishEvent(_ context.Context, _ *cpTypes.Event) error {
	return f.publishErr
}

// recordingControlPlane records every published event successfully.
type recordingControlPlane struct {
	noopControlPlane
	published []*cpTypes.Event
}

func (r *recordingControlPlane) PublishEvent(_ context.Context, e *cpTypes.Event) error {
	r.published = append(r.published, e)
	return nil
}

// ---------------------------------------------------------------------------
// OfflineQueue unit tests
// ---------------------------------------------------------------------------

func TestOfflineQueue_BasicEnqueue(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 10,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	evt := makeTestEvent("evt-001", cpTypes.EventConfigApplied)
	accepted := q.Enqueue(evt)
	assert.True(t, accepted, "new event should be accepted")
	assert.Equal(t, 1, q.Len())
}

func TestOfflineQueue_DrainOrderedDelivery(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 20,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	ids := []string{"evt-001", "evt-002", "evt-003", "evt-004"}
	for _, id := range ids {
		q.Enqueue(makeTestEvent(id, cpTypes.EventConfigApplied))
	}
	assert.Equal(t, 4, q.Len())

	var received []string
	delivered := q.Drain(func(e *cpTypes.Event) error {
		received = append(received, e.ID)
		return nil
	})

	assert.Equal(t, 4, delivered, "all 4 events should be delivered")
	assert.Equal(t, 0, q.Len(), "queue should be empty after drain")
	assert.Equal(t, ids, received, "events must be delivered in insertion order")
}

func TestOfflineQueue_DrainStopsOnFirstFailure(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 20,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	for i := 1; i <= 5; i++ {
		q.Enqueue(makeTestEvent(fmt.Sprintf("evt-%03d", i), cpTypes.EventDNAChanged))
	}

	callCount := 0
	delivered := q.Drain(func(e *cpTypes.Event) error {
		callCount++
		if callCount >= 3 {
			return errors.New("simulated network error")
		}
		return nil
	})

	assert.Equal(t, 2, delivered, "first 2 events should be delivered before failure")
	assert.Equal(t, 3, q.Len(), "3 un-delivered events should remain")
}

func TestOfflineQueue_DrainEmptyQueue(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 10,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	delivered := q.Drain(func(e *cpTypes.Event) error { return nil })
	assert.Equal(t, 0, delivered)
	assert.Equal(t, 0, q.Len())
}

func TestOfflineQueue_PersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	// First instance — enqueue three events.
	q1, err := NewOfflineQueue(OfflineQueueConfig{Dir: dir, MaxSize: 10, MaxAge: time.Hour})
	require.NoError(t, err)
	q1.Enqueue(makeTestEvent("evt-001", cpTypes.EventConfigApplied))
	q1.Enqueue(makeTestEvent("evt-002", cpTypes.EventDNAChanged))
	q1.Enqueue(makeTestEvent("evt-003", cpTypes.EventError))
	assert.Equal(t, 3, q1.Len())

	// Second instance simulates a restart from the same directory.
	q2, err := NewOfflineQueue(OfflineQueueConfig{Dir: dir, MaxSize: 10, MaxAge: time.Hour})
	require.NoError(t, err)
	assert.Equal(t, 3, q2.Len(), "events must survive restart")

	var ids []string
	q2.Drain(func(e *cpTypes.Event) error {
		ids = append(ids, e.ID)
		return nil
	})
	assert.Equal(t, []string{"evt-001", "evt-002", "evt-003"}, ids)
}

func TestOfflineQueue_PersistencePartialDrainThenRestart(t *testing.T) {
	dir := t.TempDir()

	q1, err := NewOfflineQueue(OfflineQueueConfig{Dir: dir, MaxSize: 10, MaxAge: time.Hour})
	require.NoError(t, err)
	for i := 1; i <= 4; i++ {
		q1.Enqueue(makeTestEvent(fmt.Sprintf("evt-%03d", i), cpTypes.EventConfigApplied))
	}

	// Deliver only the first two events.
	calls := 0
	q1.Drain(func(e *cpTypes.Event) error {
		calls++
		if calls > 2 {
			return errors.New("stop here")
		}
		return nil
	})
	assert.Equal(t, 2, q1.Len())

	// Restart: only the remaining 2 events should be present.
	q2, err := NewOfflineQueue(OfflineQueueConfig{Dir: dir, MaxSize: 10, MaxAge: time.Hour})
	require.NoError(t, err)
	assert.Equal(t, 2, q2.Len())

	var ids []string
	q2.Drain(func(e *cpTypes.Event) error {
		ids = append(ids, e.ID)
		return nil
	})
	assert.Equal(t, []string{"evt-003", "evt-004"}, ids)
}

func TestOfflineQueue_Deduplication(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 10,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	evt := makeTestEvent("evt-dup", cpTypes.EventConfigApplied)

	accepted1 := q.Enqueue(evt)
	accepted2 := q.Enqueue(evt) // Same ID
	assert.True(t, accepted1, "first enqueue should be accepted")
	assert.False(t, accepted2, "duplicate ID should be rejected")
	assert.Equal(t, 1, q.Len(), "only one entry should be in queue")
}

func TestOfflineQueue_MaxSizeEvictsOldest(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 3,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	q.Enqueue(makeTestEvent("evt-001", cpTypes.EventConfigApplied))
	q.Enqueue(makeTestEvent("evt-002", cpTypes.EventConfigApplied))
	q.Enqueue(makeTestEvent("evt-003", cpTypes.EventConfigApplied))
	assert.Equal(t, 3, q.Len())

	// This should evict evt-001 to make room.
	q.Enqueue(makeTestEvent("evt-004", cpTypes.EventConfigApplied))
	assert.Equal(t, 3, q.Len(), "queue must not exceed MaxSize")

	var ids []string
	q.Drain(func(e *cpTypes.Event) error {
		ids = append(ids, e.ID)
		return nil
	})
	assert.Equal(t, []string{"evt-002", "evt-003", "evt-004"}, ids, "oldest event evicted")
}

func TestOfflineQueue_MaxSizeDefaultsTo1000(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:    t.TempDir(),
		MaxAge: time.Hour,
		// MaxSize intentionally omitted — should default to 1000.
	})
	require.NoError(t, err)
	assert.Equal(t, 1000, q.config.MaxSize)
}

func TestOfflineQueue_MaxAgeDefaultsTo24Hours(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 10,
		// MaxAge intentionally omitted — should default to 24h.
	})
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, q.config.MaxAge)
}

// TestOfflineQueue_ExpiresOldEntries verifies that entries past their ExpiresAt
// are silently dropped during Drain. It directly injects an already-expired
// entry into the queue's internal state (same package access) to avoid any
// time.Sleep — making the test deterministic and instant.
func TestOfflineQueue_ExpiresOldEntries(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 10,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	// Inject an already-expired entry directly (no sleep needed).
	past := time.Now().Add(-time.Hour)
	expiredEntry := &QueuedEvent{
		Event:     makeTestEvent("evt-old", cpTypes.EventConfigApplied),
		QueuedAt:  past,
		ExpiresAt: past,
		Sequence:  1,
	}
	q.mu.Lock()
	q.entries = append(q.entries, expiredEntry)
	q.seenIDs[expiredEntry.Event.ID] = struct{}{}
	q.seq = 1
	q.mu.Unlock()

	// Add a fresh event via the normal Enqueue path.
	q.Enqueue(makeTestEvent("evt-fresh", cpTypes.EventConfigApplied))

	var ids []string
	q.Drain(func(e *cpTypes.Event) error {
		ids = append(ids, e.ID)
		return nil
	})

	assert.NotContains(t, ids, "evt-old", "expired event must not be delivered")
	assert.Contains(t, ids, "evt-fresh", "non-expired event must be delivered")
}

func TestOfflineQueue_InMemoryFallback(t *testing.T) {
	// Dir intentionally empty — in-memory only (events lost on restart but
	// otherwise fully functional).
	q, err := NewOfflineQueue(OfflineQueueConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	q.Enqueue(makeTestEvent("evt-mem-001", cpTypes.EventDNAChanged))
	q.Enqueue(makeTestEvent("evt-mem-002", cpTypes.EventDNAChanged))
	assert.Equal(t, 2, q.Len())

	var ids []string
	q.Drain(func(e *cpTypes.Event) error {
		ids = append(ids, e.ID)
		return nil
	})
	assert.Equal(t, []string{"evt-mem-001", "evt-mem-002"}, ids)
	assert.Equal(t, 0, q.Len())
}

func TestOfflineQueue_QueueFileAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	q, err := NewOfflineQueue(OfflineQueueConfig{Dir: dir, MaxSize: 10, MaxAge: time.Hour})
	require.NoError(t, err)

	q.Enqueue(makeTestEvent("evt-001", cpTypes.EventConfigApplied))

	// The .tmp file must not exist after enqueue (atomic rename completed).
	assert.FileExists(t, filepath.Join(dir, "offline_queue.json"))
	assert.NoFileExists(t, filepath.Join(dir, "offline_queue.json.tmp"),
		".tmp file must be cleaned up after atomic rename")
}

func TestOfflineQueue_ConcurrentEnqueueDrain(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 100,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	done := make(chan struct{})

	// Producer: enqueue 50 events.
	go func() {
		for i := 0; i < 50; i++ {
			q.Enqueue(makeTestEvent(fmt.Sprintf("concurrent-%03d", i), cpTypes.EventConfigApplied))
		}
		close(done)
	}()

	// Consumer: continuously drain until producer finishes.
	for {
		select {
		case <-done:
			// Final drain.
			q.Drain(func(e *cpTypes.Event) error { return nil })
			goto finished
		default:
			q.Drain(func(e *cpTypes.Event) error { return nil })
		}
	}
finished:
	assert.Equal(t, 0, q.Len(), "queue should be empty after all drains")
}

// ---------------------------------------------------------------------------
// Integration tests: publishEventWithQueue behaviour
// ---------------------------------------------------------------------------

func TestPublishEventWithQueue_QueuesWhenCPNil(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 10,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	c := &TransportClient{
		offlineQueue: q,
		logger:       logging.NewLogger("info"),
		stewardID:    "s-001",
		tenantID:     "tenant-001",
		// controlPlane is nil — simulates not-yet-connected state.
	}

	evt := makeTestEvent("evt-cp-nil", cpTypes.EventConfigApplied)
	err = c.publishEventWithQueue(context.Background(), evt)
	require.NoError(t, err, "must not return error when event is queued")
	assert.Equal(t, 1, q.Len(), "event must be in queue")
}

func TestPublishEventWithQueue_QueuesOnPublishError(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 10,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	cp := &failingControlPlane{publishErr: errors.New("connection refused")}
	c := &TransportClient{
		controlPlane: cp,
		offlineQueue: q,
		logger:       logging.NewLogger("info"),
		stewardID:    "s-001",
		tenantID:     "tenant-001",
	}

	evt := makeTestEvent("evt-cp-fail", cpTypes.EventDNAChanged)
	err = c.publishEventWithQueue(context.Background(), evt)
	require.NoError(t, err, "must not return error when event is queued")
	assert.Equal(t, 1, q.Len(), "event must be in queue after publish failure")
}

func TestPublishEventWithQueue_NoQueueAndCPFails(t *testing.T) {
	cp := &failingControlPlane{publishErr: errors.New("connection refused")}
	c := &TransportClient{
		controlPlane: cp,
		offlineQueue: nil, // No queue configured.
		logger:       logging.NewLogger("info"),
		stewardID:    "s-001",
		tenantID:     "tenant-001",
	}

	evt := makeTestEvent("evt-no-q", cpTypes.EventError)
	err := c.publishEventWithQueue(context.Background(), evt)
	assert.Error(t, err, "must return error when there is no queue and CP fails")
}

func TestPublishEventWithQueue_SuccessDoesNotQueue(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir:     t.TempDir(),
		MaxSize: 10,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	cp := &recordingControlPlane{}
	c := &TransportClient{
		controlPlane: cp,
		offlineQueue: q,
		logger:       logging.NewLogger("info"),
		stewardID:    "s-001",
		tenantID:     "tenant-001",
	}

	evt := makeTestEvent("evt-ok", cpTypes.EventConfigApplied)
	err = c.publishEventWithQueue(context.Background(), evt)
	require.NoError(t, err)
	assert.Equal(t, 0, q.Len(), "successful publish must not add to queue")
	assert.Len(t, cp.published, 1, "event must be published to CP")
}

// TestPublishEventWithQueue_DrainedOnReconnect verifies that after connecting
// with a pre-populated offline queue the events are drained immediately.
func TestPublishEventWithQueue_DrainedOnReconnect(t *testing.T) {
	dir := t.TempDir()

	// Pre-populate the queue (simulates events queued during offline period).
	q, err := NewOfflineQueue(OfflineQueueConfig{Dir: dir, MaxSize: 10, MaxAge: time.Hour})
	require.NoError(t, err)
	q.Enqueue(makeTestEvent("queued-001", cpTypes.EventConfigApplied))
	q.Enqueue(makeTestEvent("queued-002", cpTypes.EventDNAChanged))
	require.Equal(t, 2, q.Len())

	cp := &recordingControlPlane{}

	// drainOfflineQueue should publish all queued events via the CP.
	c := &TransportClient{
		controlPlane: cp,
		offlineQueue: q,
		logger:       logging.NewLogger("info"),
		stewardID:    "s-001",
		tenantID:     "tenant-001",
	}
	c.drainOfflineQueue(context.Background())

	assert.Equal(t, 0, q.Len(), "queue must be empty after drain")
	assert.Len(t, cp.published, 2, "both queued events must be published")
	assert.Equal(t, "queued-001", cp.published[0].ID, "events delivered in order")
	assert.Equal(t, "queued-002", cp.published[1].ID, "events delivered in order")
}
