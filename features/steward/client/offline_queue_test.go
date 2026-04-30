// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package client provides tests for offline report queueing.
// Issue #419: steward queues reports locally when controller is unreachable.
// Issue #920: queue file is encrypted at rest with AES-256-GCM.
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
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

func (n *noopControlPlane) Name() string { return "noop" }
func (n *noopControlPlane) Initialize(_ context.Context, _ map[string]interface{}) error {
	return nil
}
func (n *noopControlPlane) Start(_ context.Context) error                                 { return nil }
func (n *noopControlPlane) Stop(_ context.Context) error                                  { return nil }
func (n *noopControlPlane) SendCommand(_ context.Context, _ *cpTypes.SignedCommand) error { return nil }
func (n *noopControlPlane) FanOutCommand(_ context.Context, _ *cpTypes.SignedCommand, ids []string) (*cpTypes.FanOutResult, error) {
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
func (n *noopControlPlane) IsConnected() bool { return false }

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
	// Shared SecretStore so the encryption key persists across simulated restarts.
	store := newInMemorySecretStore()

	// First instance — enqueue three events.
	q1, err := NewOfflineQueue(OfflineQueueConfig{Dir: dir, MaxSize: 10, MaxAge: time.Hour, SecretStore: store})
	require.NoError(t, err)
	q1.Enqueue(makeTestEvent("evt-001", cpTypes.EventConfigApplied))
	q1.Enqueue(makeTestEvent("evt-002", cpTypes.EventDNAChanged))
	q1.Enqueue(makeTestEvent("evt-003", cpTypes.EventError))
	assert.Equal(t, 3, q1.Len())

	// Second instance simulates a restart from the same directory.
	q2, err := NewOfflineQueue(OfflineQueueConfig{Dir: dir, MaxSize: 10, MaxAge: time.Hour, SecretStore: store})
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
	store := newInMemorySecretStore()

	q1, err := NewOfflineQueue(OfflineQueueConfig{Dir: dir, MaxSize: 10, MaxAge: time.Hour, SecretStore: store})
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
	q2, err := NewOfflineQueue(OfflineQueueConfig{Dir: dir, MaxSize: 10, MaxAge: time.Hour, SecretStore: store})
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
	assert.FileExists(t, filepath.Join(dir, "offline_queue.enc"))
	assert.NoFileExists(t, filepath.Join(dir, "offline_queue.enc.tmp"),
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

// ---------------------------------------------------------------------------
// Issue #920: Encryption tests
// ---------------------------------------------------------------------------

// inMemorySecretStore is a minimal SecretStore for testing that holds secrets in memory.
type inMemorySecretStore struct {
	mu      sync.Mutex
	secrets map[string]string
}

func newInMemorySecretStore() *inMemorySecretStore {
	return &inMemorySecretStore{secrets: make(map[string]string)}
}

func (s *inMemorySecretStore) StoreSecret(_ context.Context, req *secretsif.SecretRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[req.Key] = req.Value
	return nil
}

func (s *inMemorySecretStore) GetSecret(_ context.Context, key string) (*secretsif.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.secrets[key]
	if !ok {
		return nil, secretsif.ErrSecretNotFound
	}
	return &secretsif.Secret{Key: key, Value: v}, nil
}

func (s *inMemorySecretStore) DeleteSecret(_ context.Context, _ string) error { return nil }
func (s *inMemorySecretStore) ListSecrets(_ context.Context, _ *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	return nil, nil
}
func (s *inMemorySecretStore) GetSecrets(_ context.Context, _ []string) (map[string]*secretsif.Secret, error) {
	return nil, nil
}
func (s *inMemorySecretStore) StoreSecrets(_ context.Context, _ map[string]*secretsif.SecretRequest) error {
	return nil
}
func (s *inMemorySecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsif.Secret, error) {
	return nil, nil
}
func (s *inMemorySecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsif.SecretVersion, error) {
	return nil, nil
}
func (s *inMemorySecretStore) GetSecretMetadata(_ context.Context, _ string) (*secretsif.SecretMetadata, error) {
	return nil, nil
}
func (s *inMemorySecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *inMemorySecretStore) RotateSecret(_ context.Context, _ string, _ string) error {
	return nil
}
func (s *inMemorySecretStore) ExpireSecret(_ context.Context, _ string) error { return nil }
func (s *inMemorySecretStore) HealthCheck(_ context.Context) error            { return nil }
func (s *inMemorySecretStore) Close() error                                   { return nil }

// TestOfflineQueue_EncryptionRoundTrip verifies that enqueued events survive a
// restart (load → decrypt → check) when a SecretStore is provided.
func TestOfflineQueue_EncryptionRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := newInMemorySecretStore()

	q1, err := NewOfflineQueue(OfflineQueueConfig{
		Dir: dir, MaxSize: 10, MaxAge: time.Hour, SecretStore: store,
	})
	require.NoError(t, err)

	q1.Enqueue(makeTestEvent("enc-001", cpTypes.EventConfigApplied))
	q1.Enqueue(makeTestEvent("enc-002", cpTypes.EventDNAChanged))
	require.Equal(t, 2, q1.Len())

	// Verify the on-disk file exists and is NOT valid JSON (it's encrypted).
	raw, err := os.ReadFile(filepath.Join(dir, "offline_queue.enc"))
	require.NoError(t, err)
	var js interface{}
	assert.Error(t, json.Unmarshal(raw, &js), "file must not be plaintext JSON")

	// Reload from the same directory and secret store.
	q2, err := NewOfflineQueue(OfflineQueueConfig{
		Dir: dir, MaxSize: 10, MaxAge: time.Hour, SecretStore: store,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, q2.Len(), "events must survive encrypted restart")

	var ids []string
	q2.Drain(func(e *cpTypes.Event) error {
		ids = append(ids, e.ID)
		return nil
	})
	assert.Equal(t, []string{"enc-001", "enc-002"}, ids, "events must be in insertion order")
}

// TestOfflineQueue_TamperDetection verifies that mutating the encrypted file
// causes load to return an authentication error (GCM tag mismatch).
func TestOfflineQueue_TamperDetection(t *testing.T) {
	dir := t.TempDir()
	store := newInMemorySecretStore()

	q, err := NewOfflineQueue(OfflineQueueConfig{
		Dir: dir, MaxSize: 10, MaxAge: time.Hour, SecretStore: store,
	})
	require.NoError(t, err)
	q.Enqueue(makeTestEvent("tamper-001", cpTypes.EventConfigApplied))

	// Flip a byte in the middle of the ciphertext to simulate tampering.
	encPath := filepath.Join(dir, "offline_queue.enc")
	data, err := os.ReadFile(encPath)
	require.NoError(t, err)
	require.True(t, len(data) > 20, "encrypted file must have enough bytes to tamper")
	data[len(data)/2] ^= 0xFF
	require.NoError(t, os.WriteFile(encPath, data, 0600))

	// Loading must fail with an authentication/decryption error.
	q2 := &OfflineQueue{
		seenIDs:       make(map[string]struct{}),
		config:        OfflineQueueConfig{Dir: dir},
		encryptionKey: q.encryptionKey, // same key
	}
	err = q2.load()
	assert.Error(t, err, "tampered file must cause a decryption error")
	assert.Contains(t, err.Error(), "authentication failure",
		"error must mention authentication failure")
}

// TestOfflineQueue_LegacyPlaintextDeletion verifies that a pre-920 plaintext
// offline_queue.json is deleted at startup and an Info log is emitted.
func TestOfflineQueue_LegacyPlaintextDeletion(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "offline_queue.json")

	// Write a fake plaintext file.
	require.NoError(t, os.WriteFile(legacyPath, []byte(`{"entries":[],"next_seq":0}`), 0600))
	assert.FileExists(t, legacyPath)

	logger := logging.NewLogger("debug")
	store := newInMemorySecretStore()

	_, err := NewOfflineQueue(OfflineQueueConfig{
		Dir: dir, MaxSize: 10, MaxAge: time.Hour,
		SecretStore: store, Logger: logger,
	})
	require.NoError(t, err)

	// Legacy file must be gone.
	assert.NoFileExists(t, legacyPath, "legacy plaintext file must be deleted at startup")
}

// TestOfflineQueue_ConcurrentDrainSeenIDs verifies that concurrent Drain and
// Enqueue calls do not corrupt seenIDs. Run with -race.
func TestOfflineQueue_ConcurrentDrainSeenIDs(t *testing.T) {
	q, err := NewOfflineQueue(OfflineQueueConfig{
		MaxSize: 500,
		MaxAge:  time.Hour,
	})
	require.NoError(t, err)

	const enqueues = 200
	var wg sync.WaitGroup

	// Multiple concurrent producers.
	for p := 0; p < 4; p++ {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < enqueues/4; i++ {
				id := fmt.Sprintf("p%d-evt-%04d", p, i)
				q.Enqueue(makeTestEvent(id, cpTypes.EventConfigApplied))
			}
		}()
	}

	// Concurrent consumer.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < enqueues; i++ {
			q.Drain(func(e *cpTypes.Event) error { return nil })
		}
	}()

	wg.Wait()

	// Final drain to catch any stragglers.
	q.Drain(func(e *cpTypes.Event) error { return nil })

	// seenIDs must be consistent with entries.
	q.mu.Lock()
	defer q.mu.Unlock()
	assert.Equal(t, len(q.entries), len(q.seenIDs),
		"seenIDs count must match entries count after concurrent operations")
}
