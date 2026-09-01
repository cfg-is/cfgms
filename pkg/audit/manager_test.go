// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package audit_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	secretsInterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// testSecretStore is a minimal in-memory implementation of secretsInterfaces.SecretStore
// used to test WithSecretsStore wiring without requiring an external secrets backend.
// This is not a mock of CFGMS business functionality — it is a test double for the
// infrastructure boundary at pkg/secrets/interfaces.SecretStore.
type testSecretStore struct {
	secrets  map[string]string
	storeErr error
}

func newTestSecretStore() *testSecretStore {
	return &testSecretStore{secrets: make(map[string]string)}
}

func (s *testSecretStore) StoreSecret(_ context.Context, req *secretsInterfaces.SecretRequest) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	s.secrets[req.TenantID+"/"+req.Key] = req.Value
	return nil
}

func (s *testSecretStore) GetSecret(_ context.Context, key string) (*secretsInterfaces.Secret, error) {
	v, ok := s.secrets[key]
	if !ok {
		return nil, secretsInterfaces.ErrSecretNotFound
	}
	return &secretsInterfaces.Secret{Key: key, Value: v}, nil
}

func (s *testSecretStore) DeleteSecret(_ context.Context, _ string) error { return nil }
func (s *testSecretStore) ListSecrets(_ context.Context, _ *secretsInterfaces.SecretFilter) ([]*secretsInterfaces.SecretMetadata, error) {
	return nil, nil
}
func (s *testSecretStore) GetSecrets(_ context.Context, _ []string) (map[string]*secretsInterfaces.Secret, error) {
	return nil, nil
}
func (s *testSecretStore) StoreSecrets(_ context.Context, _ map[string]*secretsInterfaces.SecretRequest) error {
	return nil
}
func (s *testSecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsInterfaces.Secret, error) {
	return nil, nil
}
func (s *testSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsInterfaces.SecretVersion, error) {
	return nil, nil
}
func (s *testSecretStore) GetSecretMetadata(_ context.Context, _ string) (*secretsInterfaces.SecretMetadata, error) {
	return nil, nil
}
func (s *testSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *testSecretStore) RotateSecret(_ context.Context, _ string, _ string) error { return nil }
func (s *testSecretStore) ExpireSecret(_ context.Context, _ string) error           { return nil }
func (s *testSecretStore) HealthCheck(_ context.Context) error                      { return nil }
func (s *testSecretStore) Close() error                                             { return nil }

// newTestManager creates a real audit manager backed by OSS storage in a temp dir.
// The returned manager's drain goroutine is stopped via t.Cleanup so callers do
// not need to call Stop themselves.
func newTestManager(t *testing.T, source string) *audit.Manager {
	t.Helper()
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)

	m, err := audit.NewManager(storageManager.GetAuditStore(), source)
	require.NoError(t, err)

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.Stop(ctx)
		_ = storageManager.Close()
	})

	return m
}

// slowAuditStore wraps a real business.AuditStore and injects a configurable
// per-entry delay so we can prove that Flush actually waits for the drain
// goroutine to finish writing pending entries rather than returning
// prematurely. No mocks — every method delegates to the real backing store.
type slowAuditStore struct {
	inner business.AuditStore
	delay time.Duration
	// writes counts successfully persisted entries so tests can assert the
	// drain completed N entries before Flush returned.
	writes atomic.Int64
}

func (s *slowAuditStore) StoreAuditEntry(ctx context.Context, entry *business.AuditEntry) error {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	err := s.inner.StoreAuditEntry(ctx, entry)
	if err == nil {
		s.writes.Add(1)
	}
	return err
}

func (s *slowAuditStore) GetAuditEntry(ctx context.Context, id string) (*business.AuditEntry, error) {
	return s.inner.GetAuditEntry(ctx, id)
}
func (s *slowAuditStore) ListAuditEntries(ctx context.Context, filter *business.AuditFilter) ([]*business.AuditEntry, error) {
	return s.inner.ListAuditEntries(ctx, filter)
}
func (s *slowAuditStore) StoreAuditBatch(ctx context.Context, entries []*business.AuditEntry) error {
	if s.delay > 0 {
		time.Sleep(s.delay * time.Duration(len(entries)))
	}
	err := s.inner.StoreAuditBatch(ctx, entries)
	if err == nil {
		s.writes.Add(int64(len(entries)))
	}
	return err
}
func (s *slowAuditStore) GetAuditsByUser(ctx context.Context, userID string, tr *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.inner.GetAuditsByUser(ctx, userID, tr)
}
func (s *slowAuditStore) GetAuditsByResource(ctx context.Context, rt, rid string, tr *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.inner.GetAuditsByResource(ctx, rt, rid, tr)
}
func (s *slowAuditStore) GetAuditsByAction(ctx context.Context, action string, tr *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.inner.GetAuditsByAction(ctx, action, tr)
}
func (s *slowAuditStore) GetFailedActions(ctx context.Context, tr *business.TimeRange, limit int) ([]*business.AuditEntry, error) {
	return s.inner.GetFailedActions(ctx, tr, limit)
}
func (s *slowAuditStore) GetSuspiciousActivity(ctx context.Context, tenantID string, tr *business.TimeRange) ([]*business.AuditEntry, error) {
	return s.inner.GetSuspiciousActivity(ctx, tenantID, tr)
}
func (s *slowAuditStore) GetAuditStats(ctx context.Context) (*business.AuditStats, error) {
	return s.inner.GetAuditStats(ctx)
}
func (s *slowAuditStore) ArchiveAuditEntries(ctx context.Context, before time.Time) (int64, error) {
	return s.inner.ArchiveAuditEntries(ctx, before)
}
func (s *slowAuditStore) PurgeAuditEntries(ctx context.Context, before time.Time) (int64, error) {
	return s.inner.PurgeAuditEntries(ctx, before)
}
func (s *slowAuditStore) GetLastAuditEntry(ctx context.Context, tenantID string) (*business.AuditEntry, error) {
	return s.inner.GetLastAuditEntry(ctx, tenantID)
}
func (s *slowAuditStore) AppendChainedEntry(ctx context.Context, tenantID string, entry *business.AuditEntry, computeChecksum func(entry *business.AuditEntry) string) error {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	err := s.inner.AppendChainedEntry(ctx, tenantID, entry, computeChecksum)
	if err == nil {
		s.writes.Add(1)
	}
	return err
}
func (s *slowAuditStore) Close() error { return s.inner.Close() }

// assignmentSpyAuditStore wraps a real business.AuditStore (embedded, so every
// method except AppendChainedEntry passes straight through) and records, for
// each AppendChainedEntry call, whether the manager handed it an entry with
// SequenceNumber/PreviousChecksum/Checksum already populated. Not a mock — a
// real backing store with one method intercepted for observation.
type assignmentSpyAuditStore struct {
	business.AuditStore
	mu            sync.Mutex
	sawUnassigned []bool
}

func (s *assignmentSpyAuditStore) AppendChainedEntry(ctx context.Context, tenantID string, entry *business.AuditEntry, computeChecksum func(entry *business.AuditEntry) string) error {
	s.mu.Lock()
	s.sawUnassigned = append(s.sawUnassigned,
		entry.SequenceNumber == 0 && entry.PreviousChecksum == "" && entry.Checksum == "")
	s.mu.Unlock()
	return s.AuditStore.AppendChainedEntry(ctx, tenantID, entry, computeChecksum)
}

func (s *assignmentSpyAuditStore) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sawUnassigned)
}

func (s *assignmentSpyAuditStore) allUnassigned() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.sawUnassigned {
		if !v {
			return false
		}
	}
	return true
}

// TestManager_DelegatesSequenceAssignmentToStore proves the drain loop hands
// AppendChainedEntry an entry with SequenceNumber, PreviousChecksum, and
// Checksum still unset — it does not compute head.sequence+1 itself (the
// pre-#3754 approach that assumed no concurrent writer could interleave, false
// the moment more than one controller node runs against one database; ADR-031
// Decision 1). All three fields end up correctly populated afterward because
// the store (backed here by a real flat-file AuditStore) assigns them.
func TestManager_DelegatesSequenceAssignmentToStore(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	spy := &assignmentSpyAuditStore{AuditStore: storageManager.GetAuditStore()}

	manager, err := audit.NewManager(spy, "delegation-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Stop(ctx)
	})

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		event := audit.NewEventBuilder().
			Tenant("delegation-tenant").
			Type(business.AuditEventConfiguration).
			Action("delegation_action").
			User("user1", business.AuditUserTypeHuman).
			Resource("resource", fmt.Sprintf("res-%d", i), "").
			Severity(business.AuditSeverityMedium)
		require.NoError(t, manager.RecordEvent(ctx, event))
	}
	flushOrFail(t, manager)

	require.Equal(t, 3, spy.callCount(), "drain loop must call AppendChainedEntry once per entry")
	assert.True(t, spy.allUnassigned(),
		"manager must not pre-assign SequenceNumber/PreviousChecksum/Checksum before calling AppendChainedEntry")

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "delegation-tenant",
		Order:    "asc",
	})
	require.NoError(t, err)
	require.Len(t, entries, 3)
	for i, e := range entries {
		assert.Equal(t, uint64(i+1), e.SequenceNumber, "store must assign sequence numbers 1..3")
		assert.NotEmpty(t, e.Checksum, "store's computeChecksum callback must populate Checksum")
	}
}

// syncBuffer is a mutex-guarded io.Writer so the drain goroutine's slog output
// can be captured and read from the test goroutine without a data race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// failingAppendAuditStore wraps a real business.AuditStore (embedded, so every
// other method passes straight through to durable storage) and fails
// AppendChainedEntry for entries whose ResourceID is in failFor. Not a mock —
// the surviving entries are appended to a real store, so the chain that remains
// after an injected failure is the chain the store actually persisted.
//
// gate, when non-nil, blocks the first AppendChainedEntry call until it is
// closed and signals gateEntered when the call arrives. That parks the drain
// goroutine inside a write so a test can enqueue a known set of entries and
// have collectBatch pick all of them up as one batch — which is what makes
// "the rest of the batch is still attempted" an assertion about batch
// semantics rather than about goroutine timing.
type failingAppendAuditStore struct {
	business.AuditStore

	failFor     map[string]error
	gate        chan struct{}
	gateEntered chan struct{}
	gateOnce    sync.Once

	mu        sync.Mutex
	attempted []string
}

func (s *failingAppendAuditStore) holdFirstCall() {
	if s.gate == nil {
		return
	}
	s.gateOnce.Do(func() {
		close(s.gateEntered)
		<-s.gate
	})
}

func (s *failingAppendAuditStore) AppendChainedEntry(ctx context.Context, tenantID string, entry *business.AuditEntry, computeChecksum func(entry *business.AuditEntry) string) error {
	s.holdFirstCall()

	s.mu.Lock()
	s.attempted = append(s.attempted, entry.ResourceID)
	s.mu.Unlock()

	if err, ok := s.failFor[entry.ResourceID]; ok {
		return err
	}
	return s.AuditStore.AppendChainedEntry(ctx, tenantID, entry, computeChecksum)
}

func (s *failingAppendAuditStore) attemptedResourceIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.attempted...)
}

// TestManager_WriteBatch_ContinuesAfterAppendFailure covers writeBatch's failure
// branch (Issue #3754): entries are appended one at a time via
// AppendChainedEntry, and a store error on one entry is logged and skipped
// rather than aborting the batch. It asserts all three consequences of that
// choice:
//
//  1. every remaining entry in the same batch is still attempted after the
//     failing one — the loop does not stop at the first error;
//  2. the durable chain that survives is gap-free and internally consistent
//     (sequence 1..N with correct PreviousChecksum linkage, VerifyChain clean),
//     because the store — not the manager — assigns sequence numbers, so a
//     dropped entry consumes no sequence number;
//  3. the drop is reported: a warning naming the tenant and the store error is
//     logged, since RecordEvent enqueues asynchronously and the error can no
//     longer be returned to the caller.
func TestManager_WriteBatch_ContinuesAfterAppendFailure(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	logs := &syncBuffer{}
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prevLogger) })

	const (
		chainTenant  = "append-failure-tenant"
		warmupTenant = "append-failure-warmup-tenant"
		failedRes    = "res-2"
	)
	injectedErr := errors.New("injected append failure")

	store := &failingAppendAuditStore{
		AuditStore:  storageManager.GetAuditStore(),
		failFor:     map[string]error{failedRes: injectedErr},
		gate:        make(chan struct{}),
		gateEntered: make(chan struct{}),
	}

	manager, err := audit.NewManager(store, "append-failure-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Stop(ctx)
	})

	ctx := context.Background()
	record := func(tenant, resourceID string) {
		t.Helper()
		require.NoError(t, manager.RecordEvent(ctx, audit.NewEventBuilder().
			Tenant(tenant).
			Type(business.AuditEventConfiguration).
			Action("append_failure_action").
			User("user1", business.AuditUserTypeHuman).
			Resource("resource", resourceID, "").
			Severity(business.AuditSeverityMedium)))
	}

	// Park the drain goroutine inside the warm-up entry's write (separate tenant,
	// so it has its own chain and does not perturb the chain under assertion).
	record(warmupTenant, "warmup")
	select {
	case <-store.gateEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("drain goroutine never entered AppendChainedEntry for the warm-up entry")
	}

	// With the drain goroutine blocked, these five queue up and are collected as
	// a single batch; res-2 (the middle one) fails.
	want := []string{"res-0", "res-1", "res-2", "res-3", "res-4"}
	for _, resourceID := range want {
		record(chainTenant, resourceID)
	}
	close(store.gate)
	flushOrFail(t, manager)

	// (a) The failure did not abort the batch: every later entry was attempted.
	assert.Equal(t, append([]string{"warmup"}, want...), store.attemptedResourceIDs(),
		"a failed append must not stop writeBatch from attempting the rest of the batch")

	// (b) The surviving chain is gap-free and consistent; the failed entry is
	// absent from durable storage with no sequence number burned for it.
	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{TenantID: chainTenant, Order: "asc"})
	require.NoError(t, err)
	require.Len(t, entries, len(want)-1, "the failed entry must not be persisted")

	gotResources := make([]string, 0, len(entries))
	for i, e := range entries {
		gotResources = append(gotResources, e.ResourceID)
		assert.Equal(t, uint64(i+1), e.SequenceNumber, "surviving chain must be gap-free")
		assert.Equal(t, chainTenant, e.TenantID)
	}
	assert.Equal(t, []string{"res-0", "res-1", "res-3", "res-4"}, gotResources)
	assert.Empty(t, manager.VerifyChain(entries),
		"chain must remain verifiable after an entry is dropped by a store failure")

	// (c) The drop is visible in the logs — it cannot be returned to the caller.
	logged := logs.String()
	assert.Contains(t, logged, "audit entry append failed",
		"a dropped audit entry must be logged")
	assert.Contains(t, logged, injectedErr.Error(),
		"the store error must be included in the warning")
	assert.Contains(t, logged, chainTenant,
		"the warning must name the tenant whose chain lost an entry")
}

// flushOrFail drains the async queue and fails the test if Flush returns an error.
// Tests that query the store after RecordEvent MUST call flushOrFail first
// because RecordEvent enqueues asynchronously.
func flushOrFail(t *testing.T, m *audit.Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, m.Flush(ctx))
}

// TestNewManager tests audit manager creation
func TestNewManager(t *testing.T) {
	tests := []struct {
		name         string
		setupStorage func(t *testing.T) (business.AuditStore, error)
		wantErr      bool
	}{
		{
			name: "with git storage provider",
			setupStorage: func(t *testing.T) (business.AuditStore, error) {
				tmpDir := t.TempDir()
				storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
				if err != nil {
					return nil, err
				}
				t.Cleanup(func() { _ = storageManager.Close() })
				return storageManager.GetAuditStore(), nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditStore, err := tt.setupStorage(t)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, auditStore)

			manager, err := audit.NewManager(auditStore, "test")
			require.NoError(t, err)
			require.NotNil(t, manager)
		})
	}
}

// TestNewManager_ErrorConditions tests error conditions (previously tested as panics)
func TestNewManager_ErrorConditions(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })
	realStore := storageManager.GetAuditStore()

	tests := []struct {
		name   string
		store  business.AuditStore
		source string
	}{
		{
			name:   "nil store",
			store:  nil,
			source: "test",
		},
		{
			name:   "empty source",
			store:  realStore,
			source: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := audit.NewManager(tt.store, tt.source)
			assert.Error(t, err)
			assert.Nil(t, m)
		})
	}
}

// TestManager_RecordEvent verifies that RecordEvent persists the event to the
// store. It calls flushOrFail to drain the async queue before reading back, so
// the test fails if RecordEvent silently discards the event.
func TestManager_RecordEvent(t *testing.T) {
	manager := newTestManager(t, "test")
	ctx := context.Background()

	event := audit.NewEventBuilder().
		Tenant("test-tenant").
		Type(business.AuditEventConfiguration).
		Action("test_action").
		User("test-user", business.AuditUserTypeHuman).
		Resource("test_resource", "test-id", "Test Resource").
		Detail("test_key", "test_value").
		Severity(business.AuditSeverityMedium)

	require.NoError(t, manager.RecordEvent(ctx, event))
	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{TenantID: "test-tenant"})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "test_action", entries[0].Action)
	assert.Equal(t, "test-tenant", entries[0].TenantID)
}

// TestManager_RecordBatch verifies that RecordBatch persists all events to the
// store. It calls flushOrFail to drain the async queue before reading back, so
// the test fails if RecordBatch silently discards events.
func TestManager_RecordBatch(t *testing.T) {
	manager := newTestManager(t, "test")
	ctx := context.Background()

	events := []*audit.AuditEventBuilder{
		audit.NewEventBuilder().
			Tenant("test-tenant").
			Type(business.AuditEventAuthentication).
			Action("login").
			User("user1", business.AuditUserTypeHuman).
			Resource("session", "session1", "").
			Severity(business.AuditSeverityHigh),
		audit.NewEventBuilder().
			Tenant("test-tenant").
			Type(business.AuditEventConfiguration).
			Action("config_update").
			User("user2", business.AuditUserTypeHuman).
			Resource("config", "config1", "Test Config").
			Severity(business.AuditSeverityMedium),
	}

	require.NoError(t, manager.RecordBatch(ctx, events))
	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{TenantID: "test-tenant"})
	require.NoError(t, err)
	require.Len(t, entries, 2)

	actions := make(map[string]bool, len(entries))
	for _, e := range entries {
		actions[e.Action] = true
	}
	assert.True(t, actions["login"], "expected entry with Action=login")
	assert.True(t, actions["config_update"], "expected entry with Action=config_update")
}

// TestManager_ValidationErrors tests validation error handling
func TestManager_ValidationErrors(t *testing.T) {
	manager := newTestManager(t, "test")
	ctx := context.Background()

	tests := []struct {
		name          string
		event         *audit.AuditEventBuilder
		expectedError error
	}{
		{
			name: "missing tenant ID",
			event: audit.NewEventBuilder().
				Type(business.AuditEventConfiguration).
				Action("test_action").
				User("test-user", business.AuditUserTypeHuman).
				Resource("test_resource", "test-id", ""),
			expectedError: business.ErrTenantIDRequired,
		},
		{
			name: "missing user ID",
			event: audit.NewEventBuilder().
				Tenant("test-tenant").
				Type(business.AuditEventConfiguration).
				Action("test_action").
				Resource("test_resource", "test-id", ""),
			expectedError: business.ErrUserIDRequired,
		},
		{
			name: "missing action",
			event: audit.NewEventBuilder().
				Tenant("test-tenant").
				Type(business.AuditEventConfiguration).
				User("test-user", business.AuditUserTypeHuman).
				Resource("test_resource", "test-id", ""),
			expectedError: business.ErrActionRequired,
		},
		{
			name: "missing resource type",
			event: audit.NewEventBuilder().
				Tenant("test-tenant").
				Type(business.AuditEventConfiguration).
				Action("test_action").
				User("test-user", business.AuditUserTypeHuman),
			expectedError: business.ErrResourceTypeRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := manager.RecordEvent(ctx, tt.event)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "audit validation failed")
		})
	}
}

// TestAuditEventBuilder tests the fluent builder interface
func TestAuditEventBuilder(t *testing.T) {
	event := audit.NewEventBuilder().
		Tenant("test-tenant").
		Type(business.AuditEventAuthentication).
		Action("login").
		User("test-user", business.AuditUserTypeHuman).
		Session("session123").
		Resource("session", "session123", "User Session").
		Result(business.AuditResultSuccess).
		Request("req123", "POST", "/api/login", "192.168.1.1", "TestAgent/1.0").
		Detail("login_method", "password").
		Detail("mfa_used", true).
		Tag("security").
		Tag("authentication").
		Severity(business.AuditSeverityHigh)

	entry := &business.AuditEntry{}
	audit.BuildEntry(event, entry)

	assert.Equal(t, "test-tenant", entry.TenantID)
	assert.Equal(t, business.AuditEventAuthentication, entry.EventType)
	assert.Equal(t, "login", entry.Action)
	assert.Equal(t, "test-user", entry.UserID)
	assert.Equal(t, business.AuditUserTypeHuman, entry.UserType)
	assert.Equal(t, "session123", entry.SessionID)
	assert.Equal(t, "session", entry.ResourceType)
	assert.Equal(t, "session123", entry.ResourceID)
	assert.Equal(t, "User Session", entry.ResourceName)
	assert.Equal(t, business.AuditResultSuccess, entry.Result)
	assert.Equal(t, "req123", entry.RequestID)
	assert.Equal(t, "POST", entry.Method)
	assert.Equal(t, "/api/login", entry.Path)
	assert.Equal(t, "192.168.1.1", entry.IPAddress)
	assert.Equal(t, "TestAgent/1.0", entry.UserAgent)
	assert.Equal(t, "password", entry.Details["login_method"])
	assert.Equal(t, true, entry.Details["mfa_used"])
	assert.Contains(t, entry.Tags, "security")
	assert.Contains(t, entry.Tags, "authentication")
	assert.Equal(t, business.AuditSeverityHigh, entry.Severity)
}

// TestPredefinedEventBuilders tests predefined event builder functions
func TestPredefinedEventBuilders(t *testing.T) {
	t.Run("AuthenticationEvent", func(t *testing.T) {
		event := audit.AuthenticationEvent("tenant1", "user1", "login", business.AuditResultSuccess)
		entry := &business.AuditEntry{}
		audit.BuildEntry(event, entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, business.AuditEventAuthentication, entry.EventType)
		assert.Equal(t, "login", entry.Action)
		assert.Equal(t, "user1", entry.UserID)
		assert.Equal(t, business.AuditUserTypeHuman, entry.UserType)
		assert.Equal(t, "session", entry.ResourceType)
		assert.Equal(t, "user1", entry.ResourceID)
		assert.Equal(t, business.AuditResultSuccess, entry.Result)
		// Success is Low — routine authentication; failures/denials are High (Issue #2964).
		assert.Equal(t, business.AuditSeverityLow, entry.Severity)
	})

	t.Run("AuthorizationEvent", func(t *testing.T) {
		event := audit.AuthorizationEvent("tenant1", "user1", "config", "config1", "read", business.AuditResultDenied)
		entry := &business.AuditEntry{}
		audit.BuildEntry(event, entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, business.AuditEventAuthorization, entry.EventType)
		assert.Equal(t, "read", entry.Action)
		assert.Equal(t, "user1", entry.UserID)
		assert.Equal(t, "config", entry.ResourceType)
		assert.Equal(t, "config1", entry.ResourceID)
		assert.Equal(t, business.AuditResultDenied, entry.Result)
		// Denied is High — ordinary access denial (Issue #2964).
		assert.Equal(t, business.AuditSeverityHigh, entry.Severity)
	})

	t.Run("ConfigurationEvent", func(t *testing.T) {
		event := audit.ConfigurationEvent("tenant1", "user1", "steward_config", "steward1", "Config1", "update")
		entry := &business.AuditEntry{}
		audit.BuildEntry(event, entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, business.AuditEventConfiguration, entry.EventType)
		assert.Equal(t, "update", entry.Action)
		assert.Equal(t, "user1", entry.UserID)
		assert.Equal(t, "steward_config", entry.ResourceType)
		assert.Equal(t, "steward1", entry.ResourceID)
		assert.Equal(t, "Config1", entry.ResourceName)
		assert.Equal(t, business.AuditSeverityMedium, entry.Severity)
	})

	t.Run("SystemEvent", func(t *testing.T) {
		event := audit.SystemEvent("tenant1", "startup", "System started successfully")
		entry := &business.AuditEntry{}
		audit.BuildEntry(event, entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, business.AuditEventSystemEvent, entry.EventType)
		assert.Equal(t, "startup", entry.Action)
		assert.Equal(t, audit.SystemUserID, entry.UserID)
		assert.Equal(t, business.AuditUserTypeSystem, entry.UserType)
		assert.Equal(t, "system", entry.ResourceType)
		assert.Equal(t, "controller", entry.ResourceID)
		assert.Equal(t, "System started successfully", entry.Details["description"])
		assert.Equal(t, business.AuditSeverityLow, entry.Severity)
	})

	t.Run("SecurityEvent", func(t *testing.T) {
		event := audit.SecurityEvent("tenant1", "user1", "intrusion_detected", "Multiple failed login attempts", business.AuditSeverityCritical)
		entry := &business.AuditEntry{}
		audit.BuildEntry(event, entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, business.AuditEventSecurityEvent, entry.EventType)
		assert.Equal(t, "intrusion_detected", entry.Action)
		assert.Equal(t, "user1", entry.UserID)
		assert.Equal(t, "security", entry.ResourceType)
		assert.Equal(t, "user1", entry.ResourceID)
		assert.Equal(t, "Multiple failed login attempts", entry.Details["description"])
		assert.Equal(t, business.AuditSeverityCritical, entry.Severity)
	})
}

// TestAuthenticationEvent_Persists verifies AuthenticationEvent produces an entry that passes
// validateEntry and is successfully stored via RecordEvent.
func TestAuthenticationEvent_Persists(t *testing.T) {
	manager := newTestManager(t, "controller")
	ctx := context.Background()

	event := audit.AuthenticationEvent("tenant1", "user1", "login", business.AuditResultSuccess)
	err := manager.RecordEvent(ctx, event)
	assert.NoError(t, err, "AuthenticationEvent must not return a validation error")
}

// TestSystemEvent_Persists verifies SystemEvent produces an entry that passes validateEntry
// and is successfully stored via RecordEvent.
func TestSystemEvent_Persists(t *testing.T) {
	manager := newTestManager(t, "controller")
	ctx := context.Background()

	event := audit.SystemEvent(audit.SystemTenantID, "startup", "Controller started")
	err := manager.RecordEvent(ctx, event)
	assert.NoError(t, err, "SystemEvent must not return a validation error")
}

// TestSecurityEvent_Persists verifies SecurityEvent produces an entry that passes validateEntry
// and is successfully stored via RecordEvent.
func TestSecurityEvent_Persists(t *testing.T) {
	manager := newTestManager(t, "controller")
	ctx := context.Background()

	event := audit.SecurityEvent(audit.SystemTenantID, audit.SystemUserID, "brute_force_detected", "Multiple failed auth attempts", business.AuditSeverityHigh)
	err := manager.RecordEvent(ctx, event)
	assert.NoError(t, err, "SecurityEvent must not return a validation error")
}

// TestRedactMap verifies that Detail() values with sensitive key names are stored as [REDACTED]
// and innocuous keys are preserved after BuildEntry.
func TestRedactMap(t *testing.T) {
	event := audit.NewEventBuilder().
		Tenant("test-tenant").
		Type(business.AuditEventConfiguration).
		Action("test_action").
		User("test-user", business.AuditUserTypeHuman).
		Resource("res", "id", "").
		Detail("password", "hunter2").
		Detail("api_token", "tok_abc123").
		Detail("some_secret", "s3cr3t").
		Detail("user_count", 42).
		Detail("enabled", true).
		Detail("username", "alice").
		Severity(business.AuditSeverityMedium)

	entry := &business.AuditEntry{}
	audit.BuildEntry(event, entry)

	assert.Equal(t, "[REDACTED]", entry.Details["password"], "password should be redacted")
	assert.Equal(t, "[REDACTED]", entry.Details["api_token"], "api_token should be redacted")
	assert.Equal(t, "[REDACTED]", entry.Details["some_secret"], "some_secret should be redacted")
	assert.Equal(t, 42, entry.Details["user_count"], "user_count should not be redacted")
	assert.Equal(t, true, entry.Details["enabled"], "bool values should not be redacted")
	assert.Equal(t, "alice", entry.Details["username"], "username should not be redacted")
}

// TestRedactMap_NilAndEmpty verifies edge cases for Details redaction.
func TestRedactMap_NilAndEmpty(t *testing.T) {
	// Builder with no Details → entry.Details must be empty after build.
	event := audit.NewEventBuilder().
		Tenant("t").
		Type(business.AuditEventConfiguration).
		Action("a").
		User("u", business.AuditUserTypeHuman).
		Resource("r", "id", "").
		Severity(business.AuditSeverityLow)

	entry := &business.AuditEntry{}
	audit.BuildEntry(event, entry)
	assert.Empty(t, entry.Details, "entry with no details must produce empty Details after build")
}

// TestRedactMap_CaseInsensitive verifies that key matching is case-insensitive.
func TestRedactMap_CaseInsensitive(t *testing.T) {
	event := audit.NewEventBuilder().
		Tenant("test-tenant").
		Type(business.AuditEventConfiguration).
		Action("action").
		User("user", business.AuditUserTypeHuman).
		Resource("res", "id", "").
		Detail("Password", "secret1").
		Detail("API_KEY", "secret2").
		Detail("X-Auth-Token", "secret3").
		Detail("Username", "alice").
		Severity(business.AuditSeverityMedium)

	entry := &business.AuditEntry{}
	audit.BuildEntry(event, entry)

	assert.Equal(t, "[REDACTED]", entry.Details["Password"], "Password (mixed case) should be redacted")
	assert.Equal(t, "[REDACTED]", entry.Details["API_KEY"], "API_KEY (uppercase) should be redacted")
	assert.Equal(t, "[REDACTED]", entry.Details["X-Auth-Token"], "X-Auth-Token should be redacted")
	assert.Equal(t, "alice", entry.Details["Username"], "Username should not be redacted")
}

// TestRedactMap_NonStringOnSensitiveKey verifies that non-string values under sensitive keys
// pass through unredacted (only string values are replaced).
func TestRedactMap_NonStringOnSensitiveKey(t *testing.T) {
	event := audit.NewEventBuilder().
		Tenant("test-tenant").
		Type(business.AuditEventConfiguration).
		Action("action").
		User("user", business.AuditUserTypeHuman).
		Resource("res", "id", "").
		Detail("password", 12345).
		Detail("token_count", true).
		Detail("auth_level", 3.14).
		Severity(business.AuditSeverityMedium)

	entry := &business.AuditEntry{}
	audit.BuildEntry(event, entry)

	// Non-string values pass through — only string values are candidates for redaction.
	assert.Equal(t, 12345, entry.Details["password"], "integer under sensitive key must pass through")
	assert.Equal(t, true, entry.Details["token_count"], "bool under sensitive key must pass through")
	assert.Equal(t, 3.14, entry.Details["auth_level"], "float under sensitive key must pass through")
}

// TestRedactErrorMessage verifies that error messages containing key=value
// patterns with sensitive key names have the value portion redacted after build.
func TestRedactErrorMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains []string
		absent   []string
	}{
		{
			name:     "empty string",
			input:    "",
			contains: []string{},
			absent:   []string{},
		},
		{
			name:     "no sensitive key=value",
			input:    "login failed: username=alice, attempts=3",
			contains: []string{"username=alice", "attempts=3"},
			absent:   []string{"[REDACTED]"},
		},
		{
			name:     "single sensitive key=value",
			input:    "login failed: password=hunter2, username=alice",
			contains: []string{"password=[REDACTED]", "username=alice"},
			absent:   []string{"hunter2"},
		},
		{
			name:     "multiple sensitive key=value pairs",
			input:    "error: token=abc123, api_key=xyz789, user=bob",
			contains: []string{"token=[REDACTED]", "api_key=[REDACTED]", "user=bob"},
			absent:   []string{"abc123", "xyz789"},
		},
		{
			name:     "case-insensitive key matching",
			input:    "auth error: PASSWORD=secret, user=alice",
			contains: []string{"PASSWORD=[REDACTED]", "user=alice"},
			absent:   []string{"secret"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := audit.NewEventBuilder().
				Tenant("t").
				Type(business.AuditEventAuthentication).
				Action("login").
				User("u", business.AuditUserTypeHuman).
				Resource("session", "u", "").
				Error("E", tt.input).
				Severity(business.AuditSeverityMedium)

			entry := &business.AuditEntry{}
			audit.BuildEntry(event, entry)

			result := entry.ErrorMessage
			for _, s := range tt.contains {
				assert.Contains(t, result, s, "result should contain %q", s)
			}
			for _, s := range tt.absent {
				assert.NotContains(t, result, s, "result must not contain %q", s)
			}
		})
	}
}

// TestRecordEvent_RedactsDetails verifies that Detail("password", ...) is stored as [REDACTED].
func TestRecordEvent_RedactsDetails(t *testing.T) {
	manager := newTestManager(t, "test")
	ctx := context.Background()

	event := audit.NewEventBuilder().
		Tenant("test-tenant").
		Type(business.AuditEventConfiguration).
		Action("test_action").
		User("test-user", business.AuditUserTypeHuman).
		Resource("test_resource", "test-id", "Test Resource").
		Detail("password", "hunter2").
		Detail("api_key", "secret-key-value").
		Detail("user_count", 5).
		Severity(business.AuditSeverityMedium)

	err := manager.RecordEvent(ctx, event)
	require.NoError(t, err)

	// Flush to guarantee the asynchronously-queued entry reached the store
	// before we query it.
	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "test-tenant",
	})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.Equal(t, "[REDACTED]", entries[0].Details["password"], "password must be redacted in stored entry")
	assert.Equal(t, "[REDACTED]", entries[0].Details["api_key"], "api_key must be redacted in stored entry")
	// Storage round-trips through JSON, so integers deserialize as float64
	assert.EqualValues(t, 5, entries[0].Details["user_count"], "non-sensitive int must be stored as-is")
}

// TestChanges_Redacted verifies that Changes Before/After maps have sensitive keys redacted.
func TestChanges_Redacted(t *testing.T) {
	manager := newTestManager(t, "test")
	ctx := context.Background()

	before := map[string]interface{}{
		"password": "old-password",
		"username": "alice",
		"token":    "old-token",
	}
	after := map[string]interface{}{
		"password": "new-password",
		"username": "alice",
		"token":    "new-token",
	}

	event := audit.NewEventBuilder().
		Tenant("test-tenant").
		Type(business.AuditEventConfiguration).
		Action("update_credentials").
		User("admin", business.AuditUserTypeHuman).
		Resource("user", "alice", "Alice").
		Changes(before, after, []string{"password", "username", "token"}).
		Severity(business.AuditSeverityHigh)

	err := manager.RecordEvent(ctx, event)
	require.NoError(t, err)

	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "test-tenant",
	})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	require.NotNil(t, entries[0].Changes)
	assert.Equal(t, "[REDACTED]", entries[0].Changes.Before["password"], "Before.password must be redacted")
	assert.Equal(t, "[REDACTED]", entries[0].Changes.Before["token"], "Before.token must be redacted")
	assert.Equal(t, "alice", entries[0].Changes.Before["username"], "Before.username must not be redacted")
	assert.Equal(t, "[REDACTED]", entries[0].Changes.After["password"], "After.password must be redacted")
	assert.Equal(t, "[REDACTED]", entries[0].Changes.After["token"], "After.token must be redacted")
	assert.Equal(t, "alice", entries[0].Changes.After["username"], "After.username must not be redacted")

	// Field names are not redacted, only values
	assert.Contains(t, entries[0].Changes.Fields, "password", "field names must not be redacted")
	assert.Contains(t, entries[0].Changes.Fields, "token", "field names must not be redacted")

	// Verify original maps are not mutated
	assert.Equal(t, "old-password", before["password"], "original before map must not be mutated")
	assert.Equal(t, "new-password", after["password"], "original after map must not be mutated")
}

// TestRecordEvent_RedactsErrorMessage verifies that error messages containing key=value
// patterns with sensitive key names have the value portion redacted.
func TestRecordEvent_RedactsErrorMessage(t *testing.T) {
	manager := newTestManager(t, "test")
	ctx := context.Background()

	event := audit.NewEventBuilder().
		Tenant("test-tenant").
		Type(business.AuditEventAuthentication).
		Action("login").
		User("user1", business.AuditUserTypeHuman).
		Resource("session", "user1", "").
		Error("AUTH_FAILED", "login failed: password=hunter2, username=alice").
		Severity(business.AuditSeverityHigh)

	err := manager.RecordEvent(ctx, event)
	require.NoError(t, err)

	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "test-tenant",
	})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.NotContains(t, entries[0].ErrorMessage, "hunter2", "raw secret must not appear in stored ErrorMessage")
	assert.Contains(t, entries[0].ErrorMessage, "password=[REDACTED]", "password value must be replaced with [REDACTED]")
	assert.Contains(t, entries[0].ErrorMessage, "username=alice", "non-sensitive key=value must be preserved")
}

// TestManager_IntegrityVerification tests audit integrity verification and
// asserts that chain fields are populated on stored entries.
func TestManager_IntegrityVerification(t *testing.T) {
	manager := newTestManager(t, "test")
	ctx := context.Background()

	// Part 1: direct checksum round-trip (SequenceNumber 0 — pre-chain style).
	entry := &business.AuditEntry{
		ID:           "test-id",
		TenantID:     "test-tenant",
		Timestamp:    time.Now().UTC(),
		EventType:    business.AuditEventConfiguration,
		Action:       "test_action",
		UserID:       "test-user",
		UserType:     business.AuditUserTypeHuman,
		ResourceType: "test_resource",
		ResourceID:   "test-id",
		Result:       business.AuditResultSuccess,
		Severity:     business.AuditSeverityMedium,
		Source:       "test",
		Version:      "1.0",
	}
	entry.Checksum = audit.GenerateChecksum(manager, entry)
	assert.True(t, manager.VerifyIntegrity(entry))

	originalAction := entry.Action
	entry.Action = "tampered_action"
	assert.False(t, manager.VerifyIntegrity(entry))

	entry.Action = originalAction
	assert.True(t, manager.VerifyIntegrity(entry))

	// Part 2: record two events via the manager and verify chain fields on the second.
	event1 := audit.NewEventBuilder().
		Tenant("integrity-tenant").
		Type(business.AuditEventConfiguration).
		Action("first_action").
		User("user1", business.AuditUserTypeHuman).
		Resource("resource", "res-1", "").
		Severity(business.AuditSeverityMedium)
	require.NoError(t, manager.RecordEvent(ctx, event1))

	event2 := audit.NewEventBuilder().
		Tenant("integrity-tenant").
		Type(business.AuditEventConfiguration).
		Action("second_action").
		User("user1", business.AuditUserTypeHuman).
		Resource("resource", "res-2", "").
		Severity(business.AuditSeverityMedium)
	require.NoError(t, manager.RecordEvent(ctx, event2))

	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "integrity-tenant",
		Order:    "asc",
	})
	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Greater(t, entries[0].SequenceNumber, uint64(0), "first entry must have SequenceNumber > 0")
	assert.Greater(t, entries[1].SequenceNumber, uint64(0), "second entry must have SequenceNumber > 0")
	assert.NotEmpty(t, entries[1].PreviousChecksum, "second entry must have PreviousChecksum set")
	assert.Equal(t, entries[0].Checksum, entries[1].PreviousChecksum,
		"second entry PreviousChecksum must equal first entry Checksum")
}

// TestChain_MonotonicSequence records 5 events for the same tenant and asserts
// that the stored entries have SequenceNumbers 1 through 5 in order.
func TestChain_MonotonicSequence(t *testing.T) {
	manager := newTestManager(t, "chain-test")
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		event := audit.NewEventBuilder().
			Tenant("seq-tenant").
			Type(business.AuditEventConfiguration).
			Action("seq_action").
			User("user1", business.AuditUserTypeHuman).
			Resource("resource", fmt.Sprintf("res-%d", i), "").
			Severity(business.AuditSeverityMedium)
		require.NoError(t, manager.RecordEvent(ctx, event))
	}

	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "seq-tenant",
		Order:    "asc",
	})
	require.NoError(t, err)
	require.Len(t, entries, 5, "expected 5 stored entries")

	for i, e := range entries {
		assert.Equal(t, uint64(i+1), e.SequenceNumber,
			"entry[%d] must have SequenceNumber %d", i, i+1)
	}
}

// TestChain_PreviousChecksumLinked records 5 events and asserts that each
// entry's PreviousChecksum equals the Checksum of the preceding entry.
func TestChain_PreviousChecksumLinked(t *testing.T) {
	manager := newTestManager(t, "chain-test")
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		event := audit.NewEventBuilder().
			Tenant("link-tenant").
			Type(business.AuditEventConfiguration).
			Action("link_action").
			User("user1", business.AuditUserTypeHuman).
			Resource("resource", fmt.Sprintf("res-%d", i), "").
			Severity(business.AuditSeverityMedium)
		require.NoError(t, manager.RecordEvent(ctx, event))
	}

	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "link-tenant",
		Order:    "asc",
	})
	require.NoError(t, err)
	require.Len(t, entries, 5)

	// First entry starts the chain with empty PreviousChecksum.
	assert.Empty(t, entries[0].PreviousChecksum, "first entry must have empty PreviousChecksum")

	for i := 1; i < len(entries); i++ {
		assert.Equal(t, entries[i-1].Checksum, entries[i].PreviousChecksum,
			"entry[%d].PreviousChecksum must equal entry[%d].Checksum", i, i-1)
	}
}

// TestVerifyChain_DetectsTampering, TestVerifyChain_DetectsPreviousChecksumMismatch,
// and TestVerifyChain_DetectsDeletion together prove one half of the ADR-004
// adversary bound (Issue #3727): an actor who alters, reorders, or deletes
// entries WITHOUT recomputing the chain fields using the manager's HMAC key —
// i.e. an actor who does not hold the key — is caught by VerifyChain. See
// TestVerifyChain_KeyHolderCanForgeConsistentChain below for the other half:
// an actor who does hold the key is not caught.

// TestVerifyChain_DetectsTampering records 3 entries, then tampers with the
// middle entry's Action field in-memory and verifies VerifyChain reports a
// ChainBreak for it.
func TestVerifyChain_DetectsTampering(t *testing.T) {
	manager := newTestManager(t, "chain-test")
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		event := audit.NewEventBuilder().
			Tenant("tamper-tenant").
			Type(business.AuditEventConfiguration).
			Action("original_action").
			User("user1", business.AuditUserTypeHuman).
			Resource("resource", fmt.Sprintf("res-%d", i), "").
			Severity(business.AuditSeverityMedium)
		require.NoError(t, manager.RecordEvent(ctx, event))
	}

	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "tamper-tenant",
		Order:    "asc",
	})
	require.NoError(t, err)
	require.Len(t, entries, 3)

	// Tamper with entry[1] in-memory — do not write back to the store.
	entries[1].Action = "tampered_action"

	breaks := manager.VerifyChain(entries)
	require.NotEmpty(t, breaks, "VerifyChain must report a break for tampered entry")

	found := false
	for _, b := range breaks {
		if b.SequenceNumber == entries[1].SequenceNumber {
			found = true
			assert.Contains(t, b.Reason, "checksum mismatch")
		}
	}
	assert.True(t, found, "ChainBreak must reference the tampered entry's SequenceNumber")
}

// TestVerifyChain_Empty verifies that VerifyChain on an empty or nil slice
// returns no breaks.
func TestVerifyChain_Empty(t *testing.T) {
	manager := newTestManager(t, "chain-test")
	assert.Empty(t, manager.VerifyChain(nil), "nil slice must produce no breaks")
	assert.Empty(t, manager.VerifyChain([]*business.AuditEntry{}), "empty slice must produce no breaks")
}

// TestVerifyChain_SingleEntry verifies that a single valid entry with
// PreviousChecksum=="" passes verification.
func TestVerifyChain_SingleEntry(t *testing.T) {
	manager := newTestManager(t, "chain-test")
	ctx := context.Background()

	event := audit.NewEventBuilder().
		Tenant("single-chain-tenant").
		Type(business.AuditEventConfiguration).
		Action("single_action").
		User("user1", business.AuditUserTypeHuman).
		Resource("resource", "res-1", "").
		Severity(business.AuditSeverityMedium)
	require.NoError(t, manager.RecordEvent(ctx, event))
	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "single-chain-tenant",
	})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	breaks := manager.VerifyChain(entries)
	assert.Empty(t, breaks, "single valid entry must produce no chain breaks")
}

// TestVerifyChain_DetectsPreviousChecksumMismatch verifies that an entry whose
// PreviousChecksum does not link to the prior entry's Checksum is detected —
// even when the entry's own checksum is intact (e.g., an entry is replaced
// wholesale by a valid-checksum entry that does not belong in this chain).
func TestVerifyChain_DetectsPreviousChecksumMismatch(t *testing.T) {
	manager := newTestManager(t, "chain-test")
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		event := audit.NewEventBuilder().
			Tenant("prev-mismatch-tenant").
			Type(business.AuditEventConfiguration).
			Action("pm_action").
			User("user1", business.AuditUserTypeHuman).
			Resource("resource", fmt.Sprintf("res-%d", i), "").
			Severity(business.AuditSeverityMedium)
		require.NoError(t, manager.RecordEvent(ctx, event))
	}
	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "prev-mismatch-tenant",
		Order:    "asc",
	})
	require.NoError(t, err)
	require.Len(t, entries, 3)

	// Replace entry[1]'s PreviousChecksum with a bogus value, leaving the
	// entry's own Checksum intact (to isolate the PreviousChecksum path).
	// This simulates an attacker replacing the entry with a forged one that
	// has a valid self-checksum but wrong chain linkage.
	modifiedEntry := *entries[1]
	modifiedEntry.PreviousChecksum = "00000000000000000000000000000000000000000000000000000000000000"
	// Update the checksum so the self-checksum still matches, isolating the chain-linkage check.
	modifiedEntry.Checksum = audit.GenerateChecksum(manager, &modifiedEntry)
	modifiedSlice := []*business.AuditEntry{entries[0], &modifiedEntry, entries[2]}

	breaks := manager.VerifyChain(modifiedSlice)
	require.NotEmpty(t, breaks, "VerifyChain must report a break for PreviousChecksum mismatch")

	found := false
	for _, b := range breaks {
		if b.SequenceNumber == modifiedEntry.SequenceNumber && strings.Contains(b.Reason, "previous_checksum mismatch") {
			found = true
		}
	}
	assert.True(t, found, "ChainBreak must reference the entry with wrong PreviousChecksum")
}

// TestVerifyChain_DetectsDeletion passes a slice missing the entry with
// SequenceNumber 2 (simulating deletion) and asserts a gap is reported.
func TestVerifyChain_DetectsDeletion(t *testing.T) {
	manager := newTestManager(t, "chain-test")
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		event := audit.NewEventBuilder().
			Tenant("gap-tenant").
			Type(business.AuditEventConfiguration).
			Action("gap_action").
			User("user1", business.AuditUserTypeHuman).
			Resource("resource", fmt.Sprintf("res-%d", i), "").
			Severity(business.AuditSeverityMedium)
		require.NoError(t, manager.RecordEvent(ctx, event))
	}

	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "gap-tenant",
		Order:    "asc",
	})
	require.NoError(t, err)
	require.Len(t, entries, 3)

	// Remove the middle entry to simulate deletion.
	withGap := []*business.AuditEntry{entries[0], entries[2]}

	breaks := manager.VerifyChain(withGap)
	require.NotEmpty(t, breaks, "VerifyChain must report a break for the missing entry")

	// At least one break must be a sequence gap referencing the entry after the deletion.
	foundGap := false
	for _, b := range breaks {
		if b.SequenceNumber == entries[2].SequenceNumber && strings.Contains(b.Reason, "sequence gap") {
			foundGap = true
		}
	}
	assert.True(t, foundGap, "ChainBreak must report a sequence gap for the entry after the deletion")
}

// TestVerifyChain_KeyHolderCanForgeConsistentChain proves the ADR-004 adversary
// bound (Issue #3727): an actor who holds the chain's HMAC key can rewrite entry
// content and recompute SequenceNumber, PreviousChecksum, and Checksum for every
// entry in order — exactly as writeBatch does for legitimate writes — producing a
// chain VerifyChain reports as fully consistent, despite every entry's content
// differing from what was originally recorded.
//
// This models a host-compromised controller: WithSecretsStore loads the HMAC key
// from the controller's own secrets store, so the controller process itself is
// this "key holder" whenever a secrets store is wired — the production
// configuration, not a hypothetical. The manager under test stands in for that
// actor because it already holds the same key that produced the original chain.
//
// This is not a defect in VerifyChain; it demonstrates the documented bound of a
// keyed hash chain and is why the audit trail is not a compensating control
// against a compromised controller (see ADR-021's qualification).
func TestVerifyChain_KeyHolderCanForgeConsistentChain(t *testing.T) {
	manager := newTestManager(t, "chain-test")
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		event := audit.NewEventBuilder().
			Tenant("forge-tenant").
			Type(business.AuditEventConfiguration).
			Action("original_action").
			User("user1", business.AuditUserTypeHuman).
			Resource("resource", fmt.Sprintf("res-%d", i), "").
			Severity(business.AuditSeverityMedium)
		require.NoError(t, manager.RecordEvent(ctx, event))
	}
	flushOrFail(t, manager)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "forge-tenant",
		Order:    "asc",
	})
	require.NoError(t, err)
	require.Len(t, entries, 3)

	originalActions := make([]string, len(entries))
	for i, e := range entries {
		originalActions[i] = e.Action
	}

	// The key holder rewrites every entry's content and recomputes the chain
	// fields in sequence order — the same recompute writeBatch performs for a
	// legitimate write, available to anyone who holds m.hmacKey.
	forged := make([]*business.AuditEntry, len(entries))
	var prevChecksum string
	for i, e := range entries {
		f := *e
		f.Action = fmt.Sprintf("forged_action_%d", i)
		f.PreviousChecksum = prevChecksum
		f.Checksum = audit.GenerateChecksum(manager, &f)
		prevChecksum = f.Checksum
		forged[i] = &f
	}

	breaks := manager.VerifyChain(forged)
	assert.Empty(t, breaks,
		"an actor holding the HMAC key can recompute a fully consistent chain over rewritten content — VerifyChain must not report this as broken")

	for i, f := range forged {
		assert.NotEqual(t, originalActions[i], f.Action,
			"forged entry content must differ from what was originally recorded, proving the chain is consistent but false")
	}
}

// TestManager_Flush verifies that after RecordEvent returns successfully and
// Flush completes, every recorded entry is present in the store. This is the
// contract that shutdown guarantees rely on.
func TestManager_Flush(t *testing.T) {
	manager := newTestManager(t, "test")
	ctx := context.Background()

	const numEvents = 25
	for i := 0; i < numEvents; i++ {
		event := audit.NewEventBuilder().
			Tenant("flush-tenant").
			Type(business.AuditEventConfiguration).
			Action("flush_action").
			User("flush-user", business.AuditUserTypeHuman).
			Resource("flush_resource", fmt.Sprintf("res-%d", i), "").
			Severity(business.AuditSeverityMedium)

		require.NoError(t, manager.RecordEvent(ctx, event), "RecordEvent %d must succeed", i)
	}

	// Flush must block until every enqueued entry has been written.
	flushCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Flush(flushCtx), "Flush must complete without error")

	// Verify all events reached the store. Because Flush returned, we should
	// see exactly numEvents entries with zero retries or polling.
	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "flush-tenant",
	})
	require.NoError(t, err)
	assert.Len(t, entries, numEvents, "all recorded events must be durable after Flush")
}

// TestManager_FlushEmpty verifies Flush on an idle manager returns immediately.
func TestManager_FlushEmpty(t *testing.T) {
	manager := newTestManager(t, "test")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, manager.Flush(ctx), "Flush on empty manager must not block")
}

// TestManager_ShutdownOrderGuarantee verifies that Flush actually waits for the
// drain loop to finish writing — even when the underlying store is slow. A
// broken Flush implementation would return immediately and the slow store
// would show fewer writes than the test recorded.
func TestManager_ShutdownOrderGuarantee(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	// Wrap the real store with a 20ms per-write delay. With 10 events and
	// sequential drain writes, the drain loop needs roughly 200ms to finish —
	// easily long enough that a no-op Flush would return too early.
	slow := &slowAuditStore{
		inner: storageManager.GetAuditStore(),
		delay: 20 * time.Millisecond,
	}

	manager, err := audit.NewManager(slow, "slow-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Stop(ctx)
	})

	const numEvents = 10
	ctx := context.Background()
	for i := 0; i < numEvents; i++ {
		event := audit.NewEventBuilder().
			Tenant("slow-tenant").
			Type(business.AuditEventConfiguration).
			Action("slow_action").
			User("slow-user", business.AuditUserTypeHuman).
			Resource("slow_resource", fmt.Sprintf("res-%d", i), "").
			Severity(business.AuditSeverityMedium)

		require.NoError(t, manager.RecordEvent(ctx, event))
	}

	// At this point the drain loop is still working through the queue. Flush
	// must not return until every write has completed.
	flushCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	flushStart := time.Now()
	require.NoError(t, manager.Flush(flushCtx))
	flushDuration := time.Since(flushStart)

	// Every event must be reflected in the slow store's counter *at the moment
	// Flush returned*. This is the strict ordering guarantee callers rely on.
	assert.Equal(t, int64(numEvents), slow.writes.Load(),
		"Flush must wait for every pending write to complete (observed %d)", slow.writes.Load())

	// Sanity check: Flush actually waited rather than no-oping. With 10×20ms
	// writes the drain must take at least ~100ms in the common case.
	assert.GreaterOrEqual(t, flushDuration, 100*time.Millisecond,
		"Flush duration (%v) indicates it did not wait for the drain loop", flushDuration)
}

// TestManager_StopIdempotent verifies Stop can be called multiple times
// without panic or error — callers should not have to track whether the
// manager has already been stopped.
func TestManager_StopIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager, err := audit.NewManager(storageManager.GetAuditStore(), "stop-test")
	require.NoError(t, err)

	ctx := context.Background()

	// First Stop should drain + close cleanly.
	require.NoError(t, manager.Stop(ctx))

	// Subsequent Stops must be safe (idempotency via sync.Once).
	require.NoError(t, manager.Stop(ctx))
	require.NoError(t, manager.Stop(ctx))
}

// TestManager_RecordAfterStop verifies that RecordEvent returns an error once
// the manager has been stopped rather than blocking forever or silently
// dropping events into a closed system.
func TestManager_RecordAfterStop(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	manager, err := audit.NewManager(storageManager.GetAuditStore(), "stopped-test")
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, manager.Stop(ctx))

	event := audit.NewEventBuilder().
		Tenant("stopped-tenant").
		Type(business.AuditEventConfiguration).
		Action("stopped_action").
		User("stopped-user", business.AuditUserTypeHuman).
		Resource("res", "res-1", "").
		Severity(business.AuditSeverityMedium)

	err = manager.RecordEvent(ctx, event)
	require.Error(t, err, "RecordEvent must fail after Stop")
	assert.Contains(t, err.Error(), "stopped")
}

// TestManager_ConcurrentRecordAndFlush exercises the race detector: many
// goroutines concurrently call RecordEvent while one goroutine repeatedly
// calls Flush. No deadlock or data race should occur.
func TestManager_ConcurrentRecordAndFlush(t *testing.T) {
	manager := newTestManager(t, "concurrent")
	ctx := context.Background()

	const writers = 8
	const perWriter = 50

	var wg sync.WaitGroup
	recordErrs := make(chan error, writers*perWriter)
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				event := audit.NewEventBuilder().
					Tenant("concurrent-tenant").
					Type(business.AuditEventConfiguration).
					Action("concurrent_action").
					User("concurrent-user", business.AuditUserTypeHuman).
					Resource("res", fmt.Sprintf("w%d-%d", writerID, i), "").
					Severity(business.AuditSeverityLow)
				if err := manager.RecordEvent(ctx, event); err != nil {
					recordErrs <- err
				}
			}
		}(w)
	}

	// Periodic flushes should coexist safely with record traffic.
	flushDone := make(chan struct{})
	go func() {
		defer close(flushDone)
		for i := 0; i < 5; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = manager.Flush(ctx)
			cancel()
			time.Sleep(5 * time.Millisecond)
		}
	}()

	wg.Wait()
	close(recordErrs)
	for err := range recordErrs {
		require.NoError(t, err, "background-context audit writes must not be shed under load")
	}
	<-flushDone

	// Final flush drains everything and must succeed.
	finalCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Flush(finalCtx))
}

// TestManager_FlushRespectsContextCancellation verifies that a cancelled
// context aborts a pending Flush rather than hanging.
func TestManager_FlushRespectsContextCancellation(t *testing.T) {
	// Use a very slow store (50ms per write) and a very short Flush deadline
	// (1ms) so the deadline must expire before the drain completes.
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	slow := &slowAuditStore{
		inner: storageManager.GetAuditStore(),
		delay: 50 * time.Millisecond,
	}
	manager, err := audit.NewManager(slow, "ctx-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Stop(ctx)
	})

	// Enqueue many events so the drain will take significantly longer than
	// the flush deadline.
	for i := 0; i < 20; i++ {
		event := audit.NewEventBuilder().
			Tenant("ctx-tenant").
			Type(business.AuditEventConfiguration).
			Action("ctx_action").
			User("ctx-user", business.AuditUserTypeHuman).
			Resource("res", fmt.Sprintf("res-%d", i), "").
			Severity(business.AuditSeverityMedium)
		require.NoError(t, manager.RecordEvent(context.Background(), event))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	err = manager.Flush(ctx)
	require.Error(t, err, "Flush must return when context is cancelled")
	assert.Contains(t, err.Error(), "context")
}

// TestWithSecretsStore_LoadsExistingKey verifies that WithSecretsStore loads a
// pre-existing HMAC key from the secrets store rather than generating a new one.
// Chain integrity is confirmed by recording entries and calling VerifyChain.
func TestWithSecretsStore_LoadsExistingKey(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	// Pre-populate a known 32-byte key.
	knownKey := make([]byte, 32)
	for i := range knownKey {
		knownKey[i] = byte(i + 1)
	}
	ss := newTestSecretStore()
	ss.secrets["audit/hmac-key"] = hex.EncodeToString(knownKey)

	m, err := audit.NewManager(storageManager.GetAuditStore(), "test-src", audit.WithSecretsStore(ss))
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.Stop(ctx)
	})

	// Record an entry and confirm the chain is verifiable — proving the loaded key is functional.
	ctx := context.Background()
	event := audit.NewEventBuilder().
		Tenant("hmac-load-tenant").
		Type(business.AuditEventConfiguration).
		Action("load_action").
		User("user1", business.AuditUserTypeHuman).
		Resource("resource", "res-1", "").
		Severity(business.AuditSeverityMedium)
	require.NoError(t, m.RecordEvent(ctx, event))
	flushOrFail(t, m)

	entries, err := m.QueryEntries(ctx, &business.AuditFilter{TenantID: "hmac-load-tenant"})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	breaks := m.VerifyChain(entries)
	assert.Empty(t, breaks, "chain must be intact when manager loads a pre-existing HMAC key")
}

// TestWithSecretsStore_GeneratesAndPersistsKey verifies that when no key exists
// in the secrets store, WithSecretsStore generates a new key and persists it.
func TestWithSecretsStore_GeneratesAndPersistsKey(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	ss := newTestSecretStore() // empty store — no pre-existing key

	m, err := audit.NewManager(storageManager.GetAuditStore(), "test-src", audit.WithSecretsStore(ss))
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.Stop(ctx)
	})

	// Key must have been persisted to the secrets store.
	stored, ok := ss.secrets["audit/hmac-key"]
	require.True(t, ok, "generated key must be persisted to secrets store")
	raw, decErr := hex.DecodeString(stored)
	require.NoError(t, decErr)
	assert.Len(t, raw, 32, "persisted HMAC key must be 32 bytes")

	// Record an entry and confirm the chain is verifiable — proving the generated key is functional.
	ctx := context.Background()
	event := audit.NewEventBuilder().
		Tenant("hmac-gen-tenant").
		Type(business.AuditEventConfiguration).
		Action("gen_action").
		User("user1", business.AuditUserTypeHuman).
		Resource("resource", "res-1", "").
		Severity(business.AuditSeverityMedium)
	require.NoError(t, m.RecordEvent(ctx, event))
	flushOrFail(t, m)

	entries, err := m.QueryEntries(ctx, &business.AuditFilter{TenantID: "hmac-gen-tenant"})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	breaks := m.VerifyChain(entries)
	assert.Empty(t, breaks, "chain must be intact when using a generated and persisted HMAC key")
}

// TestWithSecretsStore_StoreFailureFailsClosed verifies that an unavailable
// durable key backend prevents the Manager from starting with an ephemeral key.
func TestWithSecretsStore_StoreFailureFailsClosed(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	ss := newTestSecretStore()
	ss.storeErr = errors.New("backend unavailable")

	_, err = audit.NewManager(storageManager.GetAuditStore(), "test-src", audit.WithSecretsStore(ss))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persist audit HMAC key")
}

// TestConvenienceBuilderSeverity verifies that the predefined convenience constructors
// emit calibrated severity at the source (Issue #2964).
// The table covers all four tiers and all four AuditResult variants so that a future
// unconditional hardcode would be caught by at least one row.
func TestConvenienceBuilderSeverity(t *testing.T) {
	cases := []struct {
		name    string
		builder *audit.AuditEventBuilder
		want    business.AuditSeverity
	}{
		// AuthenticationEvent — success must be Low (routine login/registration path)
		{
			name:    "AuthenticationEvent/success → Low",
			builder: audit.AuthenticationEvent("t", "u", "web.login.success", business.AuditResultSuccess),
			want:    business.AuditSeverityLow,
		},
		// AuthenticationEvent — failure/denied must be High (ordinary auth failure)
		{
			name:    "AuthenticationEvent/failure → High",
			builder: audit.AuthenticationEvent("t", "u", "web.login.failure", business.AuditResultFailure),
			want:    business.AuditSeverityHigh,
		},
		{
			name:    "AuthenticationEvent/denied → High",
			builder: audit.AuthenticationEvent("t", "u", "web.login.lockout", business.AuditResultDenied),
			want:    business.AuditSeverityHigh,
		},
		{
			name:    "AuthenticationEvent/error → High",
			builder: audit.AuthenticationEvent("t", "u", "web.login.error", business.AuditResultError),
			want:    business.AuditSeverityHigh,
		},
		// AuthenticationEvent — Critical override: call sites for compromise indicators
		// (revoked device, invalid PoP, session hijack) must be able to override.
		{
			name: "AuthenticationEvent/success + Critical override",
			builder: audit.AuthenticationEvent("t", "u", "steward_registered", business.AuditResultSuccess).
				Severity(business.AuditSeverityCritical),
			want: business.AuditSeverityCritical,
		},
		// AuthorizationEvent — success must be Low (routine check_permission granted)
		{
			name:    "AuthorizationEvent/success → Low",
			builder: audit.AuthorizationEvent("t", "u", "permission", "read", "check_permission", business.AuditResultSuccess),
			want:    business.AuditSeverityLow,
		},
		// AuthorizationEvent — denied must be High (ordinary access denial)
		{
			name:    "AuthorizationEvent/denied → High",
			builder: audit.AuthorizationEvent("t", "u", "permission", "write", "check_permission", business.AuditResultDenied),
			want:    business.AuditSeverityHigh,
		},
		{
			name:    "AuthorizationEvent/failure → High",
			builder: audit.AuthorizationEvent("t", "u", "permission", "admin", "check_permission", business.AuditResultFailure),
			want:    business.AuditSeverityHigh,
		},
		{
			name:    "AuthorizationEvent/error → High",
			builder: audit.AuthorizationEvent("t", "u", "permission", "admin", "check_permission", business.AuditResultError),
			want:    business.AuditSeverityHigh,
		},
		// AuthorizationEvent — sensitive management actions must override to High
		{
			name: "AuthorizationEvent/grant_permission success + High override",
			builder: audit.AuthorizationEvent("t", "u", "permission", "write", "grant_permission", business.AuditResultSuccess).
				Severity(business.AuditSeverityHigh),
			want: business.AuditSeverityHigh,
		},
		// UserManagementEvent — always High (sensitive admin actions)
		{
			name:    "UserManagementEvent/success stays High",
			builder: audit.UserManagementEvent("t", "admin", "user1", "create_user"),
			want:    business.AuditSeverityHigh,
		},
		// ConfigurationEvent — Medium baseline
		{
			name:    "ConfigurationEvent stays Medium",
			builder: audit.ConfigurationEvent("t", "admin", "config", "cfg1", "settings", "update"),
			want:    business.AuditSeverityMedium,
		},
		// SystemEvent — Low (routine system lifecycle)
		{
			name:    "SystemEvent stays Low",
			builder: audit.SystemEvent("t", "controller_start", "started"),
			want:    business.AuditSeverityLow,
		},
		// Regression guard: routine success must NOT be High or Critical
		{
			name:    "AuthenticationEvent/success not High",
			builder: audit.AuthenticationEvent("t", "u", "web.login.success", business.AuditResultSuccess),
			want:    business.AuditSeverityLow, // definitively not High
		},
		{
			name:    "AuthorizationEvent/success not High",
			builder: audit.AuthorizationEvent("t", "u", "permission", "read", "check_permission", business.AuditResultSuccess),
			want:    business.AuditSeverityLow, // definitively not High
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var entry business.AuditEntry
			audit.BuildEntry(tc.builder, &entry)
			assert.Equal(t, tc.want, entry.Severity,
				"expected severity %q but got %q for %s", tc.want, entry.Severity, tc.name)
		})
	}
}

// TestConvenienceBuilderSeverityNotHighOnSuccess verifies the key regression guard:
// routine authentication and authorization successes must never emit High or Critical severity.
// This is the canonical regression test for Issue #2964.
func TestConvenienceBuilderSeverityNotHighOnSuccess(t *testing.T) {
	successes := []struct {
		name    string
		builder *audit.AuditEventBuilder
	}{
		{"web.login.success", audit.AuthenticationEvent("t", "u", "web.login.success", business.AuditResultSuccess)},
		{"web.logout", audit.AuthenticationEvent("t", "u", "web.logout", business.AuditResultSuccess)},
		{"steward_registered", audit.AuthenticationEvent("t", "s", "steward_registered", business.AuditResultSuccess)},
		{"check_permission granted", audit.AuthorizationEvent("t", "u", "permission", "read", "check_permission", business.AuditResultSuccess)},
		{"jit_access_request", audit.AuthorizationEvent("t", "u", "jit_access", "req1", "request", business.AuditResultSuccess)},
		{"jit_access_expired", audit.AuthorizationEvent("t", "u", "jit_access", "grant1", "expired", business.AuditResultSuccess)},
	}

	for _, tc := range successes {
		t.Run(tc.name, func(t *testing.T) {
			var entry business.AuditEntry
			audit.BuildEntry(tc.builder, &entry)
			if entry.Severity == business.AuditSeverityHigh || entry.Severity == business.AuditSeverityCritical {
				t.Errorf("routine success %q emits severity %q — must be Low or Medium (Issue #2964 regression)",
					tc.name, entry.Severity)
			}
		})
	}
}
