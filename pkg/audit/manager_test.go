// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package audit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	// Import storage providers to register them
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newTestManager creates a real audit manager backed by OSS storage in a temp dir.
// It registers a cleanup to call Stop so background goroutines do not leak.
func newTestManager(t *testing.T, source string) *Manager {
	t.Helper()
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	m, err := NewManager(storageManager.GetAuditStore(), source)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.Stop(ctx)
	})
	return m
}

// slowAuditStore wraps a real AuditStore and adds a configurable delay to
// StoreAuditEntry so tests can verify Flush waits for completion.
type slowAuditStore struct {
	interfaces.AuditStore
	delay time.Duration
	mu    sync.Mutex
	count int
}

func (s *slowAuditStore) StoreAuditEntry(ctx context.Context, entry *interfaces.AuditEntry) error {
	time.Sleep(s.delay)
	err := s.AuditStore.StoreAuditEntry(ctx, entry)
	if err == nil {
		s.mu.Lock()
		s.count++
		s.mu.Unlock()
	}
	return err
}

func (s *slowAuditStore) stored() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// holdAuditStore blocks every StoreAuditEntry call until release is closed.
// ready receives a signal when the first call blocks, allowing the test to
// deterministically fill the queue before releasing.
type holdAuditStore struct {
	interfaces.AuditStore
	ready   chan struct{}
	release chan struct{}
}

func (s *holdAuditStore) StoreAuditEntry(ctx context.Context, entry *interfaces.AuditEntry) error {
	select {
	case s.ready <- struct{}{}:
	default:
	}
	<-s.release
	return s.AuditStore.StoreAuditEntry(ctx, entry)
}

// TestNewManager tests audit manager creation
func TestNewManager(t *testing.T) {
	tests := []struct {
		name         string
		setupStorage func(t *testing.T) (interfaces.AuditStore, error)
		wantErr      bool
	}{
		{
			name: "with git storage provider",
			setupStorage: func(t *testing.T) (interfaces.AuditStore, error) {
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

			manager, err := NewManager(auditStore, "test")
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
		store  interfaces.AuditStore
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
			m, err := NewManager(tt.store, tt.source)
			assert.Error(t, err)
			assert.Nil(t, m)
		})
	}
}

// TestManager_RecordEvent tests basic event recording
func TestManager_RecordEvent(t *testing.T) {
	manager := newTestManager(t, "test")
	ctx := context.Background()

	event := NewEventBuilder().
		Tenant("test-tenant").
		Type(interfaces.AuditEventConfiguration).
		Action("test_action").
		User("test-user", interfaces.AuditUserTypeHuman).
		Resource("test_resource", "test-id", "Test Resource").
		Detail("test_key", "test_value").
		Severity(interfaces.AuditSeverityMedium)

	err := manager.RecordEvent(ctx, event)
	assert.NoError(t, err)
}

// TestManager_RecordBatch tests batch event recording
func TestManager_RecordBatch(t *testing.T) {
	manager := newTestManager(t, "test")
	ctx := context.Background()

	events := []*AuditEventBuilder{
		NewEventBuilder().
			Tenant("test-tenant").
			Type(interfaces.AuditEventAuthentication).
			Action("login").
			User("user1", interfaces.AuditUserTypeHuman).
			Resource("session", "session1", "").
			Severity(interfaces.AuditSeverityHigh),
		NewEventBuilder().
			Tenant("test-tenant").
			Type(interfaces.AuditEventConfiguration).
			Action("config_update").
			User("user2", interfaces.AuditUserTypeHuman).
			Resource("config", "config1", "Test Config").
			Severity(interfaces.AuditSeverityMedium),
	}

	err := manager.RecordBatch(ctx, events)
	assert.NoError(t, err)
}

// TestManager_ValidationErrors tests validation error handling
func TestManager_ValidationErrors(t *testing.T) {
	manager := newTestManager(t, "test")
	ctx := context.Background()

	tests := []struct {
		name          string
		event         *AuditEventBuilder
		expectedError error
	}{
		{
			name: "missing tenant ID",
			event: NewEventBuilder().
				Type(interfaces.AuditEventConfiguration).
				Action("test_action").
				User("test-user", interfaces.AuditUserTypeHuman).
				Resource("test_resource", "test-id", ""),
			expectedError: interfaces.ErrTenantIDRequired,
		},
		{
			name: "missing user ID",
			event: NewEventBuilder().
				Tenant("test-tenant").
				Type(interfaces.AuditEventConfiguration).
				Action("test_action").
				Resource("test_resource", "test-id", ""),
			expectedError: interfaces.ErrUserIDRequired,
		},
		{
			name: "missing action",
			event: NewEventBuilder().
				Tenant("test-tenant").
				Type(interfaces.AuditEventConfiguration).
				User("test-user", interfaces.AuditUserTypeHuman).
				Resource("test_resource", "test-id", ""),
			expectedError: interfaces.ErrActionRequired,
		},
		{
			name: "missing resource type",
			event: NewEventBuilder().
				Tenant("test-tenant").
				Type(interfaces.AuditEventConfiguration).
				Action("test_action").
				User("test-user", interfaces.AuditUserTypeHuman),
			expectedError: interfaces.ErrResourceTypeRequired,
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
	event := NewEventBuilder().
		Tenant("test-tenant").
		Type(interfaces.AuditEventAuthentication).
		Action("login").
		User("test-user", interfaces.AuditUserTypeHuman).
		Session("session123").
		Resource("session", "session123", "User Session").
		Result(interfaces.AuditResultSuccess).
		Request("req123", "POST", "/api/login", "192.168.1.1", "TestAgent/1.0").
		Detail("login_method", "password").
		Detail("mfa_used", true).
		Tag("security").
		Tag("authentication").
		Severity(interfaces.AuditSeverityHigh)

	entry := &interfaces.AuditEntry{}
	event.build(entry)

	assert.Equal(t, "test-tenant", entry.TenantID)
	assert.Equal(t, interfaces.AuditEventAuthentication, entry.EventType)
	assert.Equal(t, "login", entry.Action)
	assert.Equal(t, "test-user", entry.UserID)
	assert.Equal(t, interfaces.AuditUserTypeHuman, entry.UserType)
	assert.Equal(t, "session123", entry.SessionID)
	assert.Equal(t, "session", entry.ResourceType)
	assert.Equal(t, "session123", entry.ResourceID)
	assert.Equal(t, "User Session", entry.ResourceName)
	assert.Equal(t, interfaces.AuditResultSuccess, entry.Result)
	assert.Equal(t, "req123", entry.RequestID)
	assert.Equal(t, "POST", entry.Method)
	assert.Equal(t, "/api/login", entry.Path)
	assert.Equal(t, "192.168.1.1", entry.IPAddress)
	assert.Equal(t, "TestAgent/1.0", entry.UserAgent)
	assert.Equal(t, "password", entry.Details["login_method"])
	assert.Equal(t, true, entry.Details["mfa_used"])
	assert.Contains(t, entry.Tags, "security")
	assert.Contains(t, entry.Tags, "authentication")
	assert.Equal(t, interfaces.AuditSeverityHigh, entry.Severity)
}

// TestPredefinedEventBuilders tests predefined event builder functions
func TestPredefinedEventBuilders(t *testing.T) {
	t.Run("AuthenticationEvent", func(t *testing.T) {
		event := AuthenticationEvent("tenant1", "user1", "login", interfaces.AuditResultSuccess)
		entry := &interfaces.AuditEntry{}
		event.build(entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, interfaces.AuditEventAuthentication, entry.EventType)
		assert.Equal(t, "login", entry.Action)
		assert.Equal(t, "user1", entry.UserID)
		assert.Equal(t, interfaces.AuditUserTypeHuman, entry.UserType)
		assert.Equal(t, "session", entry.ResourceType)
		assert.Equal(t, "user1", entry.ResourceID)
		assert.Equal(t, interfaces.AuditResultSuccess, entry.Result)
		assert.Equal(t, interfaces.AuditSeverityHigh, entry.Severity)
	})

	t.Run("AuthorizationEvent", func(t *testing.T) {
		event := AuthorizationEvent("tenant1", "user1", "config", "config1", "read", interfaces.AuditResultDenied)
		entry := &interfaces.AuditEntry{}
		event.build(entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, interfaces.AuditEventAuthorization, entry.EventType)
		assert.Equal(t, "read", entry.Action)
		assert.Equal(t, "user1", entry.UserID)
		assert.Equal(t, "config", entry.ResourceType)
		assert.Equal(t, "config1", entry.ResourceID)
		assert.Equal(t, interfaces.AuditResultDenied, entry.Result)
		assert.Equal(t, interfaces.AuditSeverityHigh, entry.Severity)
	})

	t.Run("ConfigurationEvent", func(t *testing.T) {
		event := ConfigurationEvent("tenant1", "user1", "steward_config", "steward1", "Config1", "update")
		entry := &interfaces.AuditEntry{}
		event.build(entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, interfaces.AuditEventConfiguration, entry.EventType)
		assert.Equal(t, "update", entry.Action)
		assert.Equal(t, "user1", entry.UserID)
		assert.Equal(t, "steward_config", entry.ResourceType)
		assert.Equal(t, "steward1", entry.ResourceID)
		assert.Equal(t, "Config1", entry.ResourceName)
		assert.Equal(t, interfaces.AuditSeverityMedium, entry.Severity)
	})

	t.Run("SystemEvent", func(t *testing.T) {
		event := SystemEvent("tenant1", "startup", "System started successfully")
		entry := &interfaces.AuditEntry{}
		event.build(entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, interfaces.AuditEventSystemEvent, entry.EventType)
		assert.Equal(t, "startup", entry.Action)
		assert.Equal(t, SystemUserID, entry.UserID)
		assert.Equal(t, interfaces.AuditUserTypeSystem, entry.UserType)
		assert.Equal(t, "system", entry.ResourceType)
		assert.Equal(t, "controller", entry.ResourceID)
		assert.Equal(t, "System started successfully", entry.Details["description"])
		assert.Equal(t, interfaces.AuditSeverityLow, entry.Severity)
	})

	t.Run("SecurityEvent", func(t *testing.T) {
		event := SecurityEvent("tenant1", "user1", "intrusion_detected", "Multiple failed login attempts", interfaces.AuditSeverityCritical)
		entry := &interfaces.AuditEntry{}
		event.build(entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, interfaces.AuditEventSecurityEvent, entry.EventType)
		assert.Equal(t, "intrusion_detected", entry.Action)
		assert.Equal(t, "user1", entry.UserID)
		assert.Equal(t, "security", entry.ResourceType)
		assert.Equal(t, "user1", entry.ResourceID)
		assert.Equal(t, "Multiple failed login attempts", entry.Details["description"])
		assert.Equal(t, interfaces.AuditSeverityCritical, entry.Severity)
	})
}

// TestAuthenticationEvent_Persists verifies AuthenticationEvent produces an entry that passes
// validateEntry and is successfully stored via RecordEvent.
func TestAuthenticationEvent_Persists(t *testing.T) {
	manager := newTestManager(t, "controller")
	ctx := context.Background()

	event := AuthenticationEvent("tenant1", "user1", "login", interfaces.AuditResultSuccess)
	err := manager.RecordEvent(ctx, event)
	assert.NoError(t, err, "AuthenticationEvent must not return a validation error")
}

// TestSystemEvent_Persists verifies SystemEvent produces an entry that passes validateEntry
// and is successfully stored via RecordEvent.
func TestSystemEvent_Persists(t *testing.T) {
	manager := newTestManager(t, "controller")
	ctx := context.Background()

	event := SystemEvent(SystemTenantID, "startup", "Controller started")
	err := manager.RecordEvent(ctx, event)
	assert.NoError(t, err, "SystemEvent must not return a validation error")
}

// TestSecurityEvent_Persists verifies SecurityEvent produces an entry that passes validateEntry
// and is successfully stored via RecordEvent.
func TestSecurityEvent_Persists(t *testing.T) {
	manager := newTestManager(t, "controller")
	ctx := context.Background()

	event := SecurityEvent(SystemTenantID, SystemUserID, "brute_force_detected", "Multiple failed auth attempts", interfaces.AuditSeverityHigh)
	err := manager.RecordEvent(ctx, event)
	assert.NoError(t, err, "SecurityEvent must not return a validation error")
}

// TestManager_IntegrityVerification tests audit integrity verification
func TestManager_IntegrityVerification(t *testing.T) {
	manager := newTestManager(t, "test")

	entry := &interfaces.AuditEntry{
		ID:           "test-id",
		TenantID:     "test-tenant",
		Timestamp:    time.Now().UTC(),
		EventType:    interfaces.AuditEventConfiguration,
		Action:       "test_action",
		UserID:       "test-user",
		UserType:     interfaces.AuditUserTypeHuman,
		ResourceType: "test_resource",
		ResourceID:   "test-id",
		Result:       interfaces.AuditResultSuccess,
		Severity:     interfaces.AuditSeverityMedium,
		Source:       "test",
		Version:      "1.0",
	}

	entry.Checksum = manager.generateChecksum(entry)

	assert.True(t, manager.VerifyIntegrity(entry))

	originalAction := entry.Action
	entry.Action = "tampered_action"
	assert.False(t, manager.VerifyIntegrity(entry))

	entry.Action = originalAction
	assert.True(t, manager.VerifyIntegrity(entry))
}

// TestManager_Flush verifies that after Flush returns, all previously recorded
// events are queryable from the real store.
func TestManager_Flush(t *testing.T) {
	manager := newTestManager(t, "test-flush")
	ctx := context.Background()

	const n = 20
	for i := 0; i < n; i++ {
		event := NewEventBuilder().
			Tenant("test-tenant").
			Type(interfaces.AuditEventConfiguration).
			Action("flush_test").
			User("test-user", interfaces.AuditUserTypeHuman).
			Resource("resource", "res-id", "Res")
		err := manager.RecordEvent(ctx, event)
		require.NoError(t, err)
	}

	flushCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Flush(flushCtx), "Flush must not return error")

	entries, err := manager.QueryEntries(ctx, &interfaces.AuditFilter{Actions: []string{"flush_test"}})
	require.NoError(t, err)
	assert.Len(t, entries, n, "all %d events must be in the store after Flush", n)
}

// TestManager_ShutdownOrderGuarantee verifies that Flush waits for a slow store
// to finish writing before returning, rather than dropping in-flight entries.
func TestManager_ShutdownOrderGuarantee(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	slow := &slowAuditStore{
		AuditStore: storageManager.GetAuditStore(),
		delay:      20 * time.Millisecond,
	}

	manager, err := NewManager(slow, "test-slow")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = manager.Stop(ctx)
	})

	ctx := context.Background()
	const n = 5
	for i := 0; i < n; i++ {
		event := NewEventBuilder().
			Tenant("test-tenant").
			Type(interfaces.AuditEventConfiguration).
			Action("slow_test").
			User("test-user", interfaces.AuditUserTypeHuman).
			Resource("resource", "res-id", "Res")
		require.NoError(t, manager.RecordEvent(ctx, event))
	}

	flushCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	require.NoError(t, manager.Flush(flushCtx))

	// After Flush returns, all entries must have been persisted.
	assert.Equal(t, n, slow.stored(), "Flush must wait for all slow-store writes to complete")
}

// TestManager_StopIsIdempotent verifies that calling Stop multiple times is safe.
func TestManager_StopIsIdempotent(t *testing.T) {
	manager := newTestManager(t, "test-idempotent")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, manager.Stop(ctx))
	require.NoError(t, manager.Stop(ctx)) // second call must not panic or error
}

// TestManager_RecordEventAfterStop verifies that RecordEvent returns an error
// when called after the manager has been stopped.
func TestManager_RecordEventAfterStop(t *testing.T) {
	manager := newTestManager(t, "test-after-stop")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, manager.Stop(ctx))

	event := NewEventBuilder().
		Tenant("test-tenant").
		Type(interfaces.AuditEventConfiguration).
		Action("post_stop").
		User("test-user", interfaces.AuditUserTypeHuman).
		Resource("resource", "res-id", "Res")
	err := manager.RecordEvent(context.Background(), event)
	assert.ErrorIs(t, err, errManagerStopped)
}

// TestManager_QueueFull verifies that RecordEvent returns errQueueFull when the
// internal write queue is at capacity, without blocking the caller.
func TestManager_QueueFull(t *testing.T) {
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)

	release := make(chan struct{})
	hold := &holdAuditStore{
		AuditStore: storageManager.GetAuditStore(),
		ready:      make(chan struct{}, 1),
		release:    release,
	}

	manager, err := NewManager(hold, "test-full")
	require.NoError(t, err)
	t.Cleanup(func() {
		// Unblock store so Stop/Flush can complete.
		select {
		case <-release:
		default:
			close(release)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Stop(ctx)
		_ = storageManager.Close()
	})

	ctx := context.Background()
	newEvent := func() *AuditEventBuilder {
		return NewEventBuilder().
			Tenant("test-tenant").
			Type(interfaces.AuditEventConfiguration).
			Action("queue_full_test").
			User("test-user", interfaces.AuditUserTypeHuman).
			Resource("resource", "res-id", "Res")
	}

	// The drain loop takes the first entry and blocks inside StoreAuditEntry.
	require.NoError(t, manager.RecordEvent(ctx, newEvent()))

	// Wait until the drain loop is confirmed blocked.
	select {
	case <-hold.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("drain loop did not block within timeout")
	}

	// Fill the queue buffer to capacity — all enqueues must succeed.
	for i := 0; i < defaultQueueCapacity; i++ {
		require.NoError(t, manager.RecordEvent(ctx, newEvent()), "entry %d must fit in queue", i)
	}

	// The next entry overflows the queue and must return errQueueFull.
	err = manager.RecordEvent(ctx, newEvent())
	assert.ErrorIs(t, err, errQueueFull, "RecordEvent must return errQueueFull when queue is full")
}
