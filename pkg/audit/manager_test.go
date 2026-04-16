// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package audit

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	// Import storage providers to register them
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

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
				config := map[string]interface{}{
					"repository_path": t.TempDir(),
					"branch":          "main",
					"auto_init":       true,
				}
				storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
				if err != nil {
					return nil, err
				}
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

			// Test creating audit manager
			manager := NewManager(auditStore, "test")
			require.NotNil(t, manager)
		})
	}
}

// TestNewManager_PanicConditions tests panic conditions
func TestNewManager_PanicConditions(t *testing.T) {
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
			store:  &mockAuditStore{},
			source: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Panics(t, func() {
				NewManager(tt.store, tt.source)
			})
		})
	}
}

// TestManager_RecordEvent tests basic event recording
func TestManager_RecordEvent(t *testing.T) {
	// Setup git storage for testing
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":          "main",
		"auto_init":       true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)

	manager := NewManager(storageManager.GetAuditStore(), "test")
	ctx := context.Background()

	// Test basic event recording
	event := NewEventBuilder().
		Tenant("test-tenant").
		Type(interfaces.AuditEventConfiguration).
		Action("test_action").
		User("test-user", interfaces.AuditUserTypeHuman).
		Resource("test_resource", "test-id", "Test Resource").
		Detail("test_key", "test_value").
		Severity(interfaces.AuditSeverityMedium)

	err = manager.RecordEvent(ctx, event)
	assert.NoError(t, err)
}

// TestManager_RecordBatch tests batch event recording
func TestManager_RecordBatch(t *testing.T) {
	// Setup git storage for testing
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":          "main",
		"auto_init":       true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)

	manager := NewManager(storageManager.GetAuditStore(), "test")
	ctx := context.Background()

	// Create multiple events
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

	err = manager.RecordBatch(ctx, events)
	assert.NoError(t, err)
}

// TestManager_ValidationErrors tests validation error handling
func TestManager_ValidationErrors(t *testing.T) {
	manager := NewManager(&mockAuditStore{}, "test")
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
	// Test complete event building
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

	// Build into audit entry
	entry := &interfaces.AuditEntry{}
	event.build(entry)

	// Validate all fields are set correctly
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
		assert.Equal(t, "system", entry.UserID)
		assert.Equal(t, interfaces.AuditUserTypeSystem, entry.UserType)
		assert.Equal(t, "system", entry.ResourceType)
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
		assert.Equal(t, "Multiple failed login attempts", entry.Details["description"])
		assert.Equal(t, interfaces.AuditSeverityCritical, entry.Severity)
	})
}

// TestManager_IntegrityVerification tests audit integrity verification
func TestManager_IntegrityVerification(t *testing.T) {
	manager := NewManager(&mockAuditStore{}, "test")

	// Create a test entry
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

	// Generate checksum
	entry.Checksum = manager.generateChecksum(entry)

	// Verify integrity (should pass)
	assert.True(t, manager.VerifyIntegrity(entry))

	// Tamper with the entry
	originalAction := entry.Action
	entry.Action = "tampered_action"

	// Verify integrity (should fail)
	assert.False(t, manager.VerifyIntegrity(entry))

	// Restore original action
	entry.Action = originalAction

	// Verify integrity (should pass again)
	assert.True(t, manager.VerifyIntegrity(entry))
}

// mockAuditStore is a simple mock implementation for testing
type mockAuditStore struct {
	entries map[string]*interfaces.AuditEntry
}

func (m *mockAuditStore) StoreAuditEntry(ctx context.Context, entry *interfaces.AuditEntry) error {
	if m.entries == nil {
		m.entries = make(map[string]*interfaces.AuditEntry)
	}
	m.entries[entry.ID] = entry
	return nil
}

func (m *mockAuditStore) GetAuditEntry(ctx context.Context, id string) (*interfaces.AuditEntry, error) {
	if m.entries == nil {
		return nil, interfaces.ErrAuditNotFound
	}
	entry, ok := m.entries[id]
	if !ok {
		return nil, interfaces.ErrAuditNotFound
	}
	return entry, nil
}

func (m *mockAuditStore) ListAuditEntries(ctx context.Context, filter *interfaces.AuditFilter) ([]*interfaces.AuditEntry, error) {
	if m.entries == nil {
		return []*interfaces.AuditEntry{}, nil
	}

	result := make([]*interfaces.AuditEntry, 0, len(m.entries))
	for _, entry := range m.entries {
		result = append(result, entry)
	}
	return result, nil
}

func (m *mockAuditStore) StoreAuditBatch(ctx context.Context, entries []*interfaces.AuditEntry) error {
	for _, entry := range entries {
		if err := m.StoreAuditEntry(ctx, entry); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockAuditStore) GetAuditsByUser(ctx context.Context, userID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	return []*interfaces.AuditEntry{}, nil
}

func (m *mockAuditStore) GetAuditsByResource(ctx context.Context, resourceType, resourceID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	return []*interfaces.AuditEntry{}, nil
}

func (m *mockAuditStore) GetAuditsByAction(ctx context.Context, action string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	return []*interfaces.AuditEntry{}, nil
}

func (m *mockAuditStore) GetFailedActions(ctx context.Context, timeRange *interfaces.TimeRange, limit int) ([]*interfaces.AuditEntry, error) {
	return []*interfaces.AuditEntry{}, nil
}

func (m *mockAuditStore) GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *interfaces.TimeRange) ([]*interfaces.AuditEntry, error) {
	return []*interfaces.AuditEntry{}, nil
}

func (m *mockAuditStore) GetAuditStats(ctx context.Context) (*interfaces.AuditStats, error) {
	return &interfaces.AuditStats{
		TotalEntries: int64(len(m.entries)),
		LastUpdated:  time.Now(),
	}, nil
}

func (m *mockAuditStore) ArchiveAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	return 0, nil
}

func (m *mockAuditStore) PurgeAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error) {
	return 0, nil
}

func (m *mockAuditStore) Close() error {
	return nil
}
