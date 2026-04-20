// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package audit

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	// Import storage providers to register them
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newTestManager creates a real audit manager backed by OSS storage in a temp dir.
func newTestManager(t *testing.T, source string) *Manager {
	t.Helper()
	tmpDir := t.TempDir()
	storageManager, err := interfaces.CreateOSSStorageManager(tmpDir+"/flatfile", tmpDir+"/cfgms.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	m, err := NewManager(storageManager.GetAuditStore(), source)
	require.NoError(t, err)
	return m
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
		Type(business.AuditEventConfiguration).
		Action("test_action").
		User("test-user", business.AuditUserTypeHuman).
		Resource("test_resource", "test-id", "Test Resource").
		Detail("test_key", "test_value").
		Severity(business.AuditSeverityMedium)

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
			Type(business.AuditEventAuthentication).
			Action("login").
			User("user1", business.AuditUserTypeHuman).
			Resource("session", "session1", "").
			Severity(business.AuditSeverityHigh),
		NewEventBuilder().
			Tenant("test-tenant").
			Type(business.AuditEventConfiguration).
			Action("config_update").
			User("user2", business.AuditUserTypeHuman).
			Resource("config", "config1", "Test Config").
			Severity(business.AuditSeverityMedium),
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
				Type(business.AuditEventConfiguration).
				Action("test_action").
				User("test-user", business.AuditUserTypeHuman).
				Resource("test_resource", "test-id", ""),
			expectedError: business.ErrTenantIDRequired,
		},
		{
			name: "missing user ID",
			event: NewEventBuilder().
				Tenant("test-tenant").
				Type(business.AuditEventConfiguration).
				Action("test_action").
				Resource("test_resource", "test-id", ""),
			expectedError: business.ErrUserIDRequired,
		},
		{
			name: "missing action",
			event: NewEventBuilder().
				Tenant("test-tenant").
				Type(business.AuditEventConfiguration).
				User("test-user", business.AuditUserTypeHuman).
				Resource("test_resource", "test-id", ""),
			expectedError: business.ErrActionRequired,
		},
		{
			name: "missing resource type",
			event: NewEventBuilder().
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
	event := NewEventBuilder().
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
	event.build(entry)

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
		event := AuthenticationEvent("tenant1", "user1", "login", business.AuditResultSuccess)
		entry := &business.AuditEntry{}
		event.build(entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, business.AuditEventAuthentication, entry.EventType)
		assert.Equal(t, "login", entry.Action)
		assert.Equal(t, "user1", entry.UserID)
		assert.Equal(t, business.AuditUserTypeHuman, entry.UserType)
		assert.Equal(t, "session", entry.ResourceType)
		assert.Equal(t, "user1", entry.ResourceID)
		assert.Equal(t, business.AuditResultSuccess, entry.Result)
		assert.Equal(t, business.AuditSeverityHigh, entry.Severity)
	})

	t.Run("AuthorizationEvent", func(t *testing.T) {
		event := AuthorizationEvent("tenant1", "user1", "config", "config1", "read", business.AuditResultDenied)
		entry := &business.AuditEntry{}
		event.build(entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, business.AuditEventAuthorization, entry.EventType)
		assert.Equal(t, "read", entry.Action)
		assert.Equal(t, "user1", entry.UserID)
		assert.Equal(t, "config", entry.ResourceType)
		assert.Equal(t, "config1", entry.ResourceID)
		assert.Equal(t, business.AuditResultDenied, entry.Result)
		assert.Equal(t, business.AuditSeverityHigh, entry.Severity)
	})

	t.Run("ConfigurationEvent", func(t *testing.T) {
		event := ConfigurationEvent("tenant1", "user1", "steward_config", "steward1", "Config1", "update")
		entry := &business.AuditEntry{}
		event.build(entry)

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
		event := SystemEvent("tenant1", "startup", "System started successfully")
		entry := &business.AuditEntry{}
		event.build(entry)

		assert.Equal(t, "tenant1", entry.TenantID)
		assert.Equal(t, business.AuditEventSystemEvent, entry.EventType)
		assert.Equal(t, "startup", entry.Action)
		assert.Equal(t, SystemUserID, entry.UserID)
		assert.Equal(t, business.AuditUserTypeSystem, entry.UserType)
		assert.Equal(t, "system", entry.ResourceType)
		assert.Equal(t, "controller", entry.ResourceID)
		assert.Equal(t, "System started successfully", entry.Details["description"])
		assert.Equal(t, business.AuditSeverityLow, entry.Severity)
	})

	t.Run("SecurityEvent", func(t *testing.T) {
		event := SecurityEvent("tenant1", "user1", "intrusion_detected", "Multiple failed login attempts", business.AuditSeverityCritical)
		entry := &business.AuditEntry{}
		event.build(entry)

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

	event := AuthenticationEvent("tenant1", "user1", "login", business.AuditResultSuccess)
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

	event := SecurityEvent(SystemTenantID, SystemUserID, "brute_force_detected", "Multiple failed auth attempts", business.AuditSeverityHigh)
	err := manager.RecordEvent(ctx, event)
	assert.NoError(t, err, "SecurityEvent must not return a validation error")
}

// TestManager_IntegrityVerification tests audit integrity verification
func TestManager_IntegrityVerification(t *testing.T) {
	manager := newTestManager(t, "test")

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

	entry.Checksum = manager.generateChecksum(entry)

	assert.True(t, manager.VerifyIntegrity(entry))

	originalAction := entry.Action
	entry.Action = "tampered_action"
	assert.False(t, manager.VerifyIntegrity(entry))

	entry.Action = originalAction
	assert.True(t, manager.VerifyIntegrity(entry))
}
