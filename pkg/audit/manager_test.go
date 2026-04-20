// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package audit

import (
	"context"
	"testing"
	"time"

<<<<<<< HEAD
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"

=======
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

>>>>>>> 588859d (controller: remove nine debug fmt.Printf lines (Issue #789))
	// Import storage providers to register them
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

// TestRedactMap verifies that redactMap replaces sensitive key values with [REDACTED]
// and leaves innocuous keys unchanged.
func TestRedactMap(t *testing.T) {
	input := map[string]interface{}{
		"password":    "hunter2",
		"api_token":   "tok_abc123",
		"some_secret": "s3cr3t",
		"user_count":  42,
		"enabled":     true,
		"username":    "alice",
	}

	result := redactMap(input)

	assert.Equal(t, "[REDACTED]", result["password"], "password should be redacted")
	assert.Equal(t, "[REDACTED]", result["api_token"], "api_token should be redacted")
	assert.Equal(t, "[REDACTED]", result["some_secret"], "some_secret should be redacted")
	assert.Equal(t, 42, result["user_count"], "user_count should not be redacted")
	assert.Equal(t, true, result["enabled"], "bool values should not be redacted")
	assert.Equal(t, "alice", result["username"], "username should not be redacted")

	// Verify original map is not mutated
	assert.Equal(t, "hunter2", input["password"], "original map must not be mutated")
}

// TestRedactMap_NilAndEmpty verifies edge cases for redactMap.
func TestRedactMap_NilAndEmpty(t *testing.T) {
	assert.Nil(t, redactMap(nil))
	assert.Empty(t, redactMap(map[string]interface{}{}))
}

// TestRedactMap_CaseInsensitive verifies that key matching is case-insensitive.
func TestRedactMap_CaseInsensitive(t *testing.T) {
	input := map[string]interface{}{
		"Password":     "secret1",
		"API_KEY":      "secret2",
		"X-Auth-Token": "secret3",
		"Username":     "alice",
	}

	result := redactMap(input)

	assert.Equal(t, "[REDACTED]", result["Password"], "Password (mixed case) should be redacted")
	assert.Equal(t, "[REDACTED]", result["API_KEY"], "API_KEY (uppercase) should be redacted")
	assert.Equal(t, "[REDACTED]", result["X-Auth-Token"], "X-Auth-Token should be redacted")
	assert.Equal(t, "alice", result["Username"], "Username should not be redacted")
}

// TestRedactMap_NonStringOnSensitiveKey verifies that non-string values under sensitive keys
// pass through unredacted (only string values are replaced).
func TestRedactMap_NonStringOnSensitiveKey(t *testing.T) {
	input := map[string]interface{}{
		"password":    12345,
		"token_count": true,
		"auth_level":  3.14,
	}

	result := redactMap(input)

	// Non-string values pass through — only string values are candidates for redaction
	assert.Equal(t, 12345, result["password"], "integer under sensitive key must pass through")
	assert.Equal(t, true, result["token_count"], "bool under sensitive key must pass through")
	assert.Equal(t, 3.14, result["auth_level"], "float under sensitive key must pass through")
}

// TestRedactErrorMessage verifies the direct output of redactErrorMessage.
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
			result := redactErrorMessage(tt.input)
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

	event := NewEventBuilder().
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

	event := NewEventBuilder().
		Tenant("test-tenant").
		Type(business.AuditEventConfiguration).
		Action("update_credentials").
		User("admin", business.AuditUserTypeHuman).
		Resource("user", "alice", "Alice").
		Changes(before, after, []string{"password", "username", "token"}).
		Severity(business.AuditSeverityHigh)

	err := manager.RecordEvent(ctx, event)
	require.NoError(t, err)

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

	event := NewEventBuilder().
		Tenant("test-tenant").
		Type(business.AuditEventAuthentication).
		Action("login").
		User("user1", business.AuditUserTypeHuman).
		Resource("session", "user1", "").
		Error("AUTH_FAILED", "login failed: password=hunter2, username=alice").
		Severity(business.AuditSeverityHigh)

	err := manager.RecordEvent(ctx, event)
	require.NoError(t, err)

	entries, err := manager.QueryEntries(ctx, &business.AuditFilter{
		TenantID: "test-tenant",
	})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	assert.NotContains(t, entries[0].ErrorMessage, "hunter2", "raw secret must not appear in stored ErrorMessage")
	assert.Contains(t, entries[0].ErrorMessage, "password=[REDACTED]", "password value must be replaced with [REDACTED]")
	assert.Contains(t, entries[0].ErrorMessage, "username=alice", "non-sensitive key=value must be preserved")
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
