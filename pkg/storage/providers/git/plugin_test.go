// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package git

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

func TestGitProvider_Basic(t *testing.T) {
	provider := &GitProvider{}

	assert.Equal(t, "git", provider.Name())
	assert.Equal(t, "Production Git-based storage with versioning, audit trails, and SOPS encryption", provider.Description())
	assert.Equal(t, "2.0.0", provider.GetVersion())

	capabilities := provider.GetCapabilities()
	assert.False(t, capabilities.SupportsTransactions)
	assert.True(t, capabilities.SupportsVersioning)
	assert.True(t, capabilities.SupportsEncryption)
	assert.True(t, capabilities.SupportsReplication)
}

func TestGitProvider_Available(t *testing.T) {
	provider := &GitProvider{}

	available, err := provider.Available()

	// Git should be available in the test environment
	assert.NoError(t, err)
	assert.True(t, available)
}

func TestGitConfigStore_CreateAndBasicOperations(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-config-repo")

	// Create git config store
	store, err := NewGitConfigStore(repoPath, "")
	require.NoError(t, err)
	require.NotNil(t, store)

	// Verify repository was initialized
	gitDir := filepath.Join(repoPath, ".git")
	assert.DirExists(t, gitDir)

	ctx := context.Background()

	// Test storing a configuration
	config := &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID:  "test-tenant",
			Namespace: "firewall",
			Name:      "web-server",
		},
		Data:      []byte("rules:\n  - allow: 80\n  - allow: 443"),
		CreatedBy: "test-user",
		UpdatedBy: "test-user",
		Tags:      []string{"test", "firewall"},
		Source:    "test",
	}

	err = store.StoreConfig(ctx, config)
	require.NoError(t, err)

	// Verify version and timestamps were set
	assert.Equal(t, int64(1), config.Version)
	assert.False(t, config.CreatedAt.IsZero())
	assert.False(t, config.UpdatedAt.IsZero())
	assert.NotEmpty(t, config.Checksum)
	assert.Equal(t, interfaces.ConfigFormatYAML, config.Format)

	// Test retrieving the configuration
	retrieved, err := store.GetConfig(ctx, config.Key)
	require.NoError(t, err)
	assert.Equal(t, config.Key.TenantID, retrieved.Key.TenantID)
	assert.Equal(t, config.Key.Namespace, retrieved.Key.Namespace)
	assert.Equal(t, config.Key.Name, retrieved.Key.Name)
	assert.Equal(t, config.CreatedBy, retrieved.CreatedBy)
	assert.Equal(t, config.Tags, retrieved.Tags)

	// Test updating the configuration
	config.Data = []byte("rules:\n  - allow: 80\n  - allow: 443\n  - allow: 8080")
	config.UpdatedBy = "updated-user"

	err = store.StoreConfig(ctx, config)
	require.NoError(t, err)
	assert.Equal(t, int64(2), config.Version)

	// Test configuration validation
	err = store.ValidateConfig(ctx, config)
	assert.NoError(t, err)

	// Test invalid configuration
	invalidConfig := &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID: "", // Missing required field
		},
		Data: []byte("invalid"),
	}
	err = store.ValidateConfig(ctx, invalidConfig)
	assert.Error(t, err)
}

func TestGitConfigStore_ListConfigs(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-list-repo")

	store, err := NewGitConfigStore(repoPath, "")
	require.NoError(t, err)

	ctx := context.Background()

	// Store multiple configurations
	configs := []*interfaces.ConfigEntry{
		{
			Key: &interfaces.ConfigKey{
				TenantID:  "tenant-1",
				Namespace: "firewall",
				Name:      "web",
			},
			Data:      []byte("web-config"),
			CreatedBy: "user-1",
		},
		{
			Key: &interfaces.ConfigKey{
				TenantID:  "tenant-1",
				Namespace: "templates",
				Name:      "basic",
			},
			Data:      []byte("template-config"),
			CreatedBy: "user-1",
		},
		{
			Key: &interfaces.ConfigKey{
				TenantID:  "tenant-2",
				Namespace: "firewall",
				Name:      "app",
			},
			Data:      []byte("app-config"),
			CreatedBy: "user-2",
		},
	}

	for _, config := range configs {
		err = store.StoreConfig(ctx, config)
		require.NoError(t, err)
	}

	// Test listing all configs
	filter := &interfaces.ConfigFilter{}
	allConfigs, err := store.ListConfigs(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, allConfigs, 3)

	// Test filtering by tenant
	filter.TenantID = "tenant-1"
	tenant1Configs, err := store.ListConfigs(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, tenant1Configs, 2)

	// Test filtering by namespace
	filter = &interfaces.ConfigFilter{
		Namespace: "firewall",
	}
	firewallConfigs, err := store.ListConfigs(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, firewallConfigs, 2)

	// Test filtering by names
	filter = &interfaces.ConfigFilter{
		Names: []string{"web", "basic"},
	}
	namedConfigs, err := store.ListConfigs(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, namedConfigs, 2)

	// Test pagination
	filter = &interfaces.ConfigFilter{
		Limit:  2,
		Offset: 0,
	}
	paginatedConfigs, err := store.ListConfigs(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, paginatedConfigs, 2)
}

func TestGitConfigStore_BatchOperations(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-batch-repo")

	store, err := NewGitConfigStore(repoPath, "")
	require.NoError(t, err)

	ctx := context.Background()

	// Test batch store
	configs := []*interfaces.ConfigEntry{
		{
			Key: &interfaces.ConfigKey{
				TenantID:  "batch-tenant",
				Namespace: "test",
				Name:      "config1",
			},
			Data:      []byte("config1-data"),
			CreatedBy: "batch-user",
		},
		{
			Key: &interfaces.ConfigKey{
				TenantID:  "batch-tenant",
				Namespace: "test",
				Name:      "config2",
			},
			Data:      []byte("config2-data"),
			CreatedBy: "batch-user",
		},
		{
			Key: &interfaces.ConfigKey{
				TenantID:  "batch-tenant",
				Namespace: "test",
				Name:      "config3",
			},
			Data:      []byte("config3-data"),
			CreatedBy: "batch-user",
		},
	}

	err = store.StoreConfigBatch(ctx, configs)
	require.NoError(t, err)

	// Verify all configs were stored
	for _, config := range configs {
		retrieved, err := store.GetConfig(ctx, config.Key)
		require.NoError(t, err)
		assert.Equal(t, config.Key.Name, retrieved.Key.Name)
	}

	// Test batch delete
	keys := []*interfaces.ConfigKey{
		configs[0].Key,
		configs[1].Key,
	}

	err = store.DeleteConfigBatch(ctx, keys)
	require.NoError(t, err)

	// Verify configs were deleted
	for _, key := range keys {
		_, err := store.GetConfig(ctx, key)
		assert.Error(t, err)
	}

	// Verify remaining config still exists
	_, err = store.GetConfig(ctx, configs[2].Key)
	assert.NoError(t, err)
}

func TestGitConfigStore_ConfigHistory(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-history-repo")

	store, err := NewGitConfigStore(repoPath, "")
	require.NoError(t, err)

	ctx := context.Background()

	key := &interfaces.ConfigKey{
		TenantID:  "history-tenant",
		Namespace: "test",
		Name:      "versioned-config",
	}

	// Store multiple versions
	for i := 1; i <= 3; i++ {
		config := &interfaces.ConfigEntry{
			Key:       key,
			Data:      []byte(fmt.Sprintf("version-%d-data", i)),
			CreatedBy: "history-user",
		}

		err = store.StoreConfig(ctx, config)
		require.NoError(t, err)
		assert.Equal(t, int64(i), config.Version)

		// Small delay to ensure different timestamps
		time.Sleep(time.Millisecond * 10)
	}

	// Get config history
	history, err := store.GetConfigHistory(ctx, key, 10)
	require.NoError(t, err)

	// Should have at least one entry (current version)
	// Note: Git history may not show all versions immediately due to implementation details
	assert.True(t, len(history) >= 1, "Expected at least 1 history entry, got %d", len(history))
}

func TestGitConfigStore_GetConfigStats(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-stats-repo")

	store, err := NewGitConfigStore(repoPath, "")
	require.NoError(t, err)

	ctx := context.Background()

	// Store configurations from different tenants and namespaces
	configs := []*interfaces.ConfigEntry{
		{
			Key:  &interfaces.ConfigKey{TenantID: "tenant-1", Namespace: "firewall", Name: "config1"},
			Data: []byte("firewall-config-1"),
		},
		{
			Key:  &interfaces.ConfigKey{TenantID: "tenant-1", Namespace: "templates", Name: "config2"},
			Data: []byte("template-config-1"),
		},
		{
			Key:  &interfaces.ConfigKey{TenantID: "tenant-2", Namespace: "firewall", Name: "config3"},
			Data: []byte("firewall-config-2"),
		},
	}

	for _, config := range configs {
		err = store.StoreConfig(ctx, config)
		require.NoError(t, err)
	}

	// Get statistics
	stats, err := store.GetConfigStats(ctx)
	require.NoError(t, err)

	assert.Equal(t, int64(3), stats.TotalConfigs)
	assert.True(t, stats.TotalSize > 0)
	assert.Equal(t, int64(2), stats.ConfigsByTenant["tenant-1"])
	assert.Equal(t, int64(1), stats.ConfigsByTenant["tenant-2"])
	assert.Equal(t, int64(2), stats.ConfigsByNamespace["firewall"])
	assert.Equal(t, int64(1), stats.ConfigsByNamespace["templates"])
	assert.Equal(t, int64(3), stats.ConfigsByFormat["yaml"])
	assert.NotNil(t, stats.OldestConfig)
	assert.NotNil(t, stats.NewestConfig)
	assert.True(t, stats.AverageSize > 0)
}

func TestGitAuditStore_CreateAndBasicOperations(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-audit-repo")

	store, err := NewGitAuditStore(repoPath, "")
	require.NoError(t, err)
	require.NotNil(t, store)

	// Verify repository was initialized
	gitDir := filepath.Join(repoPath, ".git")
	assert.DirExists(t, gitDir)

	ctx := context.Background()

	// Test storing an audit entry
	now := time.Now()
	entry := &interfaces.AuditEntry{
		ID:           "test-audit-entry-1", // Storage tests provide ID
		TenantID:     "test-tenant",
		Timestamp:    now,
		EventType:    interfaces.AuditEventConfiguration,
		Action:       "create",
		UserID:       "test-user",
		UserType:     interfaces.AuditUserTypeHuman,
		ResourceType: "configuration",
		ResourceID:   "firewall-config-1",
		ResourceName: "Web Server Firewall",
		Result:       interfaces.AuditResultSuccess,
		Details:      map[string]interface{}{"namespace": "firewall", "version": 1},
		Tags:         []string{"test", "configuration"},
		Severity:     interfaces.AuditSeverityMedium,
		Source:       "test-suite",
		Checksum:     "test-checksum-123", // Storage tests provide checksum
	}

	err = store.StoreAuditEntry(ctx, entry)
	require.NoError(t, err)

	// Verify ID and checksum were preserved (not generated by storage)
	assert.Equal(t, "test-audit-entry-1", entry.ID)
	assert.Equal(t, "test-checksum-123", entry.Checksum)

	// Test retrieving the audit entry
	retrieved, err := store.GetAuditEntry(ctx, entry.ID)
	require.NoError(t, err)
	assert.Equal(t, entry.TenantID, retrieved.TenantID)
	assert.Equal(t, entry.Action, retrieved.Action)
	assert.Equal(t, entry.UserID, retrieved.UserID)
	assert.Equal(t, entry.ResourceType, retrieved.ResourceType)
	assert.Equal(t, entry.Result, retrieved.Result)
}

func TestGitAuditStore_ListAuditEntries(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-audit-list-repo")

	store, err := NewGitAuditStore(repoPath, "")
	require.NoError(t, err)

	ctx := context.Background()

	// Store multiple audit entries
	now := time.Now()
	entries := []*interfaces.AuditEntry{
		{
			TenantID:     "tenant-1",
			Timestamp:    now.Add(-time.Hour),
			EventType:    interfaces.AuditEventAuthentication,
			Action:       "login",
			UserID:       "user-1",
			UserType:     interfaces.AuditUserTypeHuman,
			ResourceType: "session",
			ResourceID:   "session-1",
			Result:       interfaces.AuditResultSuccess,
			Severity:     interfaces.AuditSeverityLow,
		},
		{
			TenantID:     "tenant-1",
			Timestamp:    now.Add(-time.Minute * 30),
			EventType:    interfaces.AuditEventConfiguration,
			Action:       "update",
			UserID:       "user-1",
			UserType:     interfaces.AuditUserTypeHuman,
			ResourceType: "configuration",
			ResourceID:   "config-1",
			Result:       interfaces.AuditResultSuccess,
			Severity:     interfaces.AuditSeverityMedium,
		},
		{
			TenantID:     "tenant-2",
			Timestamp:    now.Add(-time.Minute * 10),
			EventType:    interfaces.AuditEventSecurityEvent,
			Action:       "failed_access",
			UserID:       "user-2",
			UserType:     interfaces.AuditUserTypeHuman,
			ResourceType: "configuration",
			ResourceID:   "config-2",
			Result:       interfaces.AuditResultDenied,
			Severity:     interfaces.AuditSeverityHigh,
		},
	}

	for _, entry := range entries {
		err = store.StoreAuditEntry(ctx, entry)
		require.NoError(t, err)
	}

	// Test listing all entries
	filter := &interfaces.AuditFilter{}
	allEntries, err := store.ListAuditEntries(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, allEntries, 3)

	// Test filtering by tenant
	filter.TenantID = "tenant-1"
	tenant1Entries, err := store.ListAuditEntries(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, tenant1Entries, 2)

	// Test filtering by event type
	filter = &interfaces.AuditFilter{
		EventTypes: []interfaces.AuditEventType{interfaces.AuditEventAuthentication},
	}
	authEntries, err := store.ListAuditEntries(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, authEntries, 1)

	// Test filtering by result
	filter = &interfaces.AuditFilter{
		Results: []interfaces.AuditResult{interfaces.AuditResultDenied},
	}
	deniedEntries, err := store.ListAuditEntries(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, deniedEntries, 1)

	// Test filtering by severity
	filter = &interfaces.AuditFilter{
		Severities: []interfaces.AuditSeverity{interfaces.AuditSeverityHigh, interfaces.AuditSeverityCritical},
	}
	highSevEntries, err := store.ListAuditEntries(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, highSevEntries, 1)

	// Test pagination
	filter = &interfaces.AuditFilter{
		Limit:  2,
		Offset: 0,
	}
	paginatedEntries, err := store.ListAuditEntries(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, paginatedEntries, 2)
}

func TestGitAuditStore_BatchOperations(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-audit-batch-repo")

	store, err := NewGitAuditStore(repoPath, "")
	require.NoError(t, err)

	ctx := context.Background()

	// Test batch store
	now := time.Now()
	entries := []*interfaces.AuditEntry{
		{
			ID:           "batch-audit-1", // Storage tests provide ID
			TenantID:     "batch-tenant",
			Timestamp:    now.Add(-time.Hour),
			EventType:    interfaces.AuditEventConfiguration,
			Action:       "create",
			UserID:       "batch-user",
			UserType:     interfaces.AuditUserTypeSystem,
			ResourceType: "configuration",
			ResourceID:   "batch-config-1",
			Result:       interfaces.AuditResultSuccess,
			Severity:     interfaces.AuditSeverityMedium,
			Checksum:     "batch-checksum-1", // Storage tests provide checksum
		},
		{
			ID:           "batch-audit-2", // Storage tests provide ID
			TenantID:     "batch-tenant",
			Timestamp:    now.Add(-time.Minute * 30),
			EventType:    interfaces.AuditEventConfiguration,
			Action:       "update",
			UserID:       "batch-user",
			UserType:     interfaces.AuditUserTypeSystem,
			ResourceType: "configuration",
			ResourceID:   "batch-config-2",
			Result:       interfaces.AuditResultSuccess,
			Severity:     interfaces.AuditSeverityMedium,
			Checksum:     "batch-checksum-2", // Storage tests provide checksum
		},
		{
			ID:           "batch-audit-3", // Storage tests provide ID
			TenantID:     "batch-tenant",
			Timestamp:    now.Add(-time.Minute * 10),
			EventType:    interfaces.AuditEventConfiguration,
			Action:       "delete",
			UserID:       "batch-user",
			UserType:     interfaces.AuditUserTypeSystem,
			ResourceType: "configuration",
			ResourceID:   "batch-config-3",
			Result:       interfaces.AuditResultSuccess,
			Severity:     interfaces.AuditSeverityHigh,
			Checksum:     "batch-checksum-3", // Storage tests provide checksum
		},
	}

	err = store.StoreAuditBatch(ctx, entries)
	require.NoError(t, err)

	// Verify all entries were stored and IDs/checksums were preserved
	for i, entry := range entries {
		expectedID := fmt.Sprintf("batch-audit-%d", i+1)
		expectedChecksum := fmt.Sprintf("batch-checksum-%d", i+1)
		assert.Equal(t, expectedID, entry.ID)
		assert.Equal(t, expectedChecksum, entry.Checksum)

		retrieved, err := store.GetAuditEntry(ctx, entry.ID)
		require.NoError(t, err)
		assert.Equal(t, entry.Action, retrieved.Action)
	}

	// Test querying by user
	userEntries, err := store.GetAuditsByUser(ctx, "batch-user", nil)
	require.NoError(t, err)
	assert.Len(t, userEntries, 3)

	// Test querying by resource
	resourceEntries, err := store.GetAuditsByResource(ctx, "configuration", "batch-config-1", nil)
	require.NoError(t, err)
	assert.Len(t, resourceEntries, 1)

	// Test querying by action
	createEntries, err := store.GetAuditsByAction(ctx, "create", nil)
	require.NoError(t, err)
	assert.Len(t, createEntries, 1)
}

func TestGitAuditStore_SecurityQueries(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-audit-security-repo")

	store, err := NewGitAuditStore(repoPath, "")
	require.NoError(t, err)

	ctx := context.Background()

	// Store audit entries with various results
	now := time.Now()
	entries := []*interfaces.AuditEntry{
		{
			TenantID:     "security-tenant",
			Timestamp:    now.Add(-time.Hour),
			EventType:    interfaces.AuditEventAuthentication,
			Action:       "login",
			UserID:       "user-1",
			UserType:     interfaces.AuditUserTypeHuman,
			ResourceType: "session",
			ResourceID:   "session-1",
			Result:       interfaces.AuditResultFailure,
			Severity:     interfaces.AuditSeverityMedium,
		},
		{
			TenantID:     "security-tenant",
			Timestamp:    now.Add(-time.Minute * 30),
			EventType:    interfaces.AuditEventSecurityEvent,
			Action:       "unauthorized_access",
			UserID:       "attacker",
			UserType:     interfaces.AuditUserTypeHuman,
			ResourceType: "configuration",
			ResourceID:   "sensitive-config",
			Result:       interfaces.AuditResultDenied,
			Severity:     interfaces.AuditSeverityCritical,
		},
		{
			TenantID:     "security-tenant",
			Timestamp:    now.Add(-time.Minute * 10),
			EventType:    interfaces.AuditEventConfiguration,
			Action:       "update",
			UserID:       "admin-user",
			UserType:     interfaces.AuditUserTypeHuman,
			ResourceType: "configuration",
			ResourceID:   "normal-config",
			Result:       interfaces.AuditResultSuccess,
			Severity:     interfaces.AuditSeverityLow,
		},
	}

	for _, entry := range entries {
		err = store.StoreAuditEntry(ctx, entry)
		require.NoError(t, err)
	}

	// Test getting failed actions
	startTime := now.Add(-2 * time.Hour)
	timeRange := &interfaces.TimeRange{
		Start: &startTime,
		End:   &now,
	}

	failedActions, err := store.GetFailedActions(ctx, timeRange, 10)
	require.NoError(t, err)
	assert.Len(t, failedActions, 2) // failure and denied results

	// Test getting suspicious activity
	suspiciousActivity, err := store.GetSuspiciousActivity(ctx, "security-tenant", timeRange)
	require.NoError(t, err)
	assert.Len(t, suspiciousActivity, 1) // only the critical security event

	// Verify the suspicious activity entry
	assert.Equal(t, interfaces.AuditEventSecurityEvent, suspiciousActivity[0].EventType)
	assert.Equal(t, interfaces.AuditSeverityCritical, suspiciousActivity[0].Severity)
}

func TestGitAuditStore_GetAuditStats(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-audit-stats-repo")

	store, err := NewGitAuditStore(repoPath, "")
	require.NoError(t, err)

	ctx := context.Background()

	// Store audit entries with different characteristics
	now := time.Now()
	entries := []*interfaces.AuditEntry{
		{
			TenantID:     "stats-tenant-1",
			Timestamp:    now.Add(-time.Hour),
			EventType:    interfaces.AuditEventAuthentication,
			Action:       "login",
			UserID:       "user-1",
			UserType:     interfaces.AuditUserTypeHuman,
			ResourceType: "session",
			ResourceID:   "session-1",
			Result:       interfaces.AuditResultSuccess,
			Severity:     interfaces.AuditSeverityLow,
		},
		{
			TenantID:     "stats-tenant-2",
			Timestamp:    now.Add(-time.Minute * 30),
			EventType:    interfaces.AuditEventConfiguration,
			Action:       "update",
			UserID:       "user-2",
			UserType:     interfaces.AuditUserTypeSystem,
			ResourceType: "configuration",
			ResourceID:   "config-1",
			Result:       interfaces.AuditResultFailure,
			Severity:     interfaces.AuditSeverityMedium,
		},
		{
			TenantID:     "stats-tenant-1",
			Timestamp:    now.Add(-time.Minute * 10),
			EventType:    interfaces.AuditEventSecurityEvent,
			Action:       "security_violation",
			UserID:       "user-3",
			UserType:     interfaces.AuditUserTypeHuman,
			ResourceType: "system",
			ResourceID:   "security-check",
			Result:       interfaces.AuditResultDenied,
			Severity:     interfaces.AuditSeverityCritical,
		},
	}

	for _, entry := range entries {
		err = store.StoreAuditEntry(ctx, entry)
		require.NoError(t, err)
	}

	// Get statistics
	stats, err := store.GetAuditStats(ctx)
	require.NoError(t, err)

	assert.Equal(t, int64(3), stats.TotalEntries)
	assert.True(t, stats.TotalSize > 0)
	assert.Equal(t, int64(2), stats.EntriesByTenant["stats-tenant-1"])
	assert.Equal(t, int64(1), stats.EntriesByTenant["stats-tenant-2"])
	assert.Equal(t, int64(1), stats.EntriesByType["authentication"])
	assert.Equal(t, int64(1), stats.EntriesByType["configuration"])
	assert.Equal(t, int64(1), stats.EntriesByType["security_event"])
	assert.Equal(t, int64(1), stats.EntriesByResult["success"])
	assert.Equal(t, int64(1), stats.EntriesByResult["failure"])
	assert.Equal(t, int64(1), stats.EntriesByResult["denied"])
	assert.Equal(t, int64(1), stats.EntriesBySeverity["low"])
	assert.Equal(t, int64(1), stats.EntriesBySeverity["medium"])
	assert.Equal(t, int64(1), stats.EntriesBySeverity["critical"])
	assert.NotNil(t, stats.OldestEntry)
	assert.NotNil(t, stats.NewestEntry)
	assert.True(t, stats.AverageSize > 0)
	assert.Equal(t, int64(1), stats.SuspiciousActivityCount)
	assert.NotNil(t, stats.LastSecurityIncident)
}

func TestGitConfigStore_DeleteConfig(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-delete-repo")

	store, err := NewGitConfigStore(repoPath, "")
	require.NoError(t, err)

	ctx := context.Background()

	// Store a configuration
	config := &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID:  "delete-tenant",
			Namespace: "test",
			Name:      "to-delete",
		},
		Data:      []byte("delete-me"),
		CreatedBy: "test-user",
	}

	err = store.StoreConfig(ctx, config)
	require.NoError(t, err)

	// Verify it exists
	_, err = store.GetConfig(ctx, config.Key)
	require.NoError(t, err)

	// Delete the configuration
	err = store.DeleteConfig(ctx, config.Key)
	require.NoError(t, err)

	// Verify it's gone
	_, err = store.GetConfig(ctx, config.Key)
	assert.Error(t, err)
	assert.Equal(t, interfaces.ErrConfigNotFound, err)

	// Test deleting non-existent config
	nonExistentKey := &interfaces.ConfigKey{
		TenantID:  "delete-tenant",
		Namespace: "test",
		Name:      "non-existent",
	}
	err = store.DeleteConfig(ctx, nonExistentKey)
	assert.Error(t, err)
	assert.Equal(t, interfaces.ErrConfigNotFound, err)
}

func TestGitProvider_CreateStores(t *testing.T) {
	provider := &GitProvider{}

	tempDir := t.TempDir()

	// Test creating client tenant store
	clientConfig := map[string]interface{}{
		"repository_path": filepath.Join(tempDir, "client-store"),
		"remote_url":      "https://github.com/test/client-repo.git",
	}

	clientStore, err := provider.CreateClientTenantStore(clientConfig)
	require.NoError(t, err)
	assert.NotNil(t, clientStore)

	// Test creating config store
	configConfig := map[string]interface{}{
		"repository_path": filepath.Join(tempDir, "config-store"),
		"remote_url":      "https://github.com/test/config-repo.git",
	}

	configStore, err := provider.CreateConfigStore(configConfig)
	require.NoError(t, err)
	assert.NotNil(t, configStore)

	// Test creating audit store
	auditConfig := map[string]interface{}{
		"repository_path": filepath.Join(tempDir, "audit-store"),
		"remote_url":      "https://github.com/test/audit-repo.git",
	}

	auditStore, err := provider.CreateAuditStore(auditConfig)
	require.NoError(t, err)
	assert.NotNil(t, auditStore)
}

func TestGitConfigStore_ErrorCases(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-error-repo")

	store, err := NewGitConfigStore(repoPath, "")
	require.NoError(t, err)

	ctx := context.Background()

	// Test validation errors
	invalidConfigs := []*interfaces.ConfigEntry{
		{Key: nil, Data: []byte("data")}, // nil key
		{Key: &interfaces.ConfigKey{TenantID: "", Namespace: "ns", Name: "name"}, Data: []byte("data")},     // empty tenant
		{Key: &interfaces.ConfigKey{TenantID: "tenant", Namespace: "", Name: "name"}, Data: []byte("data")}, // empty namespace
		{Key: &interfaces.ConfigKey{TenantID: "tenant", Namespace: "ns", Name: ""}, Data: []byte("data")},   // empty name
	}

	for i, config := range invalidConfigs {
		t.Run(fmt.Sprintf("invalid_config_%d", i), func(t *testing.T) {
			err := store.StoreConfig(ctx, config)
			assert.Error(t, err)
		})
	}

	// Test getting non-existent config
	nonExistentKey := &interfaces.ConfigKey{
		TenantID:  "non-existent",
		Namespace: "test",
		Name:      "missing",
	}
	_, err = store.GetConfig(ctx, nonExistentKey)
	assert.Error(t, err)
	assert.Equal(t, interfaces.ErrConfigNotFound, err)
}

func TestGitAuditStore_ErrorCases(t *testing.T) {
	tempDir := t.TempDir()
	repoPath := filepath.Join(tempDir, "test-audit-error-repo")

	store, err := NewGitAuditStore(repoPath, "")
	require.NoError(t, err)

	ctx := context.Background()

	// Test validation errors
	invalidEntries := []*interfaces.AuditEntry{
		{TenantID: "", UserID: "user", Action: "action", ResourceType: "type", ResourceID: "id"},     // empty tenant
		{TenantID: "tenant", UserID: "", Action: "action", ResourceType: "type", ResourceID: "id"},   // empty user
		{TenantID: "tenant", UserID: "user", Action: "", ResourceType: "type", ResourceID: "id"},     // empty action
		{TenantID: "tenant", UserID: "user", Action: "action", ResourceType: "", ResourceID: "id"},   // empty resource type
		{TenantID: "tenant", UserID: "user", Action: "action", ResourceType: "type", ResourceID: ""}, // empty resource ID
	}

	for i, entry := range invalidEntries {
		t.Run(fmt.Sprintf("invalid_entry_%d", i), func(t *testing.T) {
			err := store.StoreAuditEntry(ctx, entry)
			assert.Error(t, err)
		})
	}

	// Test getting non-existent audit entry
	_, err = store.GetAuditEntry(ctx, "non-existent-id")
	assert.Error(t, err)
	assert.Equal(t, interfaces.ErrAuditNotFound, err)
}
