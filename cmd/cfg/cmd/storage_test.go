// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile" // register flatfile provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"   // register sqlite provider
)

func TestIsValidPathComponent(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"tenant-1", true},
		{"my_tenant", true},
		{"abc123", true},
		{"", false},
		{".", false},
		{"..", false},
		{"foo/bar", false},
		{"foo\\bar", false},
		{"../escape", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := isValidPathComponent(tc.input)
			assert.Equal(t, tc.valid, result, "isValidPathComponent(%q)", tc.input)
		})
	}
}

func TestIsValidNamespace(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"", true},         // empty namespace is valid
		{"default", true},  // single segment
		{"a/b/c", true},    // multi-segment
		{"ns-1/sub", true}, // hyphens OK
		{"../evil", false},
		{"good/..", false},
		{"a//b", false}, // empty segment
		{"/leading", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := isValidNamespace(tc.input)
			assert.Equal(t, tc.valid, result, "isValidNamespace(%q)", tc.input)
		})
	}
}

func TestMigrateConfigStore_EmptyDir(t *testing.T) {
	ctx := context.Background()

	// Create empty configs directory
	gitRoot := t.TempDir()
	configsDir := filepath.Join(gitRoot, "configs")
	require.NoError(t, os.MkdirAll(configsDir, 0750))

	// Create target storage
	targetDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(
		filepath.Join(targetDir, "flatfile"),
		filepath.Join(targetDir, "cfgms.db"),
	)
	require.NoError(t, err)

	count, err := migrateConfigStore(ctx, configsDir, sm.GetConfigStore())
	require.NoError(t, err)
	assert.Equal(t, 0, count, "empty dir should migrate 0 configs")
}

func TestMigrateConfigStore_WithFiles(t *testing.T) {
	ctx := context.Background()

	// Create git-style config structure: configs/<tenantID>/<namespace>/<name>.<format>
	gitRoot := t.TempDir()
	configsDir := filepath.Join(gitRoot, "configs")

	tenantDir := filepath.Join(configsDir, "tenant-1", "default")
	require.NoError(t, os.MkdirAll(tenantDir, 0750))

	configData := []byte(`{"key": "value"}`)
	require.NoError(t, os.WriteFile(filepath.Join(tenantDir, "app.json"), configData, 0640))
	require.NoError(t, os.WriteFile(filepath.Join(tenantDir, "db.yaml"), []byte("host: localhost"), 0640))

	// Create target storage
	targetDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(
		filepath.Join(targetDir, "flatfile"),
		filepath.Join(targetDir, "cfgms.db"),
	)
	require.NoError(t, err)

	count, err := migrateConfigStore(ctx, configsDir, sm.GetConfigStore())
	require.NoError(t, err)
	assert.Equal(t, 2, count, "should migrate 2 config files")

	// Verify stored config can be retrieved
	entry, err := sm.GetConfigStore().GetConfig(ctx, &interfaces.ConfigKey{
		TenantID:  "tenant-1",
		Namespace: "default",
		Name:      "app",
	})
	require.NoError(t, err)
	assert.Equal(t, configData, entry.Data)
}

func TestMigrateAuditStore_EmptyDir(t *testing.T) {
	ctx := context.Background()

	// Create empty audit directory
	gitRoot := t.TempDir()
	auditDir := filepath.Join(gitRoot, "audit")
	require.NoError(t, os.MkdirAll(auditDir, 0750))

	// Create target storage
	targetDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(
		filepath.Join(targetDir, "flatfile"),
		filepath.Join(targetDir, "cfgms.db"),
	)
	require.NoError(t, err)

	count, err := migrateAuditStore(ctx, auditDir, sm.GetAuditStore())
	require.NoError(t, err)
	assert.Equal(t, 0, count, "empty dir should migrate 0 audit entries")
}

func TestMigrateTenantStore_EmptyDir(t *testing.T) {
	ctx := context.Background()

	tenantsDir := filepath.Join(t.TempDir(), "tenants")
	require.NoError(t, os.MkdirAll(tenantsDir, 0750))

	targetDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(
		filepath.Join(targetDir, "flatfile"),
		filepath.Join(targetDir, "cfgms.db"),
	)
	require.NoError(t, err)

	count, err := migrateTenantStore(ctx, tenantsDir, sm.GetTenantStore())
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestMigrateTenantStore_WithFiles(t *testing.T) {
	ctx := context.Background()

	tenantsDir := filepath.Join(t.TempDir(), "tenants")
	require.NoError(t, os.MkdirAll(tenantsDir, 0750))

	now := time.Now().Truncate(time.Second)
	tenant := interfaces.TenantData{
		ID:        "test-tenant",
		Name:      "Test Tenant",
		Status:    interfaces.TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	data, err := json.Marshal(tenant)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tenantsDir, "test-tenant.json"), data, 0640))

	targetDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(
		filepath.Join(targetDir, "flatfile"),
		filepath.Join(targetDir, "cfgms.db"),
	)
	require.NoError(t, err)

	count, err := migrateTenantStore(ctx, tenantsDir, sm.GetTenantStore())
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestMigrateRegistrationTokenStore_EmptyDir(t *testing.T) {
	ctx := context.Background()

	tokensDir := filepath.Join(t.TempDir(), "registration_tokens")
	require.NoError(t, os.MkdirAll(tokensDir, 0750))

	targetDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(
		filepath.Join(targetDir, "flatfile"),
		filepath.Join(targetDir, "cfgms.db"),
	)
	require.NoError(t, err)

	count, err := migrateRegistrationTokenStore(ctx, tokensDir, sm.GetRegistrationTokenStore())
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestMigrateClientTenantStore_EmptyDir(t *testing.T) {
	clientTenantsDir := filepath.Join(t.TempDir(), "client_tenants")
	require.NoError(t, os.MkdirAll(clientTenantsDir, 0750))

	targetDir := t.TempDir()
	sm, err := interfaces.CreateOSSStorageManager(
		filepath.Join(targetDir, "flatfile"),
		filepath.Join(targetDir, "cfgms.db"),
	)
	require.NoError(t, err)

	count, err := migrateClientTenantStore(clientTenantsDir, sm.GetClientTenantStore())
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
