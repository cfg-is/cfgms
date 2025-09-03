// Package testing provides testing utilities for CFGMS components
package testing

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	
	// Import storage providers for testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

// SetupTestStorage creates a git-based storage manager for testing
// This is the minimum durable storage required for CFGMS testing
func SetupTestStorage(t *testing.T) *interfaces.StorageManager {
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":         "main", 
		"auto_init":      true,
	}
	
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	if err != nil {
		t.Fatalf("Failed to create test storage: %v", err)
	}
	
	return storageManager
}

// SetupTestRBACManager creates an RBAC manager with git storage for testing
func SetupTestRBACManager(t *testing.T) *rbac.Manager {
	storageManager := SetupTestStorage(t)
	
	manager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
	)
	
	// Initialize with default permissions and roles
	ctx := context.Background()
	
	if err := manager.Initialize(ctx); err != nil {
		t.Fatalf("Failed to initialize test RBAC manager: %v", err)
	}
	
	return manager
}

// SetupTestAuditManager creates an audit manager with git storage for testing
func SetupTestAuditManager(t *testing.T) *audit.Manager {
	storageManager := SetupTestStorage(t)
	return audit.NewManager(storageManager.GetAuditStore(), "test")
}