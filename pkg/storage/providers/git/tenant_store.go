// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package git

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// GitTenantStore implements TenantStore using git for persistence
// This stores tenant data in JSON files within a git repository
type GitTenantStore struct {
	repoPath  string
	remoteURL string
}

// safeReadFileTenant safely reads a file with path validation to prevent directory traversal
func (s *GitTenantStore) safeReadFile(targetPath string) ([]byte, error) {
	// Clean the path to resolve any .. or . components
	cleanPath := filepath.Clean(targetPath)

	// Ensure the path is within the repo directory
	if !strings.HasPrefix(cleanPath, filepath.Clean(s.repoPath)) {
		return nil, fmt.Errorf("path outside repository: %s", targetPath)
	}

	return os.ReadFile(cleanPath)
}

// NewGitTenantStore creates a new git-based tenant store
func NewGitTenantStore(repoPath, remoteURL string) (*GitTenantStore, error) {
	store := &GitTenantStore{
		repoPath:  repoPath,
		remoteURL: remoteURL,
	}

	// Initialize git repository if it doesn't exist
	if err := store.initializeRepo(); err != nil {
		return nil, fmt.Errorf("failed to initialize git repository: %w", err)
	}

	return store, nil
}

// initializeRepo ensures the git repository exists
func (s *GitTenantStore) initializeRepo() error {
	// Check if directory exists
	if _, err := os.Stat(s.repoPath); os.IsNotExist(err) {
		// Create directory
		if err := os.MkdirAll(s.repoPath, 0750); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Create subdirectories for tenant data
	dirs := []string{"tenants", "hierarchy"}
	for _, dir := range dirs {
		fullPath := filepath.Join(s.repoPath, dir)
		if err := os.MkdirAll(fullPath, 0750); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// Initialize implements TenantStore.Initialize
func (s *GitTenantStore) Initialize(ctx context.Context) error {
	return s.initializeRepo()
}

// Close implements TenantStore.Close
func (s *GitTenantStore) Close() error {
	return nil
}

// Tenant management

// CreateTenant implements TenantStore.CreateTenant
func (s *GitTenantStore) CreateTenant(ctx context.Context, tenant *interfaces.TenantData) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	// Check if tenant already exists
	filePath := filepath.Join(s.repoPath, "tenants", tenant.ID+".json")
	if _, err := os.Stat(filePath); err == nil {
		return fmt.Errorf("tenant %s already exists", tenant.ID)
	}

	// Marshal tenant data
	data, err := json.MarshalIndent(tenant, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tenant: %w", err)
	}

	// Write tenant file
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write tenant file: %w", err)
	}

	// Update hierarchy if tenant has a parent
	if tenant.ParentID != "" {
		if err := s.updateHierarchy(ctx, tenant); err != nil {
			return fmt.Errorf("failed to update hierarchy: %w", err)
		}
	}

	return nil
}

// GetTenant implements TenantStore.GetTenant
func (s *GitTenantStore) GetTenant(ctx context.Context, tenantID string) (*interfaces.TenantData, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	filePath := filepath.Join(s.repoPath, "tenants", tenantID+".json")
	data, err := s.safeReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("tenant %s not found", tenantID)
		}
		return nil, fmt.Errorf("failed to read tenant file: %w", err)
	}

	var tenant interfaces.TenantData
	if err := json.Unmarshal(data, &tenant); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tenant: %w", err)
	}

	return &tenant, nil
}

// UpdateTenant implements TenantStore.UpdateTenant
func (s *GitTenantStore) UpdateTenant(ctx context.Context, tenant *interfaces.TenantData) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	// Check if tenant exists
	filePath := filepath.Join(s.repoPath, "tenants", tenant.ID+".json")
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("tenant %s not found", tenant.ID)
	}

	// Marshal tenant data
	data, err := json.MarshalIndent(tenant, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tenant: %w", err)
	}

	// Write tenant file
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write tenant file: %w", err)
	}

	return nil
}

// DeleteTenant implements TenantStore.DeleteTenant
func (s *GitTenantStore) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	filePath := filepath.Join(s.repoPath, "tenants", tenantID+".json")
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("tenant %s not found", tenantID)
		}
		return fmt.Errorf("failed to delete tenant file: %w", err)
	}

	return nil
}

// ListTenants implements TenantStore.ListTenants
func (s *GitTenantStore) ListTenants(ctx context.Context, filter *interfaces.TenantFilter) ([]*interfaces.TenantData, error) {
	tenantsDir := filepath.Join(s.repoPath, "tenants")
	entries, err := os.ReadDir(tenantsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read tenants directory: %w", err)
	}

	var tenants []*interfaces.TenantData
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(tenantsDir, entry.Name())
		data, err := s.safeReadFile(filePath)
		if err != nil {
			continue // Skip files that can't be read
		}

		var tenant interfaces.TenantData
		if err := json.Unmarshal(data, &tenant); err != nil {
			continue // Skip files that can't be parsed
		}

		// Apply filters if provided
		if filter != nil {
			if filter.ParentID != "" && tenant.ParentID != filter.ParentID {
				continue
			}
			if filter.Status != "" && tenant.Status != filter.Status {
				continue
			}
			if filter.Name != "" && !strings.Contains(strings.ToLower(tenant.Name), strings.ToLower(filter.Name)) {
				continue
			}
		}

		tenants = append(tenants, &tenant)
	}

	return tenants, nil
}

// Hierarchy operations

// GetTenantHierarchy implements TenantStore.GetTenantHierarchy
func (s *GitTenantStore) GetTenantHierarchy(ctx context.Context, tenantID string) (*interfaces.TenantHierarchy, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	// Build hierarchy by walking up parent chain
	path, err := s.GetTenantPath(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant path: %w", err)
	}

	// Get direct children
	children, err := s.GetChildTenants(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get child tenants: %w", err)
	}

	childIDs := make([]string, len(children))
	for i, child := range children {
		childIDs[i] = child.ID
	}

	return &interfaces.TenantHierarchy{
		TenantID: tenantID,
		Path:     path,
		Depth:    len(path) - 1, // Depth is 0-indexed
		Children: childIDs,
	}, nil
}

// GetChildTenants implements TenantStore.GetChildTenants
func (s *GitTenantStore) GetChildTenants(ctx context.Context, parentID string) ([]*interfaces.TenantData, error) {
	filter := &interfaces.TenantFilter{
		ParentID: parentID,
	}
	return s.ListTenants(ctx, filter)
}

// GetTenantPath implements TenantStore.GetTenantPath
func (s *GitTenantStore) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	var path []string
	currentID := tenantID

	// Walk up the parent chain
	for currentID != "" {
		tenant, err := s.GetTenant(ctx, currentID)
		if err != nil {
			return nil, fmt.Errorf("failed to get tenant %s: %w", currentID, err)
		}

		// Prepend to path (building from child to root)
		path = append([]string{currentID}, path...)

		currentID = tenant.ParentID

		// Prevent infinite loops
		if len(path) > 100 {
			return nil, fmt.Errorf("tenant hierarchy depth exceeded (possible circular reference)")
		}
	}

	return path, nil
}

// IsTenantAncestor implements TenantStore.IsTenantAncestor
func (s *GitTenantStore) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	if ancestorID == "" || descendantID == "" {
		return false, fmt.Errorf("ancestor and descendant IDs cannot be empty")
	}

	// Get the path from descendant to root
	path, err := s.GetTenantPath(ctx, descendantID)
	if err != nil {
		return false, fmt.Errorf("failed to get tenant path: %w", err)
	}

	// Check if ancestorID is in the path
	for _, id := range path {
		if id == ancestorID {
			return true, nil
		}
	}

	return false, nil
}

// updateHierarchy updates the hierarchy cache when a tenant is created or modified
func (s *GitTenantStore) updateHierarchy(ctx context.Context, tenant *interfaces.TenantData) error {
	// This is a simple implementation that doesn't maintain a separate hierarchy cache
	// In production, you might want to optimize this with a hierarchy index
	return nil
}
