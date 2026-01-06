// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package tenant

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// StorageAdapter adapts pkg/storage/interfaces.TenantStore to features/tenant.Store
// This allows the tenant management features to use the global storage provider system
type StorageAdapter struct {
	store interfaces.TenantStore
}

// NewStorageAdapter creates a new storage adapter
func NewStorageAdapter(store interfaces.TenantStore) Store {
	return &StorageAdapter{
		store: store,
	}
}

// convertTenantToStorage converts features/tenant.Tenant to interfaces.TenantData
func convertTenantToStorage(t *Tenant) *interfaces.TenantData {
	if t == nil {
		return nil
	}

	// Convert status - map TenantStatusInactive to TenantStatusDeleted
	status := interfaces.TenantStatus(t.Status)
	if t.Status == TenantStatusInactive {
		status = interfaces.TenantStatusDeleted
	}

	return &interfaces.TenantData{
		ID:          t.ID,
		Name:        t.Name,
		Description: t.Description,
		ParentID:    t.ParentID,
		Metadata:    t.Metadata,
		Status:      status,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
}

// convertTenantFromStorage converts interfaces.TenantData to features/tenant.Tenant
func convertTenantFromStorage(t *interfaces.TenantData) *Tenant {
	if t == nil {
		return nil
	}

	// Convert status - map TenantStatusDeleted to TenantStatusInactive
	status := TenantStatus(t.Status)
	if t.Status == interfaces.TenantStatusDeleted {
		status = TenantStatusInactive
	}

	return &Tenant{
		ID:          t.ID,
		Name:        t.Name,
		Description: t.Description,
		ParentID:    t.ParentID,
		Metadata:    t.Metadata,
		Status:      status,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
}

// convertFilterToStorage converts features/tenant.TenantFilter to interfaces.TenantFilter
func convertFilterToStorage(f *TenantFilter) *interfaces.TenantFilter {
	if f == nil {
		return nil
	}

	// Convert status - map TenantStatusInactive to TenantStatusDeleted
	status := interfaces.TenantStatus(f.Status)
	if f.Status == TenantStatusInactive {
		status = interfaces.TenantStatusDeleted
	}

	return &interfaces.TenantFilter{
		ParentID: f.ParentID,
		Status:   status,
		Name:     f.Name,
	}
}

// convertHierarchyFromStorage converts interfaces.TenantHierarchy to features/tenant.TenantHierarchy
func convertHierarchyFromStorage(h *interfaces.TenantHierarchy) *TenantHierarchy {
	if h == nil {
		return nil
	}

	return &TenantHierarchy{
		TenantID: h.TenantID,
		Path:     h.Path,
		Depth:    h.Depth,
		Children: h.Children,
	}
}

// CreateTenant implements Store.CreateTenant
func (s *StorageAdapter) CreateTenant(ctx context.Context, tenant *Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	return s.store.CreateTenant(ctx, convertTenantToStorage(tenant))
}

// GetTenant implements Store.GetTenant
func (s *StorageAdapter) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	storageData, err := s.store.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return convertTenantFromStorage(storageData), nil
}

// UpdateTenant implements Store.UpdateTenant
func (s *StorageAdapter) UpdateTenant(ctx context.Context, tenant *Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	return s.store.UpdateTenant(ctx, convertTenantToStorage(tenant))
}

// DeleteTenant implements Store.DeleteTenant
func (s *StorageAdapter) DeleteTenant(ctx context.Context, tenantID string) error {
	return s.store.DeleteTenant(ctx, tenantID)
}

// ListTenants implements Store.ListTenants
func (s *StorageAdapter) ListTenants(ctx context.Context, filter *TenantFilter) ([]*Tenant, error) {
	storageData, err := s.store.ListTenants(ctx, convertFilterToStorage(filter))
	if err != nil {
		return nil, err
	}

	tenants := make([]*Tenant, len(storageData))
	for i, t := range storageData {
		tenants[i] = convertTenantFromStorage(t)
	}
	return tenants, nil
}

// GetTenantHierarchy implements Store.GetTenantHierarchy
func (s *StorageAdapter) GetTenantHierarchy(ctx context.Context, tenantID string) (*TenantHierarchy, error) {
	storageData, err := s.store.GetTenantHierarchy(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return convertHierarchyFromStorage(storageData), nil
}

// GetChildTenants implements Store.GetChildTenants
func (s *StorageAdapter) GetChildTenants(ctx context.Context, parentID string) ([]*Tenant, error) {
	storageData, err := s.store.GetChildTenants(ctx, parentID)
	if err != nil {
		return nil, err
	}

	tenants := make([]*Tenant, len(storageData))
	for i, t := range storageData {
		tenants[i] = convertTenantFromStorage(t)
	}
	return tenants, nil
}

// GetTenantPath implements Store.GetTenantPath
func (s *StorageAdapter) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	return s.store.GetTenantPath(ctx, tenantID)
}

// IsTenantAncestor implements Store.IsTenantAncestor
func (s *StorageAdapter) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	return s.store.IsTenantAncestor(ctx, ancestorID, descendantID)
}
