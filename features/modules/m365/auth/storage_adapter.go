// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package auth

import (
	"context"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// StorageClientTenantStoreAdapter adapts the storage provider M365ClientTenantStore
// to the auth module's ClientTenantStore interface
// Story #274: M365 Auth Client Tenant Storage Migration
type StorageClientTenantStoreAdapter struct {
	store interfaces.M365ClientTenantStore
}

// NewStorageClientTenantStoreAdapter creates a new storage adapter
func NewStorageClientTenantStoreAdapter(store interfaces.M365ClientTenantStore) *StorageClientTenantStoreAdapter {
	return &StorageClientTenantStoreAdapter{
		store: store,
	}
}

// StoreClientTenant implements ClientTenantStore.StoreClientTenant
func (a *StorageClientTenantStoreAdapter) StoreClientTenant(ctx context.Context, client *ClientTenant) error {
	// Convert to storage interface type
	storageClient := &interfaces.M365ClientTenant{
		ID:               client.ID,
		TenantID:         client.TenantID,
		TenantName:       client.TenantName,
		DomainName:       client.DomainName,
		AdminEmail:       client.AdminEmail,
		ConsentedAt:      client.ConsentedAt,
		Status:           interfaces.M365ClientTenantStatus(client.Status),
		ClientIdentifier: client.ClientIdentifier,
		Metadata:         client.Metadata,
		CreatedAt:        client.CreatedAt,
		UpdatedAt:        client.UpdatedAt,
	}

	return a.store.StoreClientTenant(ctx, storageClient)
}

// GetClientTenant implements ClientTenantStore.GetClientTenant
func (a *StorageClientTenantStoreAdapter) GetClientTenant(ctx context.Context, tenantID string) (*ClientTenant, error) {
	storageClient, err := a.store.GetClientTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Convert from storage interface type
	return &ClientTenant{
		ID:               storageClient.ID,
		TenantID:         storageClient.TenantID,
		TenantName:       storageClient.TenantName,
		DomainName:       storageClient.DomainName,
		AdminEmail:       storageClient.AdminEmail,
		ConsentedAt:      storageClient.ConsentedAt,
		Status:           ClientTenantStatus(storageClient.Status),
		ClientIdentifier: storageClient.ClientIdentifier,
		Metadata:         storageClient.Metadata,
		CreatedAt:        storageClient.CreatedAt,
		UpdatedAt:        storageClient.UpdatedAt,
	}, nil
}

// GetClientTenantByIdentifier implements ClientTenantStore.GetClientTenantByIdentifier
func (a *StorageClientTenantStoreAdapter) GetClientTenantByIdentifier(ctx context.Context, clientIdentifier string) (*ClientTenant, error) {
	storageClient, err := a.store.GetClientTenantByIdentifier(ctx, clientIdentifier)
	if err != nil {
		return nil, err
	}

	// Convert from storage interface type
	return &ClientTenant{
		ID:               storageClient.ID,
		TenantID:         storageClient.TenantID,
		TenantName:       storageClient.TenantName,
		DomainName:       storageClient.DomainName,
		AdminEmail:       storageClient.AdminEmail,
		ConsentedAt:      storageClient.ConsentedAt,
		Status:           ClientTenantStatus(storageClient.Status),
		ClientIdentifier: storageClient.ClientIdentifier,
		Metadata:         storageClient.Metadata,
		CreatedAt:        storageClient.CreatedAt,
		UpdatedAt:        storageClient.UpdatedAt,
	}, nil
}

// ListClientTenants implements ClientTenantStore.ListClientTenants
func (a *StorageClientTenantStoreAdapter) ListClientTenants(ctx context.Context, status ClientTenantStatus) ([]*ClientTenant, error) {
	storageStatus := interfaces.M365ClientTenantStatus(status)
	storageClients, err := a.store.ListClientTenants(ctx, storageStatus)
	if err != nil {
		return nil, err
	}

	// Convert from storage interface type
	clients := make([]*ClientTenant, len(storageClients))
	for i, storageClient := range storageClients {
		clients[i] = &ClientTenant{
			ID:               storageClient.ID,
			TenantID:         storageClient.TenantID,
			TenantName:       storageClient.TenantName,
			DomainName:       storageClient.DomainName,
			AdminEmail:       storageClient.AdminEmail,
			ConsentedAt:      storageClient.ConsentedAt,
			Status:           ClientTenantStatus(storageClient.Status),
			ClientIdentifier: storageClient.ClientIdentifier,
			Metadata:         storageClient.Metadata,
			CreatedAt:        storageClient.CreatedAt,
			UpdatedAt:        storageClient.UpdatedAt,
		}
	}

	return clients, nil
}

// UpdateClientTenantStatus implements ClientTenantStore.UpdateClientTenantStatus
func (a *StorageClientTenantStoreAdapter) UpdateClientTenantStatus(ctx context.Context, tenantID string, status ClientTenantStatus) error {
	storageStatus := interfaces.M365ClientTenantStatus(status)
	return a.store.UpdateClientTenantStatus(ctx, tenantID, storageStatus)
}

// DeleteClientTenant implements ClientTenantStore.DeleteClientTenant
func (a *StorageClientTenantStoreAdapter) DeleteClientTenant(ctx context.Context, tenantID string) error {
	return a.store.DeleteClientTenant(ctx, tenantID)
}

// StoreAdminConsentRequest implements ClientTenantStore.StoreAdminConsentRequest
func (a *StorageClientTenantStoreAdapter) StoreAdminConsentRequest(ctx context.Context, request *AdminConsentRequest) error {
	// Convert to storage interface type
	storageRequest := &interfaces.M365AdminConsentRequest{
		ClientIdentifier: request.ClientIdentifier,
		ClientName:       request.ClientName,
		RequestedBy:      request.RequestedBy,
		State:            request.State,
		ExpiresAt:        request.ExpiresAt,
		Metadata:         request.Metadata,
		CreatedAt:        request.CreatedAt,
	}

	return a.store.StoreAdminConsentRequest(ctx, storageRequest)
}

// GetAdminConsentRequest implements ClientTenantStore.GetAdminConsentRequest
func (a *StorageClientTenantStoreAdapter) GetAdminConsentRequest(ctx context.Context, state string) (*AdminConsentRequest, error) {
	storageRequest, err := a.store.GetAdminConsentRequest(ctx, state)
	if err != nil {
		return nil, err
	}

	// Convert from storage interface type
	return &AdminConsentRequest{
		ClientIdentifier: storageRequest.ClientIdentifier,
		ClientName:       storageRequest.ClientName,
		RequestedBy:      storageRequest.RequestedBy,
		State:            storageRequest.State,
		ExpiresAt:        storageRequest.ExpiresAt,
		Metadata:         storageRequest.Metadata,
		CreatedAt:        storageRequest.CreatedAt,
	}, nil
}

// DeleteAdminConsentRequest implements ClientTenantStore.DeleteAdminConsentRequest
func (a *StorageClientTenantStoreAdapter) DeleteAdminConsentRequest(ctx context.Context, state string) error {
	return a.store.DeleteAdminConsentRequest(ctx, state)
}
