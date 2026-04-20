// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// StorageAdapter adapts business.RegistrationTokenStore to registration.Store
// This allows the registration system to use durable storage while maintaining
// backward compatibility with the existing Store interface.
type StorageAdapter struct {
	store business.RegistrationTokenStore
}

// NewStorageAdapter creates a new adapter that wraps a RegistrationTokenStore
func NewStorageAdapter(store business.RegistrationTokenStore) *StorageAdapter {
	return &StorageAdapter{store: store}
}

// SaveToken saves a registration token by converting to storage format
func (a *StorageAdapter) SaveToken(ctx context.Context, token *Token) error {
	data := tokenToData(token)
	return a.store.SaveToken(ctx, data)
}

// GetToken retrieves a token and converts from storage format
func (a *StorageAdapter) GetToken(ctx context.Context, tokenStr string) (*Token, error) {
	data, err := a.store.GetToken(ctx, tokenStr)
	if err != nil {
		return nil, err
	}
	return dataToToken(data), nil
}

// ListTokens lists all tokens for a tenant
func (a *StorageAdapter) ListTokens(ctx context.Context, tenantID string) ([]*Token, error) {
	filter := &business.RegistrationTokenFilter{
		TenantID: tenantID,
	}
	dataList, err := a.store.ListTokens(ctx, filter)
	if err != nil {
		return nil, err
	}

	tokens := make([]*Token, len(dataList))
	for i, data := range dataList {
		tokens[i] = dataToToken(data)
	}
	return tokens, nil
}

// UpdateToken updates an existing token
func (a *StorageAdapter) UpdateToken(ctx context.Context, token *Token) error {
	data := tokenToData(token)
	return a.store.UpdateToken(ctx, data)
}

// DeleteToken deletes a token
func (a *StorageAdapter) DeleteToken(ctx context.Context, tokenStr string) error {
	return a.store.DeleteToken(ctx, tokenStr)
}

// ConsumeToken atomically validates and marks a token as used, delegating to the storage provider.
func (a *StorageAdapter) ConsumeToken(ctx context.Context, tokenStr, stewardID string) error {
	return a.store.ConsumeToken(ctx, tokenStr, stewardID)
}

// tokenToData converts a Token to RegistrationTokenData
func tokenToData(token *Token) *business.RegistrationTokenData {
	return &business.RegistrationTokenData{
		Token:         token.Token,
		TenantID:      token.TenantID,
		ControllerURL: token.ControllerURL,
		Group:         token.Group,
		CreatedAt:     token.CreatedAt,
		ExpiresAt:     token.ExpiresAt,
		SingleUse:     token.SingleUse,
		UsedAt:        token.UsedAt,
		UsedBy:        token.UsedBy,
		Revoked:       token.Revoked,
		RevokedAt:     token.RevokedAt,
	}
}

// dataToToken converts a RegistrationTokenData to Token
func dataToToken(data *business.RegistrationTokenData) *Token {
	return &Token{
		Token:         data.Token,
		TenantID:      data.TenantID,
		ControllerURL: data.ControllerURL,
		Group:         data.Group,
		CreatedAt:     data.CreatedAt,
		ExpiresAt:     data.ExpiresAt,
		SingleUse:     data.SingleUse,
		UsedAt:        data.UsedAt,
		UsedBy:        data.UsedBy,
		Revoked:       data.Revoked,
		RevokedAt:     data.RevokedAt,
	}
}
