// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package registration

import (
	"context"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// StorageAdapter adapts interfaces.RegistrationTokenStore to registration.Store
// This allows the registration system to use durable storage while maintaining
// backward compatibility with the existing Store interface.
type StorageAdapter struct {
	store interfaces.RegistrationTokenStore
}

// NewStorageAdapter creates a new adapter that wraps a RegistrationTokenStore
func NewStorageAdapter(store interfaces.RegistrationTokenStore) *StorageAdapter {
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
	filter := &interfaces.RegistrationTokenFilter{
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

// tokenToData converts a Token to RegistrationTokenData
func tokenToData(token *Token) *interfaces.RegistrationTokenData {
	return &interfaces.RegistrationTokenData{
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
func dataToToken(data *interfaces.RegistrationTokenData) *Token {
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
