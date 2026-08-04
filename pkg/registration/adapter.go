// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"fmt"

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

// SaveToken saves a registration token by converting to storage format.
// A store that assigns a stable ID to a token saved without one (Issue #2970) has
// that ID written back onto the caller's token, matching memoryStore, so the caller
// can address the token by ID immediately after saving.
func (a *StorageAdapter) SaveToken(ctx context.Context, token *Token) error {
	data := tokenToData(token)
	if err := a.store.SaveToken(ctx, data); err != nil {
		return err
	}
	token.ID = data.ID
	return nil
}

// GetToken retrieves a token and converts from storage format
func (a *StorageAdapter) GetToken(ctx context.Context, tokenStr string) (*Token, error) {
	data, err := a.store.GetToken(ctx, tokenStr)
	if err != nil {
		return nil, err
	}
	return dataToToken(data), nil
}

// GetTokenByID retrieves a token by its stable UUID.
func (a *StorageAdapter) GetTokenByID(ctx context.Context, id string) (*Token, error) {
	data, err := a.store.GetTokenByID(ctx, id)
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

// RotateToken atomically revokes all prior tokens for tenant+group and returns the new token.
func (a *StorageAdapter) RotateToken(ctx context.Context, tenantID, group string) (*Token, error) {
	data, err := a.store.RotateToken(ctx, tenantID, group)
	if err != nil {
		return nil, err
	}
	return dataToToken(data), nil
}

// ClaimToken atomically reserves a valid token at the REST admission boundary.
func (a *StorageAdapter) ClaimToken(ctx context.Context, tokenStr, claimID string) (bool, error) {
	claimer, ok := a.store.(business.RegistrationTokenClaimer)
	if !ok {
		return false, fmt.Errorf("registration token store does not support atomic REST claims")
	}
	return claimer.ClaimToken(ctx, tokenStr, claimID)
}

// ReleaseTokenClaim removes an exact REST claim after a pre-issuance failure.
func (a *StorageAdapter) ReleaseTokenClaim(ctx context.Context, tokenStr, claimID string) error {
	claimer, ok := a.store.(business.RegistrationTokenClaimer)
	if !ok {
		return fmt.Errorf("registration token store does not support atomic REST claims")
	}
	return claimer.ReleaseTokenClaim(ctx, tokenStr, claimID)
}

// tokenToData converts a Token to RegistrationTokenData
func tokenToData(token *Token) *business.RegistrationTokenData {
	return &business.RegistrationTokenData{
		ID:            token.ID,
		Token:         token.Token,
		TenantID:      token.TenantID,
		ControllerURL: token.ControllerURL,
		Group:         token.Group,
		CreatedAt:     token.CreatedAt,
		ExpiresAt:     token.ExpiresAt,
		Revoked:       token.Revoked,
		RevokedAt:     token.RevokedAt,
	}
}

// dataToToken converts a RegistrationTokenData to Token
func dataToToken(data *business.RegistrationTokenData) *Token {
	return &Token{
		ID:            data.ID,
		Token:         data.Token,
		TenantID:      data.TenantID,
		ControllerURL: data.ControllerURL,
		Group:         data.Group,
		CreatedAt:     data.CreatedAt,
		ExpiresAt:     data.ExpiresAt,
		Revoked:       data.Revoked,
		RevokedAt:     data.RevokedAt,
	}
}
