// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Store defines the interface for registration token storage.
type Store interface {
	// SaveToken saves a registration token
	SaveToken(ctx context.Context, token *Token) error

	// GetToken retrieves a token by its token string
	GetToken(ctx context.Context, tokenStr string) (*Token, error)

	// ListTokens lists all tokens for a tenant
	ListTokens(ctx context.Context, tenantID string) ([]*Token, error)

	// UpdateToken updates an existing token
	UpdateToken(ctx context.Context, token *Token) error

	// DeleteToken deletes a token
	DeleteToken(ctx context.Context, tokenStr string) error

	// RotateToken atomically revokes all prior tokens for tenant+group and returns a new token.
	// controller_url is inherited from an existing active token.
	// Returns an error if no active tokens exist for the given tenant+group.
	RotateToken(ctx context.Context, tenantID, group string) (*Token, error)
}

// memoryStore is an in-memory implementation of Store (for use within this package only).
type memoryStore struct {
	mu     sync.RWMutex
	tokens map[string]*Token
}

// newMemoryStore creates a new in-memory token store.
func newMemoryStore() *memoryStore {
	return &memoryStore{
		tokens: make(map[string]*Token),
	}
}

// SaveToken saves a registration token.
func (s *memoryStore) SaveToken(ctx context.Context, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token.Token] = token
	return nil
}

// GetToken retrieves a token by its token string.
func (s *memoryStore) GetToken(ctx context.Context, tokenStr string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, exists := s.tokens[tokenStr]
	if !exists {
		return nil, fmt.Errorf("token not found")
	}

	return token, nil
}

// ListTokens lists all tokens for a tenant.
func (s *memoryStore) ListTokens(ctx context.Context, tenantID string) ([]*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var tokens []*Token
	for _, token := range s.tokens {
		if token.TenantID == tenantID {
			tokens = append(tokens, token)
		}
	}

	return tokens, nil
}

// UpdateToken updates an existing token.
func (s *memoryStore) UpdateToken(ctx context.Context, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tokens[token.Token]; !exists {
		return fmt.Errorf("token not found")
	}

	s.tokens[token.Token] = token
	return nil
}

// DeleteToken deletes a token.
func (s *memoryStore) DeleteToken(ctx context.Context, tokenStr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, tokenStr)
	return nil
}

// RotateToken atomically revokes all prior tokens for tenant+group and creates a new token
// under a single write lock, ensuring no overlap window between old and new tokens.
func (s *memoryStore) RotateToken(ctx context.Context, tenantID, group string) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Collect active tokens to identify controller_url and tokens to revoke.
	var controllerURL string
	var tokensToRevoke []string
	found := false
	for _, t := range s.tokens {
		if t.TenantID == tenantID && t.Group == group && !t.Revoked {
			tokensToRevoke = append(tokensToRevoke, t.Token)
			if !found {
				controllerURL = t.ControllerURL
				found = true
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("no active tokens found for tenant %q group %q", tenantID, group)
	}

	// Generate new token string.
	tokenStr, err := GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	now := time.Now()

	// Revoke all prior tokens atomically under the same lock.
	for _, tok := range tokensToRevoke {
		t := s.tokens[tok]
		t.Revoked = true
		t.RevokedAt = &now
		s.tokens[tok] = t
	}

	newToken := &Token{
		Token:         tokenStr,
		TenantID:      tenantID,
		ControllerURL: controllerURL,
		Group:         group,
		CreatedAt:     now,
	}
	s.tokens[tokenStr] = newToken

	return newToken, nil
}
