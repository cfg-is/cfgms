// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

import (
	"context"
	"fmt"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Store defines the interface for registration token storage.
type Store interface {
	// SaveToken saves a registration token
	SaveToken(ctx context.Context, token *Token) error

	// GetToken retrieves a token by its token string
	GetToken(ctx context.Context, tokenStr string) (*Token, error)

	// GetTokenByID retrieves a token by its stable UUID (Issue #2970).
	GetTokenByID(ctx context.Context, id string) (*Token, error)

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

	// ClaimToken atomically reserves a token at the REST admission boundary.
	// created is true only for the caller that won the claim. A retry from the
	// same device identity returns created=false without an error.
	ClaimToken(ctx context.Context, tokenStr, claimID string) (created bool, err error)

	// ReleaseTokenClaim removes an exact claim after a pre-issuance failure.
	ReleaseTokenClaim(ctx context.Context, tokenStr, claimID string) error
}

// memoryStore is an in-memory implementation of Store (for use within this package only).
type memoryStore struct {
	mu     sync.RWMutex
	tokens map[string]*Token // keyed by token string
	byID   map[string]string // id → token string
	claims map[string]string
}

// newMemoryStore creates a new in-memory token store.
func newMemoryStore() *memoryStore {
	return &memoryStore{
		tokens: make(map[string]*Token),
		byID:   make(map[string]string),
		claims: make(map[string]string),
	}
}

// SaveToken saves a registration token. Tokens saved without a stable ID receive a
// generated one so that every stored token is addressable by ID (Issue #2970),
// matching the durable store implementations.
func (s *memoryStore) SaveToken(ctx context.Context, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if token.ID == "" {
		// Preserve the ID already assigned to this token string, if any.
		if existing, ok := s.tokens[token.Token]; ok && existing.ID != "" {
			token.ID = existing.ID
		} else {
			id, err := GenerateTokenID()
			if err != nil {
				return fmt.Errorf("failed to generate token ID: %w", err)
			}
			token.ID = id
		}
	}

	s.tokens[token.Token] = token
	s.byID[token.ID] = token.Token
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

// GetTokenByID retrieves a token by its stable UUID.
func (s *memoryStore) GetTokenByID(ctx context.Context, id string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tokenStr, exists := s.byID[id]
	if !exists {
		return nil, fmt.Errorf("token not found")
	}
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

// DeleteToken deletes a token and its ID index entry.
func (s *memoryStore) DeleteToken(ctx context.Context, tokenStr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if token, ok := s.tokens[tokenStr]; ok && token.ID != "" {
		delete(s.byID, token.ID)
	}
	delete(s.tokens, tokenStr)
	delete(s.claims, tokenStr)
	return nil
}

// ClaimToken atomically reserves a valid token for one device identity.
func (s *memoryStore) ClaimToken(_ context.Context, tokenStr, claimID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.tokens[tokenStr]
	if !ok || !token.IsValid() {
		return false, fmt.Errorf("registration token is invalid, expired, or revoked")
	}
	if existing, ok := s.claims[tokenStr]; ok {
		if existing == claimID {
			return false, nil
		}
		return false, business.ErrRegistrationTokenAlreadyClaimed
	}
	s.claims[tokenStr] = claimID
	return true, nil
}

// ReleaseTokenClaim removes only the matching claim.
func (s *memoryStore) ReleaseTokenClaim(_ context.Context, tokenStr, claimID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.claims[tokenStr]; ok && existing == claimID {
		delete(s.claims, tokenStr)
	}
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

	// Generate new token string and stable ID.
	tokenStr, err := GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	tokenID, err := GenerateTokenID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(DefaultTokenTTL)

	// Revoke all prior tokens atomically under the same lock.
	for _, tok := range tokensToRevoke {
		t := s.tokens[tok]
		t.Revoked = true
		t.RevokedAt = &now
		s.tokens[tok] = t
	}

	newToken := &Token{
		ID:            tokenID,
		Token:         tokenStr,
		TenantID:      tenantID,
		ControllerURL: controllerURL,
		Group:         group,
		CreatedAt:     now,
		ExpiresAt:     &expiresAt,
	}
	s.tokens[tokenStr] = newToken
	s.byID[tokenID] = tokenStr

	return newToken, nil
}
