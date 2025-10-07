package registration

import (
	"context"
	"fmt"
	"sync"
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
}

// MemoryStore is an in-memory implementation of Store (for development/testing).
type MemoryStore struct {
	mu     sync.RWMutex
	tokens map[string]*Token
}

// NewMemoryStore creates a new in-memory token store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tokens: make(map[string]*Token),
	}
}

// SaveToken saves a registration token.
func (s *MemoryStore) SaveToken(ctx context.Context, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token.Token] = token
	return nil
}

// GetToken retrieves a token by its token string.
func (s *MemoryStore) GetToken(ctx context.Context, tokenStr string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, exists := s.tokens[tokenStr]
	if !exists {
		return nil, fmt.Errorf("token not found")
	}

	return token, nil
}

// ListTokens lists all tokens for a tenant.
func (s *MemoryStore) ListTokens(ctx context.Context, tenantID string) ([]*Token, error) {
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
func (s *MemoryStore) UpdateToken(ctx context.Context, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.tokens[token.Token]; !exists {
		return fmt.Errorf("token not found")
	}

	s.tokens[token.Token] = token
	return nil
}

// DeleteToken deletes a token.
func (s *MemoryStore) DeleteToken(ctx context.Context, tokenStr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tokens, tokenStr)
	return nil
}
