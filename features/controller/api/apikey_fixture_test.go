// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"time"
)

// apiKeyFixtureActor is the actor recorded on keys the test fixture mints.
const apiKeyFixtureActor = "test-fixture"

// generateEphemeralKey is a test fixture: it mints a durable API key that expires after
// ttl, through mintAPIKey, so tests exercise the one production key-generation and
// storage path. The key is cached, its record stored and indexed exactly as for a key
// minted by handleCreateAPIKey; the record names apiKeyFixtureActor as its creator.
func (s *Server) generateEphemeralKey(name string, permissions []string, ttl time.Duration, tenantID string) (*APIKey, error) {
	expiresAt := time.Now().UTC().Add(ttl)
	minted, err := s.mintAPIKey(context.Background(), apiKeyMintSpec{
		Name:        name,
		Permissions: permissions,
		TenantID:    tenantID,
		ExpiresAt:   &expiresAt,
		ActorID:     apiKeyFixtureActor,
	})
	if err != nil {
		return nil, err
	}
	return minted.apiKey, nil
}
