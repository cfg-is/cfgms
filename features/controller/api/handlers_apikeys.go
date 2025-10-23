// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// handleListAPIKeys handles GET /api/v1/api-keys
// M-AUTH-1: List API keys from central secret store
func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	// M-AUTH-1: For now, list ALL API keys across all tenants from memory cache
	// TODO: Add proper tenant filtering based on RBAC permissions
	s.mu.RLock()
	defer s.mu.RUnlock()

	apiKeys := make([]APIKeyInfo, 0, len(s.apiKeys))
	for _, key := range s.apiKeys {
		apiKeys = append(apiKeys, APIKeyInfo{
			ID:          key.ID,
			Name:        key.Name,
			Permissions: key.Permissions,
			CreatedAt:   key.CreatedAt,
			ExpiresAt:   key.ExpiresAt,
			TenantID:    key.TenantID,
		})
	}

	s.writeSuccessResponse(w, apiKeys)
}

// handleCreateAPIKey handles POST /api/v1/api-keys
// M-AUTH-1: Create API key and store in central secret store
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var createReq APIKeyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&createReq); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON body", "INVALID_JSON")
		return
	}

	// Validate required fields
	if createReq.Name == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "API key name is required", "MISSING_NAME")
		return
	}

	// Set default tenant if not specified
	tenantID := createReq.TenantID
	if tenantID == "" {
		tenantID = "default"
	}

	// Generate new API key (256-bit cryptographically secure)
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		s.logger.Error("Failed to generate API key", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate API key", "INTERNAL_ERROR")
		return
	}

	// Encode as base64
	keyString := base64.URLEncoding.EncodeToString(keyBytes)
	keyID := uuid.New().String()

	// Hash the key for storage (SHA-256)
	keyHash := hashAPIKey(keyString)

	// Create API key object for in-memory cache
	apiKey := &APIKey{
		ID:          keyID,
		Key:         keyString,
		Name:        createReq.Name,
		Permissions: createReq.Permissions,
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   createReq.ExpiresAt,
		TenantID:    tenantID,
	}

	// Store API key in memory cache
	s.mu.Lock()
	s.apiKeys[keyString] = apiKey
	s.mu.Unlock()

	// M-AUTH-1: Store API key hash in secret store with metadata
	secretReq := &secretsif.SecretRequest{
		Key:         keyHash, // Store hash as key for lookup
		Value:       keyHash, // Store hash as value (we never store plaintext keys)
		TenantID:    tenantID,
		CreatedBy:   "api-admin", // TODO: Get from authenticated user context
		Description: createReq.Name,
		Tags:        []string{"api-key"},
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey),
			"id":                            keyID,
			"permissions":                   serializePermissions(createReq.Permissions),
		},
	}

	// Set TTL if expiration is specified
	if createReq.ExpiresAt != nil {
		secretReq.TTL = time.Until(*createReq.ExpiresAt)
	}

	if err := s.secretStore.StoreSecret(r.Context(), secretReq); err != nil {
		s.logger.Error("Failed to persist API key to secret store", "error", err, "id", keyID)
		// Remove from memory cache since we couldn't persist
		s.mu.Lock()
		delete(s.apiKeys, keyString)
		s.mu.Unlock()
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to persist API key", "STORE_ERROR")
		return
	}

	// Create response (includes the actual key only on creation)
	result := APIKeyCreateResult{
		APIKeyInfo: APIKeyInfo{
			ID:          keyID,
			Name:        createReq.Name,
			Permissions: createReq.Permissions,
			CreatedAt:   apiKey.CreatedAt,
			ExpiresAt:   createReq.ExpiresAt,
			TenantID:    tenantID,
		},
		Key: keyString,
	}

	s.logger.Info("Created new API key",
		"id", keyID,
		"name", createReq.Name,
		"tenant_id", tenantID)

	s.writeResponse(w, http.StatusCreated, result)
}

// handleGetAPIKey handles GET /api/v1/api-keys/{id}
// M-AUTH-1: Get API key from memory cache by ID
func (s *Server) handleGetAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["id"]

	if keyID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "API key ID is required", "MISSING_KEY_ID")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find API key by ID in memory cache
	var foundKey *APIKey
	for _, key := range s.apiKeys {
		if key.ID == keyID {
			foundKey = key
			break
		}
	}

	if foundKey == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "API key not found", "KEY_NOT_FOUND")
		return
	}

	// Return key info without the actual key
	keyInfo := APIKeyInfo{
		ID:          foundKey.ID,
		Name:        foundKey.Name,
		Permissions: foundKey.Permissions,
		CreatedAt:   foundKey.CreatedAt,
		ExpiresAt:   foundKey.ExpiresAt,
		TenantID:    foundKey.TenantID,
	}

	s.writeSuccessResponse(w, keyInfo)
}

// handleDeleteAPIKey handles DELETE /api/v1/api-keys/{id}
// M-AUTH-1: Delete API key from memory cache and secret store
func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["id"]

	if keyID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "API key ID is required", "MISSING_KEY_ID")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Find and delete API key by ID from memory cache
	var keyToDelete string
	var foundKey *APIKey
	for keyString, key := range s.apiKeys {
		if key.ID == keyID {
			keyToDelete = keyString
			foundKey = key
			break
		}
	}

	if foundKey == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "API key not found", "KEY_NOT_FOUND")
		return
	}

	// Delete from memory cache
	delete(s.apiKeys, keyToDelete)

	// M-AUTH-1: Also delete from secret store
	keyHash := hashAPIKey(keyToDelete)
	secretKey := fmt.Sprintf("%s/%s", foundKey.TenantID, keyHash)
	if err := s.secretStore.DeleteSecret(r.Context(), secretKey); err != nil {
		s.logger.Warn("Failed to delete API key from secret store (memory cache already cleared)",
			"error", err, "id", keyID)
		// Continue anyway - key is removed from memory
	}

	s.logger.Info("Deleted API key",
		"id", foundKey.ID,
		"name", foundKey.Name,
		"tenant_id", foundKey.TenantID)

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":      keyID,
		"deleted": true,
	})
}

// generateEphemeralKey creates an API key with a specified TTL
// M-AUTH-1: Generate ephemeral API key and store in secret store
func (s *Server) generateEphemeralKey(name string, permissions []string, ttl time.Duration, tenantID string) (*APIKey, error) {
	// Generate cryptographically secure API key
	keyBytes := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral API key: %w", err)
	}

	keyString := base64.URLEncoding.EncodeToString(keyBytes)
	keyID := uuid.New().String()
	keyHash := hashAPIKey(keyString)
	expiresAt := time.Now().UTC().Add(ttl)

	// Create ephemeral API key
	apiKey := &APIKey{
		ID:          keyID,
		Key:         keyString,
		Name:        name,
		Permissions: permissions,
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   &expiresAt,
		TenantID:    tenantID,
	}

	// Store in memory cache
	s.mu.Lock()
	s.apiKeys[keyString] = apiKey
	s.mu.Unlock()

	// M-AUTH-1: Store in secret store with TTL
	secretReq := &secretsif.SecretRequest{
		Key:         keyHash,
		Value:       keyHash,
		TenantID:    tenantID,
		CreatedBy:   "system",
		Description: name,
		Tags:        []string{"api-key", "ephemeral"},
		TTL:         ttl,
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey),
			"id":                            keyID,
			"permissions":                   serializePermissions(permissions),
		},
	}

	ctx := context.Background()
	if err := s.secretStore.StoreSecret(ctx, secretReq); err != nil {
		// Remove from memory on storage failure
		s.mu.Lock()
		delete(s.apiKeys, keyString)
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to store ephemeral key: %w", err)
	}

	s.logger.Info("Generated ephemeral API key",
		"id", apiKey.ID,
		"name", apiKey.Name,
		"tenant_id", apiKey.TenantID,
		"ttl", ttl,
		"expires_at", expiresAt.Format(time.RFC3339))

	return apiKey, nil
}

// M-AUTH-1: Helper functions for API key management

// hashAPIKey creates a SHA-256 hash of an API key for secure storage
func hashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// serializePermissions converts permissions slice to comma-separated string
func serializePermissions(permissions []string) string {
	return strings.Join(permissions, ",")
}

// parsePermissions converts comma-separated string to permissions slice
func parsePermissions(permissionsStr string) []string {
	if permissionsStr == "" {
		return []string{}
	}
	return strings.Split(permissionsStr, ",")
}
