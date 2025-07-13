package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// handleListAPIKeys handles GET /api/v1/api-keys
func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var apiKeys []APIKeyInfo
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

	// Generate new API key
	keyBytes := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(keyBytes); err != nil {
		s.logger.Error("Failed to generate API key", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate API key", "INTERNAL_ERROR")
		return
	}

	// Encode as base64
	keyString := base64.URLEncoding.EncodeToString(keyBytes)

	// Create API key object
	apiKey := &APIKey{
		ID:          uuid.New().String(),
		Key:         keyString,
		Name:        createReq.Name,
		Permissions: createReq.Permissions,
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   createReq.ExpiresAt,
		TenantID:    createReq.TenantID,
	}

	// Store API key
	s.mu.Lock()
	s.apiKeys[keyString] = apiKey
	s.mu.Unlock()

	// Create response (includes the actual key only on creation)
	result := APIKeyCreateResult{
		APIKeyInfo: APIKeyInfo{
			ID:          apiKey.ID,
			Name:        apiKey.Name,
			Permissions: apiKey.Permissions,
			CreatedAt:   apiKey.CreatedAt,
			ExpiresAt:   apiKey.ExpiresAt,
			TenantID:    apiKey.TenantID,
		},
		Key: keyString,
	}

	s.logger.Info("Created new API key",
		"id", apiKey.ID,
		"name", apiKey.Name,
		"tenant_id", apiKey.TenantID)

	s.writeResponse(w, http.StatusCreated, result)
}

// handleGetAPIKey handles GET /api/v1/api-keys/{id}
func (s *Server) handleGetAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["id"]

	if keyID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "API key ID is required", "MISSING_KEY_ID")
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find API key by ID
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
func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["id"]

	if keyID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "API key ID is required", "MISSING_KEY_ID")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Find and delete API key by ID
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

	// Delete the key
	delete(s.apiKeys, keyToDelete)

	s.logger.Info("Deleted API key",
		"id", foundKey.ID,
		"name", foundKey.Name)

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":      keyID,
		"deleted": true,
	})
}

// generateDefaultAPIKey creates a default API key for initial setup
func (s *Server) generateDefaultAPIKey() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Don't create if keys already exist
	if len(s.apiKeys) > 0 {
		return nil
	}

	// Generate default API key
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return err
	}

	keyString := base64.URLEncoding.EncodeToString(keyBytes)

	// Create default API key with admin permissions
	defaultKey := &APIKey{
		ID:   uuid.New().String(),
		Key:  keyString,
		Name: "Default Admin Key",
		Permissions: []string{
			"stewards:read",
			"stewards:write",
			"config:read",
			"config:write",
			"certificates:read",
			"certificates:write",
			"rbac:read",
			"rbac:write",
			"api-keys:read",
			"api-keys:write",
		},
		CreatedAt: time.Now().UTC(),
		TenantID:  "default",
	}

	s.apiKeys[keyString] = defaultKey

	s.logger.Info("Generated default API key",
		"id", defaultKey.ID,
		"key", keyString) // Log the key for initial setup

	return nil
}
