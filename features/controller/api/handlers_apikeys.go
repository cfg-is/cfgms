// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// agentDevAPIPermissions is the API-key permission set for the agent.dev role.
// Corresponds to the RBAC permissions in features/rbac/defaults.go: steward.read,
// config.read, module.read, tenant.read, and config.validate. No write or admin perms.
var agentDevAPIPermissions = []string{
	"steward:read",
	"steward:list",
	"steward:read-config",
	"steward:read-modules",
	"steward:validate-config",
	"config:list",
	"config:list-deployments",
	"tenant:read",
}

// handleListAPIKeys handles GET /api/v1/api-keys
// M-AUTH-1: List API keys from central secret store, filtered to the authenticated tenant.
// Issue #4574: the store is the source of truth — a key that has never been used on this
// node (and so is not in its cache) is listed all the same.
func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	records, err := s.secretStore.ListSecrets(r.Context(), &secretsif.SecretFilter{
		TenantID: tenantID,
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey),
		},
	})
	if err != nil {
		s.logger.Error("Failed to list API keys from secret store",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list API keys", "STORE_ERROR")
		return
	}

	apiKeys := make([]APIKeyInfo, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, rec := range records {
		// Exact tenant match, as before: the store filter narrows the scan, this
		// check is what bounds the result to the caller's own tenant.
		if rec.TenantID != tenantID {
			continue
		}
		info := apiKeyInfoFromRecord(rec)
		seen[info.ID] = struct{}{}
		apiKeys = append(apiKeys, info)
	}

	// Local-only entries (recordRef == "": the env-gated test keys seeded in New) have
	// no durable record, but they authenticate on this node, so they are listed too.
	s.mu.RLock()
	for _, key := range s.apiKeys {
		if key.recordRef != "" || key.TenantID != tenantID {
			continue
		}
		if _, dup := seen[key.ID]; dup {
			continue
		}
		apiKeys = append(apiKeys, apiKeyInfoFromCache(key))
	}
	s.mu.RUnlock()

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

	// RoleID takes precedence: resolve permissions from the named role.
	// Only agent.dev is supported in this release; future roles extend this map.
	if createReq.RoleID != "" {
		switch createReq.RoleID {
		case "agent.dev":
			if len(createReq.Permissions) > 0 {
				s.writeErrorResponse(w, http.StatusBadRequest,
					"Cannot specify both role_id and permissions", "CONFLICTING_FIELDS")
				return
			}
			createReq.Permissions = agentDevAPIPermissions
		default:
			s.writeErrorResponse(w, http.StatusBadRequest,
				"Unknown role_id: "+createReq.RoleID, "UNKNOWN_ROLE")
			return
		}
	}

	// C1: Validate permissions against the known allow-list. "*" and unknown IDs are rejected.
	for _, p := range createReq.Permissions {
		if !isKnownPermission(p) {
			s.writeErrorResponse(w, http.StatusBadRequest,
				"Unknown or reserved permission ID: "+p, "INVALID_PERMISSION")
			return
		}
	}

	// Issue #4334: a caller may not grant a permission it does not itself hold. This
	// is independent of the tenant-containment check below — it closes the
	// privilege-escalation path where a caller holding only api-key:create could
	// mint a key carrying any permission in the catalogue, including ones the
	// caller was never granted.
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	for _, p := range createReq.Permissions {
		if !s.hasPermission(principal, p) {
			s.writeErrorResponse(w, http.StatusForbidden,
				"Cannot grant a permission you do not hold: "+p, "PERMISSION_ESCALATION")
			return
		}
	}

	// Set default tenant if not specified
	tenantID := createReq.TenantID
	if tenantID == "" {
		tenantID = "default"
	}

	// Issue #4334: the created key's tenant is bounded by the caller's own scope — a
	// tenant-scoped caller cannot mint a key for a sibling tenant, nor for the
	// catch-all "default" tenant outside its own subtree. An unset scope is refused
	// outright (Issue #4316 fail-closed contract): holding api-key:create does not by
	// itself prove a valid caller scope was established.
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if !s.isAuthorizedForTenant(scope, tenantID, "POST /api/v1/api-keys") {
		s.writeErrorResponse(w, http.StatusForbidden,
			"Cannot create an API key outside your tenant scope", "FORBIDDEN")
		return
	}

	// Generate new API key (256-bit cryptographically secure)
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		s.logger.Error("Failed to generate API key", "error", logging.SanitizeLogValue(err.Error()))
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
		recordRef:   keyHash,
		validatedAt: s.apiKeyNow(),
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
		s.logger.Error("Failed to persist API key to secret store", "error", logging.SanitizeLogValue(err.Error()), "id", keyID)
		// Remove from memory cache since we couldn't persist
		s.mu.Lock()
		delete(s.apiKeys, keyString)
		s.mu.Unlock()
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to persist API key", "STORE_ERROR")
		return
	}
	s.apiKeyIdx.put(keyHash, apiKeyIndexEntry{TenantID: tenantID, ID: keyID})

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

	// Bind the API key to the requested role via RBAC role assignment so that
	// the role association is recorded for auditing and management queries.
	if createReq.RoleID != "" && s.rbacManager != nil {
		ctx := rbac.WithSensitiveOperationJustification(r.Context(),
			"api-key creation: binding key "+keyID+" to role "+createReq.RoleID+" in tenant "+tenantID)
		assignErr := s.rbacManager.AssignRole(ctx, &common.RoleAssignment{
			Id:         uuid.New().String(),
			SubjectId:  keyID,
			RoleId:     createReq.RoleID,
			TenantId:   tenantID,
			AssignedBy: "api-admin",
		})
		if assignErr != nil {
			s.logger.Warn("Failed to record RBAC role assignment for API key",
				"id", keyID,
				"role_id", logging.SanitizeLogValue(createReq.RoleID),
				"tenant_id", logging.SanitizeLogValue(tenantID),
				"error", logging.SanitizeLogValue(assignErr.Error()))
			// Non-fatal: the key is usable; the role-assignment record is for audit only.
		}
	}

	s.logger.Info("Created new API key",
		"id", keyID,
		"name", logging.SanitizeLogValue(createReq.Name),
		"tenant_id", logging.SanitizeLogValue(tenantID))

	s.writeResponse(w, http.StatusCreated, result)
}

// handleGetAPIKey handles GET /api/v1/api-keys/{id}
// M-AUTH-1 / Issue #4574: read the key's record from the secret store, so the answer is
// the same on every controller node whether or not the key is cached here.
func (s *Server) handleGetAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["id"]

	if keyID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "API key ID is required", "MISSING_KEY_ID")
		return
	}

	// Issue #4334: tenant containment. Out-of-scope and not-found return the same
	// response so this endpoint cannot be used to probe for a key's existence across
	// tenants.
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	rec, local, err := s.findAPIKeyInScope(r.Context(), keyID, scope, "GET /api/v1/api-keys/{id}")
	if err != nil {
		s.logger.Error("Failed to look up API key in secret store",
			"id", logging.SanitizeLogValue(keyID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up API key", "STORE_ERROR")
		return
	}

	switch {
	case rec != nil:
		s.writeSuccessResponse(w, apiKeyInfoFromRecord(rec))
	case local != nil:
		s.writeSuccessResponse(w, apiKeyInfoFromCache(local))
	default:
		s.writeErrorResponse(w, http.StatusNotFound, "API key not found", "KEY_NOT_FOUND")
	}
}

// handleDeleteAPIKey handles DELETE /api/v1/api-keys/{id}
// M-AUTH-1 / Issue #4574: delete the key's record from the secret store — found there
// whether or not this node has it cached — then evict this node's cache entry. Other
// nodes drop their cached copy on their next re-validation (apiKeyRevalidateInterval).
func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["id"]

	if keyID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "API key ID is required", "MISSING_KEY_ID")
		return
	}

	// Issue #4334: tenant containment. Out-of-scope and not-found return the same
	// response so this endpoint cannot be used to probe for a key's existence across
	// tenants.
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	rec, local, err := s.findAPIKeyInScope(r.Context(), keyID, scope, "DELETE /api/v1/api-keys/{id}")
	if err != nil {
		s.logger.Error("Failed to look up API key in secret store",
			"id", logging.SanitizeLogValue(keyID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to look up API key", "STORE_ERROR")
		return
	}

	var name, tenantID string
	switch {
	case rec != nil:
		if err := s.deleteAPIKeyRecord(r.Context(), rec.TenantID, rec.Key); err != nil &&
			!errors.Is(err, secretsif.ErrSecretNotFound) {
			// Log a category, never err.Error(): the secret ref embeds the key hash.
			// The durable record survives, so the key still authenticates on every
			// node: report the failure rather than claim a revocation that did not
			// happen. (Not-found means a concurrent delete already won — success.)
			s.logger.Warn("Failed to delete API key from secret store",
				"reason", "secret_store_error", "id", logging.SanitizeLogValue(keyID))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete API key", "STORE_ERROR")
			return
		}
		s.apiKeyIdx.remove(rec.Key)
		name, tenantID = rec.Description, rec.TenantID
	case local != nil:
		name, tenantID = local.Name, local.TenantID
	default:
		s.writeErrorResponse(w, http.StatusNotFound, "API key not found", "KEY_NOT_FOUND")
		return
	}

	s.evictCachedAPIKeyByID(keyID)

	s.logger.Info("Deleted API key",
		"id", logging.SanitizeLogValue(keyID),
		"name", logging.SanitizeLogValue(name),
		"tenant_id", logging.SanitizeLogValue(tenantID))

	s.writeSuccessResponse(w, map[string]interface{}{
		"id":      keyID,
		"deleted": true,
	})
}

// findAPIKeyInScope locates the API key with the given ID for a caller holding scope
// (Issue #4574). The secret store is authoritative: the API-key index names the
// record's tenant, and the record is then read from that tenant alone. The local cache
// is consulted only for local-only entries (recordRef == ""), which have no durable
// record. A key outside the caller's scope is reported exactly like a missing one (both
// return nil, nil) so callers cannot distinguish the two. A store read error is
// returned as-is; it is never treated as not-found.
func (s *Server) findAPIKeyInScope(ctx context.Context, keyID string, scope ctxkeys.TenantScope, route string) (*secretsif.SecretMetadata, *APIKey, error) {
	keyHash, entry, found, err := s.locateAPIKeyByID(ctx, keyID)
	if err != nil {
		return nil, nil, err
	}
	if found {
		if !s.isAuthorizedForTenant(scope, entry.TenantID, route) {
			return nil, nil, nil
		}
		// A tenant-scoped, name-filtered listing rather than GetSecret, because an
		// expired key is still a record an operator may inspect or remove and
		// GetSecret refuses expired records. The store skips every other record
		// before decrypting it, so this opens exactly one record.
		records, err := s.secretStore.ListSecrets(ctx, &secretsif.SecretFilter{
			TenantID:       entry.TenantID,
			KeyPrefix:      keyHash,
			IncludeExpired: true,
			Metadata: map[string]string{
				secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey),
			},
		})
		if err != nil {
			return nil, nil, err
		}
		for _, rec := range records {
			if rec.Key == keyHash && rec.TenantID == entry.TenantID && rec.Metadata["id"] == keyID {
				return rec, nil, nil
			}
		}
		// Indexed but gone: deleted by another node since the last refresh.
		s.apiKeyIdx.remove(keyHash)
		return nil, nil, nil
	}

	s.mu.RLock()
	var local *APIKey
	for _, key := range s.apiKeys {
		if key.recordRef == "" && key.ID == keyID {
			local = key
			break
		}
	}
	s.mu.RUnlock()
	if local == nil || !s.isAuthorizedForTenant(scope, local.TenantID, route) {
		return nil, nil, nil
	}
	return nil, local, nil
}

// evictCachedAPIKeyByID drops every cache entry for the key with the given ID.
func (s *Server) evictCachedAPIKeyByID(keyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for keyString, key := range s.apiKeys {
		if key.ID == keyID {
			delete(s.apiKeys, keyString)
		}
	}
}

// apiKeyInfoFromRecord renders a secret-store API-key record as its public view.
func apiKeyInfoFromRecord(rec *secretsif.SecretMetadata) APIKeyInfo {
	return APIKeyInfo{
		ID:          rec.Metadata["id"],
		Name:        rec.Description,
		Permissions: parsePermissions(rec.Metadata["permissions"]),
		CreatedAt:   rec.CreatedAt,
		ExpiresAt:   rec.ExpiresAt,
		TenantID:    rec.TenantID,
	}
}

// apiKeyInfoFromCache renders a cached API key as its public view (never the key itself).
func apiKeyInfoFromCache(key *APIKey) APIKeyInfo {
	return APIKeyInfo{
		ID:          key.ID,
		Name:        key.Name,
		Permissions: key.Permissions,
		CreatedAt:   key.CreatedAt,
		ExpiresAt:   key.ExpiresAt,
		TenantID:    key.TenantID,
	}
}

// deleteAPIKeyRecord deletes an API key's durable record, addressing it by explicit
// tenant when the store supports it (Issue #4574).
func (s *Server) deleteAPIKeyRecord(ctx context.Context, tenantID, keyHash string) error {
	if acc, ok := s.secretStore.(secretsif.TenantSecretAccessor); ok {
		return acc.DeleteTenantSecret(ctx, tenantID, keyHash)
	}
	return s.secretStore.DeleteSecret(ctx, apiKeyStoreRef(tenantID, keyHash))
}

// apiKeyStoreRef is the secret-store path of an API key's durable record. It is a
// lookup path, not the credential itself. Used only for a store that does not offer
// secretsif.TenantSecretAccessor; such a store resolves the combined reference itself.
func apiKeyStoreRef(tenantID, keyHash string) string {
	return tenantID + "/" + keyHash
}

// apiKeyNow is the clock API-key re-validation reads (Issue #4574).
func (s *Server) apiKeyNow() time.Time {
	if s.apiKeyClock != nil {
		return s.apiKeyClock()
	}
	return time.Now()
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
		recordRef:   keyHash,
		validatedAt: s.apiKeyNow(),
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
	s.apiKeyIdx.put(keyHash, apiKeyIndexEntry{TenantID: tenantID, ID: keyID})

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
