// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// Issue #4574: the secret store, not a node's in-memory cache, is the source of truth
// for API keys. These tests drive real SOPS secret stores on t.TempDir() storage.

// mintStoreAPIKey creates a durable API key through generateEphemeralKey and returns
// its plaintext and ID.
func mintStoreAPIKey(t *testing.T, server *Server, permissions []string, tenantID string) (string, string) {
	t.Helper()
	key, err := server.generateEphemeralKey("store-test-key", permissions, time.Hour, tenantID)
	require.NoError(t, err)
	return key.Key, key.ID
}

// dropFromCache simulates a node that has never seen the key (fresh start, or a
// different cluster node): the key exists only in the secret store.
func dropFromCache(server *Server, apiKey string) {
	server.mu.Lock()
	delete(server.apiKeys, apiKey)
	server.mu.Unlock()
}

func isCached(server *Server, apiKey string) bool {
	server.mu.RLock()
	defer server.mu.RUnlock()
	_, ok := server.apiKeys[apiKey]
	return ok
}

// authStatus sends an authenticated request through the full router and returns the
// status. GET /api/v1/api-keys requires api-key:list, which every key minted here holds.
func authStatus(server *Server, apiKey string) int {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec.Code
}

// stewardsStatus authenticates against GET /api/v1/stewards (steward:list), a route
// that does not itself read the secret store — so it isolates the auth outcome when
// the store is made to fail.
func stewardsStatus(server *Server, apiKey string) int {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec.Code
}

func callDeleteAPIKey(server *Server, keyID string, scope ctxkeys.TenantScope) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/"+keyID, nil)
	req = mux.SetURLVars(req, map[string]string{"id": keyID})
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, scope))
	rec := httptest.NewRecorder()
	server.handleDeleteAPIKey(rec, req)
	return rec
}

// listedIDs returns the key IDs handleListAPIKeys reports for tenantID.
func listedIDs(t *testing.T, server *Server, tenantID string) []string {
	t.Helper()
	rec := callHandleListAPIKeys(server, tenantID)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var resp struct {
		Data []APIKeyInfo `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	ids := make([]string, 0, len(resp.Data))
	for _, k := range resp.Data {
		ids = append(ids, k.ID)
	}
	return ids
}

// steppingClock is an injectable clock for apiKeyClock.
type steppingClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *steppingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *steppingClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// setupPeerServers returns two API servers backed by two independent SOPS secret-store
// instances over the same storage directory and encryption key — two controller nodes
// sharing one durable store, each with its own in-memory API-key cache.
func setupPeerServers(t *testing.T) (*Server, *Server) {
	t.Helper()
	serverA := setupTestServer(t)
	repoPath := os.Getenv("CFGMS_SECRETS_REPO_PATH")
	keyFile := os.Getenv("CFGMS_SECRETS_KEY_FILE")

	serverB := setupTestServer(t)

	// Point node B at node A's secret storage with a store instance of its own.
	t.Setenv("CFGMS_SECRETS_REPO_PATH", repoPath)
	t.Setenv("CFGMS_SECRETS_KEY_FILE", keyFile)
	sharedForB, err := NewSecretStore(serverB.cfg)
	require.NoError(t, err)
	require.NoError(t, serverB.secretStore.Close())
	serverB.secretStore = sharedForB
	return serverA, serverB
}

// TestDeleteAPIKey_StoreOnlyKey_Succeeds is the AC: deleting a key that is in the
// store but not in this node's cache succeeds (not 404), removes the durable record,
// and the key no longer authenticates.
func TestDeleteAPIKey_StoreOnlyKey_Succeeds(t *testing.T) {
	server := setupTestServer(t)
	apiKey, keyID := mintStoreAPIKey(t, server, []string{"api-key:list"}, "tenant-a")
	dropFromCache(server, apiKey)

	rec := callDeleteAPIKey(server, keyID, ctxkeys.NewTenantScope("tenant-a"))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	got, err := server.lookupAPIKeyRecord(context.Background(), "", hashAPIKey(apiKey))
	require.NoError(t, err)
	assert.Nil(t, got, "the durable record must be gone")

	assert.Equal(t, http.StatusUnauthorized, authStatus(server, apiKey))
}

// TestDeleteAPIKey_EvictsLocalCacheImmediately verifies the node that serves the delete
// rejects the key at once, without waiting for re-validation.
func TestDeleteAPIKey_EvictsLocalCacheImmediately(t *testing.T) {
	server := setupTestServer(t)
	apiKey, keyID := mintStoreAPIKey(t, server, []string{"api-key:list"}, "tenant-a")
	require.Equal(t, http.StatusOK, authStatus(server, apiKey))

	rec := callDeleteAPIKey(server, keyID, ctxkeys.NewTenantScope("tenant-a"))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	assert.False(t, isCached(server, apiKey))
	assert.Equal(t, http.StatusUnauthorized, authStatus(server, apiKey))
}

// TestDeleteAPIKey_StoreOnlyKey_SiblingTenant_Returns404 verifies moving the lookup to
// the store did not widen who may delete: a sibling-tenant caller gets the same 404 as
// for a missing key, and the record survives.
func TestDeleteAPIKey_StoreOnlyKey_SiblingTenant_Returns404(t *testing.T) {
	server := setupTestServer(t)
	apiKey, keyID := mintStoreAPIKey(t, server, []string{"api-key:list"}, "tenant-b")
	dropFromCache(server, apiKey)

	rec := callDeleteAPIKey(server, keyID, ctxkeys.NewTenantScope("tenant-a"))
	assert.Equal(t, http.StatusNotFound, rec.Code, "body: %s", rec.Body.String())

	got, err := server.lookupAPIKeyRecord(context.Background(), "", hashAPIKey(apiKey))
	require.NoError(t, err)
	assert.NotNil(t, got, "a cross-tenant delete attempt must not remove the record")
	assert.Equal(t, http.StatusOK, authStatus(server, apiKey))
}

// TestDeleteAPIKey_UnknownID_Returns404 verifies a key in no store and no cache is 404.
func TestDeleteAPIKey_UnknownID_Returns404(t *testing.T) {
	server := setupTestServer(t)
	rec := callDeleteAPIKey(server, "no-such-key-id", ctxkeys.NewRootScope())
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestGetAPIKey_StoreOnlyKey_Found verifies GET by ID answers from the store too.
func TestGetAPIKey_StoreOnlyKey_Found(t *testing.T) {
	server := setupTestServer(t)
	apiKey, keyID := mintStoreAPIKey(t, server, []string{"api-key:list"}, "tenant-a")
	dropFromCache(server, apiKey)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys/"+keyID, nil)
	req = mux.SetURLVars(req, map[string]string{"id": keyID})
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("tenant-a")))
	rec := httptest.NewRecorder()
	server.handleGetAPIKey(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), keyID)
	assert.NotContains(t, rec.Body.String(), apiKey, "the key itself is never returned")
}

// TestListAPIKeys_IncludesStoreOnlyKeys is the AC: listing returns keys present in the
// store but not cached on this node, and still only the caller's tenant's keys.
func TestListAPIKeys_IncludesStoreOnlyKeys(t *testing.T) {
	server := setupTestServer(t)
	keyA, idA := mintStoreAPIKey(t, server, []string{"api-key:list"}, "tenant-a")
	keyB, idB := mintStoreAPIKey(t, server, []string{"api-key:list"}, "tenant-b")
	dropFromCache(server, keyA)
	dropFromCache(server, keyB)

	ids := listedIDs(t, server, "tenant-a")
	assert.Contains(t, ids, idA)
	assert.NotContains(t, ids, idB, "another tenant's key must never be listed")
}

// TestLoadAPIKeyFromStore_FindsKeyInAnyTenant is the AC that the lazy load no longer
// searches one hard-coded tenant: a key minted for a tenant other than "default" (or
// the root) authenticates on a node that has never cached it.
func TestLoadAPIKeyFromStore_FindsKeyInAnyTenant(t *testing.T) {
	server := setupTestServer(t)
	apiKey, keyID := mintStoreAPIKey(t, server, []string{"api-key:list"}, "tenant-x")
	dropFromCache(server, apiKey)

	assert.Equal(t, http.StatusOK, authStatus(server, apiKey))

	server.mu.RLock()
	cached := server.apiKeys[apiKey]
	server.mu.RUnlock()
	require.NotNil(t, cached)
	assert.Equal(t, keyID, cached.ID)
	assert.Equal(t, "tenant-x", cached.TenantID)
}

// TestAPIKey_DeleteOnPeerNode_RejectedWithinBound is the AC: with two API servers
// sharing one store, a key deleted via server A is rejected by server B within
// apiKeyRevalidateInterval.
func TestAPIKey_DeleteOnPeerNode_RejectedWithinBound(t *testing.T) {
	serverA, serverB := setupPeerServers(t)
	clockB := &steppingClock{now: time.Now()}
	serverB.apiKeyClock = clockB.Now

	apiKey, keyID := mintStoreAPIKey(t, serverA, []string{"api-key:list"}, "tenant-a")

	// Node B has never seen the key; it loads it from the shared store and caches it.
	require.Equal(t, http.StatusOK, authStatus(serverB, apiKey))
	require.True(t, isCached(serverB, apiKey))

	// Node B lists it and can delete it without having created it.
	assert.Contains(t, listedIDs(t, serverB, "tenant-a"), keyID)

	rec := callDeleteAPIKey(serverA, keyID, ctxkeys.NewTenantScope("tenant-a"))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, http.StatusUnauthorized, authStatus(serverA, apiKey), "the deleting node rejects at once")

	// Inside the re-validation interval node B may still serve its cached copy.
	clockB.Advance(apiKeyRevalidateInterval - time.Second)
	assert.Equal(t, http.StatusOK, authStatus(serverB, apiKey))

	// At the bound node B re-reads the store, finds the record gone and rejects.
	clockB.Advance(time.Second)
	assert.Equal(t, http.StatusUnauthorized, authStatus(serverB, apiKey))
	assert.False(t, isCached(serverB, apiKey), "the revoked entry is evicted")
	assert.NotContains(t, listedIDs(t, serverB, "tenant-a"), keyID)
}

// TestAPIKey_DeleteOnPeerNode_ViaPeerThatNeverCachedIt covers the restart case across
// nodes: node B deletes a key it has never cached, and node A (which has) rejects it
// once its entry is re-validated.
func TestAPIKey_DeleteOnPeerNode_ViaPeerThatNeverCachedIt(t *testing.T) {
	serverA, serverB := setupPeerServers(t)
	clockA := &steppingClock{now: time.Now()}
	serverA.apiKeyClock = clockA.Now

	apiKey, keyID := mintStoreAPIKey(t, serverA, []string{"api-key:list"}, "tenant-a")
	require.Equal(t, http.StatusOK, authStatus(serverA, apiKey))

	rec := callDeleteAPIKey(serverB, keyID, ctxkeys.NewTenantScope("tenant-a"))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	clockA.Advance(apiKeyRevalidateInterval)
	assert.Equal(t, http.StatusUnauthorized, authStatus(serverA, apiKey))
}

// failingListSecretStore wraps a real SecretStore and, while failing is set, makes
// ListSecrets return an error — a store outage seen by re-validation.
type failingListSecretStore struct {
	secretsif.SecretStore
	mu      sync.Mutex
	failing bool
}

func (s *failingListSecretStore) setFailing(v bool) {
	s.mu.Lock()
	s.failing = v
	s.mu.Unlock()
}

func (s *failingListSecretStore) ListSecrets(ctx context.Context, filter *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	s.mu.Lock()
	failing := s.failing
	s.mu.Unlock()
	if failing {
		return nil, errors.New("simulated store outage")
	}
	return s.SecretStore.ListSecrets(ctx, filter)
}

// TestAPIKey_RevalidationStoreError_ServesUntilMaxStalenessThenFailsClosed verifies
// the documented outage behaviour: a transient store error keeps a cached key serving
// while its last successful validation is younger than apiKeyMaxStaleness, then the
// request is refused until the store answers again.
func TestAPIKey_RevalidationStoreError_ServesUntilMaxStalenessThenFailsClosed(t *testing.T) {
	server := setupTestServer(t)
	clock := &steppingClock{now: time.Now()}
	server.apiKeyClock = clock.Now
	apiKey, _ := mintStoreAPIKey(t, server, []string{"steward:list"}, "tenant-a")

	store := &failingListSecretStore{SecretStore: server.secretStore}
	server.secretStore = store
	store.setFailing(true)

	clock.Advance(apiKeyRevalidateInterval)
	assert.Equal(t, http.StatusOK, stewardsStatus(server, apiKey), "within the staleness bound the cached key serves")

	clock.Advance(apiKeyMaxStaleness - apiKeyRevalidateInterval)
	assert.Equal(t, http.StatusServiceUnavailable, stewardsStatus(server, apiKey), "past the bound the request fails closed")
	assert.True(t, isCached(server, apiKey), "a store error is not a revocation; the entry stays cached")

	store.setFailing(false)
	assert.Equal(t, http.StatusOK, stewardsStatus(server, apiKey), "once the store answers the key works again")
}

// TestAPIKey_ExpiredKeyStopsWorking verifies a cached store-backed key is refused once
// its expiry passes, on the API-key clock.
func TestAPIKey_ExpiredKeyStopsWorking(t *testing.T) {
	server := setupTestServer(t)
	clock := &steppingClock{now: time.Now()}
	server.apiKeyClock = clock.Now
	apiKey, _ := mintStoreAPIKey(t, server, []string{"api-key:list"}, "tenant-a")
	require.Equal(t, http.StatusOK, authStatus(server, apiKey))

	clock.Advance(time.Hour + time.Second)
	assert.Equal(t, http.StatusUnauthorized, authStatus(server, apiKey))
}

// errDeleteSecretStore wraps a real SecretStore and makes DeleteSecret fail with a
// storage error.
type errDeleteSecretStore struct {
	secretsif.SecretStore
}

func (s *errDeleteSecretStore) DeleteSecret(context.Context, string) error {
	return errors.New("failed to delete secret: storage error")
}

// TestDeleteAPIKey_StoreDeleteFails_Returns500 verifies a failed durable delete is
// reported, not hidden behind a 200: the record survives, so the key still
// authenticates on every node.
func TestDeleteAPIKey_StoreDeleteFails_Returns500(t *testing.T) {
	server := setupTestServer(t)
	apiKey, keyID := mintStoreAPIKey(t, server, []string{"api-key:list"}, "tenant-a")
	server.secretStore = &errDeleteSecretStore{SecretStore: server.secretStore}

	rec := callDeleteAPIKey(server, keyID, ctxkeys.NewTenantScope("tenant-a"))
	assert.Equal(t, http.StatusInternalServerError, rec.Code, "body: %s", rec.Body.String())
	assert.Equal(t, http.StatusOK, authStatus(server, apiKey), "the record survived, so the key still works")
}
