// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	got, err := server.readAPIKeyRecord(context.Background(), "tenant-a", hashAPIKey(apiKey))
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

	got, err := server.readAPIKeyRecord(context.Background(), "tenant-b", hashAPIKey(apiKey))
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

	// Node B has never seen the key; once its index refreshes it loads it from the
	// shared store and caches it.
	clockB.Advance(apiKeyIndexMissRefreshFloor)
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
	clockB := &steppingClock{now: time.Now()}
	serverB.apiKeyClock = clockB.Now

	apiKey, keyID := mintStoreAPIKey(t, serverA, []string{"api-key:list"}, "tenant-a")
	require.Equal(t, http.StatusOK, authStatus(serverA, apiKey))

	clockB.Advance(apiKeyIndexMissRefreshFloor)
	rec := callDeleteAPIKey(serverB, keyID, ctxkeys.NewTenantScope("tenant-a"))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	clockA.Advance(apiKeyRevalidateInterval)
	assert.Equal(t, http.StatusUnauthorized, authStatus(serverA, apiKey))
}

// failingReadSecretStore wraps a real SecretStore and, while failing is set, makes
// reads (GetSecret and ListSecrets) return an error — a store outage.
type failingReadSecretStore struct {
	secretsif.SecretStore
	mu      sync.Mutex
	failing bool
}

func (s *failingReadSecretStore) setFailing(v bool) {
	s.mu.Lock()
	s.failing = v
	s.mu.Unlock()
}

func (s *failingReadSecretStore) isFailing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failing
}

func (s *failingReadSecretStore) GetSecret(ctx context.Context, key string) (*secretsif.Secret, error) {
	if s.isFailing() {
		return nil, errors.New("simulated store outage")
	}
	return s.SecretStore.GetSecret(ctx, key)
}

func (s *failingReadSecretStore) ListSecrets(ctx context.Context, filter *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	if s.isFailing() {
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

	store := &failingReadSecretStore{SecretStore: server.secretStore}
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

// countingListSecretStore wraps a real SecretStore and counts ListSecrets calls — the
// only store operation that scans.
type countingListSecretStore struct {
	secretsif.SecretStore
	mu    sync.Mutex
	lists int
}

func (s *countingListSecretStore) ListSecrets(ctx context.Context, filter *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	s.mu.Lock()
	s.lists++
	s.mu.Unlock()
	return s.SecretStore.ListSecrets(ctx, filter)
}

func (s *countingListSecretStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lists
}

// TestAPIKey_UnknownKeyFlood_AtMostOneScanPerFloor verifies an unauthenticated flood
// of unknown API keys cannot drive store scans: N concurrent unknown-key requests cost
// at most one listing per apiKeyIndexMissRefreshFloor, and none while the index is
// fresher than the floor.
func TestAPIKey_UnknownKeyFlood_AtMostOneScanPerFloor(t *testing.T) {
	server := setupTestServer(t)
	clock := &steppingClock{now: time.Now()}
	server.apiKeyClock = clock.Now
	store := &countingListSecretStore{SecretStore: server.secretStore}
	server.secretStore = store

	flood := func(round int) {
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				// Distinct sources, so the per-source authDefense budget does not
				// absorb the flood before it reaches API-key resolution.
				req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
				req.RemoteAddr = fmt.Sprintf("10.%d.%d.1:40000", round, i)
				req.Header.Set("X-API-Key", fmt.Sprintf("unknown-key-%d-%d", round, i))
				rec := httptest.NewRecorder()
				server.router.ServeHTTP(rec, req)
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
			}(i)
		}
		wg.Wait()
	}

	// The index was built at startup: still fresher than the floor → no scan.
	server.apiKeyIdx.mu.Lock()
	server.apiKeyIdx.lastAttemptAt = clock.Now()
	server.apiKeyIdx.mu.Unlock()
	flood(0)
	assert.Equal(t, 0, store.count(), "a fresh index answers misses without the store")

	clock.Advance(apiKeyIndexMissRefreshFloor)
	flood(1)
	assert.Equal(t, 1, store.count(), "one shared refresh for the whole flood")

	flood(2)
	assert.Equal(t, 1, store.count(), "no further scan inside the floor")

	clock.Advance(apiKeyIndexMissRefreshFloor)
	flood(3)
	assert.Equal(t, 2, store.count())
}

// TestAPIKey_CreatedOnPeer_AuthenticatesAfterIndexRefresh verifies a key minted on
// node A becomes usable on node B once B's index refreshes — by the miss path after
// the floor, or by the background refresher.
func TestAPIKey_CreatedOnPeer_AuthenticatesAfterIndexRefresh(t *testing.T) {
	serverA, serverB := setupPeerServers(t)
	clockB := &steppingClock{now: time.Now()}
	serverB.apiKeyClock = clockB.Now
	serverB.apiKeyIdx.mu.Lock()
	serverB.apiKeyIdx.lastAttemptAt = clockB.Now()
	serverB.apiKeyIdx.mu.Unlock()

	apiKey, _ := mintStoreAPIKey(t, serverA, []string{"steward:list"}, "tenant-a")
	assert.Equal(t, http.StatusUnauthorized, stewardsStatus(serverB, apiKey),
		"inside the floor node B does not rescan for an unknown key")

	clockB.Advance(apiKeyIndexMissRefreshFloor)
	assert.Equal(t, http.StatusOK, stewardsStatus(serverB, apiKey))

	// The background refresher path: a fresh key is located with no miss-driven scan.
	apiKey2, _ := mintStoreAPIKey(t, serverA, []string{"steward:list"}, "tenant-a")
	require.NoError(t, serverB.refreshAPIKeyIndex(context.Background()))
	assert.Equal(t, http.StatusOK, stewardsStatus(serverB, apiKey2))
}

// TestAPIKey_NestedTenant_DeleteRevokesOnPeer is the nested-tenant case: a key minted
// for a child tenant ("tenant-a-child", a child of tenant-a) is deleted by a caller scoped to the parent,
// its durable record is gone, and a second node rejects it.
func TestAPIKey_NestedTenant_DeleteRevokesOnPeer(t *testing.T) {
	serverA, serverB := setupPeerServers(t)
	clockB := &steppingClock{now: time.Now()}
	serverB.apiKeyClock = clockB.Now

	createTestTenant(t, serverA, "tenant-a", "")
	createTestTenant(t, serverA, "tenant-a-child", "tenant-a")
	const tenant = "tenant-a-child"
	apiKey, keyID := mintStoreAPIKey(t, serverA, []string{"steward:list"}, tenant)

	clockB.Advance(apiKeyIndexMissRefreshFloor)
	require.Equal(t, http.StatusOK, stewardsStatus(serverB, apiKey), "node B loads the nested-tenant key")

	rec := callDeleteAPIKey(serverA, keyID, ctxkeys.NewTenantScope("tenant-a"))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	got, err := serverA.readAPIKeyRecord(context.Background(), tenant, hashAPIKey(apiKey))
	require.NoError(t, err)
	assert.Nil(t, got, "the nested-tenant record must be gone from the store")

	assert.Equal(t, http.StatusUnauthorized, stewardsStatus(serverA, apiKey))
	clockB.Advance(apiKeyRevalidateInterval)
	assert.Equal(t, http.StatusUnauthorized, stewardsStatus(serverB, apiKey))

	// A node that never cached it rejects it too (restart case).
	dropFromCache(serverB, apiKey)
	clockB.Advance(apiKeyIndexMissRefreshFloor)
	assert.Equal(t, http.StatusUnauthorized, stewardsStatus(serverB, apiKey))
}

// gatedListSecretStore wraps a real SecretStore; ListSecrets signals entered and then
// blocks until release is closed, so a test can act while a scan is in flight.
type gatedListSecretStore struct {
	secretsif.SecretStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *gatedListSecretStore) ListSecrets(ctx context.Context, filter *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.SecretStore.ListSecrets(ctx, filter)
}

// TestAPIKeyIndex_LeaderCancelDoesNotCancelSharedScan verifies the request that starts
// a shared index scan cannot cancel it: the leader's client aborts mid-scan, and a
// concurrent request for a key created on another node still authenticates once the
// scan completes.
func TestAPIKeyIndex_LeaderCancelDoesNotCancelSharedScan(t *testing.T) {
	serverA, serverB := setupPeerServers(t)
	clockB := &steppingClock{now: time.Now()}
	serverB.apiKeyClock = clockB.Now
	clockB.Advance(apiKeyIndexMissRefreshFloor)

	apiKey, _ := mintStoreAPIKey(t, serverA, []string{"steward:list"}, "tenant-a")

	gate := &gatedListSecretStore{SecretStore: serverB.secretStore, entered: make(chan struct{}), release: make(chan struct{})}
	serverB.secretStore = gate

	// Leader: an unknown key starts the scan; its client then goes away.
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil).WithContext(leaderCtx)
		req.Header.Set("X-API-Key", "leader-unknown-key")
		rec := httptest.NewRecorder()
		serverB.router.ServeHTTP(rec, req)
		leaderDone <- rec.Code
	}()
	<-gate.entered
	cancelLeader()
	assert.Equal(t, http.StatusUnauthorized, <-leaderDone)

	// Waiter: arrives while the scan is still in flight and joins it.
	waiterDone := make(chan int, 1)
	go func() { waiterDone <- stewardsStatus(serverB, apiKey) }()
	require.Eventually(t, func() bool { return serverB.apiKeyIdx.refreshing() }, time.Second, time.Millisecond)
	close(gate.release)

	assert.Equal(t, http.StatusOK, <-waiterDone, "the shared scan survived the leader's cancellation")
}

// readGatedSecretStore wraps a real SecretStore; GetSecret performs the real read,
// signals, and holds its result until release is closed.
type readGatedSecretStore struct {
	secretsif.SecretStore
	readDone chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (s *readGatedSecretStore) GetSecret(ctx context.Context, key string) (*secretsif.Secret, error) {
	rec, err := s.SecretStore.GetSecret(ctx, key)
	s.once.Do(func() { close(s.readDone) })
	<-s.release
	return rec, err
}

// TestAPIKey_LoadRacingSameNodeDelete_DoesNotRecache verifies a load that read the
// record before a same-node delete cannot re-cache the deleted key afterwards.
func TestAPIKey_LoadRacingSameNodeDelete_DoesNotRecache(t *testing.T) {
	server := setupTestServer(t)
	apiKey, keyID := mintStoreAPIKey(t, server, []string{"steward:list"}, "tenant-a")
	dropFromCache(server, apiKey)

	gate := &readGatedSecretStore{SecretStore: server.secretStore, readDone: make(chan struct{}), release: make(chan struct{})}
	server.secretStore = gate

	loadDone := make(chan int, 1)
	go func() { loadDone <- stewardsStatus(server, apiKey) }()
	<-gate.readDone // the load has read the (still present) record

	rec := callDeleteAPIKey(server, keyID, ctxkeys.NewTenantScope("tenant-a"))
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	close(gate.release)
	assert.Equal(t, http.StatusUnauthorized, <-loadDone, "the racing load must not authenticate a deleted key")
	assert.False(t, isCached(server, apiKey), "the racing load must not re-cache a deleted key")
}

// TestAPIKey_Revalidation_ExpiredRecord_FailsClosedAtOnce verifies a record the store
// reports expired is not treated as an outage: the cached key is rejected at the
// next re-validation, not served for apiKeyMaxStaleness.
func TestAPIKey_Revalidation_ExpiredRecord_FailsClosedAtOnce(t *testing.T) {
	server := setupTestServer(t)
	clock := &steppingClock{now: time.Now()}
	server.apiKeyClock = clock.Now
	apiKey, keyID := mintStoreAPIKey(t, server, []string{"steward:list"}, "tenant-a")
	require.Equal(t, http.StatusOK, stewardsStatus(server, apiKey))

	// Rewrite the durable record with an expiry already in the past.
	require.NoError(t, server.secretStore.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key: hashAPIKey(apiKey), Value: hashAPIKey(apiKey), TenantID: "tenant-a", TTL: time.Nanosecond,
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey),
			"id":                            keyID,
			"permissions":                   "steward:list",
		},
	}))
	time.Sleep(2 * time.Millisecond)

	clock.Advance(apiKeyRevalidateInterval)
	assert.Equal(t, http.StatusUnauthorized, stewardsStatus(server, apiKey))
	assert.False(t, isCached(server, apiKey))
}

// TestAPIKey_Revalidation_UndecryptableRecord_FailsClosedAtOnce verifies a record that
// cannot be decrypted (here: rewritten under a different encryption key) is not
// treated as an outage: the cached key is rejected at the next re-validation.
func TestAPIKey_Revalidation_UndecryptableRecord_FailsClosedAtOnce(t *testing.T) {
	server := setupTestServer(t)
	repoPath := os.Getenv("CFGMS_SECRETS_REPO_PATH")
	clock := &steppingClock{now: time.Now()}
	server.apiKeyClock = clock.Now
	apiKey, keyID := mintStoreAPIKey(t, server, []string{"steward:list"}, "tenant-a")
	require.Equal(t, http.StatusOK, stewardsStatus(server, apiKey))

	// A store instance on the same data under a different encryption key.
	setTestSecretsEnv(t)
	t.Setenv("CFGMS_SECRETS_REPO_PATH", repoPath)
	foreign, err := NewSecretStore(server.cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = foreign.Close() })
	require.NoError(t, foreign.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key: hashAPIKey(apiKey), Value: hashAPIKey(apiKey), TenantID: "tenant-a",
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey),
			"id":                            keyID,
		},
	}))

	clock.Advance(apiKeyRevalidateInterval)
	assert.Equal(t, http.StatusUnauthorized, stewardsStatus(server, apiKey))
	assert.False(t, isCached(server, apiKey))
}
