// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sops

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// TestGetCacheKey_DiffersAcrossScopes is a REQUIRED test (Issue #4348):
// getCacheKey must not collide across two differing (tenantID, key) scopes.
// A bare "%s/%s" join lets tenantID="a/b", key="c" and tenantID="a",
// key="b/c" both produce "a/b/c" — the length-prefixed encoding must keep
// them distinct.
func TestGetCacheKey_DiffersAcrossScopes(t *testing.T) {
	s := &SOPSSecretStore{}

	keyOne := s.getCacheKey("a/b", "c")
	keyTwo := s.getCacheKey("a", "b/c")

	assert.NotEqual(t, keyOne, keyTwo,
		"getCacheKey must not collide across differing tenant/key scopes that share the same concatenation")
}

// TestGetCacheKey_StableForSameScope verifies the same (tenantID, key) pair
// always produces the same cache key, so caching remains effective.
func TestGetCacheKey_StableForSameScope(t *testing.T) {
	s := &SOPSSecretStore{}
	assert.Equal(t, s.getCacheKey("tenant-a", "api-key"), s.getCacheKey("tenant-a", "api-key"))
}

// TestSOPSSecretStore_CacheDoesNotCrossScopes exercises the store's real
// *cache.Cache through getCacheKey for two (tenantID, key) pairs that collide
// under the old bare "%s/%s" join — tenantID="a/b",key="c" and
// tenantID="a",key="b/c" both produced "a/b/c" — and confirms each scope
// reads back its own value rather than the other's.
//
// Secret keys cannot themselves contain "/" through the flatfile-backed
// ConfigStore's own leaf-field validation, but a database-backed ConfigStore
// (cluster/postgres deployments) imposes no such restriction, so this
// collision is reachable there via the public StoreSecret/GetSecret API —
// exercising the cache directly here keeps the test backend-independent.
func TestSOPSSecretStore_CacheDoesNotCrossScopes(t *testing.T) {
	base := t.TempDir()
	keyPath := writeTestKey(t, base)
	store, err := NewSOPSSecretStore(&SOPSSecretStoreConfig{
		StorageProvider: "flatfile",
		StorageConfig:   map[string]interface{}{"root": base + "/data"},
		CacheEnabled:    true,
		CacheTTL:        60,
		KeyFile:         keyPath,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	secretA := &secretsif.Secret{Key: "c", TenantID: "a/b", Value: "value-for-a-slash-b-scope-c"}
	secretB := &secretsif.Secret{Key: "b/c", TenantID: "a", Value: "value-for-a-scope-b-slash-c"}

	require.NoError(t, store.cache.Set(store.getCacheKey("a/b", "c"), secretA, time.Minute))
	require.NoError(t, store.cache.Set(store.getCacheKey("a", "b/c"), secretB, time.Minute))

	cachedA, found := store.cache.Get(store.getCacheKey("a/b", "c"))
	require.True(t, found)
	assert.Equal(t, "value-for-a-slash-b-scope-c", cachedA.(*secretsif.Secret).Value)

	cachedB, found := store.cache.Get(store.getCacheKey("a", "b/c"))
	require.True(t, found)
	assert.Equal(t, "value-for-a-scope-b-slash-c", cachedB.(*secretsif.Secret).Value,
		"a distinct scope must never be served from another scope's cache entry")
}
