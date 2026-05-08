// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces_test contains contract tests for the ConfigSourceRouter interface.
//
// # Usage by provider implementors
//
// To validate a new ConfigSourceRouter implementation, call RunRouterContractTests
// from the provider's test package:
//
//	func TestMyRouter_ContractSuite(t *testing.T) {
//		interfaces.RunRouterContractTests(t, myRouterFactory)
//	}
//
// where myRouterFactory returns a fully initialised ConfigSourceRouter and a cleanup
// function (to release resources).
package interfaces_test

import (
	"context"
	"testing"

	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	routerinterfaces "github.com/cfgis/cfgms/pkg/configrouting/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RouterFactory creates a ConfigSourceRouter and returns it together with a cleanup
// function that releases all associated resources.
//
// The returned router must be backed by a tenant hierarchy with at least three
// levels: root → msp → client (IDs exactly as shown). The root tenant must have
// no config_source_type metadata (so GetEffectiveConfigSource defaults to controller).
type RouterFactory func(t *testing.T) (router routerinterfaces.ConfigSourceRouter, cleanup func())

// RunRouterContractTests runs the full ConfigSourceRouter contract test suite.
// Each contract is a separate subtest for granular reporting.
func RunRouterContractTests(t *testing.T, factory RouterFactory) {
	t.Helper()

	t.Run("GetEffectiveConfigSource_DefaultsToController", func(t *testing.T) {
		testGetEffectiveConfigSource_DefaultsToController(t, factory)
	})
	t.Run("GetEffectiveConfigSource_CachesResult", func(t *testing.T) {
		testGetEffectiveConfigSource_CachesResult(t, factory)
	})
	t.Run("SnapshotSources_ReturnsAllLevels", func(t *testing.T) {
		testSnapshotSources_ReturnsAllLevels(t, factory)
	})
	t.Run("SnapshotSources_ReturnsDeepCopies", func(t *testing.T) {
		testSnapshotSources_ReturnsDeepCopies(t, factory)
	})
	t.Run("InvalidateTenantCache_ForcesRefresh", func(t *testing.T) {
		testInvalidateTenantCache_ForcesRefresh(t, factory)
	})
	t.Run("StoreConfig_Roundtrip", func(t *testing.T) {
		testStoreConfig_Roundtrip(t, factory)
	})
	t.Run("GetConfig_NotFound", func(t *testing.T) {
		testGetConfig_NotFound(t, factory)
	})
	t.Run("ListConfigs_EmptyTenantIDAllowed", func(t *testing.T) {
		testListConfigs_EmptyTenantIDAllowed(t, factory)
	})
	t.Run("DeleteConfig_Roundtrip", func(t *testing.T) {
		testDeleteConfig_Roundtrip(t, factory)
	})
	t.Run("StoreConfigBatch_Roundtrip", func(t *testing.T) {
		testStoreConfigBatch_Roundtrip(t, factory)
	})
	t.Run("GetConfigHistory_AfterStore", func(t *testing.T) {
		testGetConfigHistory_AfterStore(t, factory)
	})
	t.Run("SnapshotSources_EmptyPath", func(t *testing.T) {
		testSnapshotSources_EmptyPath(t, factory)
	})
}

func testGetEffectiveConfigSource_DefaultsToController(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	info, err := router.GetEffectiveConfigSource(context.Background(), "root")
	require.NoError(t, err)
	assert.Equal(t, pkgconfig.ConfigSourceTypeController, info.Type)
}

func testGetEffectiveConfigSource_CachesResult(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	info1, err := router.GetEffectiveConfigSource(ctx, "root")
	require.NoError(t, err)

	info2, err := router.GetEffectiveConfigSource(ctx, "root")
	require.NoError(t, err)

	assert.Equal(t, info1.Type, info2.Type, "repeated calls must return consistent results")
}

func testSnapshotSources_ReturnsAllLevels(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	path := []string{"root", "msp", "client"}
	snapshot, err := router.SnapshotSources(context.Background(), path)
	require.NoError(t, err)
	require.Len(t, snapshot, 3)

	for _, tid := range path {
		info, ok := snapshot[tid]
		require.True(t, ok, "snapshot must include entry for %q", tid)
		assert.NotNil(t, info)
	}
}

func testSnapshotSources_ReturnsDeepCopies(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	snapshot, err := router.SnapshotSources(ctx, []string{"root"})
	require.NoError(t, err)

	// Mutate snapshot entry; subsequent GetEffectiveConfigSource must not see mutation.
	entry := snapshot["root"]
	entry.Branch = "mutated-branch"

	info, err := router.GetEffectiveConfigSource(ctx, "root")
	require.NoError(t, err)
	assert.NotEqual(t, "mutated-branch", info.Branch, "mutation of snapshot must not affect cache")
}

func testInvalidateTenantCache_ForcesRefresh(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	// Prime the cache.
	_, err := router.GetEffectiveConfigSource(ctx, "client")
	require.NoError(t, err)

	// Invalidate should not panic or error.
	router.InvalidateTenantCache("client")

	// Subsequent resolution should still work after invalidation.
	info, err := router.GetEffectiveConfigSource(ctx, "client")
	require.NoError(t, err)
	assert.NotNil(t, info)
}

func testStoreConfig_Roundtrip(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	key := &cfgconfig.ConfigKey{TenantID: "client", Namespace: "test-contract", Name: "entry1"}
	entry := &cfgconfig.ConfigEntry{
		Key:    key,
		Data:   []byte("contract: test"),
		Format: cfgconfig.ConfigFormatYAML,
	}

	require.NoError(t, router.StoreConfig(ctx, entry))

	got, err := router.GetConfig(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, entry.Data, got.Data)
}

func testGetConfig_NotFound(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	key := &cfgconfig.ConfigKey{TenantID: "client", Namespace: "test-contract", Name: "does-not-exist"}
	_, err := router.GetConfig(context.Background(), key)
	assert.Error(t, err, "GetConfig must return an error for missing keys")
}

func testListConfigs_EmptyTenantIDAllowed(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	// ListConfigs with an empty TenantID filter must not return a cross-tenant error.
	filter := &cfgconfig.ConfigFilter{TenantID: ""}
	_, err := router.ListConfigs(context.Background(), filter)
	assert.NoError(t, err, "empty TenantID filter must be accepted (backward compat)")
}

func testDeleteConfig_Roundtrip(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	key := &cfgconfig.ConfigKey{TenantID: "client", Namespace: "test-contract", Name: "to-delete"}
	entry := &cfgconfig.ConfigEntry{
		Key:    key,
		Data:   []byte("delete: me"),
		Format: cfgconfig.ConfigFormatYAML,
	}

	require.NoError(t, router.StoreConfig(ctx, entry))
	require.NoError(t, router.DeleteConfig(ctx, key))

	_, err := router.GetConfig(ctx, key)
	assert.Error(t, err, "GetConfig must error after deletion")
}

func testStoreConfigBatch_Roundtrip(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	entries := []*cfgconfig.ConfigEntry{
		{
			Key:    &cfgconfig.ConfigKey{TenantID: "client", Namespace: "batch", Name: "a"},
			Data:   []byte("a: 1"),
			Format: cfgconfig.ConfigFormatYAML,
		},
		{
			Key:    &cfgconfig.ConfigKey{TenantID: "client", Namespace: "batch", Name: "b"},
			Data:   []byte("b: 2"),
			Format: cfgconfig.ConfigFormatYAML,
		},
	}

	require.NoError(t, router.StoreConfigBatch(ctx, entries))

	for _, e := range entries {
		got, err := router.GetConfig(ctx, e.Key)
		require.NoError(t, err)
		assert.Equal(t, e.Data, got.Data)
	}
}

func testGetConfigHistory_AfterStore(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	ctx := context.Background()
	key := &cfgconfig.ConfigKey{TenantID: "client", Namespace: "history", Name: "versioned"}
	entry := &cfgconfig.ConfigEntry{
		Key:    key,
		Data:   []byte("version: 1"),
		Format: cfgconfig.ConfigFormatYAML,
	}

	require.NoError(t, router.StoreConfig(ctx, entry))

	history, err := router.GetConfigHistory(ctx, key, 10)
	require.NoError(t, err)
	assert.NotEmpty(t, history, "history must not be empty after StoreConfig")
}

func testSnapshotSources_EmptyPath(t *testing.T, factory RouterFactory) {
	t.Helper()
	router, cleanup := factory(t)
	defer cleanup()

	snapshot, err := router.SnapshotSources(context.Background(), []string{})
	require.NoError(t, err)
	assert.Empty(t, snapshot, "empty path must return empty map")
}
