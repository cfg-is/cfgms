// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package flatfile_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// newTestConfigStore creates a FlatFileConfigStore backed by a temporary directory.
func newTestConfigStore(t *testing.T) *flatfile.FlatFileConfigStore {
	t.Helper()
	store, err := flatfile.NewFlatFileConfigStore(t.TempDir())
	require.NoError(t, err)
	return store
}

// testEntry builds a minimal ConfigEntry for testing.
func testEntry(tenantID, namespace, name string, data []byte, format interfaces.ConfigFormat) *interfaces.ConfigEntry {
	return &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID:  tenantID,
			Namespace: namespace,
			Name:      name,
		},
		Data:      data,
		Format:    format,
		CreatedBy: "test",
		UpdatedBy: "test",
	}
}

// TestStoreAndGetConfig verifies basic store and retrieve round-trip.
func TestStoreAndGetConfig(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	entry := testEntry("tenant1", "default", "policy", []byte(`{"key":"value"}`), interfaces.ConfigFormatJSON)
	require.NoError(t, store.StoreConfig(ctx, entry))

	got, err := store.GetConfig(ctx, entry.Key)
	require.NoError(t, err)
	assert.Equal(t, entry.Key.Name, got.Key.Name)
	assert.Equal(t, entry.Key.TenantID, got.Key.TenantID)
	assert.Equal(t, entry.Data, got.Data)
	assert.Equal(t, int64(1), got.Version)
	assert.NotEmpty(t, got.Checksum)
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())
}

// TestStoreConfigYAML verifies YAML-format storage.
func TestStoreConfigYAML(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	entry := testEntry("tenant1", "ns", "rules", []byte("key: value\n"), interfaces.ConfigFormatYAML)
	require.NoError(t, store.StoreConfig(ctx, entry))

	got, err := store.GetConfig(ctx, entry.Key)
	require.NoError(t, err)
	assert.Equal(t, interfaces.ConfigFormatYAML, got.Format)
	assert.Equal(t, entry.Data, got.Data)
}

// TestStoreConfigVersionIncrement verifies that re-storing a config increments the version.
func TestStoreConfigVersionIncrement(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	entry := testEntry("tenant1", "ns", "cfg", []byte(`v1`), interfaces.ConfigFormatJSON)
	require.NoError(t, store.StoreConfig(ctx, entry))

	entry.Data = []byte(`v2`)
	require.NoError(t, store.StoreConfig(ctx, entry))

	got, err := store.GetConfig(ctx, entry.Key)
	require.NoError(t, err)
	assert.Equal(t, int64(2), got.Version)
	assert.Equal(t, []byte(`v2`), got.Data)
}

// TestGetConfigNotFound verifies that a missing config returns ErrConfigNotFound.
func TestGetConfigNotFound(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	_, err := store.GetConfig(ctx, &interfaces.ConfigKey{
		TenantID:  "tenant1",
		Namespace: "ns",
		Name:      "nonexistent",
	})
	assert.Equal(t, interfaces.ErrConfigNotFound, err)
}

// TestDeleteConfig verifies that a stored config can be deleted.
func TestDeleteConfig(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	entry := testEntry("t1", "ns", "cfg", []byte(`data`), interfaces.ConfigFormatJSON)
	require.NoError(t, store.StoreConfig(ctx, entry))
	require.NoError(t, store.DeleteConfig(ctx, entry.Key))

	_, err := store.GetConfig(ctx, entry.Key)
	assert.Equal(t, interfaces.ErrConfigNotFound, err)
}

// TestDeleteConfigNotFound verifies that deleting a non-existent config returns ErrConfigNotFound.
func TestDeleteConfigNotFound(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	err := store.DeleteConfig(ctx, &interfaces.ConfigKey{
		TenantID:  "t1",
		Namespace: "ns",
		Name:      "gone",
	})
	assert.Equal(t, interfaces.ErrConfigNotFound, err)
}

// TestListConfigs verifies that stored configs can be listed.
func TestListConfigs(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	entries := []*interfaces.ConfigEntry{
		testEntry("t1", "ns", "alpha", []byte(`a`), interfaces.ConfigFormatJSON),
		testEntry("t1", "ns", "beta", []byte(`b`), interfaces.ConfigFormatJSON),
		testEntry("t1", "ns2", "gamma", []byte(`c`), interfaces.ConfigFormatJSON),
	}
	for _, e := range entries {
		require.NoError(t, store.StoreConfig(ctx, e))
	}

	t.Run("all entries", func(t *testing.T) {
		results, err := store.ListConfigs(ctx, &interfaces.ConfigFilter{TenantID: "t1"})
		require.NoError(t, err)
		assert.Len(t, results, 3)
	})

	t.Run("filter by namespace", func(t *testing.T) {
		results, err := store.ListConfigs(ctx, &interfaces.ConfigFilter{TenantID: "t1", Namespace: "ns"})
		require.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("filter by name", func(t *testing.T) {
		results, err := store.ListConfigs(ctx, &interfaces.ConfigFilter{TenantID: "t1", Names: []string{"alpha"}})
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "alpha", results[0].Key.Name)
	})

	t.Run("empty result", func(t *testing.T) {
		results, err := store.ListConfigs(ctx, &interfaces.ConfigFilter{TenantID: "notexist"})
		require.NoError(t, err)
		assert.Empty(t, results)
	})
}

// TestListConfigsPagination verifies offset and limit in ListConfigs.
func TestListConfigsPagination(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		e := testEntry("t1", "ns", fmt.Sprintf("cfg%d", i), []byte(`x`), interfaces.ConfigFormatJSON)
		require.NoError(t, store.StoreConfig(ctx, e))
	}

	results, err := store.ListConfigs(ctx, &interfaces.ConfigFilter{
		TenantID: "t1",
		Limit:    2,
		Offset:   1,
	})
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

// TestResolveConfigWithInheritanceTwoLevel tests two-level tenant inheritance.
func TestResolveConfigWithInheritanceTwoLevel(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	// Store at parent level (root/msp-a)
	parent := testEntry("root/msp-a", "firewall", "rules", []byte(`parent`), interfaces.ConfigFormatJSON)
	require.NoError(t, store.StoreConfig(ctx, parent))

	// Resolve from child (root/msp-a/client-1) — should fall back to parent
	childKey := &interfaces.ConfigKey{
		TenantID:  "root/msp-a/client-1",
		Namespace: "firewall",
		Name:      "rules",
	}
	got, err := store.ResolveConfigWithInheritance(ctx, childKey)
	require.NoError(t, err)
	assert.Equal(t, []byte(`parent`), got.Data)
	assert.Equal(t, "root/msp-a", got.Key.TenantID)

	// Now store a child-level override
	child := testEntry("root/msp-a/client-1", "firewall", "rules", []byte(`child`), interfaces.ConfigFormatJSON)
	require.NoError(t, store.StoreConfig(ctx, child))

	// Resolve again — should now return child override
	got, err = store.ResolveConfigWithInheritance(ctx, childKey)
	require.NoError(t, err)
	assert.Equal(t, []byte(`child`), got.Data)
}

// TestResolveConfigWithInheritanceNotFound returns ErrConfigNotFound when absent at all levels.
func TestResolveConfigWithInheritanceNotFound(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	_, err := store.ResolveConfigWithInheritance(ctx, &interfaces.ConfigKey{
		TenantID:  "root/msp-a/client-1",
		Namespace: "ns",
		Name:      "nope",
	})
	assert.Equal(t, interfaces.ErrConfigNotFound, err)
}

// TestStoreConfigValidation verifies required-field validation.
func TestStoreConfigValidation(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	t.Run("missing tenant", func(t *testing.T) {
		err := store.StoreConfig(ctx, &interfaces.ConfigEntry{
			Key:  &interfaces.ConfigKey{Namespace: "ns", Name: "n"},
			Data: []byte(`x`),
		})
		assert.Error(t, err)
	})

	t.Run("missing namespace", func(t *testing.T) {
		err := store.StoreConfig(ctx, &interfaces.ConfigEntry{
			Key:  &interfaces.ConfigKey{TenantID: "t1", Name: "n"},
			Data: []byte(`x`),
		})
		assert.Error(t, err)
	})

	t.Run("missing name", func(t *testing.T) {
		err := store.StoreConfig(ctx, &interfaces.ConfigEntry{
			Key:  &interfaces.ConfigKey{TenantID: "t1", Namespace: "ns"},
			Data: []byte(`x`),
		})
		assert.Error(t, err)
	})

	t.Run("nil key", func(t *testing.T) {
		err := store.StoreConfig(ctx, &interfaces.ConfigEntry{Data: []byte(`x`)})
		assert.Error(t, err)
	})
}

// TestPathTraversalPrevention ensures directory traversal is rejected.
func TestPathTraversalPrevention(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	err := store.StoreConfig(ctx, &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID:  "../escaped",
			Namespace: "ns",
			Name:      "cfg",
		},
		Data:   []byte(`bad`),
		Format: interfaces.ConfigFormatJSON,
	})
	require.Error(t, err)
}

// TestConcurrentWrites verifies no data corruption with 10 goroutines writing to the same namespace.
func TestConcurrentWrites(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	const numGoroutines = 10
	var wg sync.WaitGroup
	errs := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			entry := &interfaces.ConfigEntry{
				Key: &interfaces.ConfigKey{
					TenantID:  "concurrent-tenant",
					Namespace: "shared-ns",
					Name:      fmt.Sprintf("cfg-%d", i),
				},
				Data:   []byte(fmt.Sprintf(`{"writer":%d}`, i)),
				Format: interfaces.ConfigFormatJSON,
			}
			errs[i] = store.StoreConfig(ctx, entry)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d returned error", i)
	}

	// Verify all writes are readable without corruption
	results, err := store.ListConfigs(ctx, &interfaces.ConfigFilter{
		TenantID:  "concurrent-tenant",
		Namespace: "shared-ns",
	})
	require.NoError(t, err)
	assert.Len(t, results, numGoroutines)

	for _, r := range results {
		assert.NotNil(t, r.Key)
		assert.NotEmpty(t, r.Data)
	}
}

// TestStoreConfigBatch verifies batch store and retrieval.
func TestStoreConfigBatch(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	entries := []*interfaces.ConfigEntry{
		testEntry("t1", "ns", "a", []byte(`1`), interfaces.ConfigFormatJSON),
		testEntry("t1", "ns", "b", []byte(`2`), interfaces.ConfigFormatJSON),
	}
	require.NoError(t, store.StoreConfigBatch(ctx, entries))

	for _, e := range entries {
		got, err := store.GetConfig(ctx, e.Key)
		require.NoError(t, err)
		assert.Equal(t, e.Data, got.Data)
	}
}

// TestDeleteConfigBatch verifies batch deletion.
func TestDeleteConfigBatch(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	entries := []*interfaces.ConfigEntry{
		testEntry("t1", "ns", "a", []byte(`1`), interfaces.ConfigFormatJSON),
		testEntry("t1", "ns", "b", []byte(`2`), interfaces.ConfigFormatJSON),
	}
	require.NoError(t, store.StoreConfigBatch(ctx, entries))

	keys := []*interfaces.ConfigKey{entries[0].Key, entries[1].Key}
	require.NoError(t, store.DeleteConfigBatch(ctx, keys))

	for _, key := range keys {
		_, err := store.GetConfig(ctx, key)
		assert.Equal(t, interfaces.ErrConfigNotFound, err)
	}
}

// TestGetConfigHistory returns at least the current version.
func TestGetConfigHistory(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	entry := testEntry("t1", "ns", "cfg", []byte(`v1`), interfaces.ConfigFormatJSON)
	require.NoError(t, store.StoreConfig(ctx, entry))

	history, err := store.GetConfigHistory(ctx, entry.Key, 10)
	require.NoError(t, err)
	assert.NotEmpty(t, history)
	assert.Equal(t, entry.Key.Name, history[0].Key.Name)
}

// TestGetConfigVersion returns current version on match, error on mismatch.
func TestGetConfigVersion(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	entry := testEntry("t1", "ns", "cfg", []byte(`v1`), interfaces.ConfigFormatJSON)
	require.NoError(t, store.StoreConfig(ctx, entry))

	got, err := store.GetConfigVersion(ctx, entry.Key, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1), got.Version)

	_, err = store.GetConfigVersion(ctx, entry.Key, 999)
	assert.Error(t, err)
}

// TestValidateConfig verifies validation helper.
func TestValidateConfig(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	t.Run("valid entry", func(t *testing.T) {
		err := store.ValidateConfig(ctx, testEntry("t1", "ns", "cfg", []byte(`x`), interfaces.ConfigFormatJSON))
		assert.NoError(t, err)
	})

	t.Run("invalid format", func(t *testing.T) {
		e := testEntry("t1", "ns", "cfg", []byte(`x`), "")
		e.Format = "xml" // unsupported
		err := store.ValidateConfig(ctx, e)
		assert.Error(t, err)
	})

	t.Run("checksum mismatch", func(t *testing.T) {
		e := testEntry("t1", "ns", "cfg", []byte(`data`), interfaces.ConfigFormatJSON)
		e.Checksum = "badhash"
		err := store.ValidateConfig(ctx, e)
		assert.Error(t, err)
	})
}

// TestGetConfigStats returns stats for stored configs.
func TestGetConfigStats(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	entries := []*interfaces.ConfigEntry{
		testEntry("t1", "ns", "a", []byte(`data1`), interfaces.ConfigFormatJSON),
		testEntry("t1", "ns", "b", []byte(`data2`), interfaces.ConfigFormatYAML),
	}
	for _, e := range entries {
		require.NoError(t, store.StoreConfig(ctx, e))
	}

	stats, err := store.GetConfigStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), stats.TotalConfigs)
	assert.Greater(t, stats.TotalSize, int64(0))
	assert.NotNil(t, stats.OldestConfig)
	assert.NotNil(t, stats.NewestConfig)
}

// TestConfigScopeInKey verifies that scope is used in the filename.
func TestConfigScopeInKey(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	entry := &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID:  "t1",
			Namespace: "ns",
			Name:      "cfg",
			Scope:     "group1",
		},
		Data:   []byte(`scoped`),
		Format: interfaces.ConfigFormatJSON,
	}
	require.NoError(t, store.StoreConfig(ctx, entry))

	got, err := store.GetConfig(ctx, entry.Key)
	require.NoError(t, err)
	assert.Equal(t, entry.Data, got.Data)
}

// TestListConfigsSortByName verifies sort ordering.
func TestListConfigsSortByName(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	for _, name := range []string{"zzz", "aaa", "mmm"} {
		require.NoError(t, store.StoreConfig(ctx, testEntry("t1", "ns", name, []byte(`x`), interfaces.ConfigFormatJSON)))
	}

	results, err := store.ListConfigs(ctx, &interfaces.ConfigFilter{
		TenantID: "t1",
		SortBy:   "name",
		Order:    "asc",
	})
	require.NoError(t, err)
	require.Len(t, results, 3)
	assert.Equal(t, "aaa", results[0].Key.Name)
	assert.Equal(t, "mmm", results[1].Key.Name)
	assert.Equal(t, "zzz", results[2].Key.Name)
}

// TestCreatedAtPreservedOnUpdate verifies CreatedAt is not overwritten on subsequent stores.
func TestCreatedAtPreservedOnUpdate(t *testing.T) {
	store := newTestConfigStore(t)
	ctx := context.Background()

	beforeFirst := time.Now().UTC()
	entry := testEntry("t1", "ns", "cfg", []byte(`v1`), interfaces.ConfigFormatJSON)
	require.NoError(t, store.StoreConfig(ctx, entry))

	got1, err := store.GetConfig(ctx, entry.Key)
	require.NoError(t, err)
	originalCreatedAt := got1.CreatedAt

	// Verify CreatedAt was set after we began
	assert.True(t, !originalCreatedAt.Before(beforeFirst), "CreatedAt must be >= before first store")

	// Perform the second store without any sleep; rely on ordering not wall-clock comparison
	beforeSecond := time.Now().UTC()
	entry.Data = []byte(`v2`)
	require.NoError(t, store.StoreConfig(ctx, entry))

	got2, err := store.GetConfig(ctx, entry.Key)
	require.NoError(t, err)

	// CreatedAt must be unchanged across updates
	assert.Equal(t, originalCreatedAt.UnixNano(), got2.CreatedAt.UnixNano(),
		"CreatedAt must not change on update")

	// UpdatedAt must be set to at least the time before the second store
	assert.True(t, !got2.UpdatedAt.Before(beforeSecond),
		"UpdatedAt must be >= before second store call")

	// Version must have incremented
	assert.Equal(t, int64(2), got2.Version)
}
