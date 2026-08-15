// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// directoryStorageStack holds the real storage components backing an adapter
// under test, so assertions can inspect the durable state directly.
type directoryStorageStack struct {
	adapter    *DirectoryDNAStorageAdapter
	backend    *storage.SQLiteBackend
	compressor storage.Compressor
	indexer    *storage.MemoryIndexer
	logger     logging.Logger
}

// newDirectoryStorage wires a DirectoryDNAStorageAdapter to real CFGMS storage
// components: the durable SQLite DNA backend rooted in a per-test temp dir, the
// real gzip compressor, and the real in-memory indexer. Nothing is mocked, so
// the tests exercise the same code paths the controller runs in production.
func newDirectoryStorage(t *testing.T) *directoryStorageStack {
	t.Helper()

	logger := logging.NewNoopLogger()
	config := &storage.Config{
		DataDir:          t.TempDir(),
		CompressionType:  "gzip",
		CompressionLevel: 6,
	}

	backend, err := storage.NewSQLiteBackend(config, logger)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, backend.Close()) })

	compressor, err := storage.NewCompressor(config.CompressionType, config.CompressionLevel)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, compressor.Close()) })

	indexer, err := storage.NewMemoryIndexer(config, logger)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, indexer.Close()) })

	return &directoryStorageStack{
		adapter:    NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger),
		backend:    backend,
		compressor: compressor,
		indexer:    indexer,
		logger:     logger,
	}
}

// newDirectoryStorageAdapter returns just the adapter for tests that only need
// the public surface.
func newDirectoryStorageAdapter(t *testing.T) *DirectoryDNAStorageAdapter {
	t.Helper()
	return newDirectoryStorage(t).adapter
}

// Storage Integration Tests

func TestNewDirectoryDNAStorageAdapter(t *testing.T) {
	st := newDirectoryStorage(t)

	assert.NotNil(t, st.adapter)
	assert.Equal(t, st.backend, st.adapter.backend)
	assert.Equal(t, st.compressor, st.adapter.compressor)
	assert.Equal(t, st.indexer, st.adapter.indexer)
	assert.Equal(t, st.logger, st.adapter.logger)
}

func TestStoreDirectoryDNA(t *testing.T) {
	st := newDirectoryStorage(t)
	ctx := context.Background()

	// Create test DirectoryDNA
	now := time.Now()
	testDNA := &DirectoryDNA{
		ObjectID:   "user1",
		ObjectType: interfaces.DirectoryObjectTypeUser,
		ID:         "dna_user1",
		Attributes: map[string]string{
			"username":  "testuser",
			"email":     "test@example.com",
			"is_active": "true",
		},
		Provider:       "TestProvider",
		TenantID:       "tenant1",
		LastUpdated:    &now,
		AttributeCount: 3,
	}

	t.Run("successful storage", func(t *testing.T) {
		require.NoError(t, st.adapter.StoreDirectoryDNA(ctx, testDNA))

		// The record was indexed for retrieval
		refs, total, err := st.indexer.QueryRecords(ctx, "user1", &storage.QueryOptions{Limit: 10, IncludeData: true})
		require.NoError(t, err)
		require.Equal(t, int64(1), total)
		require.Len(t, refs, 1)

		// The record is durably stored with its fragment payload and tenant
		record, err := st.backend.GetRecord(ctx, refs[0].ContentHash, refs[0].ShardID)
		require.NoError(t, err)
		require.NotNil(t, record.DNA)
		require.Len(t, record.DNA.Fragments, 1)
		assert.Equal(t, directoryDNAFragmentID, record.DNA.Fragments[0].FragmentId)
		assert.Equal(t, "tenant1", record.TenantID)
		assert.Equal(t, int64(1), record.Version)
	})

	t.Run("deduplication", func(t *testing.T) {
		// Store byte-identical DNA again: content already exists, so only a
		// reference is written, but the object gains a new indexed version.
		require.NoError(t, st.adapter.StoreDirectoryDNA(ctx, testDNA))

		refs, total, err := st.indexer.QueryRecords(ctx, "user1", &storage.QueryOptions{Limit: 10})
		require.NoError(t, err)
		require.Equal(t, int64(2), total)
		require.Len(t, refs, 2)
		assert.Equal(t, refs[0].ContentHash, refs[1].ContentHash,
			"identical DNA must resolve to a single content hash")
	})
}

func TestGetDirectoryDNA(t *testing.T) {
	adapter := newDirectoryStorageAdapter(t)
	ctx := context.Background()

	// First store a DirectoryDNA record
	now := time.Now()
	originalDNA := &DirectoryDNA{
		ObjectID:   "user1",
		ObjectType: interfaces.DirectoryObjectTypeUser,
		ID:         "dna_user1",
		Attributes: map[string]string{
			"username":  "testuser",
			"email":     "test@example.com",
			"is_active": "true",
		},
		Provider:       "TestProvider",
		TenantID:       "tenant1",
		LastUpdated:    &now,
		AttributeCount: 3,
	}

	err := adapter.StoreDirectoryDNA(ctx, originalDNA)
	require.NoError(t, err)

	t.Run("successful retrieval", func(t *testing.T) {
		retrievedDNA, err := adapter.GetDirectoryDNA(ctx, "user1", interfaces.DirectoryObjectTypeUser)

		require.NoError(t, err)
		require.NotNil(t, retrievedDNA)
		assert.Equal(t, "user1", retrievedDNA.ObjectID)
		assert.Equal(t, interfaces.DirectoryObjectTypeUser, retrievedDNA.ObjectType)
		assert.Equal(t, originalDNA.Attributes, retrievedDNA.Attributes)
		assert.Equal(t, originalDNA.Provider, retrievedDNA.Provider)
		assert.Equal(t, originalDNA.TenantID, retrievedDNA.TenantID)
	})

	t.Run("record not found", func(t *testing.T) {
		retrievedDNA, err := adapter.GetDirectoryDNA(ctx, "nonexistent", interfaces.DirectoryObjectTypeUser)

		assert.Error(t, err)
		assert.Nil(t, retrievedDNA)
		assert.Contains(t, err.Error(), "no directory DNA record found")
	})
}

func TestQueryDirectoryDNA(t *testing.T) {
	adapter := newDirectoryStorageAdapter(t)
	ctx := context.Background()

	// Store multiple DirectoryDNA records
	users := []string{"user1", "user2", "user3"}
	for _, userID := range users {
		dna := &DirectoryDNA{
			ObjectID:   userID,
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_" + userID,
			Attributes: map[string]string{
				"username": userID,
				"email":    userID + "@test.com",
			},
			Provider:       "TestProvider",
			LastUpdated:    timePtr(time.Now()),
			AttributeCount: 2,
		}

		err := adapter.StoreDirectoryDNA(ctx, dna)
		require.NoError(t, err)
	}

	t.Run("query multiple objects", func(t *testing.T) {
		query := &DirectoryDNAQuery{
			ObjectIDs: users,
			Limit:     10,
		}

		results, err := adapter.QueryDirectoryDNA(ctx, query)

		require.NoError(t, err)
		assert.Len(t, results, len(users))

		// Verify all requested objects are returned
		objectIDs := make(map[string]bool)
		for _, result := range results {
			objectIDs[result.ObjectID] = true
		}

		for _, userID := range users {
			assert.True(t, objectIDs[userID])
		}
	})

	t.Run("query with limit", func(t *testing.T) {
		query := &DirectoryDNAQuery{
			ObjectIDs: users,
			Limit:     2,
		}

		results, err := adapter.QueryDirectoryDNA(ctx, query)

		require.NoError(t, err)
		assert.LessOrEqual(t, len(results), 2)
	})
}

func TestGetDirectoryHistory(t *testing.T) {
	adapter := newDirectoryStorageAdapter(t)
	ctx := context.Background()

	// Store multiple versions of the same object
	testStart := time.Now()
	baseTime := testStart.Add(-2 * time.Hour)
	for i := 0; i < 3; i++ {
		dna := &DirectoryDNA{
			ObjectID:   "user1",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user1_v" + string(rune('0'+i)),
			Attributes: map[string]string{
				"username": "testuser",
				"version":  string(rune('0' + i)),
			},
			Provider:    "TestProvider",
			LastUpdated: timePtr(baseTime.Add(time.Duration(i) * time.Hour)),
		}

		err := adapter.StoreDirectoryDNA(ctx, dna)
		require.NoError(t, err)
	}

	t.Run("get full history", func(t *testing.T) {
		history, err := adapter.GetDirectoryHistory(ctx, "user1", nil)

		require.NoError(t, err)
		assert.Len(t, history, 3)

		// Verify history contains all versions
		versions := make(map[string]bool)
		for _, dna := range history {
			versions[dna.Attributes["version"]] = true
		}

		assert.True(t, versions["0"])
		assert.True(t, versions["1"])
		assert.True(t, versions["2"])
	})

	t.Run("get history with time range", func(t *testing.T) {
		// Records carry the time they were written, not the source LastUpdated,
		// so a range covering this test run returns every version.
		inRange := &TimeRange{
			StartTime: testStart.Add(-time.Minute),
			EndTime:   time.Now().Add(time.Minute),
		}

		history, err := adapter.GetDirectoryHistory(ctx, "user1", inRange)
		require.NoError(t, err)
		assert.Len(t, history, 3)

		// A window that closed before the records were written returns nothing.
		outOfRange := &TimeRange{
			StartTime: baseTime.Add(-2 * time.Hour),
			EndTime:   baseTime.Add(-time.Hour),
		}

		history, err = adapter.GetDirectoryHistory(ctx, "user1", outOfRange)
		require.NoError(t, err)
		assert.Empty(t, history)
	})
}

func TestStoreAndGetRelationships(t *testing.T) {
	st := newDirectoryStorage(t)
	ctx := context.Background()

	// Create test relationships
	relationships := &DirectoryRelationships{
		ObjectID:    "user1",
		ObjectType:  interfaces.DirectoryObjectTypeUser,
		MemberOf:    []string{"group1", "group2"},
		ParentOU:    "ou1",
		Manager:     "manager1",
		CollectedAt: time.Now(),
		Provider:    "TestProvider",
		TenantID:    "tenant1",
	}

	t.Run("store relationships", func(t *testing.T) {
		err := st.adapter.StoreRelationships(ctx, relationships)

		require.NoError(t, err)

		// Verify the relationships record reached durable storage
		refs, total, err := st.indexer.QueryRecords(ctx, "user1", &storage.QueryOptions{Limit: 10})
		require.NoError(t, err)
		require.Equal(t, int64(1), total)

		record, err := st.backend.GetRecord(ctx, refs[0].ContentHash, refs[0].ShardID)
		require.NoError(t, err)
		require.NotNil(t, record.DNA)
		require.Len(t, record.DNA.Fragments, 1)
		assert.Equal(t, directoryRelFragmentID, record.DNA.Fragments[0].FragmentId)
		assert.Equal(t, "tenant1", record.TenantID)
	})

	t.Run("retrieve relationships", func(t *testing.T) {
		retrieved, err := st.adapter.GetRelationships(ctx, "user1")

		require.NoError(t, err)
		assert.NotNil(t, retrieved)
		assert.Equal(t, "user1", retrieved.ObjectID)
		assert.Equal(t, interfaces.DirectoryObjectTypeUser, retrieved.ObjectType)
		assert.Equal(t, []string{"group1", "group2"}, retrieved.MemberOf)
		assert.Equal(t, "ou1", retrieved.ParentOU)
		assert.Equal(t, "manager1", retrieved.Manager)
	})
}

func TestGetDirectoryStats(t *testing.T) {
	ctx := context.Background()

	t.Run("empty store returns zero type counts", func(t *testing.T) {
		adapter := newDirectoryStorageAdapter(t)

		stats, err := adapter.GetDirectoryStats(ctx)
		require.NoError(t, err)
		require.NotNil(t, stats)
		assert.Equal(t, int64(0), stats.UserCount)
		assert.Equal(t, int64(0), stats.GroupCount)
		assert.Equal(t, int64(0), stats.OUCount)
		assert.Equal(t, int64(0), stats.TotalObjects)
		assert.Equal(t, "healthy", stats.CollectionHealth)
	})

	t.Run("type counts reflect seeded objects", func(t *testing.T) {
		adapter := newDirectoryStorageAdapter(t)

		now := time.Now()
		for _, id := range []string{"u1", "u2"} {
			require.NoError(t, adapter.StoreDirectoryDNA(ctx, &DirectoryDNA{
				ObjectID: id, ObjectType: interfaces.DirectoryObjectTypeUser,
				ID: "dna_" + id, Attributes: map[string]string{}, LastUpdated: &now,
			}))
		}
		require.NoError(t, adapter.StoreDirectoryDNA(ctx, &DirectoryDNA{
			ObjectID: "g1", ObjectType: interfaces.DirectoryObjectTypeGroup,
			ID: "dna_g1", Attributes: map[string]string{}, LastUpdated: &now,
		}))

		stats, err := adapter.GetDirectoryStats(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(2), stats.UserCount)
		assert.Equal(t, int64(1), stats.GroupCount)
		assert.Equal(t, int64(0), stats.OUCount)
		assert.Equal(t, int64(3), stats.TotalObjects)
		assert.Greater(t, stats.TotalStorageUsed, int64(0))
		assert.Greater(t, stats.CompressionRatio, float64(0))
		assert.Equal(t, "healthy", stats.CollectionHealth)
	})
}

func TestGetObjectStats(t *testing.T) {
	ctx := context.Background()

	t.Run("empty store returns zero counts", func(t *testing.T) {
		adapter := newDirectoryStorageAdapter(t)

		for _, objType := range []interfaces.DirectoryObjectType{
			interfaces.DirectoryObjectTypeUser,
			interfaces.DirectoryObjectTypeGroup,
			interfaces.DirectoryObjectTypeOU,
		} {
			stats, err := adapter.GetObjectStats(ctx, objType)
			require.NoError(t, err)
			require.NotNil(t, stats)
			assert.Equal(t, objType, stats.ObjectType)
			assert.Equal(t, int64(0), stats.TotalCount)
			assert.Equal(t, int64(0), stats.ActiveCount)
		}
	})

	t.Run("counts reflect seeded objects by type", func(t *testing.T) {
		adapter := newDirectoryStorageAdapter(t)

		storeObj := func(id string, objType interfaces.DirectoryObjectType) {
			now := time.Now()
			err := adapter.StoreDirectoryDNA(ctx, &DirectoryDNA{
				ObjectID:    id,
				ObjectType:  objType,
				ID:          "dna_" + id,
				Attributes:  map[string]string{"name": id},
				LastUpdated: &now,
			})
			require.NoError(t, err)
		}

		// Seed: 3 users, 2 groups, 1 OU
		storeObj("user1", interfaces.DirectoryObjectTypeUser)
		storeObj("user2", interfaces.DirectoryObjectTypeUser)
		storeObj("user3", interfaces.DirectoryObjectTypeUser)
		storeObj("group1", interfaces.DirectoryObjectTypeGroup)
		storeObj("group2", interfaces.DirectoryObjectTypeGroup)
		storeObj("ou1", interfaces.DirectoryObjectTypeOU)

		userStats, err := adapter.GetObjectStats(ctx, interfaces.DirectoryObjectTypeUser)
		require.NoError(t, err)
		assert.Equal(t, int64(3), userStats.TotalCount)
		assert.Equal(t, int64(3), userStats.ActiveCount)
		assert.Equal(t, interfaces.DirectoryObjectTypeUser, userStats.ObjectType)
		assert.False(t, userStats.LastUpdated.IsZero(), "LastUpdated should be set after writes")

		groupStats, err := adapter.GetObjectStats(ctx, interfaces.DirectoryObjectTypeGroup)
		require.NoError(t, err)
		assert.Equal(t, int64(2), groupStats.TotalCount)

		ouStats, err := adapter.GetObjectStats(ctx, interfaces.DirectoryObjectTypeOU)
		require.NoError(t, err)
		assert.Equal(t, int64(1), ouStats.TotalCount)
	})

	t.Run("re-storing same object ID does not inflate count", func(t *testing.T) {
		adapter := newDirectoryStorageAdapter(t)

		now := time.Now()
		dna := &DirectoryDNA{
			ObjectID:    "user1",
			ObjectType:  interfaces.DirectoryObjectTypeUser,
			ID:          "dna_user1",
			Attributes:  map[string]string{"name": "first"},
			LastUpdated: &now,
		}
		require.NoError(t, adapter.StoreDirectoryDNA(ctx, dna))

		// Update the same object
		later := now.Add(time.Minute)
		dna.Attributes = map[string]string{"name": "updated"}
		dna.LastUpdated = &later
		require.NoError(t, adapter.StoreDirectoryDNA(ctx, dna))

		stats, err := adapter.GetObjectStats(ctx, interfaces.DirectoryObjectTypeUser)
		require.NoError(t, err)
		assert.Equal(t, int64(1), stats.TotalCount, "storing same objectID twice should not double count")
		// LastUpdated should reflect the more recent write
		assert.Equal(t, later.Unix(), stats.LastUpdated.Unix())
	})

	t.Run("last updated reflects most recent write", func(t *testing.T) {
		adapter := newDirectoryStorageAdapter(t)

		earlier := time.Now().Add(-time.Hour)
		later := time.Now()

		require.NoError(t, adapter.StoreDirectoryDNA(ctx, &DirectoryDNA{
			ObjectID:    "user_a",
			ObjectType:  interfaces.DirectoryObjectTypeUser,
			ID:          "dna_a",
			Attributes:  map[string]string{},
			LastUpdated: &earlier,
		}))
		require.NoError(t, adapter.StoreDirectoryDNA(ctx, &DirectoryDNA{
			ObjectID:    "user_b",
			ObjectType:  interfaces.DirectoryObjectTypeUser,
			ID:          "dna_b",
			Attributes:  map[string]string{},
			LastUpdated: &later,
		}))

		stats, err := adapter.GetObjectStats(ctx, interfaces.DirectoryObjectTypeUser)
		require.NoError(t, err)
		assert.Equal(t, int64(2), stats.TotalCount)
		assert.Equal(t, later.Unix(), stats.LastUpdated.Unix())
	})
}

func TestStorageConfiguration(t *testing.T) {
	adapter := newDirectoryStorageAdapter(t)
	ctx := context.Background()

	t.Run("disabling deduplication stores full content for identical DNA", func(t *testing.T) {
		adapter.SetDeduplication(false)

		now := time.Now()
		dna := &DirectoryDNA{
			ObjectID:    "cfg_user",
			ObjectType:  interfaces.DirectoryObjectTypeUser,
			ID:          "dna_cfg_user",
			Attributes:  map[string]string{"name": "cfg"},
			LastUpdated: &now,
		}

		require.NoError(t, adapter.StoreDirectoryDNA(ctx, dna))
		require.NoError(t, adapter.StoreDirectoryDNA(ctx, dna))

		// Both writes are retrievable as full records, not references.
		history, err := adapter.GetDirectoryHistory(ctx, "cfg_user", nil)
		require.NoError(t, err)
		assert.Len(t, history, 2)
	})

	t.Run("set compression level", func(t *testing.T) {
		adapter.SetCompressionLevel(9)
		assert.Equal(t, 9, adapter.compressionLevel)
	})

	t.Run("shard prefix applies to newly stored records", func(t *testing.T) {
		adapter.SetShardPrefix("custom")

		now := time.Now()
		require.NoError(t, adapter.StoreDirectoryDNA(ctx, &DirectoryDNA{
			ObjectID:    "shard_user",
			ObjectType:  interfaces.DirectoryObjectTypeUser,
			ID:          "dna_shard_user",
			Attributes:  map[string]string{"name": "shard"},
			LastUpdated: &now,
		}))

		assert.True(t, strings.HasPrefix(adapter.generateShardID("shard_user", interfaces.DirectoryObjectTypeUser), "custom_"))
	})
}

func TestGetStorageHealth(t *testing.T) {
	ctx := context.Background()

	storeAttribute := func(t *testing.T, adapter *DirectoryDNAStorageAdapter, objectID, value string) {
		t.Helper()
		now := time.Now()
		require.NoError(t, adapter.StoreDirectoryDNA(ctx, &DirectoryDNA{
			ObjectID:    objectID,
			ObjectType:  interfaces.DirectoryObjectTypeUser,
			ID:          "dna_" + objectID,
			Attributes:  map[string]string{"payload": value},
			LastUpdated: &now,
		}))
	}

	t.Run("healthy when compression meets target", func(t *testing.T) {
		adapter := newDirectoryStorageAdapter(t)

		// High-entropy payload: gzip cannot get near the 0.5 degradation threshold.
		raw := make([]byte, 8192)
		_, err := rand.Read(raw)
		require.NoError(t, err)
		storeAttribute(t, adapter, "entropy_user", base64.StdEncoding.EncodeToString(raw))

		health, err := adapter.GetStorageHealth(ctx)
		require.NoError(t, err)
		require.NotNil(t, health)
		assert.Equal(t, "healthy", health.Status)
		assert.Empty(t, health.Issues)
		assert.NotZero(t, health.LastCheck)
		assert.Greater(t, health.CompressionRatio, 0.5)
		assert.GreaterOrEqual(t, health.DeduplicationRatio, float64(0))
		assert.Greater(t, health.StorageUsed, int64(0))
	})

	t.Run("degraded when compression ratio is low", func(t *testing.T) {
		adapter := newDirectoryStorageAdapter(t)

		// Highly repetitive payload compresses far below the 0.5 threshold.
		storeAttribute(t, adapter, "repetitive_user", strings.Repeat("cfgms-directory-dna-", 512))

		health, err := adapter.GetStorageHealth(ctx)
		require.NoError(t, err)
		require.NotNil(t, health)
		assert.Less(t, health.CompressionRatio, 0.5)
		assert.Equal(t, "degraded", health.Status)
		assert.Contains(t, health.Issues, "Low compression ratio")
	})
}

func TestStorageIntegration(t *testing.T) {
	adapter := newDirectoryStorageAdapter(t)
	ctx := context.Background()

	// Test complete store-retrieve cycle
	originalDNA := &DirectoryDNA{
		ObjectID:   "integration_test",
		ObjectType: interfaces.DirectoryObjectTypeUser,
		ID:         "dna_integration",
		Attributes: map[string]string{
			"username":   "integrationuser",
			"email":      "integration@test.com",
			"department": "Testing",
			"is_active":  "true",
		},
		Provider:          "TestProvider",
		TenantID:          "tenant1",
		DistinguishedName: "CN=integrationuser,OU=Users,DC=test,DC=local",
		LastUpdated:       timePtr(time.Now()),
		AttributeCount:    4,
	}

	// Store the DNA
	err := adapter.StoreDirectoryDNA(ctx, originalDNA)
	require.NoError(t, err)

	// Retrieve the DNA
	retrievedDNA, err := adapter.GetDirectoryDNA(ctx, "integration_test", interfaces.DirectoryObjectTypeUser)
	require.NoError(t, err)

	// Verify the stored data survives the full compress/persist/index/retrieve cycle
	assert.Equal(t, originalDNA.ObjectID, retrievedDNA.ObjectID)
	assert.Equal(t, originalDNA.ObjectType, retrievedDNA.ObjectType)
	assert.Equal(t, originalDNA.Attributes, retrievedDNA.Attributes)
	assert.Equal(t, originalDNA.DistinguishedName, retrievedDNA.DistinguishedName)
}

// TestDirectoryDNARoundTrip verifies that a DirectoryDNA stored with the new
// Fragment-based representation is returned intact with all fields preserved.
func TestDirectoryDNARoundTrip(t *testing.T) {
	adapter := newDirectoryStorageAdapter(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	original := &DirectoryDNA{
		ObjectID:          "rt-user-1",
		ObjectType:        interfaces.DirectoryObjectTypeUser,
		ID:                "dna_rt_user1",
		Provider:          "test-provider",
		TenantID:          "tenant-42",
		DistinguishedName: "CN=rt-user-1,OU=Users,DC=example,DC=com",
		Attributes: map[string]string{
			"display_name": "Round Trip User",
			"email":        "rtuser@example.com",
			"object_type":  "user",
		},
		AttributeCount:  3,
		SyncFingerprint: "fp-abc123",
		LastUpdated:     &now,
	}

	require.NoError(t, adapter.StoreDirectoryDNA(ctx, original))

	retrieved, err := adapter.GetDirectoryDNA(ctx, "rt-user-1", interfaces.DirectoryObjectTypeUser)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, original.ObjectID, retrieved.ObjectID)
	assert.Equal(t, original.ObjectType, retrieved.ObjectType)
	assert.Equal(t, original.ID, retrieved.ID)
	assert.Equal(t, original.Provider, retrieved.Provider)
	assert.Equal(t, original.TenantID, retrieved.TenantID)
	assert.Equal(t, original.DistinguishedName, retrieved.DistinguishedName)
	assert.Equal(t, original.Attributes, retrieved.Attributes)
	assert.Equal(t, original.AttributeCount, retrieved.AttributeCount)
	assert.Equal(t, original.SyncFingerprint, retrieved.SyncFingerprint)
	require.NotNil(t, retrieved.LastUpdated)
	assert.Equal(t, now.Unix(), retrieved.LastUpdated.UTC().Unix())
}

// TestDirectoryRelationshipsRoundTrip verifies that DirectoryRelationships stored
// with the new Fragment-based representation are returned intact.
func TestDirectoryRelationshipsRoundTrip(t *testing.T) {
	adapter := newDirectoryStorageAdapter(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	original := &DirectoryRelationships{
		ObjectID:      "rt-group-1",
		ObjectType:    interfaces.DirectoryObjectTypeGroup,
		MemberOf:      []string{"parent-group-a", "parent-group-b"},
		Members:       []string{"user-1", "user-2", "user-3"},
		ChildOUs:      []string{"child-ou-1"},
		UsersInOU:     []string{"ou-user-1"},
		GroupsInOU:    []string{"ou-group-1"},
		DirectReports: []string{"report-1"},
		Manager:       "mgr-1",
		ParentOU:      "root-ou",
		Provider:      "test-provider",
		TenantID:      "tenant-42",
		CollectedAt:   now,
	}

	require.NoError(t, adapter.StoreRelationships(ctx, original))

	retrieved, err := adapter.GetRelationships(ctx, "rt-group-1")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, original.ObjectID, retrieved.ObjectID)
	assert.Equal(t, original.ObjectType, retrieved.ObjectType)
	assert.Equal(t, original.MemberOf, retrieved.MemberOf)
	assert.Equal(t, original.Members, retrieved.Members)
	assert.Equal(t, original.ChildOUs, retrieved.ChildOUs)
	assert.Equal(t, original.UsersInOU, retrieved.UsersInOU)
	assert.Equal(t, original.GroupsInOU, retrieved.GroupsInOU)
	assert.Equal(t, original.DirectReports, retrieved.DirectReports)
	assert.Equal(t, original.Manager, retrieved.Manager)
	assert.Equal(t, original.ParentOU, retrieved.ParentOU)
	assert.Equal(t, original.Provider, retrieved.Provider)
	assert.Equal(t, original.TenantID, retrieved.TenantID)
	assert.Equal(t, now.Unix(), retrieved.CollectedAt.UTC().Unix())
}

// TestUnmarshalFromProto covers the decode paths of the Fragment-based
// DirectoryDNA representation, including the two failure modes a stored record
// can present: a Fragment whose canonical_bytes are not valid JSON, and an
// envelope that carries no directory DNA Fragment at all.
func TestUnmarshalFromProto(t *testing.T) {
	t.Run("decodes the directory DNA fragment", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Second)
		original := &DirectoryDNA{
			ObjectID:    "decode-user-1",
			ObjectType:  interfaces.DirectoryObjectTypeUser,
			ID:          "dna_decode_user1",
			Provider:    "test-provider",
			TenantID:    "tenant-42",
			Attributes:  map[string]string{"display_name": "Decode User"},
			LastUpdated: &now,
		}

		encoded, err := marshalToProto(original)
		require.NoError(t, err)

		decoded, err := unmarshalFromProto(encoded)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		assert.Equal(t, original.ObjectID, decoded.ObjectID)
		assert.Equal(t, original.ID, decoded.ID)
		assert.Equal(t, original.TenantID, decoded.TenantID)
		assert.Equal(t, original.Attributes, decoded.Attributes)
	})

	t.Run("skips fragments from other authorities", func(t *testing.T) {
		encoded, err := marshalToProto(&DirectoryDNA{
			ObjectID:   "decode-user-2",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_decode_user2",
		})
		require.NoError(t, err)

		// Prepend an unrelated fragment so the loop must skip past it.
		encoded.Fragments = append([]*commonpb.Fragment{{
			FragmentId:     "hardware:v1",
			Authority:      "inventory",
			CanonicalBytes: []byte("not json at all"),
		}}, encoded.Fragments...)

		decoded, err := unmarshalFromProto(encoded)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		assert.Equal(t, "dna_decode_user2", decoded.ID)
	})

	t.Run("reports invalid fragment payload", func(t *testing.T) {
		decoded, err := unmarshalFromProto(&commonpb.DNA{
			Id: "decode-user-3",
			Fragments: []*commonpb.Fragment{{
				FragmentId:     directoryDNAFragmentID,
				Authority:      directoryAuthority,
				CanonicalBytes: []byte("{\"object_id\": "),
			}},
		})

		require.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "failed to unmarshal directory DNA")
	})

	t.Run("reports missing directory DNA fragment", func(t *testing.T) {
		decoded, err := unmarshalFromProto(&commonpb.DNA{Id: "decode-user-4"})

		require.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "directory DNA fragment not found in stored record")
	})

	t.Run("reports relationships fragment as missing directory DNA", func(t *testing.T) {
		encoded, err := marshalRelToProto(&DirectoryRelationships{
			ObjectID:    "decode-user-5",
			ObjectType:  interfaces.DirectoryObjectTypeUser,
			CollectedAt: time.Now(),
		})
		require.NoError(t, err)

		decoded, err := unmarshalFromProto(encoded)

		require.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "directory DNA fragment not found in stored record")
	})
}

// TestUnmarshalRelFromProto covers the decode paths of the Fragment-based
// DirectoryRelationships representation, including a Fragment with an
// undecodable payload and an envelope carrying no relationships Fragment.
func TestUnmarshalRelFromProto(t *testing.T) {
	t.Run("decodes the relationships fragment", func(t *testing.T) {
		original := &DirectoryRelationships{
			ObjectID:    "decode-group-1",
			ObjectType:  interfaces.DirectoryObjectTypeGroup,
			Members:     []string{"user-1", "user-2"},
			MemberOf:    []string{"parent-group"},
			Provider:    "test-provider",
			TenantID:    "tenant-42",
			CollectedAt: time.Now().UTC().Truncate(time.Second),
		}

		encoded, err := marshalRelToProto(original)
		require.NoError(t, err)

		decoded, err := unmarshalRelFromProto(encoded)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		assert.Equal(t, original.ObjectID, decoded.ObjectID)
		assert.Equal(t, original.Members, decoded.Members)
		assert.Equal(t, original.MemberOf, decoded.MemberOf)
		assert.Equal(t, original.TenantID, decoded.TenantID)
	})

	t.Run("skips fragments from other authorities", func(t *testing.T) {
		encoded, err := marshalRelToProto(&DirectoryRelationships{
			ObjectID:    "decode-group-2",
			ObjectType:  interfaces.DirectoryObjectTypeGroup,
			CollectedAt: time.Now(),
		})
		require.NoError(t, err)

		encoded.Fragments = append([]*commonpb.Fragment{{
			FragmentId:     "hardware:v1",
			Authority:      "inventory",
			CanonicalBytes: []byte("not json at all"),
		}}, encoded.Fragments...)

		decoded, err := unmarshalRelFromProto(encoded)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		assert.Equal(t, "decode-group-2", decoded.ObjectID)
	})

	t.Run("reports invalid fragment payload", func(t *testing.T) {
		decoded, err := unmarshalRelFromProto(&commonpb.DNA{
			Id: "rel_decode-group-3",
			Fragments: []*commonpb.Fragment{{
				FragmentId:     directoryRelFragmentID,
				Authority:      directoryAuthority,
				CanonicalBytes: []byte("[not-an-object]"),
			}},
		})

		require.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "failed to unmarshal directory relationships")
	})

	t.Run("reports missing relationships fragment", func(t *testing.T) {
		decoded, err := unmarshalRelFromProto(&commonpb.DNA{Id: "rel_decode-group-4"})

		require.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "directory relationships fragment not found in stored record")
	})

	t.Run("reports directory DNA fragment as missing relationships", func(t *testing.T) {
		encoded, err := marshalToProto(&DirectoryDNA{
			ObjectID:   "decode-group-5",
			ObjectType: interfaces.DirectoryObjectTypeGroup,
			ID:         "dna_decode_group5",
		})
		require.NoError(t, err)

		decoded, err := unmarshalRelFromProto(encoded)

		require.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "directory relationships fragment not found in stored record")
	})
}

// TestStorageErrorHandling exercises the adapter's error paths against a real
// backend that has been closed — a genuine failure, not injected behaviour.
func TestStorageErrorHandling(t *testing.T) {
	logger := logging.NewNoopLogger()
	config := &storage.Config{DataDir: t.TempDir(), CompressionType: "gzip", CompressionLevel: 6}

	backend, err := storage.NewSQLiteBackend(config, logger)
	require.NoError(t, err)

	compressor, err := storage.NewCompressor(config.CompressionType, config.CompressionLevel)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, compressor.Close()) })

	indexer, err := storage.NewMemoryIndexer(config, logger)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, indexer.Close()) })

	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	ctx := context.Background()

	testDNA := &DirectoryDNA{
		ObjectID:   "error_test",
		ObjectType: interfaces.DirectoryObjectTypeUser,
		ID:         "dna_error",
		Attributes: map[string]string{
			"username": "erroruser",
		},
		LastUpdated: timePtr(time.Now()),
	}

	// Closing the backend makes every subsequent backend call fail for real.
	require.NoError(t, backend.Close())

	t.Run("store reports backend failure", func(t *testing.T) {
		err := adapter.StoreDirectoryDNA(ctx, testDNA)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to determine next directory DNA version")
	})

	t.Run("relationship store reports backend failure", func(t *testing.T) {
		err := adapter.StoreRelationships(ctx, &DirectoryRelationships{
			ObjectID:    "error_test",
			ObjectType:  interfaces.DirectoryObjectTypeUser,
			CollectedAt: time.Now(),
		})

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to determine next relationships version")
	})

	t.Run("retrieval reports missing record", func(t *testing.T) {
		retrieved, err := adapter.GetDirectoryDNA(ctx, "error_test", interfaces.DirectoryObjectTypeUser)

		require.Error(t, err)
		assert.Nil(t, retrieved)
		assert.Contains(t, err.Error(), "no directory DNA record found")
	})
}
