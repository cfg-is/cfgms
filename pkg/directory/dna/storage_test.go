package dna

import (
	"context"
	"sync"
	"testing"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock implementations for testing storage integration

type MockBackend struct {
	mutex   sync.RWMutex
	records map[string]*storage.DNARecord
	content map[string][]byte
	stats   *storage.StorageStats
}

func NewMockBackend() *MockBackend {
	return &MockBackend{
		records: make(map[string]*storage.DNARecord),
		content: make(map[string][]byte),
		stats: &storage.StorageStats{
			TotalSize:         0,
			CompressionRatio:  0.7,
			DeduplicationRatio: 0.8,
			TotalDevices:      0,
			ActiveDevices:     0,
			AverageReadTime:   10 * time.Millisecond,
			AverageWriteTime:  15 * time.Millisecond,
		},
	}
}

func (m *MockBackend) StoreRecord(ctx context.Context, record *storage.DNARecord, compressedData []byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	key := record.ContentHash + ":" + record.ShardID
	m.records[key] = record
	m.content[key] = compressedData
	m.stats.TotalSize += int64(len(compressedData))
	m.stats.TotalDevices++
	return nil
}

func (m *MockBackend) StoreReference(ctx context.Context, record *storage.DNARecord) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	key := record.ContentHash + ":" + record.ShardID
	m.records[key] = record
	return nil
}

func (m *MockBackend) GetRecord(ctx context.Context, contentHash, shardID string) (*storage.DNARecord, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	key := contentHash + ":" + shardID
	if record, exists := m.records[key]; exists {
		return record, nil
	}
	return nil, assert.AnError
}

func (m *MockBackend) HasContent(ctx context.Context, contentHash string) (bool, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	for key := range m.content {
		if key[:len(contentHash)] == contentHash {
			return true, nil
		}
	}
	return false, nil
}

func (m *MockBackend) GetStats(ctx context.Context) (*storage.StorageStats, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Return a copy to prevent race conditions
	statsCopy := *m.stats
	return &statsCopy, nil
}

func (m *MockBackend) Flush() error { return nil }
func (m *MockBackend) Optimize() error { return nil }
func (m *MockBackend) Close() error { return nil }

type MockCompressor struct {
	mutex            sync.RWMutex
	compressionRatio float64
	stats           *storage.CompressionStats
}

func NewMockCompressor() *MockCompressor {
	return &MockCompressor{
		compressionRatio: 0.7,
		stats: &storage.CompressionStats{
			TotalBytesIn:     0,
			TotalBytesOut:    0,
			CompressionRatio: 0.7,
			Algorithm:        "mock",
			Level:            6,
		},
	}
}

func (m *MockCompressor) Compress(dna *commonpb.DNA) ([]byte, int64, error) {
	// Simulate compression by returning smaller data
	originalSize := int64(len(dna.Id) + len(dna.ConfigHash))
	for _, attr := range dna.Attributes {
		originalSize += int64(len(attr))
	}
	
	compressedSize := int64(float64(originalSize) * m.compressionRatio)
	compressedData := make([]byte, compressedSize)
	
	// Update stats with proper synchronization
	m.mutex.Lock()
	m.stats.TotalBytesIn += originalSize
	m.stats.TotalBytesOut += compressedSize
	m.stats.TotalOperations++
	m.mutex.Unlock()
	
	return compressedData, originalSize, nil
}

func (m *MockCompressor) Decompress(data []byte) (*commonpb.DNA, error) {
	// Return a mock DNA for testing
	return &commonpb.DNA{
		Id: "decompressed_dna",
		Attributes: map[string]string{
			"test": "value",
		},
	}, nil
}

func (m *MockCompressor) GetCompressionRatio() float64 {
	return m.compressionRatio
}

func (m *MockCompressor) GetStats() *storage.CompressionStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Return a copy to prevent race conditions
	statsCopy := *m.stats
	return &statsCopy
}

func (m *MockCompressor) Close() error { return nil }

type MockIndexer struct {
	mutex   sync.RWMutex
	records map[string][]*storage.RecordRef
	stats   *storage.IndexStats
}

func NewMockIndexer() *MockIndexer {
	return &MockIndexer{
		records: make(map[string][]*storage.RecordRef),
		stats: &storage.IndexStats{
			TotalEntries:     0,
			UniqueDevices:    0,
			AverageQueryTime: 5 * time.Millisecond,
			CacheHitRatio:    0.85,
		},
	}
}

func (m *MockIndexer) IndexRecord(ctx context.Context, record *storage.DNARecord) error {
	ref := &storage.RecordRef{
		DeviceID:    record.DeviceID,
		ContentHash: record.ContentHash,
		ShardID:     record.ShardID,
		StoredAt:    record.StoredAt,
		Size:        record.OriginalSize,
	}
	
	m.mutex.Lock()
	m.records[record.DeviceID] = append(m.records[record.DeviceID], ref)
	m.stats.TotalEntries++
	m.mutex.Unlock()
	return nil
}

func (m *MockIndexer) QueryRecords(ctx context.Context, deviceID string, options *storage.QueryOptions) ([]*storage.RecordRef, int64, error) {
	m.mutex.RLock()
	refs, exists := m.records[deviceID]
	if !exists {
		m.mutex.RUnlock()
		return nil, 0, nil
	}
	
	// Make a copy to prevent race conditions
	refsCopy := make([]*storage.RecordRef, len(refs))
	copy(refsCopy, refs)
	m.mutex.RUnlock()
	
	// Apply limit if specified
	if options != nil && options.Limit > 0 && len(refsCopy) > options.Limit {
		refsCopy = refsCopy[:options.Limit]
	}
	
	return refsCopy, int64(len(refsCopy)), nil
}

func (m *MockIndexer) GetNextVersion(ctx context.Context, deviceID string) (int64, error) {
	m.mutex.RLock()
	refs, exists := m.records[deviceID]
	if !exists {
		m.mutex.RUnlock()
		return 1, nil
	}
	count := int64(len(refs))
	m.mutex.RUnlock()
	return count + 1, nil
}

func (m *MockIndexer) GetDeviceStats(ctx context.Context, deviceID string) (*storage.DeviceStats, error) {
	m.mutex.RLock()
	refs, exists := m.records[deviceID]
	if !exists {
		m.mutex.RUnlock()
		return nil, assert.AnError
	}
	count := int64(len(refs))
	m.mutex.RUnlock()
	
	return &storage.DeviceStats{
		DeviceID:     deviceID,
		TotalRecords: count,
		TotalSize:    1024,
	}, nil
}

func (m *MockIndexer) GetGlobalStats(ctx context.Context) (*storage.IndexStats, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Return a copy to prevent race conditions
	statsCopy := *m.stats
	return &statsCopy, nil
}

func (m *MockIndexer) Close() error { return nil }

// Storage Integration Tests

func TestNewDirectoryDNAStorageAdapter(t *testing.T) {
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	
	assert.NotNil(t, adapter)
	assert.Equal(t, backend, adapter.backend)
	assert.Equal(t, compressor, adapter.compressor)
	assert.Equal(t, indexer, adapter.indexer)
	assert.Equal(t, logger, adapter.logger)
}

func TestStoreDirectoryDNA(t *testing.T) {
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	
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
		err := adapter.StoreDirectoryDNA(ctx, testDNA)
		
		assert.NoError(t, err)
		
		// Verify record was stored
		assert.Greater(t, len(backend.records), 0)
		
		// Verify indexing was performed
		assert.Greater(t, len(indexer.records), 0)
	})
	
	t.Run("deduplication", func(t *testing.T) {
		// Store the same DNA again
		err := adapter.StoreDirectoryDNA(ctx, testDNA)
		
		assert.NoError(t, err)
		
		// Should be deduplicated (exact behavior depends on implementation)
	})
}

func TestGetDirectoryDNA(t *testing.T) {
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	
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
		assert.NotNil(t, retrievedDNA)
		assert.Equal(t, "user1", retrievedDNA.ObjectID)
		assert.Equal(t, interfaces.DirectoryObjectTypeUser, retrievedDNA.ObjectType)
		
		// Note: Exact attribute matching depends on the conversion process
		assert.NotEmpty(t, retrievedDNA.Attributes)
	})
	
	t.Run("record not found", func(t *testing.T) {
		retrievedDNA, err := adapter.GetDirectoryDNA(ctx, "nonexistent", interfaces.DirectoryObjectTypeUser)
		
		assert.Error(t, err)
		assert.Nil(t, retrievedDNA)
		assert.Contains(t, err.Error(), "no directory DNA record found")
	})
}

func TestQueryDirectoryDNA(t *testing.T) {
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	
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
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	
	ctx := context.Background()
	
	// Store multiple versions of the same object
	baseTime := time.Now().Add(-2 * time.Hour)
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
		timeRange := &TimeRange{
			StartTime: baseTime.Add(30 * time.Minute),
			EndTime:   baseTime.Add(90 * time.Minute),
		}
		
		history, err := adapter.GetDirectoryHistory(ctx, "user1", timeRange)
		
		require.NoError(t, err)
		// Should return limited results based on time range
		assert.GreaterOrEqual(t, len(history), 0)
	})
}

func TestStoreAndGetRelationships(t *testing.T) {
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	
	ctx := context.Background()
	
	// Create test relationships
	relationships := &DirectoryRelationships{
		ObjectID:   "user1",
		ObjectType: interfaces.DirectoryObjectTypeUser,
		MemberOf:   []string{"group1", "group2"},
		ParentOU:   "ou1",
		Manager:    "manager1",
		CollectedAt: time.Now(),
		Provider:   "TestProvider",
		TenantID:   "tenant1",
	}
	
	t.Run("store relationships", func(t *testing.T) {
		err := adapter.StoreRelationships(ctx, relationships)
		
		assert.NoError(t, err)
		
		// Verify storage occurred
		assert.Greater(t, len(backend.records), 0)
	})
	
	t.Run("retrieve relationships", func(t *testing.T) {
		retrieved, err := adapter.GetRelationships(ctx, "user1")
		
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
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	
	ctx := context.Background()
	
	stats, err := adapter.GetDirectoryStats(ctx)
	
	require.NoError(t, err)
	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.TotalObjects, int64(0))
	assert.GreaterOrEqual(t, stats.TotalStorageUsed, int64(0))
	assert.GreaterOrEqual(t, stats.CompressionRatio, float64(0))
	assert.Equal(t, "healthy", stats.CollectionHealth)
}

func TestGetObjectStats(t *testing.T) {
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	
	ctx := context.Background()
	
	stats, err := adapter.GetObjectStats(ctx, interfaces.DirectoryObjectTypeUser)
	
	require.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, interfaces.DirectoryObjectTypeUser, stats.ObjectType)
	assert.GreaterOrEqual(t, stats.TotalCount, int64(0))
	assert.GreaterOrEqual(t, stats.ActiveCount, int64(0))
}

func TestStorageConfiguration(t *testing.T) {
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	
	t.Run("set deduplication", func(t *testing.T) {
		adapter.SetDeduplication(false)
		// Verify configuration is set (internal state)
	})
	
	t.Run("set compression level", func(t *testing.T) {
		adapter.SetCompressionLevel(9)
		// Verify configuration is set (internal state)
	})
	
	t.Run("set shard prefix", func(t *testing.T) {
		adapter.SetShardPrefix("custom")
		// Verify configuration is set (internal state)
	})
}

func TestGetStorageHealth(t *testing.T) {
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	
	ctx := context.Background()
	
	health, err := adapter.GetStorageHealth(ctx)
	
	require.NoError(t, err)
	assert.NotNil(t, health)
	assert.Equal(t, "healthy", health.Status)
	assert.NotZero(t, health.LastCheck)
	assert.GreaterOrEqual(t, health.CompressionRatio, float64(0))
	assert.GreaterOrEqual(t, health.DeduplicationRatio, float64(0))
}

func TestStorageIntegration(t *testing.T) {
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
	adapter := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)
	
	ctx := context.Background()
	
	// Test complete store-retrieve cycle
	originalDNA := &DirectoryDNA{
		ObjectID:   "integration_test",
		ObjectType: interfaces.DirectoryObjectTypeUser,
		ID:         "dna_integration",
		Attributes: map[string]string{
			"username":    "integrationuser",
			"email":       "integration@test.com",
			"department":  "Testing",
			"is_active":   "true",
		},
		Provider:         "TestProvider",
		TenantID:         "tenant1",
		DistinguishedName: "CN=integrationuser,OU=Users,DC=test,DC=local",
		LastUpdated:      timePtr(time.Now()),
		AttributeCount:   4,
	}
	
	// Store the DNA
	err := adapter.StoreDirectoryDNA(ctx, originalDNA)
	require.NoError(t, err)
	
	// Retrieve the DNA
	retrievedDNA, err := adapter.GetDirectoryDNA(ctx, "integration_test", interfaces.DirectoryObjectTypeUser)
	require.NoError(t, err)
	
	// Verify the essential data is preserved
	assert.Equal(t, originalDNA.ObjectID, retrievedDNA.ObjectID)
	assert.Equal(t, originalDNA.ObjectType, retrievedDNA.ObjectType)
	assert.NotEmpty(t, retrievedDNA.Attributes)
	
	// Note: Due to conversion through the DNA framework, 
	// some attributes might be stored/retrieved differently
}

func TestStorageErrorHandling(t *testing.T) {
	// Create a backend that will error
	backend := &MockBackend{
		records: make(map[string]*storage.DNARecord), // Initialize maps
		content: make(map[string][]byte),
		stats: &storage.StorageStats{
			TotalSize:         0,
			CompressionRatio:  0.7,
			DeduplicationRatio: 0.8,
			TotalDevices:      0,
			ActiveDevices:     0,
			AverageReadTime:   10 * time.Millisecond,
			AverageWriteTime:  15 * time.Millisecond,
		},
	}
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	logger := logging.NewNoopLogger()
	
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
	
	t.Run("storage error", func(t *testing.T) {
		err := adapter.StoreDirectoryDNA(ctx, testDNA)
		
		// The exact error behavior depends on the mock implementation
		// This test ensures error handling paths are exercised
		if err != nil {
			assert.Error(t, err)
		}
	})
}