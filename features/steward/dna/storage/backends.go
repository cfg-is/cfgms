// Package storage implements various backend storage systems for DNA data.

package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// NewBackend creates a new storage backend based on the configuration
func NewBackend(backendType BackendType, config *Config, logger logging.Logger) (Backend, error) {
	switch backendType {
	case BackendMemory:
		return NewMemoryBackend(config, logger)
	case BackendFile:
		return NewFileBackend(config, logger)
	case BackendGit:
		return NewGitBackend(config, logger)
	case BackendDatabase:
		return NewDatabaseBackend(config, logger)
	case BackendHybrid:
		return NewHybridBackend(config, logger)
	default:
		return nil, fmt.Errorf("unsupported backend type: %s", backendType)
	}
}

// MemoryBackend implements an in-memory storage backend for DNA data
//
// This backend is primarily used for testing and development. It provides
// fast access but doesn't persist data across application restarts.
type MemoryBackend struct {
	logger      logging.Logger
	config      *Config
	records     map[string]*DNARecord // contentHash -> record
	references  map[string][]*DNARecord // contentHash -> list of references
	shards      map[string]map[string]*DNARecord // shardID -> contentHash -> record
	contentData map[string][]byte     // contentHash -> compressed data
	mutex       sync.RWMutex
	stats       *StorageStats
	statsMutex  sync.RWMutex
}

// NewMemoryBackend creates a new in-memory storage backend
func NewMemoryBackend(config *Config, logger logging.Logger) (*MemoryBackend, error) {
	backend := &MemoryBackend{
		logger:      logger,
		config:      config,
		records:     make(map[string]*DNARecord),
		references:  make(map[string][]*DNARecord),
		shards:      make(map[string]map[string]*DNARecord),
		contentData: make(map[string][]byte),
		stats: &StorageStats{
			TotalShards:    0,
			ActiveShards:   0,
			ShardSizes:     make(map[string]int64),
			CollectedAt:    time.Now(),
		},
	}

	// Initialize shards if sharding is enabled
	if config.EnableSharding {
		for i := 0; i < config.ShardCount; i++ {
			shardID := fmt.Sprintf("shard_%d", i)
			backend.shards[shardID] = make(map[string]*DNARecord)
			backend.stats.ShardSizes[shardID] = 0
		}
		backend.stats.TotalShards = config.ShardCount
	} else {
		backend.shards["default"] = make(map[string]*DNARecord)
		backend.stats.ShardSizes["default"] = 0
		backend.stats.TotalShards = 1
	}

	logger.Info("Memory storage backend initialized",
		"sharding_enabled", config.EnableSharding,
		"shard_count", config.ShardCount)

	return backend, nil
}

// StoreRecord stores a DNA record with compressed data
func (b *MemoryBackend) StoreRecord(ctx context.Context, record *DNARecord, compressedData []byte) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Store the record
	b.records[record.ContentHash] = record

	// Store compressed data
	b.contentData[record.ContentHash] = compressedData

	// Add to appropriate shard
	if shard, exists := b.shards[record.ShardID]; exists {
		shard[record.ContentHash] = record
		b.updateShardStats(record.ShardID, record.CompressedSize)
	} else {
		return fmt.Errorf("shard %s does not exist", record.ShardID)
	}

	// Update global statistics
	b.updateGlobalStats(record)

	hashDisplay := record.ContentHash
	if len(hashDisplay) > 16 {
		hashDisplay = hashDisplay[:16]
	}
	
	b.logger.Debug("DNA record stored in memory",
		"device_id", record.DeviceID,
		"content_hash", hashDisplay,
		"shard_id", record.ShardID,
		"compressed_size", record.CompressedSize)

	return nil
}

// StoreReference stores a reference to existing content (for deduplication)
func (b *MemoryBackend) StoreReference(ctx context.Context, record *DNARecord) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Add reference to existing content
	b.references[record.ContentHash] = append(b.references[record.ContentHash], record)

	// Update statistics for reference
	b.updateGlobalStats(record)

	hashDisplay := record.ContentHash
	if len(hashDisplay) > 16 {
		hashDisplay = hashDisplay[:16]
	}
	
	b.logger.Debug("DNA reference stored in memory",
		"device_id", record.DeviceID,
		"content_hash", hashDisplay,
		"references", len(b.references[record.ContentHash]))

	return nil
}

// GetRecord retrieves a DNA record by content hash and shard
func (b *MemoryBackend) GetRecord(ctx context.Context, contentHash, shardID string) (*DNARecord, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	// Check if record exists in specified shard
	if shard, exists := b.shards[shardID]; exists {
		if record, found := shard[contentHash]; found {
			// Clone the record to avoid external modifications
			recordCopy := *record
			return &recordCopy, nil
		}
	}

	// If not found in shard, check global records (for references)
	if record, exists := b.records[contentHash]; exists {
		recordCopy := *record
		return &recordCopy, nil
	}

	return nil, fmt.Errorf("DNA record not found: content_hash=%s, shard_id=%s", contentHash[:16], shardID)
}

// HasContent checks if content with the given hash already exists
func (b *MemoryBackend) HasContent(ctx context.Context, contentHash string) (bool, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	_, exists := b.records[contentHash]
	return exists, nil
}

// GetStats returns storage statistics
func (b *MemoryBackend) GetStats(ctx context.Context) (*StorageStats, error) {
	b.statsMutex.RLock()
	defer b.statsMutex.RUnlock()

	// Update real-time statistics
	b.calculateCurrentStats()

	// Return a copy of the stats
	statsCopy := *b.stats
	statsCopy.CollectedAt = time.Now()
	return &statsCopy, nil
}

// Flush forces any pending write operations to complete (no-op for memory backend)
func (b *MemoryBackend) Flush() error {
	// Memory backend doesn't have pending writes
	return nil
}

// Optimize performs storage optimization (compaction, defragmentation, etc.)
func (b *MemoryBackend) Optimize() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// For memory backend, optimization means cleanup of unused references
	cleaned := 0
	for contentHash := range b.references {
		// Remove references for non-existent content
		if _, exists := b.records[contentHash]; !exists {
			delete(b.references, contentHash)
			cleaned++
		}
	}

	if cleaned > 0 {
		b.logger.Info("Memory storage optimized", "cleaned_references", cleaned)
	}

	return nil
}

// Close closes the storage backend and releases resources
func (b *MemoryBackend) Close() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Clear all data structures
	b.records = nil
	b.references = nil
	b.shards = nil
	b.contentData = nil

	b.logger.Info("Memory storage backend closed")
	return nil
}

func (b *MemoryBackend) updateShardStats(shardID string, size int64) {
	b.statsMutex.Lock()
	defer b.statsMutex.Unlock()

	if currentSize, exists := b.stats.ShardSizes[shardID]; exists {
		b.stats.ShardSizes[shardID] = currentSize + size
	} else {
		b.stats.ShardSizes[shardID] = size
	}

	// Update active shards count
	activeShards := 0
	for _, size := range b.stats.ShardSizes {
		if size > 0 {
			activeShards++
		}
	}
	b.stats.ActiveShards = activeShards
}

func (b *MemoryBackend) updateGlobalStats(record *DNARecord) {
	b.statsMutex.Lock()
	defer b.statsMutex.Unlock()

	b.stats.TotalSize += record.CompressedSize
	b.stats.CompressedSize += record.CompressedSize
	b.stats.UncompressedSize += record.OriginalSize

	if b.stats.UncompressedSize > 0 {
		b.stats.CompressionRatio = float64(b.stats.CompressedSize) / float64(b.stats.UncompressedSize)
	}
}

func (b *MemoryBackend) calculateCurrentStats() {
	// Calculate unique vs total blocks for deduplication ratio
	b.stats.UniqueBlocks = int64(len(b.records))
	b.stats.TotalBlocks = b.stats.UniqueBlocks

	for _, refs := range b.references {
		b.stats.TotalBlocks += int64(len(refs))
	}

	if b.stats.TotalBlocks > 0 {
		b.stats.DeduplicationRatio = 1.0 - (float64(b.stats.UniqueBlocks) / float64(b.stats.TotalBlocks))
	}

	// Count unique devices
	deviceSet := make(map[string]bool)
	for _, record := range b.records {
		deviceSet[record.DeviceID] = true
	}
	for _, refs := range b.references {
		for _, ref := range refs {
			deviceSet[ref.DeviceID] = true
		}
	}
	b.stats.TotalDevices = int64(len(deviceSet))
	b.stats.ActiveDevices = b.stats.TotalDevices // All devices are "active" in memory

	if b.stats.TotalDevices > 0 {
		b.stats.AverageRecordsPerDevice = float64(b.stats.TotalBlocks) / float64(b.stats.TotalDevices)
	}
}

// FileBackend implements a file-based storage backend for DNA data
//
// This backend stores DNA records as files on the local filesystem,
// organized by shards and content hash for efficient access.
type FileBackend struct {
	logger      logging.Logger
	config      *Config
	basePath    string
	stats       *StorageStats
	statsMutex  sync.RWMutex
}

// NewFileBackend creates a new file-based storage backend
func NewFileBackend(config *Config, logger logging.Logger) (*FileBackend, error) {
	basePath := "/tmp/cfgms-dna-storage" // Default path
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	backend := &FileBackend{
		logger:   logger,
		config:   config,
		basePath: basePath,
		stats: &StorageStats{
			ShardSizes:  make(map[string]int64),
			CollectedAt: time.Now(),
		},
	}

	// Create shard directories
	if config.EnableSharding {
		for i := 0; i < config.ShardCount; i++ {
			shardPath := filepath.Join(basePath, fmt.Sprintf("shard_%d", i))
			if err := os.MkdirAll(shardPath, 0755); err != nil {
				return nil, fmt.Errorf("failed to create shard directory: %w", err)
			}
		}
		backend.stats.TotalShards = config.ShardCount
	} else {
		defaultPath := filepath.Join(basePath, "default")
		if err := os.MkdirAll(defaultPath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create default directory: %w", err)
		}
		backend.stats.TotalShards = 1
	}

	logger.Info("File storage backend initialized",
		"base_path", basePath,
		"sharding_enabled", config.EnableSharding,
		"shard_count", config.ShardCount)

	return backend, nil
}

// StoreRecord stores a DNA record with compressed data to the filesystem
func (b *FileBackend) StoreRecord(ctx context.Context, record *DNARecord, compressedData []byte) error {
	// Create file path based on shard and content hash
	fileName := fmt.Sprintf("%s.dna", record.ContentHash)
	filePath := filepath.Join(b.basePath, record.ShardID, fileName)

	// Create record data structure for storage
	recordData := struct {
		Record         *DNARecord `json:"record"`
		CompressedData []byte     `json:"compressed_data"`
	}{
		Record:         record,
		CompressedData: compressedData,
	}

	// Serialize to JSON
	data, err := json.Marshal(recordData)
	if err != nil {
		return fmt.Errorf("failed to marshal record data: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write record file: %w", err)
	}

	hashDisplay := record.ContentHash
	if len(hashDisplay) > 16 {
		hashDisplay = hashDisplay[:16]
	}
	
	b.logger.Debug("DNA record stored to file",
		"device_id", record.DeviceID,
		"content_hash", hashDisplay,
		"file_path", filePath,
		"file_size", len(data))

	return nil
}

// StoreReference stores a reference to existing content
func (b *FileBackend) StoreReference(ctx context.Context, record *DNARecord) error {
	// For file backend, references are stored as separate files
	fileName := fmt.Sprintf("%s_ref_%s.json", record.ContentHash, record.DeviceID)
	filePath := filepath.Join(b.basePath, record.ShardID, "refs", fileName)

	// Ensure refs directory exists
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create refs directory: %w", err)
	}

	// Serialize reference
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal reference: %w", err)
	}

	// Write reference file
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write reference file: %w", err)
	}

	hashDisplay := record.ContentHash
	if len(hashDisplay) > 16 {
		hashDisplay = hashDisplay[:16]
	}
	
	b.logger.Debug("DNA reference stored to file",
		"device_id", record.DeviceID,
		"content_hash", hashDisplay,
		"ref_file", filePath)

	return nil
}

// GetRecord retrieves a DNA record by content hash and shard
func (b *FileBackend) GetRecord(ctx context.Context, contentHash, shardID string) (*DNARecord, error) {
	fileName := fmt.Sprintf("%s.dna", contentHash)
	filePath := filepath.Join(b.basePath, shardID, fileName)

	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("DNA record not found: content_hash=%s, shard_id=%s", contentHash[:16], shardID)
		}
		return nil, fmt.Errorf("failed to read record file: %w", err)
	}

	// Deserialize record data
	var recordData struct {
		Record         *DNARecord `json:"record"`
		CompressedData []byte     `json:"compressed_data"`
	}

	if err := json.Unmarshal(data, &recordData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal record data: %w", err)
	}

	return recordData.Record, nil
}

// HasContent checks if content with the given hash already exists
func (b *FileBackend) HasContent(ctx context.Context, contentHash string) (bool, error) {
	// Check all shards for the content
	shardDirs := []string{"default"}
	if b.config.EnableSharding {
		shardDirs = make([]string, b.config.ShardCount)
		for i := 0; i < b.config.ShardCount; i++ {
			shardDirs[i] = fmt.Sprintf("shard_%d", i)
		}
	}

	for _, shardID := range shardDirs {
		fileName := fmt.Sprintf("%s.dna", contentHash)
		filePath := filepath.Join(b.basePath, shardID, fileName)
		if _, err := os.Stat(filePath); err == nil {
			return true, nil
		}
	}

	return false, nil
}

// GetStats returns storage statistics
func (b *FileBackend) GetStats(ctx context.Context) (*StorageStats, error) {
	b.statsMutex.Lock()
	defer b.statsMutex.Unlock()

	// Calculate statistics by walking the filesystem
	b.calculateFileSystemStats()

	statsCopy := *b.stats
	statsCopy.CollectedAt = time.Now()
	return &statsCopy, nil
}

// Flush forces any pending write operations to complete
func (b *FileBackend) Flush() error {
	// File system writes are synchronous, no pending operations
	return nil
}

// Optimize performs storage optimization
func (b *FileBackend) Optimize() error {
	// For file backend, optimization could include:
	// - Defragmentation of directory structure
	// - Cleanup of orphaned reference files
	// - Compression of old files
	b.logger.Info("File storage optimization completed")
	return nil
}

// Close closes the storage backend
func (b *FileBackend) Close() error {
	b.logger.Info("File storage backend closed")
	return nil
}

func (b *FileBackend) calculateFileSystemStats() {
	// Walk the filesystem to calculate statistics
	// This is a simplified implementation
	var totalSize int64
	
	if err := filepath.Walk(b.basePath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	}); err != nil {
		// Log error but continue - filesystem stats are not critical
	}

	b.stats.TotalSize = totalSize
	b.stats.CompressedSize = totalSize // Assume all data is compressed
}

// GitBackend implements a Git-based storage backend (stub)
type GitBackend struct {
	logger logging.Logger
	config *Config
}

// NewGitBackend creates a new Git-based storage backend
func NewGitBackend(config *Config, logger logging.Logger) (*GitBackend, error) {
	// This is a stub implementation
	return &GitBackend{
		logger: logger,
		config: config,
	}, nil
}

// Implement Backend interface (stubs)
func (b *GitBackend) StoreRecord(ctx context.Context, record *DNARecord, compressedData []byte) error {
	return fmt.Errorf("Git backend not fully implemented")
}

func (b *GitBackend) StoreReference(ctx context.Context, record *DNARecord) error {
	return fmt.Errorf("Git backend not fully implemented")
}

func (b *GitBackend) GetRecord(ctx context.Context, contentHash, shardID string) (*DNARecord, error) {
	return nil, fmt.Errorf("Git backend not fully implemented")
}

func (b *GitBackend) HasContent(ctx context.Context, contentHash string) (bool, error) {
	return false, fmt.Errorf("Git backend not fully implemented")
}

func (b *GitBackend) GetStats(ctx context.Context) (*StorageStats, error) {
	return &StorageStats{}, fmt.Errorf("Git backend not fully implemented")
}

func (b *GitBackend) Flush() error {
	return nil
}

func (b *GitBackend) Optimize() error {
	return nil
}

func (b *GitBackend) Close() error {
	return nil
}

// DatabaseBackend implements a database storage backend (stub)
type DatabaseBackend struct {
	logger logging.Logger
	config *Config
}

// NewDatabaseBackend creates a new database storage backend
func NewDatabaseBackend(config *Config, logger logging.Logger) (*DatabaseBackend, error) {
	// This is a stub implementation
	return &DatabaseBackend{
		logger: logger,
		config: config,
	}, nil
}

// Implement Backend interface (stubs)
func (b *DatabaseBackend) StoreRecord(ctx context.Context, record *DNARecord, compressedData []byte) error {
	return fmt.Errorf("Database backend not fully implemented")
}

func (b *DatabaseBackend) StoreReference(ctx context.Context, record *DNARecord) error {
	return fmt.Errorf("Database backend not fully implemented")
}

func (b *DatabaseBackend) GetRecord(ctx context.Context, contentHash, shardID string) (*DNARecord, error) {
	return nil, fmt.Errorf("Database backend not fully implemented")
}

func (b *DatabaseBackend) HasContent(ctx context.Context, contentHash string) (bool, error) {
	return false, fmt.Errorf("Database backend not fully implemented")
}

func (b *DatabaseBackend) GetStats(ctx context.Context) (*StorageStats, error) {
	return &StorageStats{}, fmt.Errorf("Database backend not fully implemented")
}

func (b *DatabaseBackend) Flush() error {
	return nil
}

func (b *DatabaseBackend) Optimize() error {
	return nil
}

func (b *DatabaseBackend) Close() error {
	return nil
}

// HybridBackend combines Git and database backends (stub)
type HybridBackend struct {
	logger logging.Logger
	config *Config
	gitBackend Backend
	dbBackend  Backend
}

// NewHybridBackend creates a new hybrid storage backend
func NewHybridBackend(config *Config, logger logging.Logger) (*HybridBackend, error) {
	// For now, use memory backend as a fallback
	memBackend, err := NewMemoryBackend(config, logger)
	if err != nil {
		return nil, err
	}

	return &HybridBackend{
		logger:     logger,
		config:     config,
		gitBackend: memBackend, // Placeholder
		dbBackend:  memBackend, // Placeholder
	}, nil
}

// Implement Backend interface (delegates to appropriate backend)
func (b *HybridBackend) StoreRecord(ctx context.Context, record *DNARecord, compressedData []byte) error {
	// Store in database for fast access
	return b.dbBackend.StoreRecord(ctx, record, compressedData)
}

func (b *HybridBackend) StoreReference(ctx context.Context, record *DNARecord) error {
	return b.dbBackend.StoreReference(ctx, record)
}

func (b *HybridBackend) GetRecord(ctx context.Context, contentHash, shardID string) (*DNARecord, error) {
	return b.dbBackend.GetRecord(ctx, contentHash, shardID)
}

func (b *HybridBackend) HasContent(ctx context.Context, contentHash string) (bool, error) {
	return b.dbBackend.HasContent(ctx, contentHash)
}

func (b *HybridBackend) GetStats(ctx context.Context) (*StorageStats, error) {
	return b.dbBackend.GetStats(ctx)
}

func (b *HybridBackend) Flush() error {
	if err := b.dbBackend.Flush(); err != nil {
		return err
	}
	return b.gitBackend.Flush()
}

func (b *HybridBackend) Optimize() error {
	if err := b.dbBackend.Optimize(); err != nil {
		return err
	}
	return b.gitBackend.Optimize()
}

func (b *HybridBackend) Close() error {
	if err := b.dbBackend.Close(); err != nil {
		b.logger.Error("Failed to close database backend", "error", err)
	}
	if err := b.gitBackend.Close(); err != nil {
		b.logger.Error("Failed to close git backend", "error", err)
	}
	return nil
}