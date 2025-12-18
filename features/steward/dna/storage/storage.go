// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package storage provides efficient DNA storage with deduplication and compression.
//
// The storage system implements content-addressable storage for DNA data with:
// - Content-based deduplication across devices
// - Compression with 70%+ space savings target
// - Historical queries for state change analysis
// - Automatic retention and archival policies
// - Horizontal scaling through sharding
//
// Architecture:
//   - Content-addressable blocks for DNA attributes
//   - Reference-based storage linking devices to content blocks
//   - Compressed storage with metadata indexing
//   - Time-series organization for historical queries
//
// Basic usage:
//
//	storage := storage.NewManager(config)
//	err := storage.Store(deviceID, dna)
//	history, err := storage.GetHistory(deviceID, timeRange)
package storage

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Manager provides efficient DNA storage with deduplication and compression.
//
// The manager handles the complete lifecycle of DNA storage including:
// - Content deduplication across devices
// - Compression and encoding
// - Historical queries and analysis
// - Retention policy enforcement
// - Storage optimization
type Manager struct {
	logger     logging.Logger
	config     *Config
	storage    Backend
	compressor Compressor
	indexer    Indexer
}

// Config defines the configuration for DNA storage management.
type Config struct {
	// Storage backend configuration
	Backend BackendType `json:"backend" yaml:"backend"`
	DataDir string      `json:"data_dir" yaml:"data_dir"` // Directory for storage files (default: "data")

	// Compression configuration
	CompressionLevel       int     `json:"compression_level" yaml:"compression_level"`               // 1-9, higher = better compression
	CompressionType        string  `json:"compression_type" yaml:"compression_type"`                 // "gzip", "lz4", "zstd"
	TargetCompressionRatio float64 `json:"target_compression_ratio" yaml:"target_compression_ratio"` // 0.3 = 70% savings

	// Deduplication configuration
	EnableDeduplication bool   `json:"enable_deduplication" yaml:"enable_deduplication"`
	BlockSize           int    `json:"block_size" yaml:"block_size"`         // Size for content blocks
	HashAlgorithm       string `json:"hash_algorithm" yaml:"hash_algorithm"` // "sha256", "blake2b"

	// Retention configuration
	RetentionPeriod     time.Duration `json:"retention_period" yaml:"retention_period"`             // How long to keep DNA records
	ArchivalPeriod      time.Duration `json:"archival_period" yaml:"archival_period"`               // When to archive old records
	MaxRecordsPerDevice int           `json:"max_records_per_device" yaml:"max_records_per_device"` // Limit per device

	// Sharding configuration
	EnableSharding   bool   `json:"enable_sharding" yaml:"enable_sharding"`
	ShardCount       int    `json:"shard_count" yaml:"shard_count"`             // Number of shards
	ShardingStrategy string `json:"sharding_strategy" yaml:"sharding_strategy"` // "device_id", "time_based", "hybrid"

	// Performance configuration
	BatchSize          int           `json:"batch_size" yaml:"batch_size"`                       // Batch operations
	FlushInterval      time.Duration `json:"flush_interval" yaml:"flush_interval"`               // How often to flush writes
	CacheSize          int           `json:"cache_size" yaml:"cache_size"`                       // In-memory cache size
	MaxStoragePerMonth int64         `json:"max_storage_per_month" yaml:"max_storage_per_month"` // 100MB default
}

// BackendType defines the storage backend type
type BackendType string

const (
	BackendSQLite   BackendType = "sqlite"   // SQLite embedded database (DEFAULT)
	BackendMemory   BackendType = "memory"   // In-memory only (DEPRECATED - data loss risk)
	BackendFile     BackendType = "file"     // File system storage (fallback)
	BackendGit      BackendType = "git"      // Git-based storage (DEPRECATED)
	BackendDatabase BackendType = "database" // External PostgreSQL database (scale)
	BackendHybrid   BackendType = "hybrid"   // Git + database (DEPRECATED)
)

// DNARecord represents a stored DNA record with metadata
type DNARecord struct {
	DeviceID         string        `json:"device_id"`
	DNA              *commonpb.DNA `json:"dna"`
	StoredAt         time.Time     `json:"stored_at"`
	ContentHash      string        `json:"content_hash"`
	CompressedSize   int64         `json:"compressed_size"`
	OriginalSize     int64         `json:"original_size"`
	CompressionRatio float64       `json:"compression_ratio"`
	Version          int64         `json:"version"`  // Incremental version for this device
	ShardID          string        `json:"shard_id"` // Which shard contains this record
}

// TimeRange defines a time range for historical queries
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// QueryOptions defines options for DNA queries
type QueryOptions struct {
	TimeRange   *TimeRange `json:"time_range,omitempty"`
	Limit       int        `json:"limit,omitempty"`
	Offset      int        `json:"offset,omitempty"`
	IncludeData bool       `json:"include_data"`         // Include full DNA data or just metadata
	Attributes  []string   `json:"attributes,omitempty"` // Filter to specific attributes
}

// HistoryResult contains the results of a historical query
type HistoryResult struct {
	Records    []*DNARecord   `json:"records"`
	TotalCount int64          `json:"total_count"`
	TimeRange  *TimeRange     `json:"time_range"`
	Metadata   *QueryMetadata `json:"metadata"`
}

// QueryMetadata provides metadata about query execution
type QueryMetadata struct {
	ExecutionTime      time.Duration `json:"execution_time"`
	CacheHit           bool          `json:"cache_hit"`
	RecordsScanned     int64         `json:"records_scanned"`
	BytesProcessed     int64         `json:"bytes_processed"`
	CompressionSavings int64         `json:"compression_savings"`
}

// NewManager creates a new DNA storage manager with the specified configuration.
//
// The manager initializes all required components including storage backend,
// compression engine, indexer, and begins background maintenance tasks.
func NewManager(config *Config, logger logging.Logger) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid storage config: %w", err)
	}

	// Initialize storage backend
	backend, err := NewBackend(config.Backend, config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage backend: %w", err)
	}

	// Initialize compressor
	compressor, err := NewCompressor(config.CompressionType, config.CompressionLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compressor: %w", err)
	}

	// Initialize indexer
	indexer, err := NewIndexer(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize indexer: %w", err)
	}

	manager := &Manager{
		logger:     logger,
		config:     config,
		storage:    backend,
		compressor: compressor,
		indexer:    indexer,
	}

	// Start background maintenance tasks
	go manager.startMaintenanceTasks()

	logger.Info("DNA storage manager initialized",
		"backend", config.Backend,
		"compression", config.CompressionType,
		"deduplication", config.EnableDeduplication,
		"sharding", config.EnableSharding)

	return manager, nil
}

// Store stores a DNA record for the specified device with deduplication and compression.
//
// The storage process includes:
// 1. Content hash calculation for deduplication
// 2. Compression to achieve target space savings
// 3. Shard assignment for horizontal scaling
// 4. Index updates for fast queries
// 5. Retention policy enforcement
func (m *Manager) Store(ctx context.Context, deviceID string, dna *commonpb.DNA) error {
	startTime := time.Now()

	// Generate content hash for deduplication
	contentHash, err := m.generateContentHash(dna)
	if err != nil {
		return fmt.Errorf("failed to generate content hash: %w", err)
	}

	// Check for deduplication opportunity
	if m.config.EnableDeduplication {
		if exists, err := m.storage.HasContent(ctx, contentHash); err == nil && exists {
			// Content already exists, just create reference
			return m.storeReference(ctx, deviceID, contentHash, dna, startTime)
		}
	}

	// Compress DNA data
	compressed, originalSize, err := m.compressor.Compress(dna)
	if err != nil {
		return fmt.Errorf("failed to compress DNA data: %w", err)
	}

	compressedSize := int64(len(compressed))
	compressionRatio := float64(compressedSize) / float64(originalSize)

	// Validate compression efficiency
	if compressionRatio > (1.0 - m.config.TargetCompressionRatio) {
		m.logger.Warn("DNA compression below target",
			"device_id", deviceID,
			"target_ratio", m.config.TargetCompressionRatio,
			"actual_ratio", compressionRatio)
	}

	// Determine shard for storage
	shardID := m.getShardID(deviceID, time.Now())

	// Get next version number for this device
	version, err := m.indexer.GetNextVersion(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("failed to get next version: %w", err)
	}

	// Create DNA record
	record := &DNARecord{
		DeviceID:         deviceID,
		DNA:              dna,
		StoredAt:         time.Now(),
		ContentHash:      contentHash,
		CompressedSize:   compressedSize,
		OriginalSize:     originalSize,
		CompressionRatio: compressionRatio,
		Version:          version,
		ShardID:          shardID,
	}

	// Store compressed data and record
	if err := m.storage.StoreRecord(ctx, record, compressed); err != nil {
		return fmt.Errorf("failed to store DNA record: %w", err)
	}

	// Update index
	if err := m.indexer.IndexRecord(ctx, record); err != nil {
		m.logger.Error("Failed to update index", "error", err, "device_id", deviceID)
		// Don't fail the store operation for index errors
	}

	// Trigger retention policy if needed
	go m.enforceRetentionPolicy(deviceID)

	duration := time.Since(startTime)
	m.logger.Debug("DNA stored successfully",
		"device_id", deviceID,
		"content_hash", contentHash[:16],
		"original_size", originalSize,
		"compressed_size", compressedSize,
		"compression_ratio", compressionRatio,
		"version", version,
		"shard_id", shardID,
		"duration", duration)

	return nil
}

// GetHistory retrieves historical DNA records for a device within the specified time range.
//
// The query process includes:
// 1. Index lookup for efficient filtering
// 2. Shard-aware data retrieval
// 3. Decompression of stored data
// 4. Result aggregation and formatting
func (m *Manager) GetHistory(ctx context.Context, deviceID string, options *QueryOptions) (*HistoryResult, error) {
	startTime := time.Now()

	if options == nil {
		options = &QueryOptions{IncludeData: true}
	}

	// Query index for matching records
	recordRefs, totalCount, err := m.indexer.QueryRecords(ctx, deviceID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to query DNA records: %w", err)
	}

	var records []*DNARecord
	var bytesProcessed int64
	var compressionSavings int64

	// Retrieve and decompress records
	for _, ref := range recordRefs {
		record, err := m.storage.GetRecord(ctx, ref.ContentHash, ref.ShardID)
		if err != nil {
			m.logger.Error("Failed to retrieve DNA record", "error", err, "content_hash", ref.ContentHash)
			continue
		}

		// Override the device ID with the one from the reference (for deduplication support)
		record.DeviceID = ref.DeviceID
		record.Version = ref.Version
		record.StoredAt = ref.StoredAt

		// Decompress data if requested
		if options.IncludeData {
			if err := m.decompressRecord(record); err != nil {
				m.logger.Error("Failed to decompress DNA record", "error", err, "content_hash", ref.ContentHash)
				continue
			}
		}

		// Filter attributes if requested
		if len(options.Attributes) > 0 && record.DNA != nil {
			record.DNA = m.filterAttributes(record.DNA, options.Attributes)
		}

		records = append(records, record)
		bytesProcessed += record.OriginalSize
		compressionSavings += (record.OriginalSize - record.CompressedSize)
	}

	executionTime := time.Since(startTime)

	result := &HistoryResult{
		Records:    records,
		TotalCount: totalCount,
		TimeRange:  options.TimeRange,
		Metadata: &QueryMetadata{
			ExecutionTime:      executionTime,
			CacheHit:           false, // TODO: Implement caching
			RecordsScanned:     int64(len(recordRefs)),
			BytesProcessed:     bytesProcessed,
			CompressionSavings: compressionSavings,
		},
	}

	m.logger.Debug("DNA history retrieved",
		"device_id", deviceID,
		"records_found", len(records),
		"total_count", totalCount,
		"execution_time", executionTime,
		"bytes_processed", bytesProcessed,
		"compression_savings", compressionSavings)

	return result, nil
}

// GetCurrent retrieves the most recent DNA record for a device.
func (m *Manager) GetCurrent(ctx context.Context, deviceID string) (*DNARecord, error) {
	options := &QueryOptions{
		Limit:       1,
		IncludeData: true,
	}

	result, err := m.GetHistory(ctx, deviceID, options)
	if err != nil {
		return nil, err
	}

	if len(result.Records) == 0 {
		return nil, fmt.Errorf("no DNA records found for device %s", deviceID)
	}

	return result.Records[0], nil
}

// GetStorageStats returns storage statistics for monitoring and optimization.
func (m *Manager) GetStorageStats(ctx context.Context) (*StorageStats, error) {
	return m.storage.GetStats(ctx)
}

// Close gracefully shuts down the storage manager and flushes pending operations.
func (m *Manager) Close() error {
	m.logger.Info("Shutting down DNA storage manager")

	// Close components in order
	if err := m.indexer.Close(); err != nil {
		m.logger.Error("Failed to close indexer", "error", err)
	}

	if err := m.compressor.Close(); err != nil {
		m.logger.Error("Failed to close compressor", "error", err)
	}

	if err := m.storage.Close(); err != nil {
		m.logger.Error("Failed to close storage backend", "error", err)
	}

	return nil
}

// DefaultConfig returns a default configuration for DNA storage
//
// New simplified defaults for Issue #159:
// - SQLite backend for zero-setup deployment
// - Removed complex features (compression, deduplication, sharding)
// - Databases handle optimization internally
func DefaultConfig() *Config {
	return &Config{
		Backend:                BackendSQLite,       // DEFAULT: SQLite embedded database
		DataDir:                "data",              // Default data directory
		CompressionLevel:       6,                   // Kept for compatibility
		CompressionType:        "zstd",              // Kept for compatibility
		TargetCompressionRatio: 0.3,                 // Kept for compatibility
		EnableDeduplication:    false,               // Simplified: Let database handle it
		BlockSize:              64 * 1024,           // Kept for compatibility
		HashAlgorithm:          "sha256",            // Kept for compatibility
		RetentionPeriod:        90 * 24 * time.Hour, // 90 days
		ArchivalPeriod:         30 * 24 * time.Hour, // Archive after 30 days
		MaxRecordsPerDevice:    1000,                // Limit per device
		EnableSharding:         false,               // Simplified: Single database file
		ShardCount:             1,                   // Simplified: No sharding
		ShardingStrategy:       "device_id",         // Kept for compatibility
		BatchSize:              100,                 // Kept for compatibility
		FlushInterval:          5 * time.Minute,     // Kept for compatibility
		CacheSize:              1000,                // Kept for compatibility
		MaxStoragePerMonth:     100 * 1024 * 1024,   // 100MB per device per month
	}
}

// Helper methods

func (m *Manager) generateContentHash(dna *commonpb.DNA) (string, error) {
	// Create deterministic hash of DNA content for deduplication
	hasher := sha256.New()

	// Hash DNA ID and attributes in deterministic order
	hasher.Write([]byte(dna.Id))

	// Sort attributes for consistent hashing
	keys := make([]string, 0, len(dna.Attributes))
	for k := range dna.Attributes {
		keys = append(keys, k)
	}

	// Simple sort for deterministic ordering
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}

	for _, key := range keys {
		hasher.Write([]byte(key))
		hasher.Write([]byte(dna.Attributes[key]))
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

func (m *Manager) getShardID(deviceID string, timestamp time.Time) string {
	if !m.config.EnableSharding {
		return "default"
	}

	switch m.config.ShardingStrategy {
	case "device_id":
		// Hash device ID to determine shard
		hasher := sha256.New()
		hasher.Write([]byte(deviceID))
		hash := hasher.Sum(nil)
		shardNum := int(hash[0]) % m.config.ShardCount
		return fmt.Sprintf("shard_%d", shardNum)

	case "time_based":
		// Shard by time (daily shards)
		day := timestamp.Format("2006-01-02")
		hasher := sha256.New()
		hasher.Write([]byte(day))
		hash := hasher.Sum(nil)
		shardNum := int(hash[0]) % m.config.ShardCount
		return fmt.Sprintf("time_%d_%s", shardNum, day)

	case "hybrid":
		// Combine device ID and time for balanced distribution
		key := fmt.Sprintf("%s_%s", deviceID, timestamp.Format("2006-01-02"))
		hasher := sha256.New()
		hasher.Write([]byte(key))
		hash := hasher.Sum(nil)
		shardNum := int(hash[0]) % m.config.ShardCount
		return fmt.Sprintf("shard_%d", shardNum)

	default:
		return "default"
	}
}

func (m *Manager) storeReference(ctx context.Context, deviceID, contentHash string, dna *commonpb.DNA, startTime time.Time) error {
	// Content already exists, just create a reference record
	version, err := m.indexer.GetNextVersion(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("failed to get next version: %w", err)
	}

	record := &DNARecord{
		DeviceID:    deviceID,
		DNA:         dna,
		StoredAt:    time.Now(),
		ContentHash: contentHash,
		Version:     version,
		ShardID:     m.getShardID(deviceID, time.Now()),
	}

	// Store reference (not full data)
	if err := m.storage.StoreReference(ctx, record); err != nil {
		return fmt.Errorf("failed to store DNA reference: %w", err)
	}

	// Update index
	if err := m.indexer.IndexRecord(ctx, record); err != nil {
		m.logger.Error("Failed to update index", "error", err, "device_id", deviceID)
	}

	duration := time.Since(startTime)
	m.logger.Debug("DNA reference stored (deduplicated)",
		"device_id", deviceID,
		"content_hash", contentHash[:16],
		"version", version,
		"duration", duration)

	return nil
}

func (m *Manager) decompressRecord(record *DNARecord) error {
	// This would be implemented based on the storage backend
	// For now, assume DNA is already available
	return nil
}

func (m *Manager) filterAttributes(dna *commonpb.DNA, attributes []string) *commonpb.DNA {
	if len(attributes) == 0 {
		return dna
	}

	filtered := &commonpb.DNA{
		Id:              dna.Id,
		Attributes:      make(map[string]string),
		LastUpdated:     dna.LastUpdated,
		ConfigHash:      dna.ConfigHash,
		LastSyncTime:    dna.LastSyncTime,
		AttributeCount:  dna.AttributeCount,
		SyncFingerprint: dna.SyncFingerprint,
	}

	for _, attr := range attributes {
		if value, exists := dna.Attributes[attr]; exists {
			filtered.Attributes[attr] = value
		}
	}

	return filtered
}

func (m *Manager) startMaintenanceTasks() {
	ticker := time.NewTicker(m.config.FlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Run periodic maintenance
		m.runMaintenance()
	}
}

func (m *Manager) runMaintenance() {
	// Flush pending writes
	if err := m.storage.Flush(); err != nil {
		m.logger.Error("Failed to flush storage", "error", err)
	}

	// Run retention policy enforcement
	if err := m.enforceGlobalRetentionPolicy(); err != nil {
		m.logger.Error("Failed to enforce retention policy", "error", err)
	}

	// Optimize storage
	if err := m.storage.Optimize(); err != nil {
		m.logger.Error("Failed to optimize storage", "error", err)
	}
}

func (m *Manager) enforceRetentionPolicy(deviceID string) {
	// Device-specific retention policy enforcement
	// This would remove old records based on configured policies
}

func (m *Manager) enforceGlobalRetentionPolicy() error {
	// Global retention policy enforcement across all devices
	return nil
}

func validateConfig(config *Config) error {
	if config.CompressionLevel < 1 || config.CompressionLevel > 9 {
		return fmt.Errorf("compression level must be between 1 and 9")
	}

	if config.TargetCompressionRatio <= 0 || config.TargetCompressionRatio >= 1 {
		return fmt.Errorf("target compression ratio must be between 0 and 1")
	}

	if config.ShardCount <= 0 {
		return fmt.Errorf("shard count must be positive")
	}

	return nil
}
