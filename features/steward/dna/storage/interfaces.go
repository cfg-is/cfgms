// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package storage defines interfaces for DNA storage backends and components.

package storage

import (
	"context"
	"io"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// Backend defines the interface for DNA storage backends.
//
// Backends implement the actual storage mechanism for DNA records,
// supporting various storage types like file systems, databases, or Git repositories.
type Backend interface {
	// StoreRecord stores a DNA record with compressed data
	StoreRecord(ctx context.Context, record *DNARecord, compressedData []byte) error

	// StoreReference stores a reference to existing content (for deduplication)
	StoreReference(ctx context.Context, record *DNARecord) error

	// GetRecord retrieves a DNA record by content hash and shard
	GetRecord(ctx context.Context, contentHash, shardID string) (*DNARecord, error)

	// HasContent checks if content with the given hash already exists
	HasContent(ctx context.Context, contentHash string) (bool, error)

	// GetStats returns storage statistics
	GetStats(ctx context.Context) (*StorageStats, error)

	// Flush forces any pending write operations to complete
	Flush() error

	// Optimize performs storage optimization (compaction, defragmentation, etc.)
	Optimize() error

	// Close closes the storage backend and releases resources
	Close() error
}

// Compressor defines the interface for DNA data compression.
//
// Compressors implement various compression algorithms optimized for DNA data
// to achieve the target space savings while maintaining acceptable performance.
type Compressor interface {
	// Compress compresses DNA data and returns compressed bytes and original size
	Compress(dna *commonpb.DNA) ([]byte, int64, error)

	// Decompress decompresses data back to DNA structure
	Decompress(data []byte) (*commonpb.DNA, error)

	// GetCompressionRatio returns the actual compression ratio achieved
	GetCompressionRatio() float64

	// GetStats returns compression statistics
	GetStats() *CompressionStats

	// Close closes the compressor and releases resources
	Close() error
}

// Indexer defines the interface for DNA record indexing and querying.
//
// Indexers provide fast lookup and filtering capabilities for DNA records,
// supporting historical queries and metadata operations.
type Indexer interface {
	// IndexRecord adds a DNA record to the index
	IndexRecord(ctx context.Context, record *DNARecord) error

	// QueryRecords queries DNA records for a device with options
	QueryRecords(ctx context.Context, deviceID string, options *QueryOptions) ([]*RecordRef, int64, error)

	// GetNextVersion gets the next version number for a device
	GetNextVersion(ctx context.Context, deviceID string) (int64, error)

	// GetDeviceStats returns statistics for a specific device
	GetDeviceStats(ctx context.Context, deviceID string) (*DeviceStats, error)

	// GetGlobalStats returns global indexing statistics
	GetGlobalStats(ctx context.Context) (*IndexStats, error)

	// Close closes the indexer and releases resources
	Close() error
}

// RecordRef represents a reference to a stored DNA record
type RecordRef struct {
	DeviceID    string    `json:"device_id"`
	ContentHash string    `json:"content_hash"`
	ShardID     string    `json:"shard_id"`
	Version     int64     `json:"version"`
	StoredAt    time.Time `json:"stored_at"`
	Size        int64     `json:"size"`
}

// StorageStats provides statistics about storage usage and performance
type StorageStats struct {
	// Storage usage
	TotalSize        int64   `json:"total_size"`        // Total storage used in bytes
	CompressedSize   int64   `json:"compressed_size"`   // Compressed data size
	UncompressedSize int64   `json:"uncompressed_size"` // Original data size
	CompressionRatio float64 `json:"compression_ratio"` // Overall compression ratio

	// Deduplication
	UniqueBlocks       int64   `json:"unique_blocks"`       // Number of unique content blocks
	TotalBlocks        int64   `json:"total_blocks"`        // Total blocks (including duplicates)
	DeduplicationRatio float64 `json:"deduplication_ratio"` // Space saved through deduplication

	// Device statistics
	TotalDevices            int64   `json:"total_devices"`          // Number of devices with DNA records
	ActiveDevices           int64   `json:"active_devices"`         // Devices with recent DNA records
	AverageRecordsPerDevice float64 `json:"avg_records_per_device"` // Average records per device

	// Shard statistics
	TotalShards  int              `json:"total_shards"`  // Number of shards
	ActiveShards int              `json:"active_shards"` // Shards with data
	ShardSizes   map[string]int64 `json:"shard_sizes"`   // Size per shard

	// Performance metrics
	WriteOpsPerSecond float64       `json:"write_ops_per_second"` // Write operations per second
	ReadOpsPerSecond  float64       `json:"read_ops_per_second"`  // Read operations per second
	AverageWriteTime  time.Duration `json:"avg_write_time"`       // Average write latency
	AverageReadTime   time.Duration `json:"avg_read_time"`        // Average read latency

	// Growth trends
	GrowthRatePerDay      int64 `json:"growth_rate_per_day"`  // Bytes per day growth rate
	ProjectedGrowth30Days int64 `json:"projected_growth_30d"` // Projected growth in 30 days

	// Collection timestamp
	CollectedAt time.Time `json:"collected_at"`
}

// CompressionStats provides statistics about compression performance
type CompressionStats struct {
	TotalBytesIn     int64         `json:"total_bytes_in"`    // Total bytes compressed
	TotalBytesOut    int64         `json:"total_bytes_out"`   // Total compressed bytes
	CompressionRatio float64       `json:"compression_ratio"` // Overall compression ratio
	AverageTime      time.Duration `json:"average_time"`      // Average compression time
	TotalOperations  int64         `json:"total_operations"`  // Number of compression operations
	Algorithm        string        `json:"algorithm"`         // Compression algorithm used
	Level            int           `json:"level"`             // Compression level
}

// DeviceStats provides statistics for a specific device
type DeviceStats struct {
	DeviceID         string        `json:"device_id"`
	TotalRecords     int64         `json:"total_records"`     // Total DNA records for device
	OldestRecord     time.Time     `json:"oldest_record"`     // Timestamp of oldest record
	NewestRecord     time.Time     `json:"newest_record"`     // Timestamp of newest record
	TotalSize        int64         `json:"total_size"`        // Total storage used
	AverageSize      int64         `json:"average_size"`      // Average record size
	CompressionRatio float64       `json:"compression_ratio"` // Compression ratio for device
	UpdateFrequency  time.Duration `json:"update_frequency"`  // Average time between updates
	AttributeCount   int           `json:"attribute_count"`   // Number of unique attributes
	ChangeFrequency  float64       `json:"change_frequency"`  // Percentage of attributes that change
	LastChange       time.Time     `json:"last_change"`       // When last change occurred
}

// IndexStats provides statistics about the indexing system
type IndexStats struct {
	TotalEntries      int64         `json:"total_entries"`        // Total index entries
	UniqueDevices     int64         `json:"unique_devices"`       // Number of unique devices
	IndexSize         int64         `json:"index_size"`           // Size of index data
	AverageQueryTime  time.Duration `json:"avg_query_time"`       // Average query execution time
	CacheHitRatio     float64       `json:"cache_hit_ratio"`      // Cache hit ratio
	TotalQueries      int64         `json:"total_queries"`        // Total queries executed
	QueryOpsPerSecond float64       `json:"query_ops_per_second"` // Query operations per second
	LastOptimization  time.Time     `json:"last_optimization"`    // When index was last optimized
}

// ArchivePolicy defines policies for archiving old DNA records
type ArchivePolicy struct {
	Enabled            bool          `json:"enabled"`
	ArchiveAfter       time.Duration `json:"archive_after"`        // Archive records older than this
	CompressionLevel   int           `json:"compression_level"`    // Higher compression for archived data
	StorageBackend     BackendType   `json:"storage_backend"`      // Backend for archived data
	DeleteAfterArchive bool          `json:"delete_after_archive"` // Delete from primary storage after archiving
}

// RetentionPolicy defines policies for DNA record retention
type RetentionPolicy struct {
	Enabled             bool          `json:"enabled"`
	RetainFor           time.Duration `json:"retain_for"`             // How long to retain records
	MaxRecordsPerDevice int           `json:"max_records_per_device"` // Maximum records per device
	MaxStoragePerDevice int64         `json:"max_storage_per_device"` // Maximum storage per device
	PreferredDeletion   string        `json:"preferred_deletion"`     // "oldest", "largest", "duplicate"
}

// ShardManager defines interface for shard management
type ShardManager interface {
	// GetShardForDevice returns the appropriate shard for a device at a given time
	GetShardForDevice(deviceID string, timestamp time.Time) string

	// ListShards returns all available shards
	ListShards() []string

	// GetShardStats returns statistics for a specific shard
	GetShardStats(shardID string) (*ShardStats, error)

	// RebalanceShards redistributes data across shards for optimal performance
	RebalanceShards(ctx context.Context) error

	// CreateShard creates a new shard
	CreateShard(shardID string) error

	// DeleteShard removes a shard and its data
	DeleteShard(shardID string) error
}

// ShardStats provides statistics for a specific shard
type ShardStats struct {
	ShardID          string    `json:"shard_id"`
	RecordCount      int64     `json:"record_count"`      // Number of records in shard
	TotalSize        int64     `json:"total_size"`        // Total size of shard data
	DeviceCount      int64     `json:"device_count"`      // Number of devices in shard
	OldestRecord     time.Time `json:"oldest_record"`     // Oldest record timestamp
	NewestRecord     time.Time `json:"newest_record"`     // Newest record timestamp
	CompressionRatio float64   `json:"compression_ratio"` // Compression ratio for shard
	LoadFactor       float64   `json:"load_factor"`       // How full the shard is (0-1)
	IsActive         bool      `json:"is_active"`         // Whether shard is actively used
}

// DataExporter defines interface for exporting DNA data
type DataExporter interface {
	// Export exports DNA data in various formats
	Export(ctx context.Context, query *ExportQuery, writer io.Writer) error

	// GetSupportedFormats returns supported export formats
	GetSupportedFormats() []string

	// ValidateQuery validates an export query
	ValidateQuery(query *ExportQuery) error
}

// ExportQuery defines parameters for data export
type ExportQuery struct {
	DeviceIDs       []string   `json:"device_ids,omitempty"`  // Specific devices to export
	TimeRange       *TimeRange `json:"time_range,omitempty"`  // Time range to export
	Attributes      []string   `json:"attributes,omitempty"`  // Specific attributes to export
	Format          string     `json:"format"`                // Export format (json, csv, parquet)
	Compression     string     `json:"compression,omitempty"` // Output compression
	IncludeMetadata bool       `json:"include_metadata"`      // Include record metadata
	BatchSize       int        `json:"batch_size,omitempty"`  // Batch size for streaming
}

// HealthChecker defines interface for storage health monitoring
type HealthChecker interface {
	// CheckHealth performs comprehensive health check
	CheckHealth(ctx context.Context) (*HealthReport, error)

	// CheckConnectivity tests backend connectivity
	CheckConnectivity(ctx context.Context) error

	// CheckPerformance runs performance benchmarks
	CheckPerformance(ctx context.Context) (*PerformanceReport, error)

	// CheckIntegrity verifies data integrity
	CheckIntegrity(ctx context.Context) (*IntegrityReport, error)
}

// HealthReport provides comprehensive health status
type HealthReport struct {
	Status            HealthStatus       `json:"status"`                    // Overall health status
	Timestamp         time.Time          `json:"timestamp"`                 // When health was checked
	BackendHealth     *BackendHealth     `json:"backend_health"`            // Backend-specific health
	CompressionHealth *CompressionHealth `json:"compression_health"`        // Compression system health
	IndexHealth       *IndexHealth       `json:"index_health"`              // Index system health
	StorageHealth     *StorageHealth     `json:"storage_health"`            // Storage system health
	Issues            []HealthIssue      `json:"issues,omitempty"`          // Any health issues found
	Recommendations   []string           `json:"recommendations,omitempty"` // Improvement recommendations
}

// HealthStatus represents the overall health status
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// BackendHealth provides backend-specific health information
type BackendHealth struct {
	Status        HealthStatus  `json:"status"`
	Connectivity  bool          `json:"connectivity"`   // Can connect to backend
	LatencyP50    time.Duration `json:"latency_p50"`    // 50th percentile latency
	LatencyP95    time.Duration `json:"latency_p95"`    // 95th percentile latency
	ErrorRate     float64       `json:"error_rate"`     // Error rate percentage
	ThroughputRPS float64       `json:"throughput_rps"` // Requests per second
}

// CompressionHealth provides compression system health information
type CompressionHealth struct {
	Status       HealthStatus  `json:"status"`
	AverageRatio float64       `json:"average_ratio"` // Current compression ratio
	TargetRatio  float64       `json:"target_ratio"`  // Target compression ratio
	AverageTime  time.Duration `json:"average_time"`  // Average compression time
	ErrorRate    float64       `json:"error_rate"`    // Compression error rate
	MemoryUsage  int64         `json:"memory_usage"`  // Memory used by compressor
}

// IndexHealth provides index system health information
type IndexHealth struct {
	Status             HealthStatus  `json:"status"`
	QueryLatencyP50    time.Duration `json:"query_latency_p50"`   // 50th percentile query latency
	QueryLatencyP95    time.Duration `json:"query_latency_p95"`   // 95th percentile query latency
	CacheHitRatio      float64       `json:"cache_hit_ratio"`     // Cache hit ratio
	IndexSize          int64         `json:"index_size"`          // Total index size
	FragmentationRatio float64       `json:"fragmentation_ratio"` // Index fragmentation
}

// StorageHealth provides storage system health information
type StorageHealth struct {
	Status            HealthStatus  `json:"status"`
	TotalSize         int64         `json:"total_size"`         // Total storage used
	AvailableSpace    int64         `json:"available_space"`    // Available storage space
	UsagePercentage   float64       `json:"usage_percentage"`   // Storage usage percentage
	IOLatencyP50      time.Duration `json:"io_latency_p50"`     // I/O latency 50th percentile
	IOLatencyP95      time.Duration `json:"io_latency_p95"`     // I/O latency 95th percentile
	IOErrorRate       float64       `json:"io_error_rate"`      // I/O error rate
	ReplicationHealth HealthStatus  `json:"replication_health"` // Replication status if applicable
}

// HealthIssue represents a specific health issue
type HealthIssue struct {
	Severity    IssueSeverity `json:"severity"`    // Issue severity level
	Component   string        `json:"component"`   // Component with the issue
	Description string        `json:"description"` // Issue description
	Impact      string        `json:"impact"`      // Impact on system
	Resolution  string        `json:"resolution"`  // Suggested resolution
	Timestamp   time.Time     `json:"timestamp"`   // When issue was detected
}

// IssueSeverity represents the severity of a health issue
type IssueSeverity string

const (
	IssueSeverityLow      IssueSeverity = "low"
	IssueSeverityMedium   IssueSeverity = "medium"
	IssueSeverityHigh     IssueSeverity = "high"
	IssueSeverityCritical IssueSeverity = "critical"
)

// PerformanceReport provides detailed performance metrics
type PerformanceReport struct {
	Timestamp         time.Time     `json:"timestamp"`
	WriteLatency      time.Duration `json:"write_latency"`      // Average write latency
	ReadLatency       time.Duration `json:"read_latency"`       // Average read latency
	CompressionTime   time.Duration `json:"compression_time"`   // Average compression time
	DecompressionTime time.Duration `json:"decompression_time"` // Average decompression time
	ThroughputWrites  float64       `json:"throughput_writes"`  // Writes per second
	ThroughputReads   float64       `json:"throughput_reads"`   // Reads per second
	CpuUsage          float64       `json:"cpu_usage"`          // CPU usage percentage
	MemoryUsage       int64         `json:"memory_usage"`       // Memory usage in bytes
	DiskIOPS          float64       `json:"disk_iops"`          // Disk I/O operations per second
}

// IntegrityReport provides data integrity verification results
type IntegrityReport struct {
	Timestamp         time.Time `json:"timestamp"`
	TotalRecords      int64     `json:"total_records"`      // Total records checked
	ValidRecords      int64     `json:"valid_records"`      // Records that passed validation
	CorruptRecords    int64     `json:"corrupt_records"`    // Records with corruption
	MissingRecords    int64     `json:"missing_records"`    // Records referenced but missing
	ChecksumErrors    int64     `json:"checksum_errors"`    // Checksum validation failures
	CompressionErrors int64     `json:"compression_errors"` // Compression/decompression errors
	IntegrityRatio    float64   `json:"integrity_ratio"`    // Percentage of valid records
	IssuesSummary     []string  `json:"issues_summary"`     // Summary of issues found
}
