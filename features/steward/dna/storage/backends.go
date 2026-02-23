// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package storage implements various backend storage systems for DNA data.

// #nosec G304 - DNA storage system requires file access for system state persistence
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/lib/pq"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

// NewBackend creates a new storage backend based on the configuration
func NewBackend(backendType BackendType, config *Config, logger logging.Logger) (Backend, error) {
	switch backendType {
	case BackendSQLite:
		return NewSQLiteBackend(config, logger)
	case BackendDatabase:
		return NewDatabaseBackend(config, logger)
	case BackendFile:
		return NewFileBackend(config, logger)
	default:
		return nil, fmt.Errorf("unsupported backend type '%s' - supported types: sqlite (default), database (PostgreSQL), file (fallback)", backendType)
	}
}

// FileBackend implements a file-based storage backend for DNA data
//
// This backend stores DNA records as files on the local filesystem,
// organized by shards and content hash for efficient access.
type FileBackend struct {
	logger     logging.Logger
	config     *Config
	basePath   string
	stats      *StorageStats
	statsMutex sync.RWMutex
}

// NewFileBackend creates a new file-based storage backend
func NewFileBackend(config *Config, logger logging.Logger) (*FileBackend, error) {
	basePath := "/tmp/cfgms-dna-storage" // Default path
	if err := os.MkdirAll(basePath, 0750); err != nil {
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
			if err := os.MkdirAll(shardPath, 0750); err != nil {
				return nil, fmt.Errorf("failed to create shard directory: %w", err)
			}
		}
		backend.stats.TotalShards = config.ShardCount
	} else {
		defaultPath := filepath.Join(basePath, "default")
		if err := os.MkdirAll(defaultPath, 0750); err != nil {
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
	if err := os.WriteFile(filePath, data, 0600); err != nil {
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
	if err := os.MkdirAll(filepath.Dir(filePath), 0750); err != nil {
		return fmt.Errorf("failed to create refs directory: %w", err)
	}

	// Serialize reference
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal reference: %w", err)
	}

	// Write reference file
	if err := os.WriteFile(filePath, data, 0600); err != nil {
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
		} else if err != nil {
			_ = err // Explicitly ignore file access errors during size calculation
		}
		return nil
	}); err != nil {
		// Log error but continue - filesystem stats are not critical
		_ = err // Explicitly ignore filesystem walk errors
	}

	b.stats.TotalSize = totalSize
	b.stats.CompressedSize = totalSize // Assume all data is compressed
}

// DatabaseBackend implements a PostgreSQL database storage backend for DNA data
//
// This backend provides production-ready persistent storage with:
// - PostgreSQL database with ACID guarantees and concurrent access
// - JSON/JSONB storage with native PostgreSQL JSON functions
// - Connection pooling for high-concurrency workloads
// - Advanced indexing and query optimization
// - Horizontal scaling support with database replication
// - Migration support from SQLite → PostgreSQL
type DatabaseBackend struct {
	logger     logging.Logger
	config     *Config
	db         *sql.DB
	connString string
	stats      *StorageStats
	statsMutex sync.RWMutex

	// Prepared statements for performance
	stmts struct {
		insertRecord    *sql.Stmt
		insertReference *sql.Stmt
		getRecord       *sql.Stmt
		hasContent      *sql.Stmt
		getNextVersion  *sql.Stmt
	}
}

// NewDatabaseBackend creates a new PostgreSQL-based DNA storage backend
func NewDatabaseBackend(config *Config, logger logging.Logger) (*DatabaseBackend, error) {
	// Get connection string from environment or config
	connString := os.Getenv("CFGMS_DNA_DATABASE_URL")
	if connString == "" {
		connString = buildDNAConnString(logger)
	}

	// Open PostgreSQL connection
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, fmt.Errorf("failed to open PostgreSQL database: %w", err)
	}

	// Configure connection pool for PostgreSQL
	db.SetMaxOpenConns(10)                 // Allow multiple concurrent connections
	db.SetMaxIdleConns(5)                  // Keep some connections idle
	db.SetConnMaxLifetime(5 * time.Minute) // Rotate connections

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close() // Ignore close error in error path
		return nil, fmt.Errorf("failed to connect to PostgreSQL database: %w", err)
	}

	backend := &DatabaseBackend{
		logger:     logger,
		config:     config,
		db:         db,
		connString: connString,
		stats: &StorageStats{
			ShardSizes:  make(map[string]int64),
			CollectedAt: time.Now(),
		},
	}

	// Initialize database schema
	if err := backend.initializeSchema(); err != nil {
		_ = db.Close() // Ignore close error in error path
		return nil, fmt.Errorf("failed to initialize PostgreSQL schema: %w", err)
	}

	// Prepare statements
	if err := backend.prepareStatements(); err != nil {
		_ = db.Close() // Ignore close error in error path
		return nil, fmt.Errorf("failed to prepare PostgreSQL statements: %w", err)
	}

	// Calculate initial statistics
	if err := backend.calculateStats(); err != nil {
		logger.Warn("Failed to calculate initial PostgreSQL statistics", "error", err)
	}

	logger.Info("PostgreSQL DNA storage backend initialized",
		"connection_string", "postgres://***:***@host:port/db", // Redacted for security
		"max_connections", 10,
		"connection_lifetime", "5m")

	return backend, nil
}

// StoreRecord stores a DNA record in PostgreSQL with JSONB
func (b *DatabaseBackend) StoreRecord(ctx context.Context, record *DNARecord, compressedData []byte) error {
	// Serialize DNA to JSON for PostgreSQL JSONB storage
	dnaJSON, err := json.Marshal(record.DNA)
	if err != nil {
		return fmt.Errorf("failed to marshal DNA to JSON: %w", err)
	}

	// Execute insert with prepared statement
	_, err = b.stmts.insertRecord.ExecContext(ctx,
		record.DeviceID,
		record.StoredAt,
		record.Version,
		string(dnaJSON),
		record.ContentHash,
		record.OriginalSize,
		record.CompressedSize,
		record.CompressionRatio,
		record.ShardID,
	)

	if err != nil {
		return fmt.Errorf("failed to insert DNA record into PostgreSQL: %w", err)
	}

	// Update statistics
	b.updateStats(record)

	hashDisplay := record.ContentHash
	if len(hashDisplay) > 16 {
		hashDisplay = hashDisplay[:16]
	}

	b.logger.Debug("DNA record stored in PostgreSQL",
		"device_id", record.DeviceID,
		"content_hash", hashDisplay,
		"version", record.Version,
		"compressed_size", record.CompressedSize)

	return nil
}

// StoreReference stores a reference to existing content for deduplication
func (b *DatabaseBackend) StoreReference(ctx context.Context, record *DNARecord) error {
	// Execute reference insert
	_, err := b.stmts.insertReference.ExecContext(ctx,
		record.DeviceID,
		record.ContentHash,
		record.Version,
		record.StoredAt,
		record.ShardID,
	)

	if err != nil {
		return fmt.Errorf("failed to insert DNA reference into PostgreSQL: %w", err)
	}

	hashDisplay := record.ContentHash
	if len(hashDisplay) > 16 {
		hashDisplay = hashDisplay[:16]
	}

	b.logger.Debug("DNA reference stored in PostgreSQL",
		"device_id", record.DeviceID,
		"content_hash", hashDisplay,
		"version", record.Version)

	return nil
}

// GetRecord retrieves a DNA record by content hash
func (b *DatabaseBackend) GetRecord(ctx context.Context, contentHash, shardID string) (*DNARecord, error) {
	var record DNARecord
	var dnaJSON string
	var timestamp time.Time

	err := b.stmts.getRecord.QueryRowContext(ctx, contentHash).Scan(
		&record.DeviceID,
		&timestamp,
		&record.Version,
		&dnaJSON,
		&record.ContentHash,
		&record.OriginalSize,
		&record.CompressedSize,
		&record.CompressionRatio,
		&record.ShardID,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("DNA record not found: content_hash=%s", contentHash[:min(16, len(contentHash))])
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query DNA record from PostgreSQL: %w", err)
	}

	record.StoredAt = timestamp

	// Deserialize DNA from JSON
	var dna commonpb.DNA
	if err := json.Unmarshal([]byte(dnaJSON), &dna); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DNA from JSON: %w", err)
	}
	record.DNA = &dna

	return &record, nil
}

// HasContent checks if content exists in PostgreSQL
func (b *DatabaseBackend) HasContent(ctx context.Context, contentHash string) (bool, error) {
	var count int
	err := b.stmts.hasContent.QueryRowContext(ctx, contentHash).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check content existence in PostgreSQL: %w", err)
	}

	return count > 0, nil
}

// GetStats returns comprehensive storage statistics from PostgreSQL
func (b *DatabaseBackend) GetStats(ctx context.Context) (*StorageStats, error) {
	b.statsMutex.Lock()
	defer b.statsMutex.Unlock()

	// Refresh statistics from database
	if err := b.calculateStats(); err != nil {
		b.logger.Warn("Failed to calculate fresh PostgreSQL statistics", "error", err)
	}

	// Return copy of current statistics
	statsCopy := *b.stats
	statsCopy.CollectedAt = time.Now()
	return &statsCopy, nil
}

// Flush ensures all pending writes are committed (PostgreSQL handles this automatically)
func (b *DatabaseBackend) Flush() error {
	// PostgreSQL handles transaction commits automatically
	// We could force a checkpoint, but it's usually not necessary
	return nil
}

// Optimize performs PostgreSQL-specific optimization
func (b *DatabaseBackend) Optimize() error {
	b.logger.Info("Optimizing PostgreSQL database")

	// Update table statistics
	if _, err := b.db.Exec("ANALYZE dna_history, dna_references"); err != nil {
		b.logger.Warn("Failed to analyze PostgreSQL tables", "error", err)
	}

	// Check for index bloat and suggest reindexing if needed
	// This is a simplified check - production systems would have more sophisticated monitoring
	var indexBloat float64
	err := b.db.QueryRow(`
		SELECT COALESCE(
			(SELECT COUNT(*) FROM pg_stat_user_indexes WHERE schemaname = 'public'),
			0
		)
	`).Scan(&indexBloat)

	if err == nil && indexBloat > 100 { // Arbitrary threshold
		b.logger.Info("Consider reindexing PostgreSQL tables", "index_count", indexBloat)
	}

	b.logger.Info("PostgreSQL optimization completed")
	return nil
}

// Close closes the PostgreSQL connection and cleans up resources
func (b *DatabaseBackend) Close() error {
	b.logger.Info("Closing PostgreSQL DNA storage backend")

	// Close prepared statements
	if b.stmts.insertRecord != nil {
		if err := b.stmts.insertRecord.Close(); err != nil {
			b.logger.Warn("Failed to close insertRecord statement", "error", err)
		}
	}
	if b.stmts.insertReference != nil {
		if err := b.stmts.insertReference.Close(); err != nil {
			b.logger.Warn("Failed to close insertReference statement", "error", err)
		}
	}
	if b.stmts.getRecord != nil {
		if err := b.stmts.getRecord.Close(); err != nil {
			b.logger.Warn("Failed to close getRecord statement", "error", err)
		}
	}
	if b.stmts.hasContent != nil {
		if err := b.stmts.hasContent.Close(); err != nil {
			b.logger.Warn("Failed to close hasContent statement", "error", err)
		}
	}
	if b.stmts.getNextVersion != nil {
		if err := b.stmts.getNextVersion.Close(); err != nil {
			b.logger.Warn("Failed to close getNextVersion statement", "error", err)
		}
	}

	// Close database connection
	if err := b.db.Close(); err != nil {
		return fmt.Errorf("failed to close PostgreSQL database: %w", err)
	}

	b.logger.Info("PostgreSQL storage backend closed successfully")
	return nil
}

// initializeSchema creates the PostgreSQL schema (similar to SQLite but optimized for PostgreSQL)
func (b *DatabaseBackend) initializeSchema() error {
	// PostgreSQL schema with JSONB and better indexing
	schema := `
		-- Main DNA history table with JSONB for better performance
		CREATE TABLE IF NOT EXISTS dna_history (
			id BIGSERIAL PRIMARY KEY,
			device_id TEXT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			version BIGINT NOT NULL,
			dna_json JSONB NOT NULL,
			content_hash TEXT NOT NULL,
			original_size BIGINT NOT NULL,
			compressed_size BIGINT NOT NULL,
			compression_ratio REAL NOT NULL,
			shard_id TEXT NOT NULL DEFAULT 'default',
			created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
			
			-- Ensure unique version per device
			UNIQUE(device_id, version)
		);

		-- Indexes optimized for PostgreSQL
		CREATE INDEX IF NOT EXISTS idx_dna_device_timestamp ON dna_history(device_id, timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_dna_device_version ON dna_history(device_id, version DESC);
		CREATE INDEX IF NOT EXISTS idx_dna_content_hash ON dna_history(content_hash);
		CREATE INDEX IF NOT EXISTS idx_dna_shard_id ON dna_history(shard_id);
		CREATE INDEX IF NOT EXISTS idx_dna_created_at ON dna_history(created_at);
		CREATE INDEX IF NOT EXISTS idx_dna_timestamp_global ON dna_history(timestamp DESC);

		-- GIN index for JSONB queries (PostgreSQL-specific)
		CREATE INDEX IF NOT EXISTS idx_dna_json_gin ON dna_history USING GIN(dna_json);

		-- Reference table for deduplication
		CREATE TABLE IF NOT EXISTS dna_references (
			id BIGSERIAL PRIMARY KEY,
			device_id TEXT NOT NULL,
			content_hash TEXT NOT NULL,
			version BIGINT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			shard_id TEXT NOT NULL DEFAULT 'default',
			
			-- Ensure unique reference per device/version
			UNIQUE(device_id, version)
		);

		-- Indexes for reference table
		CREATE INDEX IF NOT EXISTS idx_ref_device_version ON dna_references(device_id, version DESC);
		CREATE INDEX IF NOT EXISTS idx_ref_content_hash ON dna_references(content_hash);

		-- Statistics table
		CREATE TABLE IF NOT EXISTS storage_stats (
			id SERIAL PRIMARY KEY,
			stat_name TEXT NOT NULL UNIQUE,
			stat_value TEXT NOT NULL,
			updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
		);

		-- Insert initial statistics
		INSERT INTO storage_stats (stat_name, stat_value) 
		VALUES ('total_records', '0'), ('total_devices', '0'), ('schema_version', '1')
		ON CONFLICT (stat_name) DO NOTHING;
	`

	if _, err := b.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to initialize PostgreSQL schema: %w", err)
	}

	b.logger.Info("PostgreSQL schema initialized successfully")
	return nil
}

// prepareStatements prepares PostgreSQL statements for optimal performance
func (b *DatabaseBackend) prepareStatements() error {
	var err error

	// Insert DNA record statement
	b.stmts.insertRecord, err = b.db.Prepare(`
		INSERT INTO dna_history 
		(device_id, timestamp, version, dna_json, content_hash, 
		 original_size, compressed_size, compression_ratio, shard_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare PostgreSQL insert record statement: %w", err)
	}

	// Insert reference statement
	b.stmts.insertReference, err = b.db.Prepare(`
		INSERT INTO dna_references 
		(device_id, content_hash, version, timestamp, shard_id)
		VALUES ($1, $2, $3, $4, $5)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare PostgreSQL insert reference statement: %w", err)
	}

	// Get record statement
	b.stmts.getRecord, err = b.db.Prepare(`
		SELECT device_id, timestamp, version, dna_json, content_hash,
		       original_size, compressed_size, compression_ratio, shard_id
		FROM dna_history
		WHERE content_hash = $1
		LIMIT 1
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare PostgreSQL get record statement: %w", err)
	}

	// Has content statement
	b.stmts.hasContent, err = b.db.Prepare(`
		SELECT COUNT(*)
		FROM dna_history
		WHERE content_hash = $1
		LIMIT 1
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare PostgreSQL has content statement: %w", err)
	}

	// Get next version statement
	b.stmts.getNextVersion, err = b.db.Prepare(`
		SELECT COALESCE(MAX(version), 0) + 1
		FROM dna_history
		WHERE device_id = $1
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare PostgreSQL get next version statement: %w", err)
	}

	return nil
}

// calculateStats calculates storage statistics from PostgreSQL
func (b *DatabaseBackend) calculateStats() error {
	// PostgreSQL-optimized statistics query
	row := b.db.QueryRow(`
		SELECT 
			COUNT(*) as total_records,
			COUNT(DISTINCT device_id) as total_devices,
			COALESCE(SUM(original_size), 0) as total_original_size,
			COALESCE(SUM(compressed_size), 0) as total_compressed_size,
			CASE 
				WHEN SUM(original_size) > 0 
				THEN CAST(SUM(compressed_size) AS REAL) / CAST(SUM(original_size) AS REAL)
				ELSE 1.0 
			END as overall_compression_ratio,
			COUNT(DISTINCT content_hash) as unique_content_blocks,
			CASE 
				WHEN COUNT(*) > 0 
				THEN 1.0 - (CAST(COUNT(DISTINCT content_hash) AS REAL) / CAST(COUNT(*) AS REAL))
				ELSE 0.0 
			END as deduplication_ratio
		FROM dna_history
	`)

	err := row.Scan(
		&b.stats.TotalBlocks,
		&b.stats.TotalDevices,
		&b.stats.UncompressedSize,
		&b.stats.CompressedSize,
		&b.stats.CompressionRatio,
		&b.stats.UniqueBlocks,
		&b.stats.DeduplicationRatio,
	)

	if err != nil {
		return fmt.Errorf("failed to calculate PostgreSQL statistics: %w", err)
	}

	b.stats.TotalSize = b.stats.CompressedSize
	b.stats.ActiveDevices = b.stats.TotalDevices

	if b.stats.TotalDevices > 0 {
		b.stats.AverageRecordsPerDevice = float64(b.stats.TotalBlocks) / float64(b.stats.TotalDevices)
	}

	// PostgreSQL can have multiple shards but for simplicity we'll use one
	b.stats.TotalShards = 1
	b.stats.ActiveShards = 1
	b.stats.ShardSizes = map[string]int64{
		"default": b.stats.TotalSize,
	}

	return nil
}

// buildDNAConnString constructs a PostgreSQL connection string from individual env vars.
// CFGMS_DNA_DB_PASSWORD is required — no hardcoded defaults for credentials.
func buildDNAConnString(_ logging.Logger) string {
	password := os.Getenv("CFGMS_DNA_DB_PASSWORD")
	if password == "" {
		log.Fatal("FATAL: CFGMS_DNA_DB_PASSWORD environment variable is required for DNA database backend. " +
			"Set this variable or use CFGMS_DNA_DATABASE_URL for a full connection string. " +
			"See docs/deployment/ for configuration examples.")
	}

	host := os.Getenv("CFGMS_DNA_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("CFGMS_DNA_DB_PORT")
	if port == "" {
		port = "5432"
	}
	dbName := os.Getenv("CFGMS_DNA_DB_NAME")
	if dbName == "" {
		dbName = "cfgms_dna"
	}
	user := os.Getenv("CFGMS_DNA_DB_USER")
	if user == "" {
		user = "cfgms"
	}
	sslMode := os.Getenv("CFGMS_DNA_DB_SSLMODE")
	if sslMode == "" {
		sslMode = "require"
	}

	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		user, password, host, port, dbName, sslMode)
}

// updateStats updates statistics after storing a record
func (b *DatabaseBackend) updateStats(record *DNARecord) {
	b.statsMutex.Lock()
	defer b.statsMutex.Unlock()

	b.stats.TotalSize += record.CompressedSize
	b.stats.CompressedSize += record.CompressedSize
	b.stats.UncompressedSize += record.OriginalSize
	b.stats.TotalBlocks++
	b.stats.UniqueBlocks++

	if b.stats.UncompressedSize > 0 {
		b.stats.CompressionRatio = float64(b.stats.CompressedSize) / float64(b.stats.UncompressedSize)
	}

	if b.stats.ShardSizes == nil {
		b.stats.ShardSizes = make(map[string]int64)
	}
	b.stats.ShardSizes[record.ShardID] = b.stats.TotalSize
}
