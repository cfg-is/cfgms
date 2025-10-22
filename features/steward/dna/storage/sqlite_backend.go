package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

// SQLiteBackend implements DNA storage using SQLite database
//
// This backend provides persistent storage with ACID guarantees, optimal for
// single-instance deployments and development. Features include:
// - Single SQLite database file for zero-setup deployment
// - JSON storage with SQLite JSON functions for querying
// - Automatic version management per device
// - Time-series optimized schema with proper indexing
// - Content-based deduplication support
// - Built-in data integrity and corruption recovery
type SQLiteBackend struct {
	logger     logging.Logger
	config     *Config
	db         *sql.DB
	migrator   *SQLiteMigrator
	dbPath     string
	mutex      sync.RWMutex
	stats      *StorageStats
	statsMutex sync.RWMutex

	// Prepared statements for performance
	stmts struct {
		insertRecord    *sql.Stmt
		insertReference *sql.Stmt
		getRecord       *sql.Stmt
		hasContent      *sql.Stmt
		getStats        *sql.Stmt
		getNextVersion  *sql.Stmt
	}
}

// NewSQLiteBackend creates a new SQLite-based DNA storage backend
func NewSQLiteBackend(config *Config, logger logging.Logger) (*SQLiteBackend, error) {
	// Determine database path
	dbPath := "data/dna.db" // Default path

	// Ensure data directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Open SQLite database
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=ON&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Configure connection pool for SQLite
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0) // No connection lifetime limit

	backend := &SQLiteBackend{
		logger:   logger,
		config:   config,
		db:       db,
		dbPath:   dbPath,
		migrator: NewSQLiteMigrator(db, logger),
		stats: &StorageStats{
			ShardSizes:  make(map[string]int64),
			CollectedAt: time.Now(),
		},
	}

	// Initialize database schema
	if err := backend.migrator.InitializeSchema(); err != nil {
		_ = db.Close() // Ignore close error in error path
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Apply any pending migrations
	if err := backend.migrator.ApplyMigrations(); err != nil {
		_ = db.Close() // Ignore close error in error path
		return nil, fmt.Errorf("failed to apply migrations: %w", err)
	}

	// Validate schema
	if err := backend.migrator.ValidateSchema(); err != nil {
		_ = db.Close() // Ignore close error in error path
		return nil, fmt.Errorf("schema validation failed: %w", err)
	}

	// Prepare statements for optimal performance
	if err := backend.prepareStatements(); err != nil {
		_ = db.Close() // Ignore close error in error path
		return nil, fmt.Errorf("failed to prepare statements: %w", err)
	}

	// Initial statistics calculation
	if err := backend.calculateStats(); err != nil {
		logger.Warn("Failed to calculate initial statistics", "error", err)
	}

	logger.Info("SQLite DNA storage backend initialized",
		"database_path", dbPath,
		"schema_version", "1",
		"wal_mode", "enabled")

	return backend, nil
}

// StoreRecord stores a DNA record with compressed data in SQLite
func (b *SQLiteBackend) StoreRecord(ctx context.Context, record *DNARecord, compressedData []byte) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Serialize DNA to JSON
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
		return fmt.Errorf("failed to insert DNA record: %w", err)
	}

	// Update statistics
	b.updateStats(record)

	hashDisplay := record.ContentHash
	if len(hashDisplay) > 16 {
		hashDisplay = hashDisplay[:16]
	}

	b.logger.Debug("DNA record stored in SQLite",
		"device_id", record.DeviceID,
		"content_hash", hashDisplay,
		"version", record.Version,
		"compressed_size", record.CompressedSize,
		"original_size", record.OriginalSize)

	return nil
}

// StoreReference stores a reference to existing content for deduplication
func (b *SQLiteBackend) StoreReference(ctx context.Context, record *DNARecord) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Execute reference insert
	_, err := b.stmts.insertReference.ExecContext(ctx,
		record.DeviceID,
		record.ContentHash,
		record.Version,
		record.StoredAt,
		record.ShardID,
	)

	if err != nil {
		return fmt.Errorf("failed to insert DNA reference: %w", err)
	}

	hashDisplay := record.ContentHash
	if len(hashDisplay) > 16 {
		hashDisplay = hashDisplay[:16]
	}

	b.logger.Debug("DNA reference stored in SQLite",
		"device_id", record.DeviceID,
		"content_hash", hashDisplay,
		"version", record.Version)

	return nil
}

// GetRecord retrieves a DNA record by content hash and shard
func (b *SQLiteBackend) GetRecord(ctx context.Context, contentHash, shardID string) (*DNARecord, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

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
		return nil, fmt.Errorf("failed to query DNA record: %w", err)
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

// HasContent checks if content with the given hash already exists
func (b *SQLiteBackend) HasContent(ctx context.Context, contentHash string) (bool, error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	var count int
	err := b.stmts.hasContent.QueryRowContext(ctx, contentHash).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check content existence: %w", err)
	}

	return count > 0, nil
}

// GetStats returns comprehensive storage statistics
func (b *SQLiteBackend) GetStats(ctx context.Context) (*StorageStats, error) {
	b.statsMutex.Lock()
	defer b.statsMutex.Unlock()

	// Refresh statistics from database
	if err := b.calculateStats(); err != nil {
		b.logger.Warn("Failed to calculate fresh statistics", "error", err)
	}

	// Return copy of current statistics
	statsCopy := *b.stats
	statsCopy.CollectedAt = time.Now()
	return &statsCopy, nil
}

// Flush forces any pending write operations to complete
func (b *SQLiteBackend) Flush() error {
	// SQLite writes are synchronous in WAL mode, but we can ensure WAL checkpoint
	if _, err := b.db.Exec("PRAGMA wal_checkpoint(PASSIVE)"); err != nil {
		b.logger.Warn("Failed to checkpoint WAL", "error", err)
		// Don't fail on checkpoint errors - they're not critical
	}
	return nil
}

// Optimize performs SQLite-specific optimization
func (b *SQLiteBackend) Optimize() error {
	return b.migrator.OptimizeDatabase()
}

// Close closes the SQLite database and cleans up resources
func (b *SQLiteBackend) Close() error {
	b.logger.Info("Closing SQLite DNA storage backend")

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
	if b.stmts.getStats != nil {
		if err := b.stmts.getStats.Close(); err != nil {
			b.logger.Warn("Failed to close getStats statement", "error", err)
		}
	}
	if b.stmts.getNextVersion != nil {
		if err := b.stmts.getNextVersion.Close(); err != nil {
			b.logger.Warn("Failed to close getNextVersion statement", "error", err)
		}
	}

	// Close database connection
	if err := b.db.Close(); err != nil {
		return fmt.Errorf("failed to close SQLite database: %w", err)
	}

	b.logger.Info("SQLite storage backend closed successfully")
	return nil
}

// prepareStatements prepares frequently used SQL statements for optimal performance
func (b *SQLiteBackend) prepareStatements() error {
	var err error

	// Insert DNA record statement
	b.stmts.insertRecord, err = b.db.Prepare(`
		INSERT INTO dna_history 
		(device_id, timestamp, version, dna_json, content_hash, 
		 original_size, compressed_size, compression_ratio, shard_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert record statement: %w", err)
	}

	// Insert reference statement
	b.stmts.insertReference, err = b.db.Prepare(`
		INSERT INTO dna_references 
		(device_id, content_hash, version, timestamp, shard_id)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert reference statement: %w", err)
	}

	// Get record statement
	b.stmts.getRecord, err = b.db.Prepare(`
		SELECT device_id, timestamp, version, dna_json, content_hash,
		       original_size, compressed_size, compression_ratio, shard_id
		FROM dna_history
		WHERE content_hash = ?
		LIMIT 1
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare get record statement: %w", err)
	}

	// Has content statement
	b.stmts.hasContent, err = b.db.Prepare(`
		SELECT COUNT(*)
		FROM dna_history
		WHERE content_hash = ?
		LIMIT 1
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare has content statement: %w", err)
	}

	// Get next version statement
	b.stmts.getNextVersion, err = b.db.Prepare(`
		SELECT COALESCE(MAX(version), 0) + 1
		FROM dna_history
		WHERE device_id = ?
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare get next version statement: %w", err)
	}

	return nil
}

// calculateStats calculates current storage statistics from the database
func (b *SQLiteBackend) calculateStats() error {
	// Use the storage_summary view for efficient statistics
	row := b.db.QueryRow(`
		SELECT total_records, total_devices, total_original_size, 
		       total_compressed_size, overall_compression_ratio,
		       unique_content_blocks, deduplication_ratio
		FROM storage_summary
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
		return fmt.Errorf("failed to calculate statistics: %w", err)
	}

	b.stats.TotalSize = b.stats.CompressedSize
	b.stats.ActiveDevices = b.stats.TotalDevices // All devices are active in SQLite

	if b.stats.TotalDevices > 0 {
		b.stats.AverageRecordsPerDevice = float64(b.stats.TotalBlocks) / float64(b.stats.TotalDevices)
	}

	// Calculate shard sizes (simplified for SQLite - usually single shard)
	b.stats.TotalShards = 1
	b.stats.ActiveShards = 1
	b.stats.ShardSizes = map[string]int64{
		"default": b.stats.TotalSize,
	}

	return nil
}

// updateStats updates statistics after storing a record
func (b *SQLiteBackend) updateStats(record *DNARecord) {
	b.statsMutex.Lock()
	defer b.statsMutex.Unlock()

	b.stats.TotalSize += record.CompressedSize
	b.stats.CompressedSize += record.CompressedSize
	b.stats.UncompressedSize += record.OriginalSize
	b.stats.TotalBlocks++
	b.stats.UniqueBlocks++ // Simplified - assumes no deduplication for stats update

	if b.stats.UncompressedSize > 0 {
		b.stats.CompressionRatio = float64(b.stats.CompressedSize) / float64(b.stats.UncompressedSize)
	}

	// Update shard sizes
	if b.stats.ShardSizes == nil {
		b.stats.ShardSizes = make(map[string]int64)
	}
	b.stats.ShardSizes[record.ShardID] = b.stats.TotalSize
}

// GetNextVersion returns the next version number for a device
func (b *SQLiteBackend) GetNextVersion(ctx context.Context, deviceID string) (int64, error) {
	var nextVersion int64
	err := b.stmts.getNextVersion.QueryRowContext(ctx, deviceID).Scan(&nextVersion)
	if err != nil {
		return 0, fmt.Errorf("failed to get next version for device %s: %w", deviceID, err)
	}
	return nextVersion, nil
}

// Helper function for minimum of two integers (Go 1.21+ has min built-in)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
