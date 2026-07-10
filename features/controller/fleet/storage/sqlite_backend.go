// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	_ "modernc.org/sqlite"

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
	// Determine database path from config
	dataDir := config.DataDir
	if dataDir == "" {
		dataDir = "data" // Fallback default
	}
	dbPath := filepath.Join(dataDir, "dna.db")

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Open SQLite database (modernc.org/sqlite: pure-Go, CGO-free)
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// Configure connection pool for SQLite
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0) // No connection lifetime limit

	// Pragmas applied explicitly (portable across mattn and modernc drivers)
	for _, pragma := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA foreign_keys = ON",
		"PRAGMA synchronous = NORMAL",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("failed to set %s: %w", pragma, err)
		}
	}

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

// extractDNAAttr extracts an attribute from DNA, returning empty string if not found.
func extractDNAAttr(dna *commonpb.DNA, key string) string {
	if dna == nil || dna.Attributes == nil {
		return ""
	}
	return dna.Attributes[key]
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

	// Extract fleet query fields from DNA attributes for indexed columns
	osVal := extractDNAAttr(record.DNA, "os")
	arch := extractDNAAttr(record.DNA, "architecture")
	hostname := extractDNAAttr(record.DNA, "hostname")

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
		record.TenantID,
		osVal,
		arch,
		hostname,
		record.Status,
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
		&record.TenantID,
		&record.Status,
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
	// ON CONFLICT keeps the write idempotent when two DNA snapshots for the same
	// device resolve to the same version. GetNextVersion (MAX(version)+1) runs
	// outside this insert's lock, so a duplicate/concurrent publish — e.g. the
	// heartbeat path and the ring-subscription path both firing on reconnect — can
	// assign the same (device_id, version); without the upsert the second insert
	// fails the UNIQUE constraint, crashing DNA persist and churning the control
	// channel. The latest snapshot wins.
	b.stmts.insertRecord, err = b.db.Prepare(`
		INSERT INTO dna_history
		(device_id, timestamp, version, dna_json, content_hash,
		 original_size, compressed_size, compression_ratio, shard_id,
		 tenant_id, os, architecture, hostname, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id, version) DO UPDATE SET
			timestamp=excluded.timestamp,
			dna_json=excluded.dna_json,
			content_hash=excluded.content_hash,
			original_size=excluded.original_size,
			compressed_size=excluded.compressed_size,
			compression_ratio=excluded.compression_ratio,
			shard_id=excluded.shard_id,
			tenant_id=excluded.tenant_id,
			os=excluded.os,
			architecture=excluded.architecture,
			hostname=excluded.hostname,
			status=excluded.status
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert record statement: %w", err)
	}

	// Insert reference statement. Same idempotency rationale as insertRecord:
	// dna_references also has UNIQUE(device_id, version), and the dedup branch
	// (storeReference) is the likely path when a duplicate/concurrent publish
	// republishes identical DNA (a dedup hit). ON CONFLICT keeps it from failing
	// the constraint; the latest reference wins.
	b.stmts.insertReference, err = b.db.Prepare(`
		INSERT INTO dna_references
		(device_id, content_hash, version, timestamp, shard_id)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(device_id, version) DO UPDATE SET
			content_hash=excluded.content_hash,
			timestamp=excluded.timestamp,
			shard_id=excluded.shard_id
	`)
	if err != nil {
		return fmt.Errorf("failed to prepare insert reference statement: %w", err)
	}

	// Get record statement
	b.stmts.getRecord, err = b.db.Prepare(`
		SELECT device_id, timestamp, version, dna_json, content_hash,
		       original_size, compressed_size, compression_ratio, shard_id,
		       tenant_id, status
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

// pruneCandidate holds the minimal data needed to evaluate one version for pruning.
type pruneCandidate struct {
	version     int64
	contentHash string
	storedAt    time.Time
	inHistory   bool // true = row lives in dna_history; false = reference-only (dna_references)
}

// PruneDevice removes dna_history and dna_references rows for deviceID that exceed
// the given retention bounds.
//
// maxCount > 0 keeps the newest N versions (by version number); 0 disables the cap.
// Non-zero cutoff prunes any row whose timestamp is before that instant; zero disables.
//
// Implements the dedup-safe algorithm: a dna_history row is never deleted while any
// live dna_references row (from any device) still points at its content_hash.
// The write mutex is held for the entire check-and-delete cycle so no concurrent
// Store/StoreReference call can interleave between the reference count check and
// the delete.
//
// Returns the count of rows actually deleted.
func (b *SQLiteBackend) PruneDevice(ctx context.Context, deviceID string, maxCount int, cutoff time.Time) (int64, error) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin prune transaction for %s: %w", deviceID, err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after successful Commit

	deleted, err := pruneDeviceInTx(ctx, tx, deviceID, maxCount, cutoff)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit prune transaction for %s: %w", deviceID, err)
	}
	return deleted, nil
}

// PruneAllDevices applies retention bounds to every device in the store.
// Errors for individual devices are logged and skipped so a single bad row does not
// abort the full fleet sweep.
func (b *SQLiteBackend) PruneAllDevices(ctx context.Context, maxCount int, cutoff time.Time) (int64, error) {
	// Collect device IDs under a short read lock so we do not hold a write lock
	// across the full fleet sweep.
	b.mutex.RLock()
	rows, err := b.db.QueryContext(ctx, `
		SELECT DISTINCT device_id FROM dna_history
		UNION
		SELECT DISTINCT device_id FROM dna_references
	`)
	if err != nil {
		b.mutex.RUnlock()
		return 0, fmt.Errorf("failed to enumerate devices for global retention sweep: %w", err)
	}
	var deviceIDs []string
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			_ = rows.Close()
			b.mutex.RUnlock()
			return 0, fmt.Errorf("failed to scan device ID during global sweep: %w", scanErr)
		}
		deviceIDs = append(deviceIDs, id)
	}
	_ = rows.Close()
	b.mutex.RUnlock()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("device enumeration row error: %w", err)
	}

	var total int64
	for _, id := range deviceIDs {
		n, pruneErr := b.PruneDevice(ctx, id, maxCount, cutoff)
		if pruneErr != nil {
			b.logger.Error("Failed to prune device during global retention sweep",
				"device_id", logging.SanitizeLogValue(id), "error", pruneErr)
			continue // do not abort the full sweep on a single device failure
		}
		total += n
	}
	return total, nil
}

// pruneDeviceInTx is the inner implementation of the dedup-safe pruning algorithm,
// running inside an already-open transaction. Caller must hold b.mutex (write lock).
//
// Algorithm (per story spec):
//  1. Collect all (version, content_hash, storedAt) for the device from both tables.
//  2. Identify candidates: versions exceeding maxCount cap OR older than cutoff.
//  3. Split candidates into reference-only (dna_references) and history-owning (dna_history).
//  4. Delete reference-only candidates from dna_references first — this ensures the
//     subsequent live-reference count for history candidates only sees truly live rows.
//  5. For each history candidate, count remaining dna_references WHERE content_hash matches.
//     If count > 0 another device still needs this content — skip the dna_history delete.
//     If count == 0 no live reference remains — delete the dna_history row.
func pruneDeviceInTx(ctx context.Context, tx *sql.Tx, deviceID string, maxCount int, cutoff time.Time) (int64, error) {
	// Collect history rows for this device.
	hRows, err := tx.QueryContext(ctx,
		`SELECT version, content_hash, timestamp FROM dna_history WHERE device_id = ?`,
		deviceID)
	if err != nil {
		return 0, fmt.Errorf("failed to query dna_history for %s: %w", deviceID, err)
	}
	histByVersion := make(map[int64]pruneCandidate)
	for hRows.Next() {
		var c pruneCandidate
		c.inHistory = true
		if err := hRows.Scan(&c.version, &c.contentHash, &c.storedAt); err != nil {
			_ = hRows.Close()
			return 0, fmt.Errorf("failed to scan dna_history row for %s: %w", deviceID, err)
		}
		histByVersion[c.version] = c
	}
	if err := hRows.Close(); err != nil {
		return 0, fmt.Errorf("failed to close dna_history rows for %s: %w", deviceID, err)
	}

	// Collect reference rows for this device.
	rRows, err := tx.QueryContext(ctx,
		`SELECT version, content_hash, timestamp FROM dna_references WHERE device_id = ?`,
		deviceID)
	if err != nil {
		return 0, fmt.Errorf("failed to query dna_references for %s: %w", deviceID, err)
	}
	refByVersion := make(map[int64]pruneCandidate)
	for rRows.Next() {
		var c pruneCandidate
		c.inHistory = false
		if err := rRows.Scan(&c.version, &c.contentHash, &c.storedAt); err != nil {
			_ = rRows.Close()
			return 0, fmt.Errorf("failed to scan dna_references row for %s: %w", deviceID, err)
		}
		refByVersion[c.version] = c
	}
	if err := rRows.Close(); err != nil {
		return 0, fmt.Errorf("failed to close dna_references rows for %s: %w", deviceID, err)
	}

	// Build sorted (descending) list of all versions across both tables.
	allVersions := make([]int64, 0, len(histByVersion)+len(refByVersion))
	for v := range histByVersion {
		allVersions = append(allVersions, v)
	}
	for v := range refByVersion {
		if _, alreadyInHist := histByVersion[v]; !alreadyInHist {
			allVersions = append(allVersions, v)
		}
	}
	sort.Slice(allVersions, func(i, j int) bool { return allVersions[i] > allVersions[j] })

	// keepByCount: versions within the count cap (newest N). Only populated when maxCount > 0.
	keepByCount := make(map[int64]bool)
	if maxCount > 0 {
		for i, v := range allVersions {
			if i < maxCount {
				keepByCount[v] = true
			}
		}
	}

	// Classify candidates.
	var histCandidates []pruneCandidate
	var refCandidates []pruneCandidate
	for _, v := range allVersions {
		var c pruneCandidate
		if h, ok := histByVersion[v]; ok {
			c = h
		} else {
			c = refByVersion[v]
		}

		prunable := false
		if maxCount > 0 && !keepByCount[v] {
			prunable = true // exceeds count cap
		}
		if !cutoff.IsZero() && c.storedAt.Before(cutoff) {
			prunable = true // older than retention period
		}
		if !prunable {
			continue
		}
		if c.inHistory {
			histCandidates = append(histCandidates, c)
		} else {
			refCandidates = append(refCandidates, c)
		}
	}

	if len(histCandidates) == 0 && len(refCandidates) == 0 {
		return 0, nil
	}

	// Step 4: delete reference-only candidates first.
	// After this point, any remaining dna_references row is a truly live reference —
	// not a row that was also a candidate in this same prune pass.
	var deleted int64
	for _, c := range refCandidates {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM dna_references WHERE device_id = ? AND version = ?`,
			deviceID, c.version)
		if err != nil {
			return deleted, fmt.Errorf("failed to delete dna_references row (device=%s, version=%d): %w",
				deviceID, c.version, err)
		}
		n, _ := res.RowsAffected()
		deleted += n
	}

	// Step 5: for each history candidate, check whether any live dna_references row
	// still points at its content_hash. The ref candidates for this device and pass
	// were already deleted in step 4, so only truly live references remain.
	for _, c := range histCandidates {
		var liveRefCount int64
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM dna_references WHERE content_hash = ?`,
			c.contentHash).Scan(&liveRefCount); err != nil {
			return deleted, fmt.Errorf("failed to count live refs for content_hash (device=%s, version=%d): %w",
				deviceID, c.version, err)
		}
		if liveRefCount > 0 {
			// Another device (or a non-pruned version of this device) still references
			// this content — the dna_history row has become shared canonical storage.
			continue
		}
		res, err := tx.ExecContext(ctx,
			`DELETE FROM dna_history WHERE device_id = ? AND version = ?`,
			deviceID, c.version)
		if err != nil {
			return deleted, fmt.Errorf("failed to delete dna_history row (device=%s, version=%d): %w",
				deviceID, c.version, err)
		}
		n, _ := res.RowsAffected()
		deleted += n
	}

	return deleted, nil
}
