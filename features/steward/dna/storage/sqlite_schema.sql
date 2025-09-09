-- CFGMS DNA Storage SQLite Schema
-- Optimized for DNA record storage with time-series queries

-- Enable WAL mode for better concurrent access
PRAGMA journal_mode = WAL;

-- Enable foreign key constraints
PRAGMA foreign_keys = ON;

-- Main DNA history table
CREATE TABLE IF NOT EXISTS dna_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version INTEGER NOT NULL,
    dna_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    original_size INTEGER NOT NULL,
    compressed_size INTEGER NOT NULL,
    compression_ratio REAL NOT NULL,
    shard_id TEXT NOT NULL DEFAULT 'default',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    -- Ensure unique version per device
    UNIQUE(device_id, version)
);

-- Indexes for optimal query performance
CREATE INDEX IF NOT EXISTS idx_device_timestamp ON dna_history(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_device_version ON dna_history(device_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_content_hash ON dna_history(content_hash);
CREATE INDEX IF NOT EXISTS idx_shard_id ON dna_history(shard_id);
CREATE INDEX IF NOT EXISTS idx_created_at ON dna_history(created_at);

-- Index for time-based queries across all devices
CREATE INDEX IF NOT EXISTS idx_timestamp_global ON dna_history(timestamp DESC);

-- Reference table for deduplication tracking
CREATE TABLE IF NOT EXISTS dna_references (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    version INTEGER NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    shard_id TEXT NOT NULL DEFAULT 'default',
    
    -- Ensure unique reference per device/version
    UNIQUE(device_id, version)
);

-- Indexes for reference table
CREATE INDEX IF NOT EXISTS idx_ref_device_version ON dna_references(device_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_ref_content_hash ON dna_references(content_hash);

-- Statistics tracking table for performance monitoring
CREATE TABLE IF NOT EXISTS storage_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stat_name TEXT NOT NULL UNIQUE,
    stat_value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial statistics
INSERT OR IGNORE INTO storage_stats (stat_name, stat_value) VALUES 
    ('total_records', '0'),
    ('total_devices', '0'),
    ('total_size', '0'),
    ('compression_ratio', '1.0'),
    ('schema_version', '1');

-- View for latest DNA per device (optimization for common queries)
CREATE VIEW IF NOT EXISTS latest_dna_per_device AS
SELECT 
    device_id,
    MAX(version) as latest_version,
    MAX(timestamp) as latest_timestamp
FROM dna_history
GROUP BY device_id;

-- View for storage statistics
CREATE VIEW IF NOT EXISTS storage_summary AS
SELECT
    COUNT(*) as total_records,
    COUNT(DISTINCT device_id) as total_devices,
    SUM(original_size) as total_original_size,
    SUM(compressed_size) as total_compressed_size,
    CASE 
        WHEN SUM(original_size) > 0 
        THEN ROUND(CAST(SUM(compressed_size) AS REAL) / CAST(SUM(original_size) AS REAL), 3)
        ELSE 1.0 
    END as overall_compression_ratio,
    COUNT(DISTINCT content_hash) as unique_content_blocks,
    ROUND(
        CASE 
            WHEN COUNT(*) > 0 
            THEN 1.0 - (CAST(COUNT(DISTINCT content_hash) AS REAL) / CAST(COUNT(*) AS REAL))
            ELSE 0.0 
        END, 3
    ) as deduplication_ratio,
    MIN(timestamp) as earliest_record,
    MAX(timestamp) as latest_record
FROM dna_history;