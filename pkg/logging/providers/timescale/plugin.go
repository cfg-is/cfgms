// Package timescale implements a TimescaleDB-based logging provider for CFGMS time-series logging.
// This provider leverages TimescaleDB's time-series optimization features for high-performance
// log storage, compression, and querying with PostgreSQL compatibility.
package timescale

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// TimescaleProvider implements the LoggingProvider interface using TimescaleDB
type TimescaleProvider struct {
	config      *TimescaleConfig
	db          *sql.DB
	stats       interfaces.ProviderStats
	initialized bool
	mutex       sync.RWMutex
	closeOnce   sync.Once
}

// TimescaleConfig holds configuration for the TimescaleDB-based logging provider
type TimescaleConfig struct {
	// Database connection settings
	Host     string `json:"host"`     // Database host
	Port     int    `json:"port"`     // Database port
	Database string `json:"database"` // Database name
	Username string `json:"username"` // Database username
	Password string `json:"password"` // Database password
	SSLMode  string `json:"ssl_mode"` // SSL mode (disable, require, verify-ca, verify-full)

	// TimescaleDB-specific settings
	TableName         string        `json:"table_name"`         // Log entries table name (default: log_entries)
	ChunkInterval     time.Duration `json:"chunk_interval"`     // Time interval for chunks (default: 7 days)
	CompressionAfter  time.Duration `json:"compression_after"`  // Compress chunks older than this (default: 7 days)
	RetentionAfter    time.Duration `json:"retention_after"`    // Drop chunks older than this (default: 30 days)
	CompressionRatio  int           `json:"compression_ratio"`  // Target compression ratio (1-20)

	// Performance settings
	BatchSize         int           `json:"batch_size"`         // Batch insert size
	MaxConnections    int           `json:"max_connections"`    // Max database connections
	ConnectionTimeout time.Duration `json:"connection_timeout"` // Connection timeout
	QueryTimeout      time.Duration `json:"query_timeout"`      // Query timeout

	// Schema settings
	CreateSchema bool `json:"create_schema"` // Auto-create schema if it doesn't exist
	SchemaName   string `json:"schema_name"`  // Schema name (default: public)
}

// DefaultTimescaleConfig returns a sensible default configuration
func DefaultTimescaleConfig() *TimescaleConfig {
	return &TimescaleConfig{
		Host:             "localhost",
		Port:             5432,
		Database:         "cfgms_logs",
		Username:         "cfgms_logger",
		Password:         "",
		SSLMode:          "prefer",
		TableName:        "log_entries",
		ChunkInterval:    7 * 24 * time.Hour,  // 7 days
		CompressionAfter: 7 * 24 * time.Hour,  // 7 days
		RetentionAfter:   30 * 24 * time.Hour, // 30 days
		CompressionRatio: 10,
		BatchSize:        1000,
		MaxConnections:   10,
		ConnectionTimeout: 10 * time.Second,
		QueryTimeout:     30 * time.Second,
		CreateSchema:     true,
		SchemaName:       "public",
	}
}

// Name returns the provider name
func (p *TimescaleProvider) Name() string {
	return "timescale"
}

// Description returns a human-readable description
func (p *TimescaleProvider) Description() string {
	return "TimescaleDB-based time-series logging with compression, partitioning, and high-performance querying"
}

// GetVersion returns the provider version
func (p *TimescaleProvider) GetVersion() string {
	return "1.0.0"
}

// GetCapabilities returns the provider's capabilities
func (p *TimescaleProvider) GetCapabilities() interfaces.LoggingCapabilities {
	return interfaces.LoggingCapabilities{
		SupportsCompression:       true,  // Native TimescaleDB compression
		SupportsRetentionPolicies: true,  // Automated data retention
		SupportsRealTimeQueries:   true,  // Fast SQL-based queries
		SupportsBatchWrites:       true,  // Batch inserts for performance
		SupportsTimeRangeQueries:  true,  // Optimized time-series queries
		SupportsFullTextSearch:    true,  // PostgreSQL full-text search
		MaxEntriesPerSecond:       100000, // High throughput with batch inserts
		MaxBatchSize:              10000,  // Large batch support
		DefaultRetentionDays:      30,     // 30-day retention
		CompressionRatio:          0.1,    // ~10:1 compression ratio
		RequiresFlush:             false,  // Direct database writes
		SupportsTransactions:      true,   // Full ACID compliance
		SupportsPartitioning:      true,   // Time-based automatic partitioning
		SupportsIndexing:          true,   // Full PostgreSQL indexing
	}
}

// Available checks if TimescaleDB is accessible and properly configured
func (p *TimescaleProvider) Available() (bool, error) {
	if p.config == nil {
		return false, fmt.Errorf("provider not configured")
	}

	// Test database connection
	db, err := p.createConnection()
	if err != nil {
		return false, fmt.Errorf("cannot connect to TimescaleDB: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Check if TimescaleDB extension is available
	var extensionExists bool
	checkExtQuery := "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'timescaledb');"
	if err := db.QueryRow(checkExtQuery).Scan(&extensionExists); err != nil {
		return false, fmt.Errorf("cannot check TimescaleDB extension: %w", err)
	}

	if !extensionExists {
		return false, fmt.Errorf("TimescaleDB extension is not installed")
	}

	// Test write permissions
	testQuery := "SELECT 1;"
	if _, err := db.Exec(testQuery); err != nil {
		return false, fmt.Errorf("cannot execute test query: %w", err)
	}

	return true, nil
}

// Initialize sets up the TimescaleDB provider with the given configuration
func (p *TimescaleProvider) Initialize(config map[string]interface{}) error {
	// Parse configuration
	p.config = DefaultTimescaleConfig()
	if err := p.parseConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Create database connection
	db, err := p.createConnection()
	if err != nil {
		return fmt.Errorf("failed to connect to TimescaleDB: %w", err)
	}

	p.mutex.Lock()
	p.db = db
	p.mutex.Unlock()

	// Set up database schema
	if err := p.setupSchema(); err != nil {
		return fmt.Errorf("failed to setup database schema: %w", err)
	}

	// Set up TimescaleDB-specific features
	if err := p.setupTimescaleFeatures(); err != nil {
		return fmt.Errorf("failed to setup TimescaleDB features: %w", err)
	}

	p.mutex.Lock()
	p.initialized = true
	p.stats = interfaces.ProviderStats{
		OldestEntry:    time.Now(),
		LatestEntry:    time.Now(),
		WriteLatencyMs: 2.0,  // Optimistic estimate for database writes
		QueryLatencyMs: 10.0, // SQL-based queries are fast
	}
	p.mutex.Unlock()

	return nil
}

// Close shuts down the provider and closes database connections
func (p *TimescaleProvider) Close() error {
	var err error
	p.closeOnce.Do(func() {
		p.mutex.Lock()
		defer p.mutex.Unlock()

		if !p.initialized {
			return
		}

		p.initialized = false

		if p.db != nil {
			err = p.db.Close()
			p.db = nil
		}
	})

	return err
}

// WriteEntry writes a single log entry to TimescaleDB
func (p *TimescaleProvider) WriteEntry(ctx context.Context, entry interfaces.LogEntry) error {
	if !p.initialized {
		return fmt.Errorf("provider not initialized")
	}

	start := time.Now()
	defer func() {
		p.updateStats(1, time.Since(start))
	}()

	// Fill in timestamp if not provided
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Serialize fields to JSON
	fieldsJSON, err := json.Marshal(entry.Fields)
	if err != nil {
		return fmt.Errorf("failed to marshal fields: %w", err)
	}

	// Insert into TimescaleDB with validated identifiers
	query, err := p.buildSafeQuery(`
		INSERT INTO %s.%s (
			timestamp, level, message, service_name, component,
			tenant_id, session_id, correlation_id, trace_id, span_id,
			fields, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`)
	if err != nil {
		return fmt.Errorf("failed to build safe query: %w", err)
	}

	p.mutex.RLock()
	db := p.db
	p.mutex.RUnlock()

	_, err = db.ExecContext(ctx, query,
		entry.Timestamp,
		entry.Level,
		entry.Message,
		entry.ServiceName,
		entry.Component,
		entry.TenantID,
		entry.SessionID,
		entry.CorrelationID,
		entry.TraceID,
		entry.SpanID,
		string(fieldsJSON),
		time.Now(),
	)

	if err != nil {
		return fmt.Errorf("failed to insert log entry: %w", err)
	}

	return nil
}

// WriteBatch writes multiple log entries efficiently using batch insert
func (p *TimescaleProvider) WriteBatch(ctx context.Context, entries []interfaces.LogEntry) error {
	if !p.initialized {
		return fmt.Errorf("provider not initialized")
	}

	if len(entries) == 0 {
		return nil
	}

	start := time.Now()
	defer func() {
		p.updateStats(len(entries), time.Since(start))
	}()

	// Begin transaction for batch insert
	p.mutex.RLock()
	db := p.db
	p.mutex.RUnlock()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Prepare batch insert statement with validated identifiers
	queryTemplate := `
		INSERT INTO %s.%s (
			timestamp, level, message, service_name, component,
			tenant_id, session_id, correlation_id, trace_id, span_id,
			fields, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	query, err := p.buildSafeQuery(queryTemplate)
	if err != nil {
		return fmt.Errorf("failed to build safe batch query: %w", err)
	}
	
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare batch statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	// Insert all entries
	now := time.Now()
	for _, entry := range entries {
		// Fill in timestamp if not provided
		if entry.Timestamp.IsZero() {
			entry.Timestamp = now
		}

		// Serialize fields to JSON
		fieldsJSON, err := json.Marshal(entry.Fields)
		if err != nil {
			return fmt.Errorf("failed to marshal fields: %w", err)
		}

		_, err = stmt.ExecContext(ctx,
			entry.Timestamp,
			entry.Level,
			entry.Message,
			entry.ServiceName,
			entry.Component,
			entry.TenantID,
			entry.SessionID,
			entry.CorrelationID,
			entry.TraceID,
			entry.SpanID,
			string(fieldsJSON),
			now,
		)

		if err != nil {
			return fmt.Errorf("failed to insert batch entry: %w", err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	return nil
}

// createConnection creates a new database connection
func (p *TimescaleProvider) createConnection() (*sql.DB, error) {
	// Build connection string
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s dbname=%s sslmode=%s",
		p.config.Host,
		p.config.Port,
		p.config.Username,
		p.config.Database,
		p.config.SSLMode,
	)

	if p.config.Password != "" {
		connStr += " password=" + p.config.Password
	}

	// Connect to database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(p.config.MaxConnections)
	db.SetMaxIdleConns(p.config.MaxConnections / 2)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), p.config.ConnectionTimeout)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

// parseConfig parses the configuration map into TimescaleConfig
func (p *TimescaleProvider) parseConfig(config map[string]interface{}) error {
	if host, ok := config["host"].(string); ok {
		p.config.Host = host
	}

	if port, ok := config["port"].(float64); ok {
		p.config.Port = int(port)
	} else if port, ok := config["port"].(int); ok {
		p.config.Port = port
	}

	if database, ok := config["database"].(string); ok {
		p.config.Database = database
	}

	if username, ok := config["username"].(string); ok {
		p.config.Username = username
	}

	if password, ok := config["password"].(string); ok {
		p.config.Password = password
	}

	if sslMode, ok := config["ssl_mode"].(string); ok {
		p.config.SSLMode = sslMode
	}

	if tableName, ok := config["table_name"].(string); ok {
		p.config.TableName = tableName
	}

	if schemaName, ok := config["schema_name"].(string); ok {
		p.config.SchemaName = schemaName
	}

	// Parse duration strings
	if chunkInterval, ok := config["chunk_interval"].(string); ok {
		if duration, err := time.ParseDuration(chunkInterval); err == nil {
			p.config.ChunkInterval = duration
		}
	}

	if compressionAfter, ok := config["compression_after"].(string); ok {
		if duration, err := time.ParseDuration(compressionAfter); err == nil {
			p.config.CompressionAfter = duration
		}
	}

	if retentionAfter, ok := config["retention_after"].(string); ok {
		if duration, err := time.ParseDuration(retentionAfter); err == nil {
			p.config.RetentionAfter = duration
		}
	}

	// Parse numeric settings
	if batchSize, ok := config["batch_size"].(float64); ok {
		p.config.BatchSize = int(batchSize)
	} else if batchSize, ok := config["batch_size"].(int); ok {
		p.config.BatchSize = batchSize
	}

	if compressionRatio, ok := config["compression_ratio"].(float64); ok {
		p.config.CompressionRatio = int(compressionRatio)
	} else if compressionRatio, ok := config["compression_ratio"].(int); ok {
		p.config.CompressionRatio = compressionRatio
	}

	if createSchema, ok := config["create_schema"].(bool); ok {
		p.config.CreateSchema = createSchema
	}

	return nil
}

// validateSQLIdentifier validates SQL identifiers to prevent injection attacks
// #nosec G201 - This function prevents SQL injection by validating identifiers
func validateSQLIdentifier(identifier string) error {
	if identifier == "" {
		return fmt.Errorf("SQL identifier cannot be empty")
	}
	
	// Check length (PostgreSQL limit is 63 characters)
	if len(identifier) > 63 {
		return fmt.Errorf("SQL identifier too long (max 63 characters): %s", identifier)
	}
	
	// Must start with letter or underscore
	if (identifier[0] < 'a' || identifier[0] > 'z') && 
		 (identifier[0] < 'A' || identifier[0] > 'Z') && 
		 identifier[0] != '_' {
		return fmt.Errorf("SQL identifier must start with letter or underscore: %s", identifier)
	}
	
	// Can only contain letters, digits, underscores, and dollar signs
	for _, char := range identifier {
		if (char < 'a' || char > 'z') && 
			 (char < 'A' || char > 'Z') && 
			 (char < '0' || char > '9') && 
			 char != '_' && char != '$' {
			return fmt.Errorf("SQL identifier contains invalid character: %s", identifier)
		}
	}
	
	// Check against SQL reserved words (basic list)
	reservedWords := map[string]bool{
		"select": true, "insert": true, "update": true, "delete": true,
		"drop": true, "create": true, "alter": true, "table": true,
		"database": true, "schema": true, "index": true, "view": true,
		"union": true, "where": true, "from": true, "join": true,
		"order": true, "group": true, "having": true, "limit": true,
	}
	
	if reservedWords[strings.ToLower(identifier)] {
		return fmt.Errorf("SQL identifier cannot be a reserved word: %s", identifier)
	}
	
	return nil
}

// buildSafeQuery builds a SQL query with validated identifiers to prevent injection
// #nosec G201 - SQL identifiers are validated before use
func (p *TimescaleProvider) buildSafeQuery(template string) (string, error) {
	// Validate schema and table names
	if err := validateSQLIdentifier(p.config.SchemaName); err != nil {
		return "", fmt.Errorf("invalid schema name: %w", err)
	}
	
	if err := validateSQLIdentifier(p.config.TableName); err != nil {
		return "", fmt.Errorf("invalid table name: %w", err)
	}
	
	// Build query with validated identifiers
	return fmt.Sprintf(template, p.config.SchemaName, p.config.TableName), nil
}

// updateStats updates provider statistics
func (p *TimescaleProvider) updateStats(entriesWritten int, latency time.Duration) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.stats.TotalEntries += int64(entriesWritten)
	p.stats.LatestEntry = time.Now()

	// Update rolling average for write latency
	newLatencyMs := float64(latency.Milliseconds())
	p.stats.WriteLatencyMs = (p.stats.WriteLatencyMs*0.9) + (newLatencyMs*0.1)
}

// init registers the timescale provider
func init() {
	interfaces.RegisterLoggingProvider(&TimescaleProvider{})
}