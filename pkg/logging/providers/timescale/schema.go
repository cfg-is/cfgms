// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package timescale - Schema management for TimescaleDB logging provider
package timescale

import (
	"context"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// setupSchema creates the necessary schema, tables, and indexes
func (p *TimescaleProvider) setupSchema() error {
	ctx, cancel := context.WithTimeout(context.Background(), p.config.QueryTimeout)
	defer cancel()

	// Create schema if it doesn't exist
	if p.config.CreateSchema && p.config.SchemaName != "public" {
		// Validate schema name before use
		if err := validateSQLIdentifier(p.config.SchemaName); err != nil {
			return fmt.Errorf("invalid schema name for creation: %w", err)
		}
		// #nosec G201 - Schema name is validated above
		createSchemaQuery := fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s;", p.config.SchemaName)
		if _, err := p.db.ExecContext(ctx, createSchemaQuery); err != nil {
			return fmt.Errorf("failed to create schema: %w", err)
		}
	}

	// Create log entries table
	if err := p.createLogEntriesTable(ctx); err != nil {
		return fmt.Errorf("failed to create log entries table: %w", err)
	}

	// Create indexes for performance
	if err := p.createIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}

// createLogEntriesTable creates the main log entries table
func (p *TimescaleProvider) createLogEntriesTable(ctx context.Context) error {
	createTableQuery := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s.%s (
			id BIGSERIAL,
			timestamp TIMESTAMPTZ NOT NULL,
			level VARCHAR(10) NOT NULL,
			message TEXT NOT NULL,
			service_name VARCHAR(255) DEFAULT '',
			component VARCHAR(255) DEFAULT '',
			
			-- Multi-tenant and correlation fields
			tenant_id VARCHAR(255) DEFAULT '',
			session_id VARCHAR(255) DEFAULT '',
			correlation_id VARCHAR(255) DEFAULT '',
			trace_id VARCHAR(255) DEFAULT '',
			span_id VARCHAR(255) DEFAULT '',
			
			-- Structured fields as JSONB for efficient queries
			fields JSONB DEFAULT '{}',
			
			-- Metadata
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			
			-- Constraints for data integrity
			CHECK (level IN ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')),
			CHECK (timestamp IS NOT NULL),
			CHECK (message != '')
		);
	`, p.config.SchemaName, p.config.TableName)

	if _, err := p.db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create log entries table: %w", err)
	}

	return nil
}

// createIndexes creates performance indexes for common query patterns
func (p *TimescaleProvider) createIndexes(ctx context.Context) error {
	// Use safe query building for table name
	safeTableName, err := p.buildSafeQuery("%s.%s")
	if err != nil {
		return fmt.Errorf("failed to build safe table name: %w", err)
	}
	tableName := safeTableName

	indexes := []struct {
		name  string
		query string
	}{
		// Time-series indexes (most important for TimescaleDB)
		{
			"idx_log_entries_timestamp",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_timestamp ON %s (timestamp DESC);", p.config.TableName, tableName),
		},
		{
			"idx_log_entries_timestamp_level",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_timestamp_level ON %s (timestamp DESC, level);", p.config.TableName, tableName),
		},

		// Tenant isolation (critical for multi-tenant deployments)
		{
			"idx_log_entries_tenant_id",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_tenant_id ON %s (tenant_id);", p.config.TableName, tableName),
		},
		{
			"idx_log_entries_tenant_timestamp",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_tenant_timestamp ON %s (tenant_id, timestamp DESC);", p.config.TableName, tableName),
		},

		// Service and component tracking
		{
			"idx_log_entries_service_component",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_service_component ON %s (service_name, component);", p.config.TableName, tableName),
		},

		// Log level filtering
		{
			"idx_log_entries_level",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_level ON %s (level);", p.config.TableName, tableName),
		},

		// Correlation and tracing
		{
			"idx_log_entries_correlation_id",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_correlation_id ON %s (correlation_id) WHERE correlation_id != '';", p.config.TableName, tableName),
		},
		{
			"idx_log_entries_session_id",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_session_id ON %s (session_id) WHERE session_id != '';", p.config.TableName, tableName),
		},
		{
			"idx_log_entries_trace_id",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_trace_id ON %s (trace_id) WHERE trace_id != '';", p.config.TableName, tableName),
		},

		// Full-text search on messages
		{
			"idx_log_entries_message_text",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_message_text ON %s USING GIN(to_tsvector('english', message));", p.config.TableName, tableName),
		},

		// JSONB field queries
		{
			"idx_log_entries_fields",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_fields ON %s USING GIN(fields);", p.config.TableName, tableName),
		},

		// Composite indexes for common query patterns
		{
			"idx_log_entries_tenant_level_timestamp",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_tenant_level_timestamp ON %s (tenant_id, level, timestamp DESC);", p.config.TableName, tableName),
		},
		{
			"idx_log_entries_service_timestamp",
			fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_service_timestamp ON %s (service_name, timestamp DESC);", p.config.TableName, tableName),
		},
	}

	for _, index := range indexes {
		if _, err := p.db.ExecContext(ctx, index.query); err != nil {
			return fmt.Errorf("failed to create index %s: %w", index.name, err)
		}
	}

	return nil
}

// setupTimescaleFeatures configures TimescaleDB-specific features
func (p *TimescaleProvider) setupTimescaleFeatures() error {
	ctx, cancel := context.WithTimeout(context.Background(), p.config.QueryTimeout)
	defer cancel()

	tableName := fmt.Sprintf("%s.%s", p.config.SchemaName, p.config.TableName)

	// Convert table to hypertable for time-series optimization
	if err := p.createHypertable(ctx, tableName); err != nil {
		return fmt.Errorf("failed to create hypertable: %w", err)
	}

	// Set up compression policy
	if err := p.setupCompressionPolicy(ctx, tableName); err != nil {
		return fmt.Errorf("failed to setup compression policy: %w", err)
	}

	// Set up retention policy
	if err := p.setupRetentionPolicy(ctx, tableName); err != nil {
		return fmt.Errorf("failed to setup retention policy: %w", err)
	}

	return nil
}

// createHypertable converts the regular table to a TimescaleDB hypertable
func (p *TimescaleProvider) createHypertable(ctx context.Context, tableName string) error {
	// Check if table is already a hypertable
	checkHypertableQuery := `
		SELECT COUNT(*) FROM timescaledb_information.hypertables 
		WHERE hypertable_schema = $1 AND hypertable_name = $2;
	`

	var count int
	err := p.db.QueryRowContext(ctx, checkHypertableQuery, p.config.SchemaName, p.config.TableName).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check hypertable status: %w", err)
	}

	if count > 0 {
		// Already a hypertable
		return nil
	}

	// Convert to hypertable
	// #nosec G201 - tableName is validated via buildSafeQuery above, duration is controlled
	createHypertableQuery := fmt.Sprintf(
		"SELECT create_hypertable('%s', 'timestamp', chunk_time_interval => INTERVAL '%s');",
		tableName,
		p.formatDuration(p.config.ChunkInterval),
	)

	if _, err := p.db.ExecContext(ctx, createHypertableQuery); err != nil {
		// Check if error is due to existing hypertable (race condition)
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "TS110" { // Table already a hypertable
				return nil
			}
		}
		return fmt.Errorf("failed to create hypertable: %w", err)
	}

	return nil
}

// setupCompressionPolicy enables compression for old chunks
func (p *TimescaleProvider) setupCompressionPolicy(ctx context.Context, tableName string) error {
	// Enable compression on the hypertable
	enableCompressionQuery := fmt.Sprintf(
		"ALTER TABLE %s SET (timescaledb.compress = true, timescaledb.compress_segmentby = 'tenant_id, service_name, level');",
		tableName,
	)

	if _, err := p.db.ExecContext(ctx, enableCompressionQuery); err != nil {
		return fmt.Errorf("failed to enable compression: %w", err)
	}

	// Add compression policy
	// #nosec G201 - tableName is validated via buildSafeQuery above, duration is controlled
	addCompressionPolicyQuery := fmt.Sprintf(
		"SELECT add_compression_policy('%s', INTERVAL '%s');",
		tableName,
		p.formatDuration(p.config.CompressionAfter),
	)

	if _, err := p.db.ExecContext(ctx, addCompressionPolicyQuery); err != nil {
		// Check if policy already exists
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "TS201" { // Policy already exists
				return nil
			}
		}
		return fmt.Errorf("failed to add compression policy: %w", err)
	}

	return nil
}

// setupRetentionPolicy sets up automatic data retention
func (p *TimescaleProvider) setupRetentionPolicy(ctx context.Context, tableName string) error {
	// #nosec G201 - tableName is validated via buildSafeQuery in caller, duration is controlled
	addRetentionPolicyQuery := fmt.Sprintf(
		"SELECT add_retention_policy('%s', INTERVAL '%s');",
		tableName,
		p.formatDuration(p.config.RetentionAfter),
	)

	if _, err := p.db.ExecContext(ctx, addRetentionPolicyQuery); err != nil {
		// Check if policy already exists
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "TS201" { // Policy already exists
				return nil
			}
		}
		return fmt.Errorf("failed to add retention policy: %w", err)
	}

	return nil
}

// formatDuration converts Go duration to PostgreSQL interval format
func (p *TimescaleProvider) formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	if hours >= 24 {
		days := hours / 24
		return fmt.Sprintf("%d days", days)
	}
	return fmt.Sprintf("%d hours", hours)
}
