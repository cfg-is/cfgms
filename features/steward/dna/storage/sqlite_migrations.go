// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package storage

import (
	"database/sql"
	_ "embed"
	"fmt"

	"github.com/cfgis/cfgms/pkg/logging"
)

//go:embed sqlite_schema.sql
var sqliteSchema string

// Migration represents a database schema migration
type Migration struct {
	Version     int
	Description string
	SQL         string
}

// SQLiteMigrator handles database schema migrations for SQLite
type SQLiteMigrator struct {
	db     *sql.DB
	logger logging.Logger
}

// NewSQLiteMigrator creates a new SQLite migrator
func NewSQLiteMigrator(db *sql.DB, logger logging.Logger) *SQLiteMigrator {
	return &SQLiteMigrator{
		db:     db,
		logger: logger,
	}
}

// InitializeSchema creates the initial database schema
func (m *SQLiteMigrator) InitializeSchema() error {
	m.logger.Info("Initializing SQLite DNA storage schema")

	// Execute the schema creation
	if _, err := m.db.Exec(sqliteSchema); err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	m.logger.Info("SQLite schema initialized successfully")
	return nil
}

// GetCurrentVersion returns the current schema version
func (m *SQLiteMigrator) GetCurrentVersion() (int, error) {
	// Check if migrations table exists
	var tableName string
	err := m.db.QueryRow(`
		SELECT name FROM sqlite_master 
		WHERE type='table' AND name='migrations'
	`).Scan(&tableName)

	if err == sql.ErrNoRows {
		// No migrations table, schema is at version 0
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("failed to check migrations table: %w", err)
	}

	// Get latest migration version
	var version int
	err = m.db.QueryRow(`
		SELECT COALESCE(MAX(version), 0) FROM migrations
	`).Scan(&version)

	if err != nil {
		return 0, fmt.Errorf("failed to get current version: %w", err)
	}

	return version, nil
}

// ApplyMigrations applies all pending migrations
func (m *SQLiteMigrator) ApplyMigrations() error {
	// Ensure migrations table exists
	if err := m.createMigrationsTable(); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	currentVersion, err := m.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	migrations := m.getAllMigrations()

	for _, migration := range migrations {
		if migration.Version <= currentVersion {
			continue // Skip already applied migrations
		}

		m.logger.Info("Applying migration",
			"version", migration.Version,
			"description", migration.Description)

		if err := m.applyMigration(&migration); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}
	}

	m.logger.Info("All migrations applied successfully", "current_version", len(migrations))
	return nil
}

// createMigrationsTable creates the migrations tracking table
func (m *SQLiteMigrator) createMigrationsTable() error {
	query := `
		CREATE TABLE IF NOT EXISTS migrations (
			version INTEGER PRIMARY KEY,
			description TEXT NOT NULL,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`

	if _, err := m.db.Exec(query); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	return nil
}

// applyMigration applies a single migration
func (m *SQLiteMigrator) applyMigration(migration *Migration) error {
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			m.logger.Warn("Failed to rollback transaction", "error", err)
		}
	}()

	// Apply the migration SQL
	if _, err := tx.Exec(migration.SQL); err != nil {
		return fmt.Errorf("failed to execute migration SQL: %w", err)
	}

	// Record the migration
	if _, err := tx.Exec(`
		INSERT INTO migrations (version, description) VALUES (?, ?)
	`, migration.Version, migration.Description); err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}

	return nil
}

// getAllMigrations returns all available migrations in order
func (m *SQLiteMigrator) getAllMigrations() []Migration {
	return []Migration{
		{
			Version:     1,
			Description: "Initial DNA storage schema with optimized indexes",
			SQL:         sqliteSchema,
		},
		// Future migrations would be added here:
		// {
		//     Version:     2,
		//     Description: "Add device metadata table",
		//     SQL:         "CREATE TABLE device_metadata ...",
		// },
	}
}

// ValidateSchema performs basic schema validation
func (m *SQLiteMigrator) ValidateSchema() error {
	requiredTables := []string{
		"dna_history",
		"dna_references",
		"storage_stats",
	}

	requiredViews := []string{
		"latest_dna_per_device",
		"storage_summary",
	}

	// Check tables
	for _, table := range requiredTables {
		var count int
		err := m.db.QueryRow(`
			SELECT COUNT(*) FROM sqlite_master 
			WHERE type='table' AND name=?
		`, table).Scan(&count)

		if err != nil {
			return fmt.Errorf("failed to check table %s: %w", table, err)
		}

		if count == 0 {
			return fmt.Errorf("required table %s not found", table)
		}
	}

	// Check views
	for _, view := range requiredViews {
		var count int
		err := m.db.QueryRow(`
			SELECT COUNT(*) FROM sqlite_master 
			WHERE type='view' AND name=?
		`, view).Scan(&count)

		if err != nil {
			return fmt.Errorf("failed to check view %s: %w", view, err)
		}

		if count == 0 {
			return fmt.Errorf("required view %s not found", view)
		}
	}

	m.logger.Info("Schema validation passed")
	return nil
}

// OptimizeDatabase performs SQLite optimization operations
func (m *SQLiteMigrator) OptimizeDatabase() error {
	m.logger.Info("Optimizing SQLite database")

	// Update table statistics
	if _, err := m.db.Exec("ANALYZE"); err != nil {
		m.logger.Warn("Failed to analyze database", "error", err)
	}

	// Vacuum if needed (reclaim space)
	var pageCount, unusedPages int
	err := m.db.QueryRow("PRAGMA page_count").Scan(&pageCount)
	if err == nil {
		err = m.db.QueryRow("PRAGMA freelist_count").Scan(&unusedPages)
		if err == nil && unusedPages > pageCount/10 { // >10% unused
			m.logger.Info("Running VACUUM to reclaim space",
				"total_pages", pageCount,
				"unused_pages", unusedPages)

			if _, err := m.db.Exec("VACUUM"); err != nil {
				m.logger.Warn("Failed to vacuum database", "error", err)
			}
		}
	}

	// Update integrity check
	var integrityResult string
	err = m.db.QueryRow("PRAGMA integrity_check(1)").Scan(&integrityResult)
	if err != nil {
		return fmt.Errorf("failed to check database integrity: %w", err)
	}

	if integrityResult != "ok" {
		return fmt.Errorf("database integrity check failed: %s", integrityResult)
	}

	m.logger.Info("Database optimization completed")
	return nil
}
