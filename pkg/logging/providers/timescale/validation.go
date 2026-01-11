// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package timescale - SQL identifier validation for security
package timescale

import (
	"fmt"
	"regexp"
	"strings"
)

// M-INPUT-3: SQL identifier whitelist validation (security audit finding)
// This prevents SQL injection through schema/table names even though they come from config.
// Defense-in-depth: validate all SQL identifiers against strict rules.

var (
	// validIdentifierPattern matches valid PostgreSQL/SQL identifiers
	// Allows: alphanumeric, underscore, must start with letter or underscore
	// Length: 1-63 characters (PostgreSQL limit)
	validIdentifierPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)

	// allowedSchemaNames defines the whitelist of valid schema names
	// M-INPUT-3: Only predefined schemas are allowed for security
	allowedSchemaNames = map[string]bool{
		"public":     true, // Default PostgreSQL schema
		"cfgms_logs": true, // CFGMS logging schema
		"logs":       true, // Alternative logging schema
		"audit":      true, // Audit logging schema
		"timescale":  true, // TimescaleDB-specific schema
	}

	// allowedTableNames defines the whitelist of valid table names
	// M-INPUT-3: Only predefined table names are allowed for security
	allowedTableNames = map[string]bool{
		"log_entries":      true, // Default log entries table
		"logs":             true, // Alternative log table name
		"audit_logs":       true, // Audit log entries
		"system_logs":      true, // System log entries
		"application_logs": true, // Application log entries
		"security_logs":    true, // Security log entries
		"performance_logs": true, // Performance log entries
	}

	// allowedTablePrefixes defines allowed table name prefixes for testing
	// M-INPUT-3: Allow test tables with specific prefixes
	allowedTablePrefixes = []string{
		"log_entries_test_", // Test tables for unit/integration tests
		"logs_test_",        // Alternative test table prefix
		"audit_test_",       // Audit test tables
	}
)

// ValidateSQLIdentifier validates a SQL identifier (schema, table, column name)
// M-INPUT-3: Strict validation to prevent SQL injection
func ValidateSQLIdentifier(identifier string, identifierType string) error {
	if identifier == "" {
		return fmt.Errorf("SQL identifier cannot be empty (%s)", identifierType)
	}

	// Check pattern (alphanumeric + underscore, starts with letter/underscore)
	if !validIdentifierPattern.MatchString(identifier) {
		return fmt.Errorf("invalid SQL identifier '%s' (%s): must be alphanumeric with underscores, starting with letter or underscore, max 63 chars", identifier, identifierType)
	}

	return nil
}

// ValidateSchemaName validates a schema name against whitelist
// M-INPUT-3: Defense-in-depth - only allow predefined schemas
func ValidateSchemaName(schemaName string) error {
	// First check basic SQL identifier rules
	if err := ValidateSQLIdentifier(schemaName, "schema_name"); err != nil {
		return err
	}

	// M-INPUT-3: Check against whitelist
	if !allowedSchemaNames[schemaName] {
		return fmt.Errorf("schema name '%s' not in allowed list (allowed: public, cfgms_logs, logs, audit, timescale)", schemaName)
	}

	return nil
}

// ValidateTableName validates a table name against whitelist
// M-INPUT-3: Defense-in-depth - only allow predefined tables
func ValidateTableName(tableName string) error {
	// First check basic SQL identifier rules
	if err := ValidateSQLIdentifier(tableName, "table_name"); err != nil {
		return err
	}

	// M-INPUT-3: Check against exact whitelist first
	if allowedTableNames[tableName] {
		return nil
	}

	// M-INPUT-3: Check if name starts with allowed prefix (for test tables)
	for _, prefix := range allowedTablePrefixes {
		if strings.HasPrefix(tableName, prefix) {
			return nil
		}
	}

	return fmt.Errorf("table name '%s' not in allowed list (allowed: log_entries, logs, audit_logs, system_logs, etc.)", tableName)
}

// ValidateSchemaTablePair validates both schema and table name
// M-INPUT-3: Validates the full qualified table name
func ValidateSchemaTablePair(schemaName, tableName string) error {
	if err := ValidateSchemaName(schemaName); err != nil {
		return fmt.Errorf("invalid schema: %w", err)
	}

	if err := ValidateTableName(tableName); err != nil {
		return fmt.Errorf("invalid table: %w", err)
	}

	return nil
}
