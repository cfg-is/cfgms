// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package timescale - Tests for SQL identifier validation
package timescale

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateSQLIdentifier tests basic SQL identifier validation
func TestValidateSQLIdentifier(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		wantErr    bool
	}{
		{
			name:       "valid identifier with letters",
			identifier: "log_entries",
			wantErr:    false,
		},
		{
			name:       "valid identifier starting with underscore",
			identifier: "_private_table",
			wantErr:    false,
		},
		{
			name:       "valid identifier with numbers",
			identifier: "table_123",
			wantErr:    false,
		},
		{
			name:       "invalid - starts with number",
			identifier: "123_table",
			wantErr:    true,
		},
		{
			name:       "invalid - contains hyphen",
			identifier: "log-entries",
			wantErr:    true,
		},
		{
			name:       "invalid - contains space",
			identifier: "log entries",
			wantErr:    true,
		},
		{
			name:       "invalid - contains special chars",
			identifier: "logs; DROP TABLE users--",
			wantErr:    true,
		},
		{
			name:       "invalid - empty string",
			identifier: "",
			wantErr:    true,
		},
		{
			name:       "invalid - SQL injection attempt",
			identifier: "users' OR '1'='1",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSQLIdentifier(tt.identifier, "test")
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateSchemaName tests schema name whitelist validation
func TestValidateSchemaName(t *testing.T) {
	tests := []struct {
		name       string
		schemaName string
		wantErr    bool
	}{
		{
			name:       "valid - public schema",
			schemaName: "public",
			wantErr:    false,
		},
		{
			name:       "valid - cfgms_logs schema",
			schemaName: "cfgms_logs",
			wantErr:    false,
		},
		{
			name:       "valid - logs schema",
			schemaName: "logs",
			wantErr:    false,
		},
		{
			name:       "valid - audit schema",
			schemaName: "audit",
			wantErr:    false,
		},
		{
			name:       "invalid - not in whitelist",
			schemaName: "custom_schema",
			wantErr:    true,
		},
		{
			name:       "invalid - SQL injection attempt",
			schemaName: "public; DROP SCHEMA audit--",
			wantErr:    true,
		},
		{
			name:       "invalid - empty",
			schemaName: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSchemaName(tt.schemaName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateTableName tests table name whitelist validation
func TestValidateTableName(t *testing.T) {
	tests := []struct {
		name      string
		tableName string
		wantErr   bool
	}{
		{
			name:      "valid - log_entries table",
			tableName: "log_entries",
			wantErr:   false,
		},
		{
			name:      "valid - logs table",
			tableName: "logs",
			wantErr:   false,
		},
		{
			name:      "valid - audit_logs table",
			tableName: "audit_logs",
			wantErr:   false,
		},
		{
			name:      "valid - system_logs table",
			tableName: "system_logs",
			wantErr:   false,
		},
		{
			name:      "invalid - not in whitelist",
			tableName: "custom_table",
			wantErr:   true,
		},
		{
			name:      "invalid - SQL injection attempt",
			tableName: "logs; DELETE FROM users--",
			wantErr:   true,
		},
		{
			name:      "invalid - empty",
			tableName: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTableName(tt.tableName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateSchemaTablePair tests combined schema/table validation
func TestValidateSchemaTablePair(t *testing.T) {
	tests := []struct {
		name       string
		schemaName string
		tableName  string
		wantErr    bool
	}{
		{
			name:       "valid pair - public.log_entries",
			schemaName: "public",
			tableName:  "log_entries",
			wantErr:    false,
		},
		{
			name:       "valid pair - audit.audit_logs",
			schemaName: "audit",
			tableName:  "audit_logs",
			wantErr:    false,
		},
		{
			name:       "invalid schema",
			schemaName: "malicious_schema",
			tableName:  "log_entries",
			wantErr:    true,
		},
		{
			name:       "invalid table",
			schemaName: "public",
			tableName:  "malicious_table",
			wantErr:    true,
		},
		{
			name:       "both invalid",
			schemaName: "bad_schema",
			tableName:  "bad_table",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSchemaTablePair(tt.schemaName, tt.tableName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
