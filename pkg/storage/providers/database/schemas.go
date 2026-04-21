// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package database provides schema management for PostgreSQL storage provider
package database

import (
	"context"
	"database/sql"
	"fmt"
)

// DatabaseSchemas manages database schema creation and migrations
type DatabaseSchemas struct{}

// NewDatabaseSchemas creates a new schema manager
func NewDatabaseSchemas() DatabaseSchemas {
	return DatabaseSchemas{}
}

// CreateClientTenantsTable creates the client_tenants table with proper indexing
func (s DatabaseSchemas) CreateClientTenantsTable(ctx context.Context, db *sql.DB) error {
	// Create table with proper data types and constraints
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS client_tenants (
			id VARCHAR(255) PRIMARY KEY,
			tenant_id VARCHAR(255) UNIQUE NOT NULL,
			tenant_name VARCHAR(500) NOT NULL,
			domain_name VARCHAR(255) NOT NULL,
			admin_email VARCHAR(255) NOT NULL,
			consented_at TIMESTAMP WITH TIME ZONE NOT NULL,
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			client_identifier VARCHAR(255) NOT NULL,
			metadata JSONB DEFAULT '{}',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create client_tenants table: %w", err)
	}

	// Create indexes for performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_client_tenants_tenant_id ON client_tenants(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_client_tenants_client_identifier ON client_tenants(client_identifier);",
		"CREATE INDEX IF NOT EXISTS idx_client_tenants_status ON client_tenants(status);",
		"CREATE INDEX IF NOT EXISTS idx_client_tenants_created_at ON client_tenants(created_at);",
		"CREATE INDEX IF NOT EXISTS idx_client_tenants_domain_name ON client_tenants(domain_name);",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// CreateAdminConsentRequestsTable creates the admin_consent_requests table
func (s DatabaseSchemas) CreateAdminConsentRequestsTable(ctx context.Context, db *sql.DB) error {
	// Create table for admin consent requests
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS admin_consent_requests (
			client_identifier VARCHAR(255) NOT NULL,
			client_name VARCHAR(500) NOT NULL,
			requested_by VARCHAR(255) NOT NULL,
			state VARCHAR(255) PRIMARY KEY,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			metadata JSONB DEFAULT '{}'
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create admin_consent_requests table: %w", err)
	}

	// Create indexes for performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_admin_consent_requests_client_identifier ON admin_consent_requests(client_identifier);",
		"CREATE INDEX IF NOT EXISTS idx_admin_consent_requests_expires_at ON admin_consent_requests(expires_at);",
		"CREATE INDEX IF NOT EXISTS idx_admin_consent_requests_requested_by ON admin_consent_requests(requested_by);",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// CreateConfigsTable creates the configs table for configuration storage
func (s DatabaseSchemas) CreateConfigsTable(ctx context.Context, db *sql.DB) error {
	// Create table with proper data types and constraints
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS configs (
			id SERIAL PRIMARY KEY,
			tenant_id VARCHAR(255) NOT NULL,
			namespace VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			scope VARCHAR(255) DEFAULT '',
			version BIGINT NOT NULL DEFAULT 1,
			format VARCHAR(10) NOT NULL DEFAULT 'yaml',
			data TEXT NOT NULL,
			checksum VARCHAR(64) NOT NULL,
			metadata JSONB DEFAULT '{}',
			tags TEXT[] DEFAULT '{}',
			source VARCHAR(255) DEFAULT '',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			created_by VARCHAR(255) DEFAULT '',
			updated_by VARCHAR(255) DEFAULT '',
			
			-- Ensure unique configuration per tenant/namespace/name/scope combination
			UNIQUE(tenant_id, namespace, name, scope)
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create configs table: %w", err)
	}

	// Create indexes for performance and tenant isolation
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_configs_tenant_id ON configs(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_configs_tenant_namespace ON configs(tenant_id, namespace);",
		"CREATE INDEX IF NOT EXISTS idx_configs_tenant_namespace_name ON configs(tenant_id, namespace, name);",
		"CREATE INDEX IF NOT EXISTS idx_configs_created_at ON configs(created_at);",
		"CREATE INDEX IF NOT EXISTS idx_configs_updated_at ON configs(updated_at);",
		"CREATE INDEX IF NOT EXISTS idx_configs_version ON configs(version);",
		"CREATE INDEX IF NOT EXISTS idx_configs_tags ON configs USING GIN(tags);", // GIN index for array search
		"CREATE INDEX IF NOT EXISTS idx_configs_format ON configs(format);",
		"CREATE INDEX IF NOT EXISTS idx_configs_created_by ON configs(created_by);",
		"CREATE INDEX IF NOT EXISTS idx_configs_updated_by ON configs(updated_by);",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// CreateConfigHistoryTable creates the config_history table for version tracking
func (s DatabaseSchemas) CreateConfigHistoryTable(ctx context.Context, db *sql.DB) error {
	// Create history table for configuration versioning
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS config_history (
			id SERIAL PRIMARY KEY,
			config_id INTEGER NOT NULL,
			tenant_id VARCHAR(255) NOT NULL,
			namespace VARCHAR(255) NOT NULL,
			name VARCHAR(255) NOT NULL,
			scope VARCHAR(255) DEFAULT '',
			version BIGINT NOT NULL,
			format VARCHAR(10) NOT NULL,
			data TEXT NOT NULL,
			checksum VARCHAR(64) NOT NULL,
			metadata JSONB DEFAULT '{}',
			tags TEXT[] DEFAULT '{}',
			source VARCHAR(255) DEFAULT '',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_by VARCHAR(255) DEFAULT '',
			operation VARCHAR(50) NOT NULL DEFAULT 'update' -- 'create', 'update', 'delete'
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create config_history table: %w", err)
	}

	// Create indexes for historical queries
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_config_history_config_id ON config_history(config_id);",
		"CREATE INDEX IF NOT EXISTS idx_config_history_tenant_id ON config_history(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_config_history_tenant_namespace_name ON config_history(tenant_id, namespace, name);",
		"CREATE INDEX IF NOT EXISTS idx_config_history_version ON config_history(version);",
		"CREATE INDEX IF NOT EXISTS idx_config_history_created_at ON config_history(created_at);",
		"CREATE INDEX IF NOT EXISTS idx_config_history_operation ON config_history(operation);",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// CreateAuditEntriesTable creates the audit_entries table for audit logging
func (s DatabaseSchemas) CreateAuditEntriesTable(ctx context.Context, db *sql.DB) error {
	// Create table with proper data types for audit entries
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS audit_entries (
			id VARCHAR(255) PRIMARY KEY,
			tenant_id VARCHAR(255) NOT NULL,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			event_type VARCHAR(50) NOT NULL,
			action VARCHAR(100) NOT NULL,
			user_id VARCHAR(255) NOT NULL,
			user_type VARCHAR(20) NOT NULL DEFAULT 'human',
			session_id VARCHAR(255) DEFAULT '',
			resource_type VARCHAR(100) NOT NULL,
			resource_id VARCHAR(255) NOT NULL,
			resource_name VARCHAR(500) DEFAULT '',
			result VARCHAR(20) NOT NULL,
			error_code VARCHAR(100) DEFAULT '',
			error_message TEXT DEFAULT '',
			request_id VARCHAR(255) DEFAULT '',
			ip_address INET,
			user_agent TEXT DEFAULT '',
			method VARCHAR(20) DEFAULT '',
			path VARCHAR(1000) DEFAULT '',
			details JSONB DEFAULT '{}',
			changes JSONB DEFAULT '{}',
			tags TEXT[] DEFAULT '{}',
			severity VARCHAR(20) NOT NULL DEFAULT 'low',
			source VARCHAR(100) NOT NULL,
			version VARCHAR(20) DEFAULT '1.0',
			checksum VARCHAR(64) NOT NULL,
			sequence_number BIGINT NOT NULL DEFAULT 0,
			previous_checksum VARCHAR(64) NOT NULL DEFAULT ''
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create audit_entries table: %w", err)
	}

	// Create indexes for efficient audit queries and tenant isolation
	indexes := []string{
		// Primary query patterns
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_tenant_id ON audit_entries(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_timestamp ON audit_entries(timestamp);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_tenant_timestamp ON audit_entries(tenant_id, timestamp);",

		// User and session tracking
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_user_id ON audit_entries(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_session_id ON audit_entries(session_id);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_user_type ON audit_entries(user_type);",

		// Event and action analysis
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_event_type ON audit_entries(event_type);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_action ON audit_entries(action);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_event_action ON audit_entries(event_type, action);",

		// Resource tracking
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_resource_type ON audit_entries(resource_type);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_resource_id ON audit_entries(resource_id);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_resource_type_id ON audit_entries(resource_type, resource_id);",

		// Security monitoring
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_result ON audit_entries(result);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_severity ON audit_entries(severity);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_failed_actions ON audit_entries(result) WHERE result IN ('failure', 'error', 'denied');",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_security_events ON audit_entries(event_type, severity) WHERE event_type = 'security_event';",

		// Network and request tracking
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_ip_address ON audit_entries(ip_address);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_request_id ON audit_entries(request_id);",

		// Full-text search and tags
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_tags ON audit_entries USING GIN(tags);",       // GIN index for array search
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_details ON audit_entries USING GIN(details);", // GIN index for JSONB search

		// Compliance and reporting
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_source ON audit_entries(source);",
		"CREATE INDEX IF NOT EXISTS idx_audit_entries_tenant_event_timestamp ON audit_entries(tenant_id, event_type, timestamp);",

		// Time-based partitioning support (for future sharding) - temporarily disabled
		// Complex date functions in indexes require careful IMMUTABLE handling
		// "CREATE INDEX IF NOT EXISTS idx_audit_entries_daily_partition ON audit_entries(tenant_id, date_trunc('day', timestamp));",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// CreateAuditStatsView creates a materialized view for audit statistics
func (s DatabaseSchemas) CreateAuditStatsView(ctx context.Context, db *sql.DB) error {
	// Create materialized view for performance optimization of statistics queries
	createViewQuery := `
		CREATE MATERIALIZED VIEW IF NOT EXISTS audit_stats AS
		SELECT 
			tenant_id,
			event_type,
			result,
			severity,
			DATE(timestamp) as audit_date,
			COUNT(*) as entry_count,
			MIN(timestamp) as earliest_entry,
			MAX(timestamp) as latest_entry
		FROM audit_entries
		GROUP BY tenant_id, event_type, result, severity, DATE(timestamp);
	`

	if _, err := db.ExecContext(ctx, createViewQuery); err != nil {
		return fmt.Errorf("failed to create audit_stats materialized view: %w", err)
	}

	// Create indexes on the materialized view
	viewIndexes := []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_stats_unique ON audit_stats(tenant_id, event_type, result, severity, audit_date);",
		"CREATE INDEX IF NOT EXISTS idx_audit_stats_tenant_id ON audit_stats(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_audit_stats_audit_date ON audit_stats(audit_date);",
		"CREATE INDEX IF NOT EXISTS idx_audit_stats_event_type ON audit_stats(event_type);",
	}

	for _, indexQuery := range viewIndexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create materialized view index: %w", err)
		}
	}

	return nil
}

// RefreshAuditStatsView refreshes the materialized view (should be called periodically)
func (s DatabaseSchemas) RefreshAuditStatsView(ctx context.Context, db *sql.DB) error {
	refreshQuery := "REFRESH MATERIALIZED VIEW CONCURRENTLY audit_stats;"

	if _, err := db.ExecContext(ctx, refreshQuery); err != nil {
		return fmt.Errorf("failed to refresh audit_stats materialized view: %w", err)
	}

	return nil
}

// SetupHealthMonitoring creates health check functions and monitoring tables
func (s DatabaseSchemas) SetupHealthMonitoring(ctx context.Context, db *sql.DB) error {
	// Create a simple health check table
	createHealthTableQuery := `
		CREATE TABLE IF NOT EXISTS storage_health (
			id SERIAL PRIMARY KEY,
			provider_name VARCHAR(50) NOT NULL,
			last_check TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			status VARCHAR(20) NOT NULL,
			details JSONB DEFAULT '{}',
			response_time_ms INTEGER DEFAULT 0
		);
	`

	if _, err := db.ExecContext(ctx, createHealthTableQuery); err != nil {
		return fmt.Errorf("failed to create storage_health table: %w", err)
	}

	// Create index for health monitoring
	healthIndexQuery := "CREATE INDEX IF NOT EXISTS idx_storage_health_provider ON storage_health(provider_name, last_check);"
	if _, err := db.ExecContext(ctx, healthIndexQuery); err != nil {
		return fmt.Errorf("failed to create health monitoring index: %w", err)
	}

	return nil
}

// CreateRBACTables creates all RBAC-related tables with proper indexing
func (s DatabaseSchemas) CreateRBACTables(ctx context.Context, db *sql.DB) error {
	// Create permissions table
	if err := s.CreateRBACPermissionsTable(ctx, db); err != nil {
		return err
	}

	// Create roles table
	if err := s.CreateRBACRolesTable(ctx, db); err != nil {
		return err
	}

	// Create subjects table
	if err := s.CreateRBACSubjectsTable(ctx, db); err != nil {
		return err
	}

	// Create role assignments table
	if err := s.CreateRBACRoleAssignmentsTable(ctx, db); err != nil {
		return err
	}

	return nil
}

// CreateTenantTables creates all tenant-related tables with proper indexing
func (s DatabaseSchemas) CreateTenantTables(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cfgms_tenants (
			id VARCHAR(255) PRIMARY KEY,
			name VARCHAR(500) NOT NULL,
			description TEXT DEFAULT '',
			parent_id VARCHAR(255) DEFAULT NULL,
			metadata JSONB DEFAULT '{}',
			status VARCHAR(50) NOT NULL DEFAULT 'active',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			FOREIGN KEY (parent_id) REFERENCES cfgms_tenants(id) ON DELETE RESTRICT
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_tenants table: %w", err)
	}

	// Create indexes for performance and hierarchy queries
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_cfgms_tenants_parent_id ON cfgms_tenants(parent_id);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_tenants_status ON cfgms_tenants(status);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_tenants_name ON cfgms_tenants(name);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_tenants_created_at ON cfgms_tenants(created_at);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_tenants_metadata ON cfgms_tenants USING GIN(metadata);",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create cfgms_tenants index: %w", err)
		}
	}

	return nil
}

// CreateRBACPermissionsTable creates the rbac_permissions table
func (s DatabaseSchemas) CreateRBACPermissionsTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS rbac_permissions (
			id VARCHAR(255) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			description TEXT DEFAULT '',
			resource_type VARCHAR(100) NOT NULL,
			actions JSONB NOT NULL DEFAULT '[]',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create rbac_permissions table: %w", err)
	}

	// Create indexes for performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_rbac_permissions_resource_type ON rbac_permissions(resource_type);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_permissions_name ON rbac_permissions(name);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_permissions_actions ON rbac_permissions USING GIN(actions);",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create rbac_permissions index: %w", err)
		}
	}

	return nil
}

// CreateRBACRolesTable creates the rbac_roles table
func (s DatabaseSchemas) CreateRBACRolesTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS rbac_roles (
			id VARCHAR(255) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			description TEXT DEFAULT '',
			permission_ids JSONB NOT NULL DEFAULT '[]',
			is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
			tenant_id VARCHAR(255) DEFAULT '',
			parent_role_id VARCHAR(255) DEFAULT NULL,
			inheritance_type INTEGER DEFAULT 0,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			FOREIGN KEY (parent_role_id) REFERENCES rbac_roles(id) ON DELETE SET NULL
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create rbac_roles table: %w", err)
	}

	// Create indexes for performance and tenant isolation
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_rbac_roles_tenant_id ON rbac_roles(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_roles_is_system_role ON rbac_roles(is_system_role);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_roles_name ON rbac_roles(name);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_roles_parent_role_id ON rbac_roles(parent_role_id);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_roles_permission_ids ON rbac_roles USING GIN(permission_ids);",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create rbac_roles index: %w", err)
		}
	}

	return nil
}

// CreateRBACSubjectsTable creates the rbac_subjects table
func (s DatabaseSchemas) CreateRBACSubjectsTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS rbac_subjects (
			id VARCHAR(255) PRIMARY KEY,
			type INTEGER NOT NULL,
			display_name VARCHAR(500) NOT NULL,
			tenant_id VARCHAR(255) NOT NULL,
			role_ids JSONB NOT NULL DEFAULT '[]',
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			attributes JSONB DEFAULT '{}',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create rbac_subjects table: %w", err)
	}

	// Create indexes for performance and tenant isolation
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_rbac_subjects_tenant_id ON rbac_subjects(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_subjects_type ON rbac_subjects(type);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_subjects_tenant_type ON rbac_subjects(tenant_id, type);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_subjects_is_active ON rbac_subjects(is_active);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_subjects_role_ids ON rbac_subjects USING GIN(role_ids);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_subjects_attributes ON rbac_subjects USING GIN(attributes);",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create rbac_subjects index: %w", err)
		}
	}

	return nil
}

// CreateRBACRoleAssignmentsTable creates the rbac_role_assignments table
func (s DatabaseSchemas) CreateRBACRoleAssignmentsTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS rbac_role_assignments (
			id VARCHAR(255) PRIMARY KEY,
			subject_id VARCHAR(255) NOT NULL,
			role_id VARCHAR(255) NOT NULL,
			tenant_id VARCHAR(255) NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
			created_by VARCHAR(255) DEFAULT '',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			FOREIGN KEY (subject_id) REFERENCES rbac_subjects(id) ON DELETE CASCADE,
			FOREIGN KEY (role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE,
			UNIQUE(subject_id, role_id, tenant_id)
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create rbac_role_assignments table: %w", err)
	}

	// Create indexes for performance and tenant isolation
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_rbac_assignments_subject_id ON rbac_role_assignments(subject_id);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_assignments_role_id ON rbac_role_assignments(role_id);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_assignments_tenant_id ON rbac_role_assignments(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_assignments_subject_tenant ON rbac_role_assignments(subject_id, tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_rbac_assignments_expires_at ON rbac_role_assignments(expires_at);",
		// Active assignments index - disabled due to NOW() function not being IMMUTABLE in WHERE clause
		// "CREATE INDEX IF NOT EXISTS idx_rbac_assignments_active ON rbac_role_assignments(subject_id, tenant_id) WHERE expires_at IS NULL OR expires_at > NOW();",
		"CREATE INDEX IF NOT EXISTS idx_rbac_assignments_expires_null ON rbac_role_assignments(subject_id, tenant_id) WHERE expires_at IS NULL;",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create rbac_role_assignments index: %w", err)
		}
	}

	return nil
}

// CreateRegistrationTokensTable creates the registration_tokens table for token persistence
func (s DatabaseSchemas) CreateRegistrationTokensTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cfgms_registration_tokens (
			token VARCHAR(255) PRIMARY KEY,
			tenant_id VARCHAR(255) NOT NULL,
			controller_url VARCHAR(1000) NOT NULL,
			group_name VARCHAR(255) DEFAULT '',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
			single_use BOOLEAN NOT NULL DEFAULT FALSE,
			used_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
			used_by VARCHAR(255) DEFAULT '',
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_registration_tokens table: %w", err)
	}

	// Create indexes for performance and tenant isolation
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_tenant_id ON cfgms_registration_tokens(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_group_name ON cfgms_registration_tokens(group_name);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_created_at ON cfgms_registration_tokens(created_at);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_expires_at ON cfgms_registration_tokens(expires_at);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_revoked ON cfgms_registration_tokens(revoked);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_single_use ON cfgms_registration_tokens(single_use);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_used_at ON cfgms_registration_tokens(used_at);",
		// Composite index for filtering unused, non-revoked tokens by tenant
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_tenant_active ON cfgms_registration_tokens(tenant_id) WHERE revoked = FALSE;",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create cfgms_registration_tokens index: %w", err)
		}
	}

	return nil
}

// CreateAllTables creates all necessary database tables and indexes
func (s DatabaseSchemas) CreateAllTables(ctx context.Context, db *sql.DB) error {
	// Create tables in dependency order
	if err := s.CreateClientTenantsTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateAdminConsentRequestsTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateConfigsTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateConfigHistoryTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateAuditEntriesTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateAuditStatsView(ctx, db); err != nil {
		return err
	}

	if err := s.SetupHealthMonitoring(ctx, db); err != nil {
		return err
	}

	if err := s.CreateRBACTables(ctx, db); err != nil {
		return err
	}

	return nil
}

// DropAllTables drops all tables (for testing or clean reinstall)
func (s DatabaseSchemas) DropAllTables(ctx context.Context, db *sql.DB) error {
	// Drop in reverse dependency order (foreign keys need to be dropped first)
	dropQueries := []string{
		"DROP MATERIALIZED VIEW IF EXISTS audit_stats;",
		"DROP TABLE IF EXISTS storage_health;",
		"DROP TABLE IF EXISTS audit_entries;",
		"DROP TABLE IF EXISTS config_history;",
		"DROP TABLE IF EXISTS configs;",
		"DROP TABLE IF EXISTS admin_consent_requests;",
		"DROP TABLE IF EXISTS client_tenants;",
		"DROP TABLE IF EXISTS cfgms_registration_tokens;",
		"DROP TABLE IF EXISTS rbac_role_assignments;", // Has foreign keys to subjects and roles
		"DROP TABLE IF EXISTS rbac_subjects;",
		"DROP TABLE IF EXISTS rbac_roles;", // Has self-reference foreign key
		"DROP TABLE IF EXISTS rbac_permissions;",
	}

	for _, query := range dropQueries {
		if _, err := db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("failed to drop table: %w", err)
		}
	}

	return nil
}
