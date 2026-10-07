// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides schema management for PostgreSQL storage provider
package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/cfgis/cfgms/pkg/logging"
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

	return ensureAuditSequenceUniqueIndex(ctx, db)
}

// auditSequenceUniqueIndex is the chain-integrity defense-in-depth index
// (Issue #3754): it guarantees at the database level that no tenant ever has
// two entries sharing a SequenceNumber, even if a bug in AppendChainedEntry's
// locking were to slip past it. Partial so pre-chain legacy rows
// (sequence_number = 0, see VerifyChain) remain unconstrained — many such rows
// share tenant_id.
const auditSequenceUniqueIndex = "idx_audit_entries_tenant_sequence_unique"

// ensureAuditSequenceUniqueIndex creates auditSequenceUniqueIndex unless rows
// written before Issue #3754 already collide on (tenant_id, sequence_number).
// Those rows predate database-serialized sequence assignment, when concurrent
// writers could compute the same MAX+1. Building the index over them fails with
// 23505 and would stop the controller from starting (Issue #4499), so the index
// is skipped and the collision count logged instead. The rows are left as they
// are: the audit log is tamper-evident and is never rewritten here, and
// VerifyChain still reports the fork.
func ensureAuditSequenceUniqueIndex(ctx context.Context, db *sql.DB) error {
	var exists bool
	if err := db.QueryRowContext(ctx,
		"SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1)",
		auditSequenceUniqueIndex).Scan(&exists); err != nil {
		return fmt.Errorf("failed to check for index %s: %w", auditSequenceUniqueIndex, err)
	}
	if exists {
		return nil
	}

	var duplicateGroups int64
	if err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
			SELECT 1 FROM audit_entries
			WHERE sequence_number > 0
			GROUP BY tenant_id, sequence_number
			HAVING COUNT(*) > 1
		) duplicates`).Scan(&duplicateGroups); err != nil {
		return fmt.Errorf("failed to check audit_entries for duplicate sequence numbers: %w", err)
	}
	if duplicateGroups > 0 {
		logging.ForComponent("storage_database").Warn(
			"audit_entries holds duplicate sequence numbers written before Issue #3754; skipping unique index",
			"index", auditSequenceUniqueIndex,
			"duplicate_groups", duplicateGroups)
		return nil
	}

	if _, err := db.ExecContext(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS "+auditSequenceUniqueIndex+
		" ON audit_entries(tenant_id, sequence_number) WHERE sequence_number > 0;"); err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	return nil
}

// CreateAuditChainHeadsTable creates audit_chain_heads, the row-lock target
// AppendChainedEntry uses to serialize concurrent chain writers for the same
// tenant — including across separate controller nodes sharing this database
// (ADR-004 amendment, ADR-031 Decision 1, Issue #3754). One row per tenant;
// SELECT ... FOR UPDATE on that row is what makes sequence assignment atomic.
func (s DatabaseSchemas) CreateAuditChainHeadsTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS audit_chain_heads (
			tenant_id       VARCHAR(255) PRIMARY KEY,
			sequence_number BIGINT NOT NULL DEFAULT 0,
			checksum        VARCHAR(64) NOT NULL DEFAULT ''
		);
	`
	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create audit_chain_heads table: %w", err)
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

// BackfillTenantLifecycle adds the ADR-027 Decision 2 suspension provenance
// columns to a pre-existing cfgms_tenants table (migration 008). Idempotent:
// ADD COLUMN IF NOT EXISTS is a no-op on an up-to-date table.
func (s DatabaseSchemas) BackfillTenantLifecycle(ctx context.Context, db *sql.DB) error {
	alters := []string{
		`ALTER TABLE cfgms_tenants ADD COLUMN IF NOT EXISTS directly_suspended BOOLEAN DEFAULT false`,
		`ALTER TABLE cfgms_tenants ADD COLUMN IF NOT EXISTS cascade_suspended_from VARCHAR(255)`,
	}
	for _, stmt := range alters {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to backfill cfgms_tenants lifecycle columns: %w", err)
		}
	}
	return nil
}

// BackfillTenantBillingLabel adds the opaque billing_label column to a
// pre-existing cfgms_tenants table (migration 012), fills rows that have none
// with random values (never derived from any tenant field), and adds the unique
// index. Idempotent: labels that already exist are never changed.
func (s DatabaseSchemas) BackfillTenantBillingLabel(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`ALTER TABLE cfgms_tenants ADD COLUMN IF NOT EXISTS billing_label VARCHAR(64)`,
		`UPDATE cfgms_tenants
		 SET billing_label = 'bl-' ||
		     substr(replace(gen_random_uuid()::text, '-', ''), 1, 12) ||
		     substr(replace(gen_random_uuid()::text, '-', ''), 25, 8)
		 WHERE billing_label IS NULL OR billing_label = ''`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_cfgms_tenants_billing_label ON cfgms_tenants(billing_label)`,
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to backfill cfgms_tenants billing label: %w", err)
		}
	}
	return nil
}

// CreatePendingDeletionsTable creates cfgms_tenant_pending_deletions for ADR-027
// Decisions 3-4 (Issue #3182). Idempotent via CREATE TABLE IF NOT EXISTS.
func (s DatabaseSchemas) CreatePendingDeletionsTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cfgms_tenant_pending_deletions (
			subtree_root_id   VARCHAR(255) PRIMARY KEY,
			requested_by      VARCHAR(255) NOT NULL,
			requested_at      TIMESTAMP WITH TIME ZONE NOT NULL,
			eligible_at       TIMESTAMP WITH TIME ZONE NOT NULL,
			state             VARCHAR(50)  NOT NULL DEFAULT 'hold',
			pinned_member_ids JSONB        NOT NULL DEFAULT '[]'
		)
	`
	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_tenant_pending_deletions table: %w", err)
	}
	return nil
}

// CreateTenantTables creates all tenant-related tables with proper indexing.
// directly_suspended and cascade_suspended_from (ADR-027 Decision 2) are
// included in the CREATE TABLE; BackfillTenantLifecycle handles pre-existing
// deployments missing these columns.
func (s DatabaseSchemas) CreateTenantTables(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cfgms_tenants (
			id VARCHAR(255) PRIMARY KEY,
			name VARCHAR(500) NOT NULL,
			description TEXT DEFAULT '',
			parent_id VARCHAR(255) DEFAULT NULL,
			metadata JSONB DEFAULT '{}',
			status VARCHAR(50) NOT NULL DEFAULT 'active',
			directly_suspended BOOLEAN DEFAULT false,
			cascade_suspended_from VARCHAR(255),
			billing_label VARCHAR(64),
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			FOREIGN KEY (parent_id) REFERENCES cfgms_tenants(id) ON DELETE RESTRICT
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_tenants table: %w", err)
	}

	// Migration for deployments created before ADR-027 (Issue #3158).
	if err := s.BackfillTenantLifecycle(ctx, db); err != nil {
		return err
	}

	// Opaque billing label column, fill and unique index (Issue #4645).
	if err := s.BackfillTenantBillingLabel(ctx, db); err != nil {
		return err
	}

	// Create the pending-deletions table (ADR-027 Decisions 3-4, Issue #3182).
	if err := s.CreatePendingDeletionsTable(ctx, db); err != nil {
		return err
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

// CreateRegistrationTokensTable creates the registration_tokens table for token persistence.
// Migration note: single_use, used_at, and used_by columns were removed in Issue #1690
// (perennial token model with immediate-invalidation rotation). The id column (stable,
// non-secret UUID used by the web UI to address a token) was added in Issue #2970 —
// BackfillRegistrationTokenIDs handles pre-existing deployments.
// Bearer values are persisted as deterministic SHA-256 lookup keys by the store.
// Legacy rows without expiry remain readable so operators can rotate them.
func (s DatabaseSchemas) CreateRegistrationTokensTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cfgms_registration_tokens (
			token VARCHAR(255) PRIMARY KEY,
			id VARCHAR(36),
			tenant_id VARCHAR(255) NOT NULL,
			controller_url VARCHAR(1000) NOT NULL,
			group_name VARCHAR(255) DEFAULT '',
			label VARCHAR(100) NOT NULL DEFAULT '',
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			revoked_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_registration_tokens table: %w", err)
	}

	// Migration for deployments created before Issue #2970: add the column and
	// assign a UUID to every pre-existing row so the web UI can address them.
	if err := s.BackfillRegistrationTokenIDs(ctx, db); err != nil {
		return err
	}

	// Migration for deployments created before the operator label (Issue #4599).
	// Idempotent: ADD COLUMN IF NOT EXISTS is a no-op on an up-to-date table.
	if _, err := db.ExecContext(ctx,
		`ALTER TABLE cfgms_registration_tokens ADD COLUMN IF NOT EXISTS label VARCHAR(100) NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("failed to add label column to cfgms_registration_tokens: %w", err)
	}

	// A claim gates certificate issuance for one device identity. Registration
	// tokens are perennial (Issue #1690), so the key is (token, claim_id): many
	// devices enrol on one fleet token, but a given device can be issued a key
	// only once per token. A table left over from the original single-column key
	// is dropped — claims are short-lived in-flight guards, and keeping them
	// would preserve exactly the rows that block re-enrolment.
	if err := dropSingleColumnRegistrationClaimKey(ctx, db); err != nil {
		return err
	}
	createClaimsTableQuery := `
		CREATE TABLE IF NOT EXISTS cfgms_registration_token_claims (
			token      VARCHAR(255) NOT NULL,
			claim_id   VARCHAR(255) NOT NULL,
			claimed_at TIMESTAMP WITH TIME ZONE NOT NULL,
			PRIMARY KEY (token, claim_id)
		);
	`
	if _, err := db.ExecContext(ctx, createClaimsTableQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_registration_token_claims table: %w", err)
	}

	// Create indexes for performance and tenant isolation
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_tenant_id ON cfgms_registration_tokens(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_group_name ON cfgms_registration_tokens(group_name);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_created_at ON cfgms_registration_tokens(created_at);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_expires_at ON cfgms_registration_tokens(expires_at);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_revoked ON cfgms_registration_tokens(revoked);",
		// Unique lookup index for GetTokenByID (Issue #2970).
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_id ON cfgms_registration_tokens(id);",
		// Composite index for filtering non-revoked tokens by tenant
		"CREATE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_tenant_active ON cfgms_registration_tokens(tenant_id) WHERE revoked = FALSE;",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create cfgms_registration_tokens index: %w", err)
		}
	}

	return nil
}

// dropSingleColumnRegistrationClaimKey removes a cfgms_registration_token_claims
// table that still carries the original single-column `token` primary key. That
// key admitted one device per token for the token's whole lifetime, which
// silently reverted the perennial token model (Issue #1690) — a fleet token
// could enrol exactly one endpoint. CREATE TABLE IF NOT EXISTS alone would leave
// the old key in place, so the stale table is dropped and recreated with
// PRIMARY KEY (token, claim_id).
//
// Dropping the rows is safe: a claim is a short-lived in-flight admission guard,
// so any registration still mid-flight simply retries.
func dropSingleColumnRegistrationClaimKey(ctx context.Context, db *sql.DB) error {
	var keyColumns int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name = kcu.constraint_name
		 AND tc.table_schema = kcu.table_schema
		WHERE tc.table_name = 'cfgms_registration_token_claims'
		  AND tc.constraint_type = 'PRIMARY KEY'`).Scan(&keyColumns)
	if err != nil {
		return fmt.Errorf("failed to inspect cfgms_registration_token_claims primary key: %w", err)
	}
	// 0 = table absent (nothing to migrate); 2 = already the corrected key.
	if keyColumns != 1 {
		return nil
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE cfgms_registration_token_claims`); err != nil {
		return fmt.Errorf("failed to drop legacy cfgms_registration_token_claims table: %w", err)
	}
	return nil
}

// BackfillRegistrationTokenIDs adds the id column to a pre-existing
// cfgms_registration_tokens table and assigns a UUID to every row that lacks one
// (Issue #2970). Without the back-fill, legacy rows would report an empty token_id
// and could never be revoked or deleted from the web UI — exactly the tokens most
// likely to need revoking. Idempotent: ADD COLUMN IF NOT EXISTS is a no-op on an
// up-to-date table and the UPDATE matches no rows once every row has an id.
func (s DatabaseSchemas) BackfillRegistrationTokenIDs(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx,
		`ALTER TABLE cfgms_registration_tokens ADD COLUMN IF NOT EXISTS id VARCHAR(36)`); err != nil {
		return fmt.Errorf("failed to add id column to cfgms_registration_tokens: %w", err)
	}

	rows, err := db.QueryContext(ctx,
		`SELECT token FROM cfgms_registration_tokens WHERE id IS NULL OR id = ''`)
	if err != nil {
		return fmt.Errorf("failed to select registration tokens missing an id: %w", err)
	}
	var tokensMissingID []string
	for rows.Next() {
		var tokenStr string
		if err := rows.Scan(&tokenStr); err != nil {
			_ = rows.Close()
			return fmt.Errorf("failed to scan registration token missing an id: %w", err)
		}
		tokensMissingID = append(tokensMissingID, tokenStr)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("error iterating registration tokens missing an id: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close registration token back-fill rows: %w", err)
	}

	for _, tokenStr := range tokensMissingID {
		id, err := generateTokenID()
		if err != nil {
			return fmt.Errorf("failed to generate registration token id for back-fill: %w", err)
		}
		if _, err := db.ExecContext(ctx,
			`UPDATE cfgms_registration_tokens SET id = $1 WHERE token = $2`, id, tokenStr); err != nil {
			return fmt.Errorf("failed to back-fill registration token id: %w", err)
		}
	}

	return nil
}

// CreateLeaseTable creates the cfgms_leases table backing pkg/lease — the
// fenced, quorum-equivalent singleton-claim primitive (ADR-031 Decision 5,
// Issue #3756). A row is never deleted by Release; it is force-expired so the
// token column remains the lease's monotonic high-water mark across releases.
func (s DatabaseSchemas) CreateLeaseTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cfgms_leases (
			name       TEXT PRIMARY KEY,
			holder_id  TEXT NOT NULL,
			token      BIGINT NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		);
	`
	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_leases table: %w", err)
	}

	indexQuery := "CREATE INDEX IF NOT EXISTS idx_leases_expires_at ON cfgms_leases(expires_at);"
	if _, err := db.ExecContext(ctx, indexQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_leases index: %w", err)
	}

	return nil
}

// CreateRoutingTable creates the cfgms_routing table backing the shared
// steward-routing table (ADR-031 Decision 3, Issue #3764): which controller
// node currently holds a steward's control-plane connection. updated_at is
// the liveness timestamp business.RoutingStore.LookupNode evaluates against
// business.RoutingStaleAfter, always compared using the database server's own
// now() so no caller clock enters the decision (see business.RoutingStore).
func (s DatabaseSchemas) CreateRoutingTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cfgms_routing (
			steward_id TEXT PRIMARY KEY,
			node_id    TEXT NOT NULL,
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
		);
	`
	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_routing table: %w", err)
	}

	indexQuery := "CREATE INDEX IF NOT EXISTS idx_routing_node_id ON cfgms_routing(node_id);"
	if _, err := db.ExecContext(ctx, indexQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_routing index: %w", err)
	}

	return nil
}

// CreateScriptRunTables creates the script run, job and execution-grant tables
// backing business.ScriptRunStore (Issue #4528). In cluster mode every
// controller node reads and completes runs through these shared tables.
func (s DatabaseSchemas) CreateScriptRunTables(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS script_runs (
			run_id         TEXT PRIMARY KEY,
			tenant_id      TEXT NOT NULL,
			created_by     TEXT NOT NULL DEFAULT '',
			created_at     TIMESTAMP WITH TIME ZONE NOT NULL,
			status         TEXT NOT NULL,
			filter_json    JSONB,
			script_ref     TEXT NOT NULL DEFAULT '',
			inline_content TEXT NOT NULL DEFAULT '',
			shell          TEXT NOT NULL DEFAULT '',
			job_count      INTEGER NOT NULL DEFAULT 0,
			completed_jobs INTEGER NOT NULL DEFAULT 0,
			failed_jobs    INTEGER NOT NULL DEFAULT 0
		);`,
		"CREATE INDEX IF NOT EXISTS idx_script_runs_tenant_created ON script_runs(tenant_id, created_at DESC);",
		`CREATE TABLE IF NOT EXISTS script_run_jobs (
			job_id       TEXT PRIMARY KEY,
			run_id       TEXT NOT NULL,
			device_id    TEXT NOT NULL,
			execution_id TEXT NOT NULL DEFAULT '',
			status       TEXT NOT NULL,
			created_at   TIMESTAMP WITH TIME ZONE NOT NULL,
			completed_at TIMESTAMP WITH TIME ZONE,
			output       TEXT NOT NULL DEFAULT '',
			stderr       TEXT NOT NULL DEFAULT '',
			exit_code    INTEGER NOT NULL DEFAULT 0
		);`,
		"CREATE INDEX IF NOT EXISTS idx_script_run_jobs_run_id ON script_run_jobs(run_id);",
		`CREATE TABLE IF NOT EXISTS execution_grants (
			execution_id TEXT PRIMARY KEY,
			device_id    TEXT NOT NULL,
			tenant_id    TEXT NOT NULL,
			scope_json   JSONB NOT NULL,
			created_at   TIMESTAMP WITH TIME ZONE NOT NULL,
			expires_at   TIMESTAMP WITH TIME ZONE NOT NULL,
			consumed     BOOLEAN NOT NULL DEFAULT false
		);`,
		"CREATE INDEX IF NOT EXISTS idx_execution_grants_device ON execution_grants(device_id, execution_id);",
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to create script run tables: %w", err)
		}
	}
	return nil
}

// CreateExecutionQueueTable creates the cfgms_execution_queue table backing
// business.ExecutionQueueStore (Issue #4528). payload holds the feature's full
// queue entry; the remaining columns are what the store selects and
// transitions on. The partial unique index enforces "one queued entry per
// device and parameter hash" across every node.
func (s DatabaseSchemas) CreateExecutionQueueTable(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS cfgms_execution_queue (
			execution_id  TEXT PRIMARY KEY,
			device_id     TEXT NOT NULL,
			param_hash    TEXT NOT NULL,
			state         TEXT NOT NULL,
			queued_at     TIMESTAMP WITH TIME ZONE NOT NULL,
			expires_at    TIMESTAMP WITH TIME ZONE NOT NULL,
			dispatched_at TIMESTAMP WITH TIME ZONE,
			completed_at  TIMESTAMP WITH TIME ZONE,
			payload       JSONB NOT NULL
		);`,
		"CREATE INDEX IF NOT EXISTS idx_execution_queue_device_state ON cfgms_execution_queue(device_id, state);",
		"CREATE INDEX IF NOT EXISTS idx_execution_queue_state ON cfgms_execution_queue(state);",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_execution_queue_queued_dedup ON cfgms_execution_queue(device_id, param_hash) WHERE state = 'queued';",
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to create cfgms_execution_queue table: %w", err)
		}
	}
	return nil
}

// CreateNodeRegistryTable creates the cfgms_node_registry table backing the
// shared controller-node registry (Issue #3763, ADR-031 Decision 5's
// post-Raft membership mechanism): each ClusterMode node's advertised
// identity, visible to every node. updated_at is the liveness timestamp
// business.NodeRegistryStore.ListNodes evaluates against
// business.NodeRegistryStaleAfter, always compared using the database
// server's own now() so no caller clock enters the decision.
func (s DatabaseSchemas) CreateNodeRegistryTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cfgms_node_registry (
			node_id    TEXT PRIMARY KEY,
			address    TEXT NOT NULL,
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
		);
	`
	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_node_registry table: %w", err)
	}

	return nil
}

// CreateCertRevocationsTable creates the cfgms_cert_revocations table backing
// the cluster-visible CertRevocationStore (ADR-031 Decision 1, Issue #3852).
func (s DatabaseSchemas) CreateCertRevocationsTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS cfgms_cert_revocations (
			serial     TEXT NOT NULL PRIMARY KEY,
			revoked_at TIMESTAMP WITH TIME ZONE NOT NULL,
			reason     TEXT NOT NULL DEFAULT ''
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create cfgms_cert_revocations table: %w", err)
	}
	return nil
}

// CreateSigningCursorTable creates the cfgms_signing_cursor table backing the
// cluster-visible SigningCursorStore (ADR-031 Decision 1, Issue #3852). The
// table only ever holds the single row keyed 'default' — one controller CA,
// one signing cursor.
func (s DatabaseSchemas) CreateSigningCursorTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS cfgms_signing_cursor (
			id                  TEXT NOT NULL PRIMARY KEY,
			current_serial      TEXT NOT NULL,
			rotating_serial     TEXT,
			overlap_window_days INTEGER NOT NULL,
			rotated_at          TIMESTAMP WITH TIME ZONE NOT NULL,
			retired_at          TIMESTAMP WITH TIME ZONE
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create cfgms_signing_cursor table: %w", err)
	}
	return nil
}

// CreateModuleApprovalsTable creates the cfgms_module_approvals table backing the
// cluster-visible, CAS-protected ModuleApprovalStore (ADR-031 Decision 1, Issue
// #3886). address is the opaque publisher/name/version/content-hash key
// features/controller/modules/cache derives from a bundle.ContentAddress.
func (s DatabaseSchemas) CreateModuleApprovalsTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS cfgms_module_approvals (
			address TEXT NOT NULL PRIMARY KEY,
			status  TEXT NOT NULL
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create cfgms_module_approvals table: %w", err)
	}
	return nil
}

// CreateRateCountersTable creates the cfgms_rate_counters table backing the
// cluster-visible RateCounterStore (ADR-031 Decision 1, Issue #3896). key is
// the caller-namespaced counter identity (e.g. "<route>:<source-address>" for
// the per-source rate limiters, "sign:session:<id>"/"sign:ip:<addr>" for the
// operator-payload sign-ceremony throttle); window_start marks when the
// current fixed window for that key began.
//
// expires_at records window_start plus that key's own window — the instant the
// row is dead — because the window length belongs to the caller, not to the
// table, so a sweep cannot infer it from window_start alone. It exists to make
// reclamation possible: overwrite-in-place only ever reclaims a key that
// recurs, and the keys here include the source address of unauthenticated
// routes, where an attacker rotating addresses never repeats one. Rows are
// therefore pruned by DatabaseRateCounterStore.PruneExpired against the
// expires_at index. This table is sized for churn, not audit retention, unlike
// cfgms_cert_revocations.
func (s DatabaseSchemas) CreateRateCountersTable(ctx context.Context, db *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS cfgms_rate_counters (
			key          TEXT NOT NULL PRIMARY KEY,
			window_start TIMESTAMP WITH TIME ZONE NOT NULL,
			expires_at   TIMESTAMP WITH TIME ZONE NOT NULL,
			count        INTEGER NOT NULL
		);`,
		// Bring a table created before expires_at existed up to the current
		// shape. Every row in it is an ephemeral counter, so pre-existing rows
		// are marked already-expired rather than migrated: the next sweep
		// prunes them and the next Increment for those keys opens a fresh
		// window, which is what an unknown-window row is worth.
		`ALTER TABLE cfgms_rate_counters ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE;`,
		`UPDATE cfgms_rate_counters SET expires_at = window_start WHERE expires_at IS NULL;`,
		`ALTER TABLE cfgms_rate_counters ALTER COLUMN expires_at SET NOT NULL;`,
		// Prune sweeps are a range scan on expires_at; without this index each
		// sweep is a sequential scan of the whole table.
		`CREATE INDEX IF NOT EXISTS idx_cfgms_rate_counters_expires_at ON cfgms_rate_counters (expires_at);`,
	}
	for _, stmt := range statements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to create cfgms_rate_counters table: %w", err)
		}
	}
	return nil
}

// CreateIPTrustRangesTable creates the cfgms_ip_trust_ranges table for tenant-scoped IP trust.
func (s DatabaseSchemas) CreateIPTrustRangesTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cfgms_ip_trust_ranges (
			id              TEXT PRIMARY KEY,
			tenant_id       TEXT NOT NULL,
			cidr            TEXT NOT NULL,
			pre_seeded      BOOLEAN NOT NULL DEFAULT FALSE,
			trusted_since   TIMESTAMP WITH TIME ZONE NOT NULL,
			last_activity   TIMESTAMP WITH TIME ZONE,
			last_activity_ip TEXT,
			revoked         BOOLEAN NOT NULL DEFAULT FALSE,
			revoked_at      TIMESTAMP WITH TIME ZONE,
			UNIQUE(tenant_id, cidr)
		);
	`

	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_ip_trust_ranges table: %w", err)
	}

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_ip_trust_tenant_revoked ON cfgms_ip_trust_ranges(tenant_id, revoked);",
		"CREATE INDEX IF NOT EXISTS idx_ip_trust_tenant_cidr    ON cfgms_ip_trust_ranges(tenant_id, cidr);",
	}

	for _, indexQuery := range indexes {
		if _, err := db.ExecContext(ctx, indexQuery); err != nil {
			return fmt.Errorf("failed to create cfgms_ip_trust_ranges index: %w", err)
		}
	}

	return nil
}

// CreatePendingRegistrationsTable creates the cfgms_pending_registrations table (Issue #1696).
// No cert bundle columns are included — generate-on-claim issues certs in memory only.
// Device identity columns added by Issue #3403 so the claim step can write a complete
// StewardRecord without re-contacting the steward.
func (s DatabaseSchemas) CreatePendingRegistrationsTable(ctx context.Context, db *sql.DB) error {
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cfgms_pending_registrations (
			pending_id           TEXT PRIMARY KEY,
			steward_id           TEXT NOT NULL DEFAULT '',
			tenant_id            TEXT NOT NULL,
			token_str            TEXT NOT NULL,
			source_ip            TEXT NOT NULL DEFAULT '',
			registered_at        TIMESTAMP WITH TIME ZONE NOT NULL,
			expires_at           TIMESTAMP WITH TIME ZONE NOT NULL,
			claimed_at           TIMESTAMP WITH TIME ZONE,
			status               TEXT NOT NULL DEFAULT 'pending',
			device_id            TEXT NOT NULL DEFAULT '',
			identity_key_pub     BYTEA NOT NULL DEFAULT '',
			key_protection_level TEXT NOT NULL DEFAULT '',
			csr_pem              TEXT NOT NULL DEFAULT '',
			hostname             TEXT NOT NULL DEFAULT '',
			platform             TEXT NOT NULL DEFAULT '',
			key_fingerprint      TEXT NOT NULL DEFAULT ''
		);
	`
	if _, err := db.ExecContext(ctx, createTableQuery); err != nil {
		return fmt.Errorf("failed to create cfgms_pending_registrations table: %w", err)
	}

	// Idempotent migrations for existing deployments (Issue #3403; csr_pem added by #3780).
	alterations := []string{
		`ALTER TABLE cfgms_pending_registrations ADD COLUMN IF NOT EXISTS device_id            TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE cfgms_pending_registrations ADD COLUMN IF NOT EXISTS identity_key_pub     BYTEA NOT NULL DEFAULT ''`,
		`ALTER TABLE cfgms_pending_registrations ADD COLUMN IF NOT EXISTS key_protection_level TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE cfgms_pending_registrations ADD COLUMN IF NOT EXISTS csr_pem              TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE cfgms_pending_registrations ADD COLUMN IF NOT EXISTS hostname             TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE cfgms_pending_registrations ADD COLUMN IF NOT EXISTS platform             TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE cfgms_pending_registrations ADD COLUMN IF NOT EXISTS key_fingerprint      TEXT NOT NULL DEFAULT ''`,
	}
	for _, alt := range alterations {
		if _, err := db.ExecContext(ctx, alt); err != nil {
			return fmt.Errorf("failed to apply cfgms_pending_registrations alteration: %w", err)
		}
	}

	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_cfgms_pending_registrations_tenant_id  ON cfgms_pending_registrations(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_pending_registrations_status     ON cfgms_pending_registrations(status);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_pending_registrations_expires_at ON cfgms_pending_registrations(expires_at);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_pending_registrations_token_str  ON cfgms_pending_registrations(token_str);",
	}
	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create cfgms_pending_registrations index: %w", err)
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

	if err := s.CreateAuditChainHeadsTable(ctx, db); err != nil {
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

	if err := s.CreateIPTrustRangesTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateLeaseTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateRoutingTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateScriptRunTables(ctx, db); err != nil {
		return err
	}

	if err := s.CreateExecutionQueueTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateNodeRegistryTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateRefreshPoliciesTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreatePendingRefreshRequestsTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateAssurancePolicyOverridesTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateBlastRadiusPolicyOverridesTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateAlertStatesTable(ctx, db); err != nil {
		return err
	}

	if err := s.CreateWorkflowApprovalsTable(ctx, db); err != nil {
		return err
	}

	return nil
}

// CreateAssurancePolicyOverridesTable creates the assurance_policy_overrides table (Issue #2845).
// Each row holds one per-permission override for a tenant. SetPolicy replaces
// the full set for a tenant transactionally (delete-then-insert).
func (s DatabaseSchemas) CreateAssurancePolicyOverridesTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS assurance_policy_overrides (
			tenant_id             TEXT NOT NULL,
			permission_id         TEXT NOT NULL,
			min_override          INTEGER,
			require_user_presence BOOLEAN NOT NULL DEFAULT FALSE,
			PRIMARY KEY (tenant_id, permission_id)
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create assurance_policy_overrides table: %w", err)
	}
	if _, err := db.ExecContext(ctx,
		"CREATE INDEX IF NOT EXISTS idx_assurance_policy_overrides_tenant_id ON assurance_policy_overrides(tenant_id);",
	); err != nil {
		return fmt.Errorf("failed to create assurance_policy_overrides index: %w", err)
	}
	return nil
}

// CreateBlastRadiusPolicyOverridesTable creates the blast_radius_policy_overrides
// table (Issue #3698). Each row holds one per-tenant MaxTargets override; a
// SetPolicy call upserts the tenant's single row.
func (s DatabaseSchemas) CreateBlastRadiusPolicyOverridesTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS blast_radius_policy_overrides (
			tenant_id   TEXT PRIMARY KEY,
			max_targets INTEGER
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create blast_radius_policy_overrides table: %w", err)
	}
	return nil
}

// CreateTenantCrossingsTable creates the tenant_crossings table (ADR-025 Decision 2:
// client-granted support access and tenant-crossing break-glass elevation).
func (s DatabaseSchemas) CreateTenantCrossingsTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS tenant_crossings (
			id             TEXT PRIMARY KEY,
			tenant_id      TEXT NOT NULL,
			principal_id   TEXT NOT NULL,
			kind           TEXT NOT NULL,
			granted_by     TEXT NOT NULL,
			justification  TEXT NOT NULL DEFAULT '',
			created_at     TIMESTAMPTZ NOT NULL,
			expires_at     TIMESTAMPTZ NOT NULL,
			revoked_at     TIMESTAMPTZ
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create tenant_crossings table: %w", err)
	}
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_tenant_crossings_tenant_id ON tenant_crossings(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_tenant_crossings_active_lookup ON tenant_crossings(principal_id, tenant_id, expires_at, revoked_at);",
	}
	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create tenant_crossings index: %w", err)
		}
	}
	return nil
}

// CreateRefreshPoliciesTable creates the refresh_policies table (Issue #2329).
func (s DatabaseSchemas) CreateRefreshPoliciesTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS refresh_policies (
			tenant_id           TEXT NOT NULL PRIMARY KEY,
			mode                TEXT NOT NULL DEFAULT 'require_approval',
			max_dormancy_days   INTEGER
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create refresh_policies table: %w", err)
	}
	return nil
}

// CreatePendingRefreshRequestsTable creates the pending_refresh_requests table (Issue #2329).
func (s DatabaseSchemas) CreatePendingRefreshRequestsTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS pending_refresh_requests (
			pending_id                  TEXT NOT NULL PRIMARY KEY,
			device_id                   TEXT NOT NULL,
			tenant_id                   TEXT NOT NULL,
			source_ip                   TEXT NOT NULL DEFAULT '',
			provenance_matched_fields   INTEGER NOT NULL DEFAULT 0,
			provenance_total_fields     INTEGER NOT NULL DEFAULT 0,
			claim_bundle                BYTEA NOT NULL DEFAULT ''::bytea,
			csr_pem                     TEXT NOT NULL DEFAULT '',
			status                      TEXT NOT NULL DEFAULT 'pending',
			created_at                  TIMESTAMP WITH TIME ZONE NOT NULL,
			expires_at                  TIMESTAMP WITH TIME ZONE NOT NULL,
			resolved_at                 TIMESTAMP WITH TIME ZONE
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create pending_refresh_requests table: %w", err)
	}
	// Idempotent migration for existing deployments (Issue #3781).
	if _, err := db.ExecContext(ctx,
		`ALTER TABLE pending_refresh_requests ADD COLUMN IF NOT EXISTS csr_pem TEXT NOT NULL DEFAULT ''`,
	); err != nil {
		return fmt.Errorf("failed to backfill pending_refresh_requests csr_pem column: %w", err)
	}
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_pending_refresh_tenant_id  ON pending_refresh_requests(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_pending_refresh_status     ON pending_refresh_requests(status);",
		"CREATE INDEX IF NOT EXISTS idx_pending_refresh_expires_at ON pending_refresh_requests(expires_at);",
	}
	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create pending_refresh_requests index: %w", err)
		}
	}
	return nil
}

// CreateRefreshNoncesTable creates the refresh_nonces table backing the durable
// NonceStore (Issue #3755, ADR-031 amendment to ADR-011). Each row is a
// single-use registration-refresh challenge nonce; GetAndConsumeNonce deletes
// the row it reads via DELETE ... RETURNING, which is atomic across concurrent
// readers on different controller nodes.
func (s DatabaseSchemas) CreateRefreshNoncesTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS refresh_nonces (
			key        TEXT NOT NULL PRIMARY KEY,
			entry      BYTEA NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create refresh_nonces table: %w", err)
	}
	if _, err := db.ExecContext(ctx,
		"CREATE INDEX IF NOT EXISTS idx_refresh_nonces_expires_at ON refresh_nonces(expires_at);",
	); err != nil {
		return fmt.Errorf("failed to create refresh_nonces index: %w", err)
	}
	return nil
}

// CreateSessionsTable creates the sessions table with HMAC-hashed token column and RLS.
func (s DatabaseSchemas) CreateSessionsTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS sessions (
			session_id_hash  TEXT NOT NULL PRIMARY KEY,
			user_id          TEXT NOT NULL,
			tenant_id        TEXT NOT NULL,
			session_type     TEXT NOT NULL,
			created_at       TIMESTAMP WITH TIME ZONE NOT NULL,
			last_activity    TIMESTAMP WITH TIME ZONE NOT NULL,
			expires_at       TIMESTAMP WITH TIME ZONE NOT NULL,
			status           TEXT NOT NULL,
			persistent       BOOLEAN NOT NULL DEFAULT TRUE,
			client_info      JSONB NOT NULL DEFAULT '{}',
			metadata         JSONB NOT NULL DEFAULT '{}',
			session_data     JSONB NOT NULL DEFAULT '{}',
			security_context JSONB NOT NULL DEFAULT '{}',
			compliance_flags JSONB NOT NULL DEFAULT '[]',
			created_by       TEXT NOT NULL DEFAULT '',
			modified_at      TIMESTAMP WITH TIME ZONE,
			modified_by      TEXT NOT NULL DEFAULT ''
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create sessions table: %w", err)
	}
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id    ON sessions(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_sessions_user_id      ON sessions(user_id);",
		"CREATE INDEX IF NOT EXISTS idx_sessions_status       ON sessions(status);",
		"CREATE INDEX IF NOT EXISTS idx_sessions_expires_at   ON sessions(expires_at);",
		"CREATE INDEX IF NOT EXISTS idx_sessions_tenant_user  ON sessions(tenant_id, user_id);",
	}
	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create sessions index: %w", err)
		}
	}
	rls := []string{
		`ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE sessions FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS tenant_isolation_policy ON sessions;`,
		`DROP POLICY IF EXISTS rls_read   ON sessions;`,
		`DROP POLICY IF EXISTS rls_write  ON sessions;`,
		`DROP POLICY IF EXISTS rls_update ON sessions;`,
		`DROP POLICY IF EXISTS rls_delete ON sessions;`,
		// SELECT: permissive when no tenant context (auth lookups), filtered when context is set.
		`CREATE POLICY rls_read ON sessions FOR SELECT USING (
			coalesce(current_setting('app.current_tenant', true), '') = ''
			OR tenant_id = current_setting('app.current_tenant', true)
		);`,
		// INSERT: tenant must be set in the transaction before inserting.
		`CREATE POLICY rls_write ON sessions FOR INSERT WITH CHECK (
			tenant_id = current_setting('app.current_tenant', true)
		);`,
		// UPDATE/DELETE (Issue #4321): the target row must belong to the caller's
		// current tenant, and an UPDATE may not move a row to a different tenant --
		// an unset tenant matches nothing (fail closed), not every row.
		`CREATE POLICY rls_update ON sessions FOR UPDATE
			USING (tenant_id = current_setting('app.current_tenant', true))
			WITH CHECK (tenant_id = current_setting('app.current_tenant', true));`,
		`CREATE POLICY rls_delete ON sessions FOR DELETE
			USING (tenant_id = current_setting('app.current_tenant', true));`,
	}
	for _, stmt := range rls {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to configure sessions RLS: %w", err)
		}
	}
	return nil
}

// CreateStewardRecordsTable creates the steward_records table with RLS.
func (s DatabaseSchemas) CreateStewardRecordsTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS steward_records (
			id                   TEXT NOT NULL PRIMARY KEY,
			tenant_id            TEXT NOT NULL,
			hostname             TEXT NOT NULL DEFAULT '',
			platform             TEXT NOT NULL DEFAULT '',
			arch                 TEXT NOT NULL DEFAULT '',
			version              TEXT NOT NULL DEFAULT '',
			ip_address           TEXT NOT NULL DEFAULT '',
			status               TEXT NOT NULL,
			registered_at        TIMESTAMP WITH TIME ZONE NOT NULL,
			last_seen            TIMESTAMP WITH TIME ZONE NOT NULL,
			last_heartbeat_at    TIMESTAMP WITH TIME ZONE,
			device_id            TEXT NOT NULL DEFAULT '',
			identity_key_pub     BYTEA,
			key_protection_level TEXT NOT NULL DEFAULT '',
			last_provenance_json TEXT NOT NULL DEFAULT '',
			hidden               BOOLEAN NOT NULL DEFAULT FALSE
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create steward_records table: %w", err)
	}
	if _, err := db.ExecContext(ctx,
		`ALTER TABLE steward_records ADD COLUMN IF NOT EXISTS hidden BOOLEAN NOT NULL DEFAULT FALSE;`,
	); err != nil {
		return fmt.Errorf("failed to add hidden column to steward_records: %w", err)
	}
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_steward_records_tenant_id   ON steward_records(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_steward_records_status      ON steward_records(status);",
		"CREATE INDEX IF NOT EXISTS idx_steward_records_device_id   ON steward_records(device_id);",
		// Issue #3403: the plain index above does not stop two stewards in one tenant
		// claiming the same device_id concurrently — the check-then-act guard in
		// handlers_registration.go can be passed by both callers before either commits.
		// This partial unique index is the backstop that makes the winner deterministic.
		// device_id is NOT NULL DEFAULT '' and empty means "not asserted", so rows with
		// no device_id are excluded rather than colliding with each other.
		// Issue #4534: a deregistered (decommissioned) record no longer reserves its
		// device_id, so the machine can enroll again; it keeps the device_id for
		// history matching. Revoked records still reserve it. The index is renamed
		// so existing databases replace the old predicate; the new name keeps the
		// old one as a prefix, which is what RegisterSteward's conflict detection
		// matches on.
		"DROP INDEX IF EXISTS uq_steward_records_tenant_device;",
		"CREATE UNIQUE INDEX IF NOT EXISTS uq_steward_records_tenant_device_active ON steward_records(tenant_id, device_id) WHERE device_id <> '' AND status <> 'deregistered';",
		"CREATE INDEX IF NOT EXISTS idx_steward_records_last_seen   ON steward_records(last_seen);",
	}
	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create steward_records index: %w", err)
		}
	}
	rls := []string{
		`ALTER TABLE steward_records ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE steward_records FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS tenant_isolation_policy ON steward_records;`,
		`DROP POLICY IF EXISTS rls_read   ON steward_records;`,
		`DROP POLICY IF EXISTS rls_write  ON steward_records;`,
		`DROP POLICY IF EXISTS rls_update ON steward_records;`,
		`DROP POLICY IF EXISTS rls_delete ON steward_records;`,
		// SELECT: permissive when no tenant context (fleet management), filtered when
		// context is set. The app.tenant_move_target clause exists for
		// UpdateStewardTenant (Issue #4321): an UPDATE whose WHERE reads the row also
		// applies SELECT policies to the NEW row, so a moved row (tenant_id = target)
		// must be visible or Postgres rejects it with "new row violates row-level
		// security policy". The clause admits exactly one extra tenant, the one the
		// transaction named as its move target -- no wider than setting
		// app.current_tenant to that tenant, which any session can already do.
		`CREATE POLICY rls_read ON steward_records FOR SELECT USING (
			coalesce(current_setting('app.current_tenant', true), '') = ''
			OR tenant_id = current_setting('app.current_tenant', true)
			OR (coalesce(current_setting('app.tenant_move_target', true), '') <> ''
				AND tenant_id = current_setting('app.tenant_move_target', true))
		);`,
		// INSERT: tenant must be set in the transaction before inserting.
		`CREATE POLICY rls_write ON steward_records FOR INSERT WITH CHECK (
			tenant_id = current_setting('app.current_tenant', true)
		);`,
		// UPDATE (Issue #4321): the target row must belong to the caller's current
		// tenant -- an unset tenant matches nothing (fail closed), not every row.
		// WITH CHECK allows a row to keep its own tenant, OR to move to exactly the
		// tenant named by the transaction-local app.tenant_move_target -- not to any
		// other tenant. That GUC is set by exactly one caller, UpdateStewardTenant
		// (steward_store.go) -- a real product feature that moves a steward to a
		// different tenant, gated at the Go/API layer (handlers_stewards.go's
		// handleMoveSteward requires a root caller or a scoped admin whose scope
		// covers both tenants). USING and a plain tenant-scoped WITH CHECK read the
		// same current_setting('app.current_tenant') value within one statement, so
		// without a named target a tenant-scoped WITH CHECK would make that move
		// impossible for any caller; a bare raw-SQL session that never names a
		// target still cannot move a row cross-tenant. See
		// TestRLSWritePolicy_StewardRecordsTenantMove_IntentionallyAllowed,
		// TestRLSWritePolicy_StewardRecordsTenantMove_UnauthorizedRefused and
		// TestRLSWritePolicy_StewardRecordsTenantMove_NonTargetTenantRefused.
		`CREATE POLICY rls_update ON steward_records FOR UPDATE
			USING (tenant_id = current_setting('app.current_tenant', true))
			WITH CHECK (
				tenant_id = current_setting('app.current_tenant', true)
				OR (coalesce(current_setting('app.tenant_move_target', true), '') <> ''
					AND tenant_id = current_setting('app.tenant_move_target', true))
			);`,
		`CREATE POLICY rls_delete ON steward_records FOR DELETE
			USING (tenant_id = current_setting('app.current_tenant', true));`,
	}
	for _, stmt := range rls {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to configure steward_records RLS: %w", err)
		}
	}
	return nil
}

// CreateCommandRecordsTable creates the command_records table with RLS.
func (s DatabaseSchemas) CreateCommandRecordsTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS command_records (
			id            TEXT NOT NULL PRIMARY KEY,
			type          TEXT NOT NULL,
			steward_id    TEXT NOT NULL,
			tenant_id     TEXT NOT NULL,
			payload       JSONB NOT NULL DEFAULT '{}',
			status        TEXT NOT NULL,
			issued_at     TIMESTAMP WITH TIME ZONE NOT NULL,
			started_at    TIMESTAMP WITH TIME ZONE,
			completed_at  TIMESTAMP WITH TIME ZONE,
			result        JSONB NOT NULL DEFAULT '{}',
			error_message TEXT NOT NULL DEFAULT '',
			issued_by     TEXT NOT NULL DEFAULT '',
			delivery_status TEXT NOT NULL DEFAULT 'pending',
			delivery_detail TEXT NOT NULL DEFAULT ''
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create command_records table: %w", err)
	}
	// CREATE TABLE IF NOT EXISTS leaves a pre-#3757 table without the delivery
	// columns, and idx_command_records_steward_delivery below references one of
	// them. Add them first, or index creation fails and the controller cannot
	// start after upgrading (Issue #4499).
	if err := s.BackfillCommandRecordsDeliveryStatus(ctx, db); err != nil {
		return err
	}
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_command_records_tenant_id  ON command_records(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_command_records_steward_id ON command_records(steward_id);",
		"CREATE INDEX IF NOT EXISTS idx_command_records_status     ON command_records(status);",
		"CREATE INDEX IF NOT EXISTS idx_command_records_issued_at  ON command_records(issued_at);",
		// Issue #3757: reconnect-drain lookup (ListPendingDeliveries) filters by
		// steward_id + delivery_status together, then narrows the result to the
		// steward's tenant chain (idx_command_records_tenant_id covers that column) —
		// that query cannot rely on rls_read below, which is permissive when
		// app.current_tenant is unset, as it is on this read path.
		"CREATE INDEX IF NOT EXISTS idx_command_records_steward_delivery ON command_records(steward_id, delivery_status);",
	}
	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create command_records index: %w", err)
		}
	}
	rls := []string{
		`ALTER TABLE command_records ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE command_records FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS tenant_isolation_policy ON command_records;`,
		`DROP POLICY IF EXISTS rls_read   ON command_records;`,
		`DROP POLICY IF EXISTS rls_write  ON command_records;`,
		`DROP POLICY IF EXISTS rls_update ON command_records;`,
		`DROP POLICY IF EXISTS rls_delete ON command_records;`,
		// SELECT: permissive when no tenant context, filtered when context is set.
		`CREATE POLICY rls_read ON command_records FOR SELECT USING (
			coalesce(current_setting('app.current_tenant', true), '') = ''
			OR tenant_id = current_setting('app.current_tenant', true)
		);`,
		// INSERT: tenant must be set in the transaction before inserting.
		`CREATE POLICY rls_write ON command_records FOR INSERT WITH CHECK (
			tenant_id = current_setting('app.current_tenant', true)
		);`,
		// UPDATE/DELETE (Issue #4321): the target row must belong to the caller's
		// current tenant, and an UPDATE may not move a row to a different tenant --
		// an unset tenant matches nothing (fail closed), not every row.
		`CREATE POLICY rls_update ON command_records FOR UPDATE
			USING (tenant_id = current_setting('app.current_tenant', true))
			WITH CHECK (tenant_id = current_setting('app.current_tenant', true));`,
		`CREATE POLICY rls_delete ON command_records FOR DELETE
			USING (tenant_id = current_setting('app.current_tenant', true));`,
	}
	for _, stmt := range rls {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to configure command_records RLS: %w", err)
		}
	}
	return nil
}

// BackfillCommandRecordsDeliveryStatus adds the outbox delivery-lifecycle columns
// to a pre-existing command_records table (Issue #3757, ADR-031 Decision 2,
// migration 011). Safe to call on a table that already has these columns —
// ADD COLUMN IF NOT EXISTS is idempotent on Postgres. Pre-existing rows default
// to 'pending': they predate the outbox and were dispatched by the old
// fire-and-forget goroutine, so their actual delivery outcome is unknown: pending
// is the conservative choice (a drain will re-attempt rather than silently
// drop them).
func (s DatabaseSchemas) BackfillCommandRecordsDeliveryStatus(ctx context.Context, db *sql.DB) error {
	alters := []string{
		`ALTER TABLE command_records ADD COLUMN IF NOT EXISTS delivery_status TEXT NOT NULL DEFAULT 'pending'`,
		`ALTER TABLE command_records ADD COLUMN IF NOT EXISTS delivery_detail TEXT NOT NULL DEFAULT ''`,
	}
	for _, stmt := range alters {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to back-fill command_records delivery columns: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx,
		"CREATE INDEX IF NOT EXISTS idx_command_records_steward_delivery ON command_records(steward_id, delivery_status);",
	); err != nil {
		return fmt.Errorf("failed to create command_records delivery index: %w", err)
	}
	return nil
}

// CreateCommandTransitionsTable creates the immutable audit trail table.
func (s DatabaseSchemas) CreateCommandTransitionsTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS command_transitions (
			id            BIGSERIAL PRIMARY KEY,
			command_id    TEXT NOT NULL,
			status        TEXT NOT NULL,
			timestamp     TIMESTAMP WITH TIME ZONE NOT NULL,
			error_message TEXT NOT NULL DEFAULT ''
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create command_transitions table: %w", err)
	}
	if _, err := db.ExecContext(ctx,
		"CREATE INDEX IF NOT EXISTS idx_command_transitions_command_id ON command_transitions(command_id);",
	); err != nil {
		return fmt.Errorf("failed to create command_transitions index: %w", err)
	}
	return nil
}

// CreateSessionTokenStoreTable creates the session_token_store table (Issue #2775).
// This backs DatabaseSessionTokenStore (pkg/session.Store), not the business.SessionStore
// that uses the `sessions` table.
//
// Device-continuity columns (Issue #2788) are included in the initial CREATE so that
// fresh deployments get the full schema; the corresponding migration (006) uses
// ADD COLUMN IF NOT EXISTS for rolling upgrades of existing deployments.
func (s DatabaseSchemas) CreateSessionTokenStoreTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS session_token_store (
			token_hash          TEXT NOT NULL PRIMARY KEY,
			session_id          TEXT NOT NULL,
			principal_id        TEXT NOT NULL,
			connection_name     TEXT NOT NULL,
			tenant_id           TEXT NOT NULL,
			issued_at           TIMESTAMP WITH TIME ZONE NOT NULL,
			last_activity       TIMESTAMP WITH TIME ZONE NOT NULL,
			absolute_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			hash_expires_at     TIMESTAMP WITH TIME ZONE,
			assurance           INTEGER NOT NULL DEFAULT 1,
			bound_ip            TEXT    NOT NULL DEFAULT '',
			last_proven_at      TIMESTAMP WITH TIME ZONE,
			credential_id       BYTEA,
			root_scoped         BOOLEAN NOT NULL DEFAULT FALSE,
			channel             TEXT    NOT NULL DEFAULT ''
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create session_token_store table: %w", err)
	}
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_session_token_store_session_id    ON session_token_store(session_id);",
		"CREATE INDEX IF NOT EXISTS idx_session_token_store_tenant_id     ON session_token_store(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_session_token_store_hash_expires  ON session_token_store(hash_expires_at);",
		"CREATE INDEX IF NOT EXISTS idx_session_token_store_abs_expires   ON session_token_store(absolute_expires_at);",
	}
	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create session_token_store index: %w", err)
		}
	}
	rls := []string{
		`ALTER TABLE session_token_store ENABLE ROW LEVEL SECURITY;`,
		`ALTER TABLE session_token_store FORCE ROW LEVEL SECURITY;`,
		`DROP POLICY IF EXISTS rls_read   ON session_token_store;`,
		`DROP POLICY IF EXISTS rls_write  ON session_token_store;`,
		`DROP POLICY IF EXISTS rls_update ON session_token_store;`,
		`DROP POLICY IF EXISTS rls_delete ON session_token_store;`,
		`CREATE POLICY rls_read ON session_token_store FOR SELECT USING (
			coalesce(current_setting('app.current_tenant', true), '') = ''
			OR tenant_id = current_setting('app.current_tenant', true)
		);`,
		`CREATE POLICY rls_write ON session_token_store FOR INSERT WITH CHECK (
			tenant_id = current_setting('app.current_tenant', true)
		);`,
		// UPDATE/DELETE (Issue #4321): the target row must belong to the caller's
		// current tenant, and an UPDATE may not move a row to a different tenant --
		// an unset tenant matches nothing (fail closed), not every row.
		`CREATE POLICY rls_update ON session_token_store FOR UPDATE
			USING (tenant_id = current_setting('app.current_tenant', true))
			WITH CHECK (tenant_id = current_setting('app.current_tenant', true));`,
		`CREATE POLICY rls_delete ON session_token_store FOR DELETE
			USING (tenant_id = current_setting('app.current_tenant', true));`,
	}
	for _, stmt := range rls {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to configure session_token_store RLS: %w", err)
		}
	}
	return nil
}

// BackfillSessionTokenStoreContinuity adds the device-continuity columns to an existing
// session_token_store table (Issue #2788, migration 006). Safe to call on a table that
// already has these columns — ADD COLUMN IF NOT EXISTS is idempotent on Postgres.
func (s DatabaseSchemas) BackfillSessionTokenStoreContinuity(ctx context.Context, db *sql.DB) error {
	alters := []string{
		`ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS assurance      INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS bound_ip       TEXT    NOT NULL DEFAULT ''`,
		`ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS last_proven_at TIMESTAMP WITH TIME ZONE`,
		`ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS credential_id  BYTEA`,
		`ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS root_scoped    BOOLEAN NOT NULL DEFAULT FALSE`,
		`ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS channel        TEXT    NOT NULL DEFAULT ''`,
	}
	for _, stmt := range alters {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to backfill session_token_store continuity columns: %w", err)
		}
	}
	return nil
}

// DropAllTables drops all tables (for testing or clean reinstall)
func (s DatabaseSchemas) DropAllTables(ctx context.Context, db *sql.DB) error {
	// Drop in reverse dependency order (foreign keys need to be dropped first)
	dropQueries := []string{
		"DROP MATERIALIZED VIEW IF EXISTS audit_stats;",
		"DROP TABLE IF EXISTS storage_health;",
		"DROP TABLE IF EXISTS audit_chain_heads;",
		"DROP TABLE IF EXISTS audit_entries;",
		"DROP TABLE IF EXISTS config_history;",
		"DROP TABLE IF EXISTS configs;",
		"DROP TABLE IF EXISTS admin_consent_requests;",
		"DROP TABLE IF EXISTS client_tenants;",
		"DROP TABLE IF EXISTS cfgms_registration_tokens;",
		"DROP TABLE IF EXISTS cfgms_registration_token_claims;",
		"DROP TABLE IF EXISTS cfgms_ip_trust_ranges;",
		"DROP TABLE IF EXISTS cfgms_leases;",
		"DROP TABLE IF EXISTS cfgms_routing;",
		"DROP TABLE IF EXISTS cfgms_execution_queue;",
		"DROP TABLE IF EXISTS execution_grants;",
		"DROP TABLE IF EXISTS script_run_jobs;",
		"DROP TABLE IF EXISTS script_runs;",
		"DROP TABLE IF EXISTS cfgms_node_registry;",
		"DROP TABLE IF EXISTS rbac_role_assignments;", // Has foreign keys to subjects and roles
		"DROP TABLE IF EXISTS rbac_subjects;",
		"DROP TABLE IF EXISTS rbac_roles;", // Has self-reference foreign key
		"DROP TABLE IF EXISTS rbac_permissions;",
		"DROP TABLE IF EXISTS assurance_policy_overrides;",
		"DROP TABLE IF EXISTS pending_refresh_requests;",
		"DROP TABLE IF EXISTS refresh_policies;",
		"DROP TABLE IF EXISTS command_transitions;",
		"DROP TABLE IF EXISTS command_records;",
		"DROP TABLE IF EXISTS steward_records;",
		"DROP TABLE IF EXISTS sessions;",
		"DROP TABLE IF EXISTS session_token_store;",
		"DROP TABLE IF EXISTS cfgms_alert_states;",
		"DROP TABLE IF EXISTS cfgms_workflow_approvals;",
		// Issue #3401: omitted here, so pending-registration rows survived
		// setupTestDatabase and every re-run of the store's tests failed with
		// "already exists" on the second and later runs.
		"DROP TABLE IF EXISTS cfgms_pending_registrations;",
		// Issue #3402: trigger and push records must be cleaned up between test runs.
		"DROP TABLE IF EXISTS cfgms_triggers;",
		"DROP TABLE IF EXISTS cfgms_push_records;",
		"DROP TABLE IF EXISTS case_content;",
		"DROP TABLE IF EXISTS case_pins;",
		"DROP TABLE IF EXISTS cases;",
		"DROP TABLE IF EXISTS refresh_nonces;",
		"DROP TABLE IF EXISTS cfgms_cert_revocations;",
		"DROP TABLE IF EXISTS cfgms_signing_cursor;",
		"DROP TABLE IF EXISTS cfgms_module_approvals;",
		"DROP TABLE IF EXISTS cfgms_rate_counters;",
	}

	for _, query := range dropQueries {
		if _, err := db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("failed to drop table: %w", err)
		}
	}

	return nil
}

// CreateTriggersTable creates the cfgms_triggers table for durable workflow trigger persistence (Issue #3402).
func (s DatabaseSchemas) CreateTriggersTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS cfgms_triggers (
			id                 TEXT NOT NULL PRIMARY KEY,
			tenant_id          TEXT NOT NULL,
			name               TEXT NOT NULL DEFAULT '',
			type               TEXT NOT NULL DEFAULT '',
			status             TEXT NOT NULL DEFAULT '',
			workflow_name      TEXT NOT NULL DEFAULT '',
			created_at         TIMESTAMPTZ NOT NULL,
			updated_at         TIMESTAMPTZ NOT NULL,
			webhook_path       TEXT NOT NULL DEFAULT '',
			webhook_method     JSONB NOT NULL DEFAULT '[]',
			bearer_token_ref   TEXT,
			hmac_secret_ref    TEXT,
			apikey_ref         TEXT,
			basic_username_ref TEXT,
			basic_password_ref TEXT,
			config_payload     BYTEA
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create cfgms_triggers table: %w", err)
	}
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_cfgms_triggers_tenant_id  ON cfgms_triggers(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_triggers_status     ON cfgms_triggers(status);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_triggers_type       ON cfgms_triggers(type);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_triggers_created_at ON cfgms_triggers(created_at DESC);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_triggers_tenant_status ON cfgms_triggers(tenant_id, status);",
	}
	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create cfgms_triggers index: %w", err)
		}
	}
	return nil
}

// CreatePushRecordsTable creates the cfgms_push_records table for durable push-state persistence (Issue #3402).
// A new leader reads this table to resume pending and in-progress pushes after failover.
func (s DatabaseSchemas) CreatePushRecordsTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS cfgms_push_records (
			id           TEXT NOT NULL PRIMARY KEY,
			config_id    TEXT NOT NULL DEFAULT '',
			tenant_id    TEXT NOT NULL,
			version      TEXT NOT NULL DEFAULT '',
			status       TEXT NOT NULL DEFAULT 'pending',
			initiated_by TEXT NOT NULL DEFAULT '',
			data         BYTEA,
			created_at   TIMESTAMPTZ NOT NULL,
			updated_at   TIMESTAMPTZ NOT NULL
		);`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create cfgms_push_records table: %w", err)
	}
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_cfgms_push_records_tenant_id  ON cfgms_push_records(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_push_records_status     ON cfgms_push_records(status);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_push_records_config_id  ON cfgms_push_records(config_id);",
		"CREATE INDEX IF NOT EXISTS idx_cfgms_push_records_created_at ON cfgms_push_records(created_at ASC);",
		// Composite index optimises both GetPendingPushes (status filter) and
		// ListPushesByConfigID (config_id + tenant_id filter).
		"CREATE INDEX IF NOT EXISTS idx_cfgms_push_records_config_tenant ON cfgms_push_records(config_id, tenant_id);",
	}
	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create cfgms_push_records index: %w", err)
		}
	}
	return nil
}

// CreateAlertStatesTable creates the cfgms_alert_states table for tenant-scoped alert state.
func (s DatabaseSchemas) CreateAlertStatesTable(ctx context.Context, db *sql.DB) error {
	ddl := `
		CREATE TABLE IF NOT EXISTS cfgms_alert_states (
			id              TEXT PRIMARY KEY,
			tenant_id       TEXT NOT NULL,
			alert_id        TEXT NOT NULL,
			acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,
			acknowledged_by TEXT NOT NULL DEFAULT '',
			acknowledged_at TIMESTAMPTZ,
			silenced        BOOLEAN NOT NULL DEFAULT FALSE,
			silenced_by     TEXT NOT NULL DEFAULT '',
			silenced_until  TIMESTAMPTZ,
			UNIQUE(tenant_id, alert_id)
		);
	`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("failed to create cfgms_alert_states table: %w", err)
	}
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_alert_states_tenant_id ON cfgms_alert_states(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_alert_states_tenant_alert ON cfgms_alert_states(tenant_id, alert_id);",
	}
	for _, idx := range indexes {
		if _, err := db.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("failed to create cfgms_alert_states index: %w", err)
		}
	}
	return nil
}

// CreateWorkflowApprovalsTable creates the cfgms_workflow_approvals table backing
// business.ApprovalStore (Issue #4607). Rows are keyed by (tenant_id, approval_id)
// and visible to every controller node. checkpoint_ref is a reference into the
// secrets provider; checkpoint contents are never stored here. The partial indexes
// serve the pending-list, expiry sweep and resume-recovery queries.
func (s DatabaseSchemas) CreateWorkflowApprovalsTable(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS cfgms_workflow_approvals (
			tenant_id           TEXT NOT NULL,
			approval_id         TEXT NOT NULL,
			workflow_name       TEXT NOT NULL DEFAULT '',
			execution_id        TEXT NOT NULL DEFAULT '',
			step_id             TEXT NOT NULL DEFAULT '',
			step_name           TEXT NOT NULL DEFAULT '',
			message             TEXT NOT NULL DEFAULT '',
			approver_permission TEXT NOT NULL DEFAULT '',
			requested_by        TEXT NOT NULL DEFAULT '',
			status              TEXT NOT NULL DEFAULT 'pending',
			requested_at        TIMESTAMP WITH TIME ZONE NOT NULL,
			expires_at          TIMESTAMP WITH TIME ZONE,
			decided_by          TEXT NOT NULL DEFAULT '',
			decided_at          TIMESTAMP WITH TIME ZONE,
			justification       TEXT NOT NULL DEFAULT '',
			checkpoint_ref      TEXT NOT NULL DEFAULT '',
			resume_claimed_by   TEXT NOT NULL DEFAULT '',
			resume_claimed_at   TIMESTAMP WITH TIME ZONE,
			resumed_at          TIMESTAMP WITH TIME ZONE,
			PRIMARY KEY (tenant_id, approval_id)
		);`,
		"CREATE INDEX IF NOT EXISTS idx_workflow_approvals_pending ON cfgms_workflow_approvals(tenant_id, requested_at) WHERE status = 'pending';",
		"CREATE INDEX IF NOT EXISTS idx_workflow_approvals_expiry ON cfgms_workflow_approvals(expires_at) WHERE status = 'pending' AND expires_at IS NOT NULL;",
		"CREATE INDEX IF NOT EXISTS idx_workflow_approvals_unresumed ON cfgms_workflow_approvals(status) WHERE resumed_at IS NULL AND status IN ('approved', 'rejected');",
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("failed to create cfgms_workflow_approvals table: %w", err)
		}
	}
	return nil
}

// CreateCaseTables creates the three tables backing CaseStore: cases, case_pins,
// and case_content (ADR-022 §8, Issue #3602).
func (s DatabaseSchemas) CreateCaseTables(ctx context.Context, db *sql.DB) error {
	ddls := []string{
		`CREATE TABLE IF NOT EXISTS cases (
			id          TEXT PRIMARY KEY,
			tenant_id   TEXT NOT NULL,
			status      TEXT NOT NULL DEFAULT 'open',
			ticket_json TEXT NOT NULL DEFAULT '{}',
			version     BIGINT NOT NULL DEFAULT 1,
			created_at  TIMESTAMPTZ NOT NULL,
			updated_at  TIMESTAMPTZ NOT NULL
		);`,
		// Issue #3895: version column for UpdateCaseCAS. ADD COLUMN IF NOT EXISTS
		// covers deployments whose cases table predates this column.
		`ALTER TABLE cases ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 1;`,
		`CREATE INDEX IF NOT EXISTS idx_cases_tenant_id ON cases(tenant_id);`,
		`CREATE INDEX IF NOT EXISTS idx_cases_status    ON cases(status);`,

		`CREATE TABLE IF NOT EXISTS case_pins (
			id                 TEXT PRIMARY KEY,
			case_id            TEXT NOT NULL,
			ref_kind           TEXT NOT NULL,
			ref_eid            TEXT NOT NULL DEFAULT '',
			ref_edge_identity  TEXT NOT NULL DEFAULT '',
			ref_obs_version    TEXT NOT NULL DEFAULT '',
			ref_drift_record   TEXT NOT NULL DEFAULT '',
			ref_subject        TEXT NOT NULL DEFAULT '',
			ref_range_start    TIMESTAMPTZ,
			ref_range_end      TIMESTAMPTZ,
			annotation         TEXT NOT NULL DEFAULT '',
			author             TEXT NOT NULL DEFAULT '',
			pinned_at          TIMESTAMPTZ NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_case_pins_case_id ON case_pins(case_id);`,

		`CREATE TABLE IF NOT EXISTS case_content (
			id         TEXT PRIMARY KEY,
			case_id    TEXT NOT NULL,
			kind       TEXT NOT NULL,
			body       TEXT NOT NULL DEFAULT '',
			author     TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_case_content_case_id ON case_content(case_id);`,
	}
	for _, ddl := range ddls {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("failed to create case tables: %w", err)
		}
	}
	return nil
}
