// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite provides schema management for the SQLite storage provider
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
)

const currentSchemaVersion = 1

// initializeSchema creates all tables and tracks schema version.
// It is safe to call multiple times (all statements use IF NOT EXISTS).
func initializeSchema(ctx context.Context, db *sql.DB) error {
	statements := []string{
		// Schema version tracking
		`CREATE TABLE IF NOT EXISTS schema_version (
			id       INTEGER PRIMARY KEY,
			version  INTEGER NOT NULL,
			applied_at TEXT NOT NULL
		)`,

		// Tenants
		`CREATE TABLE IF NOT EXISTS tenants (
			id          TEXT PRIMARY KEY,
			name        TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			parent_id   TEXT,
			metadata    TEXT NOT NULL DEFAULT '{}',
			status      TEXT NOT NULL DEFAULT 'active',
			created_at  TEXT NOT NULL,
			updated_at  TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tenants_parent_id  ON tenants(parent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tenants_status      ON tenants(status)`,
		`CREATE INDEX IF NOT EXISTS idx_tenants_name        ON tenants(name)`,

		// Client tenants (with M365 extension columns per ADR-003 §2)
		`CREATE TABLE IF NOT EXISTS client_tenants (
			id                TEXT PRIMARY KEY,
			tenant_id         TEXT UNIQUE NOT NULL,
			tenant_name       TEXT NOT NULL,
			domain_name       TEXT NOT NULL,
			admin_email       TEXT NOT NULL,
			consented_at      TEXT NOT NULL,
			status            TEXT NOT NULL DEFAULT 'pending',
			client_identifier TEXT NOT NULL,
			metadata          TEXT NOT NULL DEFAULT '{}',
			m365_tenant_id    TEXT,
			m365_admin_email  TEXT,
			m365_consented_at TEXT,
			m365_status       TEXT,
			created_at        TEXT NOT NULL,
			updated_at        TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_client_tenants_client_identifier ON client_tenants(client_identifier)`,
		`CREATE INDEX IF NOT EXISTS idx_client_tenants_status            ON client_tenants(status)`,

		// Admin consent requests
		`CREATE TABLE IF NOT EXISTS admin_consent_requests (
			state             TEXT PRIMARY KEY,
			client_identifier TEXT NOT NULL,
			client_name       TEXT NOT NULL,
			requested_by      TEXT NOT NULL,
			expires_at        TEXT NOT NULL,
			created_at        TEXT NOT NULL,
			metadata          TEXT NOT NULL DEFAULT '{}'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_consent_requests_client_identifier ON admin_consent_requests(client_identifier)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_consent_requests_expires_at        ON admin_consent_requests(expires_at)`,

		// Audit entries (append-only, no UPDATE/DELETE)
		`CREATE TABLE IF NOT EXISTS audit_entries (
			id            TEXT PRIMARY KEY,
			tenant_id     TEXT NOT NULL,
			timestamp     TEXT NOT NULL,
			event_type    TEXT NOT NULL,
			action        TEXT NOT NULL,
			user_id       TEXT NOT NULL,
			user_type     TEXT NOT NULL,
			session_id    TEXT NOT NULL DEFAULT '',
			resource_type TEXT NOT NULL,
			resource_id   TEXT NOT NULL,
			resource_name TEXT NOT NULL DEFAULT '',
			result        TEXT NOT NULL,
			error_code    TEXT NOT NULL DEFAULT '',
			error_message TEXT NOT NULL DEFAULT '',
			request_id    TEXT NOT NULL DEFAULT '',
			ip_address    TEXT NOT NULL DEFAULT '',
			user_agent    TEXT NOT NULL DEFAULT '',
			method        TEXT NOT NULL DEFAULT '',
			path          TEXT NOT NULL DEFAULT '',
			details       TEXT NOT NULL DEFAULT '{}',
			changes       TEXT NOT NULL DEFAULT '{}',
			tags          TEXT NOT NULL DEFAULT '[]',
			severity      TEXT NOT NULL,
			source        TEXT NOT NULL,
			version       TEXT NOT NULL DEFAULT '',
			checksum      TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_tenant_id    ON audit_entries(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_timestamp    ON audit_entries(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_user_id      ON audit_entries(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_event_type   ON audit_entries(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_result       ON audit_entries(result)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_severity     ON audit_entries(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_resource_id  ON audit_entries(resource_id)`,

		// RBAC permissions
		`CREATE TABLE IF NOT EXISTS rbac_permissions (
			id            TEXT PRIMARY KEY,
			name          TEXT NOT NULL,
			description   TEXT NOT NULL DEFAULT '',
			resource_type TEXT NOT NULL,
			actions       TEXT NOT NULL DEFAULT '[]',
			created_at    TEXT NOT NULL,
			updated_at    TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_rbac_permissions_resource_type ON rbac_permissions(resource_type)`,

		// RBAC roles
		`CREATE TABLE IF NOT EXISTS rbac_roles (
			id               TEXT PRIMARY KEY,
			name             TEXT NOT NULL,
			description      TEXT NOT NULL DEFAULT '',
			permission_ids   TEXT NOT NULL DEFAULT '[]',
			is_system_role   INTEGER NOT NULL DEFAULT 0,
			tenant_id        TEXT NOT NULL DEFAULT '',
			parent_role_id   TEXT NOT NULL DEFAULT '',
			child_role_ids   TEXT NOT NULL DEFAULT '[]',
			inheritance_type INTEGER NOT NULL DEFAULT 0,
			created_at       INTEGER NOT NULL DEFAULT 0,
			updated_at       INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_rbac_roles_tenant_id      ON rbac_roles(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_rbac_roles_is_system_role  ON rbac_roles(is_system_role)`,

		// RBAC subjects
		`CREATE TABLE IF NOT EXISTS rbac_subjects (
			id           TEXT PRIMARY KEY,
			type         INTEGER NOT NULL DEFAULT 0,
			display_name TEXT NOT NULL,
			tenant_id    TEXT NOT NULL,
			role_ids     TEXT NOT NULL DEFAULT '[]',
			attributes   TEXT NOT NULL DEFAULT '{}',
			is_active    INTEGER NOT NULL DEFAULT 1,
			created_at   INTEGER NOT NULL DEFAULT 0,
			updated_at   INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_rbac_subjects_tenant_id ON rbac_subjects(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_rbac_subjects_type      ON rbac_subjects(type)`,

		// RBAC role assignments
		`CREATE TABLE IF NOT EXISTS rbac_role_assignments (
			id          TEXT PRIMARY KEY,
			subject_id  TEXT NOT NULL,
			role_id     TEXT NOT NULL,
			tenant_id   TEXT NOT NULL,
			conditions  TEXT NOT NULL DEFAULT '[]',
			expires_at  INTEGER,
			assigned_at INTEGER NOT NULL DEFAULT 0,
			assigned_by TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_rbac_role_assignments_subject_id ON rbac_role_assignments(subject_id)`,
		`CREATE INDEX IF NOT EXISTS idx_rbac_role_assignments_role_id    ON rbac_role_assignments(role_id)`,
		`CREATE INDEX IF NOT EXISTS idx_rbac_role_assignments_tenant_id  ON rbac_role_assignments(tenant_id)`,

		// Registration tokens
		`CREATE TABLE IF NOT EXISTS registration_tokens (
			token          TEXT PRIMARY KEY,
			tenant_id      TEXT NOT NULL,
			controller_url TEXT NOT NULL,
			group_name     TEXT NOT NULL DEFAULT '',
			created_at     TEXT NOT NULL,
			expires_at     TEXT,
			single_use     INTEGER NOT NULL DEFAULT 0,
			used_at        TEXT,
			used_by        TEXT NOT NULL DEFAULT '',
			revoked        INTEGER NOT NULL DEFAULT 0,
			revoked_at     TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_registration_tokens_tenant_id  ON registration_tokens(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_registration_tokens_group_name ON registration_tokens(group_name)`,

		// Durable sessions (Persistent=true only)
		`CREATE TABLE IF NOT EXISTS sessions (
			session_id       TEXT PRIMARY KEY,
			user_id          TEXT NOT NULL,
			tenant_id        TEXT NOT NULL,
			session_type     TEXT NOT NULL,
			created_at       TEXT NOT NULL,
			last_activity    TEXT NOT NULL,
			expires_at       TEXT NOT NULL,
			status           TEXT NOT NULL DEFAULT 'active',
			persistent       INTEGER NOT NULL DEFAULT 1,
			client_info      TEXT NOT NULL DEFAULT '{}',
			metadata         TEXT NOT NULL DEFAULT '{}',
			session_data     TEXT NOT NULL DEFAULT '{}',
			security_context TEXT NOT NULL DEFAULT '{}',
			compliance_flags TEXT NOT NULL DEFAULT '[]',
			created_by       TEXT NOT NULL DEFAULT '',
			modified_at      TEXT,
			modified_by      TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id      ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id    ON sessions(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_session_type ON sessions(session_type)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_status       ON sessions(status)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at   ON sessions(expires_at)`,
	}

	for _, stmt := range statements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("schema statement failed: %w\nSQL: %s", err, stmt)
		}
	}

	// Record or verify schema version
	if err := recordSchemaVersion(ctx, db); err != nil {
		return fmt.Errorf("failed to record schema version: %w", err)
	}

	return nil
}

func recordSchemaVersion(ctx context.Context, db *sql.DB) error {
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_version").Scan(&count); err != nil {
		return fmt.Errorf("failed to count schema versions: %w", err)
	}
	if count > 0 {
		return nil // already recorded
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO schema_version (id, version, applied_at) VALUES (1, ?, ?)`,
		currentSchemaVersion, formatTime(nowUTC()),
	)
	return err
}
