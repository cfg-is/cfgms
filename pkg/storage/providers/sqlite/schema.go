// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite provides schema management for the SQLite storage provider
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

const currentSchemaVersion = 2

// tableExists reports whether the named table is present in the SQLite catalog.
func tableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name,
	).Scan(&count)
	return count > 0, err
}

// columnExists reports whether the named column is present in the named table.
// SQLite PRAGMA statements do not support parameter binding, so the caller
// must pass only hard-coded, trusted table/column names — never user input.
func columnExists(ctx context.Context, db *sql.DB, table, column string) (found bool, retErr error) {
	// #nosec G202 -- PRAGMA does not support ? binding; caller passes only literals.
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false, err
	}
	defer func() {
		if err := rows.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var dfltValue sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dfltValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// backfillAuditEntries adds sequence_number and previous_checksum to a
// pre-existing audit_entries table that was created without those columns.
// Fresh databases (table absent) are skipped. Column-existence is checked
// via PRAGMA before each ALTER TABLE so the pass is fully idempotent without
// relying on driver-specific error message text.
func backfillAuditEntries(ctx context.Context, db *sql.DB) error {
	exists, err := tableExists(ctx, db, "audit_entries")
	if err != nil {
		return fmt.Errorf("sqlite: back-fill probe failed: %w", err)
	}
	if !exists {
		return nil
	}
	type col struct {
		name string
		ddl  string
	}
	for _, c := range []col{
		{"sequence_number", `ALTER TABLE audit_entries ADD COLUMN sequence_number   INTEGER NOT NULL DEFAULT 0`},
		{"previous_checksum", `ALTER TABLE audit_entries ADD COLUMN previous_checksum TEXT    NOT NULL DEFAULT ''`},
	} {
		present, err := columnExists(ctx, db, "audit_entries", c.name)
		if err != nil {
			return fmt.Errorf("sqlite: back-fill column probe failed (%s): %w", c.name, err)
		}
		if present {
			continue
		}
		if _, err := db.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("sqlite: audit_entries back-fill failed: %w\nSQL: %s", err, c.ddl)
		}
	}
	return nil
}

// backfillStewardColumns adds the four registration-refresh identity columns and
// the tenant_id column to a pre-existing stewards table created without them
// (Issue #2093 ADR-010; Issue #2341 tenant-move). Fresh databases (table absent)
// are skipped. Column-existence is checked via PRAGMA before each ALTER TABLE
// so the pass is fully idempotent.
func backfillStewardColumns(ctx context.Context, db *sql.DB) error {
	exists, err := tableExists(ctx, db, "stewards")
	if err != nil {
		return fmt.Errorf("sqlite: steward back-fill probe failed: %w", err)
	}
	if !exists {
		return nil
	}
	type col struct {
		name string
		ddl  string
	}
	for _, c := range []col{
		{"device_id", `ALTER TABLE stewards ADD COLUMN device_id TEXT NOT NULL DEFAULT ''`},
		{"identity_key_pub", `ALTER TABLE stewards ADD COLUMN identity_key_pub BLOB NOT NULL DEFAULT ''`},
		{"key_protection_level", `ALTER TABLE stewards ADD COLUMN key_protection_level TEXT NOT NULL DEFAULT ''`},
		{"last_provenance_json", `ALTER TABLE stewards ADD COLUMN last_provenance_json TEXT NOT NULL DEFAULT ''`},
		{"tenant_id", `ALTER TABLE stewards ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''`},
		{"hidden", `ALTER TABLE stewards ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0`},
	} {
		present, err := columnExists(ctx, db, "stewards", c.name)
		if err != nil {
			return fmt.Errorf("sqlite: steward back-fill column probe failed (%s): %w", c.name, err)
		}
		if present {
			continue
		}
		if _, err := db.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("sqlite: stewards back-fill failed: %w\nSQL: %s", err, c.ddl)
		}
	}
	return nil
}

// backfillSessionTokenRecords adds the device-continuity columns to a pre-existing
// session_token_records table (Issue #2788). Fresh databases (table absent) are skipped.
// Column-existence is checked via PRAGMA before each ALTER TABLE so the pass is idempotent.
//
// The assurance column defaults to 1 (AssuranceBasic) because every pre-existing row
// in session_token_records belongs to a human session (mTLS admin or web session) —
// API-key principals never write to this table.
func backfillSessionTokenRecords(ctx context.Context, db *sql.DB) error {
	exists, err := tableExists(ctx, db, "session_token_records")
	if err != nil {
		return fmt.Errorf("sqlite: session_token_records back-fill probe failed: %w", err)
	}
	if !exists {
		return nil
	}
	type col struct {
		name string
		ddl  string
	}
	for _, c := range []col{
		{"assurance", `ALTER TABLE session_token_records ADD COLUMN assurance      INTEGER NOT NULL DEFAULT 1`},
		{"bound_ip", `ALTER TABLE session_token_records ADD COLUMN bound_ip       TEXT    NOT NULL DEFAULT ''`},
		{"last_proven_at", `ALTER TABLE session_token_records ADD COLUMN last_proven_at TEXT`},
		{"credential_id", `ALTER TABLE session_token_records ADD COLUMN credential_id  BLOB`},
		{"root_scoped", `ALTER TABLE session_token_records ADD COLUMN root_scoped    INTEGER NOT NULL DEFAULT 0`},
		{"channel", `ALTER TABLE session_token_records ADD COLUMN channel         TEXT    NOT NULL DEFAULT ''`},
	} {
		present, err := columnExists(ctx, db, "session_token_records", c.name)
		if err != nil {
			return fmt.Errorf("sqlite: session_token_records back-fill column probe failed (%s): %w", c.name, err)
		}
		if present {
			continue
		}
		if _, err := db.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("sqlite: session_token_records back-fill failed: %w\nSQL: %s", err, c.ddl)
		}
	}
	return nil
}

// backfillRegistrationTokenID adds the `id` UUID column to a pre-existing
// registration_tokens table and assigns a UUID to every row that lacks one
// (Issue #2970 — stable non-secret identifier for web UI). Fresh databases
// (table absent) are skipped. Without the row back-fill, legacy tokens would
// report an empty token_id forever and could never be revoked or deleted from
// the web UI — exactly the tokens most likely to need revoking.
func backfillRegistrationTokenID(ctx context.Context, db *sql.DB) error {
	exists, err := tableExists(ctx, db, "registration_tokens")
	if err != nil {
		return fmt.Errorf("sqlite: registration_tokens back-fill probe failed: %w", err)
	}
	if !exists {
		return nil
	}
	present, err := columnExists(ctx, db, "registration_tokens", "id")
	if err != nil {
		return fmt.Errorf("sqlite: registration_tokens id-column probe failed: %w", err)
	}
	if !present {
		if _, err := db.ExecContext(ctx, `ALTER TABLE registration_tokens ADD COLUMN id TEXT`); err != nil {
			return fmt.Errorf("sqlite: registration_tokens back-fill (id) failed: %w", err)
		}
	}
	return assignMissingRegistrationTokenIDs(ctx, db)
}

// assignMissingRegistrationTokenIDs gives every registration_tokens row without an id
// a freshly generated UUID. Idempotent: matches no rows once every row has an id.
func assignMissingRegistrationTokenIDs(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx,
		`SELECT token FROM registration_tokens WHERE id IS NULL OR id = ''`)
	if err != nil {
		return fmt.Errorf("sqlite: registration_tokens id back-fill query failed: %w", err)
	}
	var tokensMissingID []string
	for rows.Next() {
		var tokenStr string
		if err := rows.Scan(&tokenStr); err != nil {
			_ = rows.Close()
			return fmt.Errorf("sqlite: registration_tokens id back-fill scan failed: %w", err)
		}
		tokensMissingID = append(tokensMissingID, tokenStr)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("sqlite: registration_tokens id back-fill iteration failed: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("sqlite: registration_tokens id back-fill close failed: %w", err)
	}

	for _, tokenStr := range tokensMissingID {
		id, err := generateTokenID()
		if err != nil {
			return fmt.Errorf("sqlite: registration_tokens id generation failed: %w", err)
		}
		if _, err := db.ExecContext(ctx,
			`UPDATE registration_tokens SET id = ? WHERE token = ?`, id, tokenStr); err != nil {
			return fmt.Errorf("sqlite: registration_tokens id back-fill update failed: %w", err)
		}
	}
	return nil
}

// migrateRegistrationTokenClaimKey rebuilds a registration_token_claims table
// that still carries the original `token TEXT PRIMARY KEY`. That key admitted
// one device per token for the lifetime of the token, which silently reverted
// the perennial token model (Issue #1690) — a fleet token could enrol exactly
// one endpoint. The corrected key is (token, claim_id).
//
// Claims are short-lived in-flight admission guards, so the rows are dropped
// rather than copied: any registration still mid-flight retries, and keeping
// them would preserve the very rows that block re-enrolment.
func migrateRegistrationTokenClaimKey(ctx context.Context, db *sql.DB) error {
	exists, err := tableExists(ctx, db, "registration_token_claims")
	if err != nil {
		return fmt.Errorf("sqlite: registration_token_claims probe failed: %w", err)
	}
	if !exists {
		return nil
	}

	var ddl string
	if err := db.QueryRowContext(ctx,
		`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'registration_token_claims'`,
	).Scan(&ddl); err != nil {
		return fmt.Errorf("sqlite: registration_token_claims DDL probe failed: %w", err)
	}
	if strings.Contains(ddl, "PRIMARY KEY (token, claim_id)") {
		return nil
	}

	if _, err := db.ExecContext(ctx, `DROP TABLE registration_token_claims`); err != nil {
		return fmt.Errorf("sqlite: registration_token_claims migration failed: %w", err)
	}
	return nil
}

// backfillCfgmsPendingRegistrationColumns adds the device-identity columns
// introduced by Issue #3403, plus csr_pem (Issue #3780), to a pre-existing
// cfgms_pending_registrations table that was created before those columns
// existed. Fresh databases (table absent or already carrying all columns) are
// skipped. Column-existence is checked via PRAGMA before each ALTER TABLE so
// the pass is fully idempotent.
func backfillCfgmsPendingRegistrationColumns(ctx context.Context, db *sql.DB) error {
	exists, err := tableExists(ctx, db, "cfgms_pending_registrations")
	if err != nil {
		return fmt.Errorf("sqlite: cfgms_pending_registrations back-fill probe failed: %w", err)
	}
	if !exists {
		return nil
	}
	type col struct {
		name string
		ddl  string
	}
	for _, c := range []col{
		{"device_id", `ALTER TABLE cfgms_pending_registrations ADD COLUMN device_id            TEXT NOT NULL DEFAULT ''`},
		{"identity_key_pub", `ALTER TABLE cfgms_pending_registrations ADD COLUMN identity_key_pub     BLOB NOT NULL DEFAULT ''`},
		{"key_protection_level", `ALTER TABLE cfgms_pending_registrations ADD COLUMN key_protection_level TEXT NOT NULL DEFAULT ''`},
		{"csr_pem", `ALTER TABLE cfgms_pending_registrations ADD COLUMN csr_pem              TEXT NOT NULL DEFAULT ''`},
		{"hostname", `ALTER TABLE cfgms_pending_registrations ADD COLUMN hostname             TEXT NOT NULL DEFAULT ''`},
		{"platform", `ALTER TABLE cfgms_pending_registrations ADD COLUMN platform             TEXT NOT NULL DEFAULT ''`},
	} {
		present, err := columnExists(ctx, db, "cfgms_pending_registrations", c.name)
		if err != nil {
			return fmt.Errorf("sqlite: cfgms_pending_registrations back-fill column probe failed (%s): %w", c.name, err)
		}
		if present {
			continue
		}
		if _, err := db.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("sqlite: cfgms_pending_registrations back-fill failed: %w\nSQL: %s", err, c.ddl)
		}
	}
	return nil
}

// backfillTenantLifecycle adds the ADR-027 Decision 2 suspension provenance
// columns to a pre-existing tenants table that was created without them (migration
// 008). Fresh databases (table absent) are skipped. Column-existence is checked
// via PRAGMA before each ALTER TABLE so the pass is fully idempotent.
func backfillTenantLifecycle(ctx context.Context, db *sql.DB) error {
	exists, err := tableExists(ctx, db, "tenants")
	if err != nil {
		return fmt.Errorf("sqlite: tenant lifecycle back-fill probe failed: %w", err)
	}
	if !exists {
		return nil
	}
	type col struct {
		name string
		ddl  string
	}
	for _, c := range []col{
		{"directly_suspended", `ALTER TABLE tenants ADD COLUMN directly_suspended INTEGER NOT NULL DEFAULT 0`},
		{"cascade_suspended_from", `ALTER TABLE tenants ADD COLUMN cascade_suspended_from TEXT`},
	} {
		present, err := columnExists(ctx, db, "tenants", c.name)
		if err != nil {
			return fmt.Errorf("sqlite: tenant lifecycle back-fill column probe failed (%s): %w", c.name, err)
		}
		if present {
			continue
		}
		if _, err := db.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("sqlite: tenant lifecycle back-fill failed: %w\nSQL: %s", err, c.ddl)
		}
	}
	return nil
}

// backfillCommandDeliveryColumns adds the outbox delivery-lifecycle columns to a
// pre-existing commands table (Issue #3757, ADR-031 Decision 2). Fresh databases
// (table absent) are skipped. Column-existence is checked via PRAGMA before each
// ALTER TABLE so the pass is fully idempotent. Pre-existing rows default to
// 'pending': their actual delivery outcome under the retired fire-and-forget
// goroutine is unknown, so pending is the conservative choice — a drain will
// re-attempt rather than silently treat them as delivered.
func backfillCommandDeliveryColumns(ctx context.Context, db *sql.DB) error {
	exists, err := tableExists(ctx, db, "commands")
	if err != nil {
		return fmt.Errorf("sqlite: command back-fill probe failed: %w", err)
	}
	if !exists {
		return nil
	}
	type col struct {
		name string
		ddl  string
	}
	for _, c := range []col{
		{"delivery_status", `ALTER TABLE commands ADD COLUMN delivery_status TEXT NOT NULL DEFAULT 'pending'`},
		{"delivery_detail", `ALTER TABLE commands ADD COLUMN delivery_detail TEXT NOT NULL DEFAULT ''`},
	} {
		present, err := columnExists(ctx, db, "commands", c.name)
		if err != nil {
			return fmt.Errorf("sqlite: command back-fill column probe failed (%s): %w", c.name, err)
		}
		if present {
			continue
		}
		if _, err := db.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("sqlite: commands back-fill failed: %w\nSQL: %s", err, c.ddl)
		}
	}
	if _, err := db.ExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_commands_steward_delivery ON commands(steward_id, delivery_status)`,
	); err != nil {
		return fmt.Errorf("sqlite: commands delivery index back-fill failed: %w", err)
	}
	return nil
}

// initializeSchema creates all tables and tracks schema version.
// It is safe to call multiple times (all statements use IF NOT EXISTS).
// All DDL statements are executed inside a single transaction to reduce WAL
// write cycles — particularly important on Windows where each individual
// transaction requires a full file-lock round-trip via the WAL SHM mechanism.
func initializeSchema(ctx context.Context, db *sql.DB) error {
	if err := backfillAuditEntries(ctx, db); err != nil {
		return err
	}
	if err := backfillStewardColumns(ctx, db); err != nil {
		return err
	}
	if err := backfillSessionTokenRecords(ctx, db); err != nil {
		return err
	}
	if err := migrateRegistrationTokenClaimKey(ctx, db); err != nil {
		return err
	}
	if err := backfillRegistrationTokenID(ctx, db); err != nil {
		return err
	}
	if err := backfillTenantLifecycle(ctx, db); err != nil {
		return err
	}
	if err := backfillCfgmsPendingRegistrationColumns(ctx, db); err != nil {
		return err
	}
	if err := backfillCommandDeliveryColumns(ctx, db); err != nil {
		return err
	}

	statements := []string{
		// Schema version tracking
		`CREATE TABLE IF NOT EXISTS schema_version (
			id       INTEGER PRIMARY KEY,
			version  INTEGER NOT NULL,
			applied_at TEXT NOT NULL
		)`,

		// Tenants — directly_suspended and cascade_suspended_from added in migration 008
		// (ADR-027 Decision 2). Pre-existing deployments receive these columns via
		// backfillTenantLifecycle() above; fresh deployments get them from CREATE TABLE.
		`CREATE TABLE IF NOT EXISTS tenants (
			id                    TEXT PRIMARY KEY,
			name                  TEXT NOT NULL,
			description           TEXT NOT NULL DEFAULT '',
			parent_id             TEXT,
			metadata              TEXT NOT NULL DEFAULT '{}',
			status                TEXT NOT NULL DEFAULT 'active',
			directly_suspended    INTEGER NOT NULL DEFAULT 0,
			cascade_suspended_from TEXT,
			created_at            TEXT NOT NULL,
			updated_at            TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tenants_parent_id  ON tenants(parent_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tenants_status      ON tenants(status)`,
		`CREATE INDEX IF NOT EXISTS idx_tenants_name        ON tenants(name)`,

		// Pending-deletion pipeline (ADR-027 Decisions 3-4, Issue #3182).
		`CREATE TABLE IF NOT EXISTS tenant_pending_deletions (
			subtree_root_id   TEXT PRIMARY KEY,
			requested_by      TEXT NOT NULL,
			requested_at      TEXT NOT NULL,
			eligible_at       TEXT NOT NULL,
			state             TEXT NOT NULL DEFAULT 'hold',
			pinned_member_ids TEXT NOT NULL DEFAULT '[]'
		)`,

		// Tenant crossings (ADR-025 Decision 2: client-granted support access and
		// tenant-crossing break-glass elevation, both time-boxed and revocable).
		`CREATE TABLE IF NOT EXISTS tenant_crossings (
			id             TEXT PRIMARY KEY,
			tenant_id      TEXT NOT NULL,
			principal_id   TEXT NOT NULL,
			kind           TEXT NOT NULL,
			granted_by     TEXT NOT NULL,
			justification  TEXT NOT NULL DEFAULT '',
			created_at     TEXT NOT NULL,
			expires_at     TEXT NOT NULL,
			revoked_at     TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tenant_crossings_tenant_id    ON tenant_crossings(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tenant_crossings_principal_id ON tenant_crossings(principal_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tenant_crossings_active_lookup ON tenant_crossings(principal_id, tenant_id, expires_at, revoked_at)`,

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
			id               TEXT PRIMARY KEY,
			tenant_id        TEXT NOT NULL,
			timestamp        TEXT NOT NULL,
			event_type       TEXT NOT NULL,
			action           TEXT NOT NULL,
			user_id          TEXT NOT NULL,
			user_type        TEXT NOT NULL,
			session_id       TEXT NOT NULL DEFAULT '',
			resource_type    TEXT NOT NULL,
			resource_id      TEXT NOT NULL,
			resource_name    TEXT NOT NULL DEFAULT '',
			result           TEXT NOT NULL,
			error_code       TEXT NOT NULL DEFAULT '',
			error_message    TEXT NOT NULL DEFAULT '',
			request_id       TEXT NOT NULL DEFAULT '',
			ip_address       TEXT NOT NULL DEFAULT '',
			user_agent       TEXT NOT NULL DEFAULT '',
			method           TEXT NOT NULL DEFAULT '',
			path             TEXT NOT NULL DEFAULT '',
			details          TEXT NOT NULL DEFAULT '{}',
			changes          TEXT NOT NULL DEFAULT '{}',
			tags             TEXT NOT NULL DEFAULT '[]',
			severity         TEXT NOT NULL,
			source           TEXT NOT NULL,
			version          TEXT NOT NULL DEFAULT '',
			checksum         TEXT NOT NULL,
			sequence_number  INTEGER NOT NULL DEFAULT 0,
			previous_checksum TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_tenant_id        ON audit_entries(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_timestamp        ON audit_entries(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_user_id          ON audit_entries(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_event_type       ON audit_entries(event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_result           ON audit_entries(result)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_severity         ON audit_entries(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_resource_id      ON audit_entries(resource_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_entries_tenant_seq       ON audit_entries(tenant_id, sequence_number)`,

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

		// Registration tokens. New tokens are short-lived and their bearer values
		// are persisted only as deterministic SHA-256 lookup keys. Legacy rows
		// without expiry remain readable so operators can rotate them.
		`CREATE TABLE IF NOT EXISTS registration_tokens (
			token          TEXT PRIMARY KEY,
			id             TEXT,
			tenant_id      TEXT NOT NULL,
			controller_url TEXT NOT NULL,
			group_name     TEXT NOT NULL DEFAULT '',
			created_at     TEXT NOT NULL,
			expires_at     TEXT,
			revoked        INTEGER NOT NULL DEFAULT 0,
			revoked_at     TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_registration_tokens_tenant_id  ON registration_tokens(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_registration_tokens_group_name ON registration_tokens(group_name)`,
		`CREATE INDEX IF NOT EXISTS idx_registration_tokens_id         ON registration_tokens(id)`,

		// A REST registration claim gates certificate/pending-record creation for
		// one device identity. Registration tokens are perennial (Issue #1690), so
		// the key is (token, claim_id) — many devices enroll on one fleet token,
		// but a given device can be issued a key only once per token.
		`CREATE TABLE IF NOT EXISTS registration_token_claims (
				token      TEXT NOT NULL,
				claim_id   TEXT NOT NULL,
				claimed_at TEXT NOT NULL,
				PRIMARY KEY (token, claim_id)
			)`,

		// Stewards — durable fleet registry (ADR-003 §2, Issue #663)
		// Records are never deleted; deregistered stewards are retained for audit.
		// Columns device_id, identity_key_pub, key_protection_level, last_provenance_json
		// were added in Issue #2093 (ADR-010 registration-refresh). tenant_id was added
		// in Issue #2341 (admin move-steward). Pre-existing rows receive empty defaults
		// via backfillStewardColumns() before this transaction.
		`CREATE TABLE IF NOT EXISTS stewards (
			id                   TEXT PRIMARY KEY,
			hostname             TEXT NOT NULL DEFAULT '',
			platform             TEXT NOT NULL DEFAULT '',
			arch                 TEXT NOT NULL DEFAULT '',
			version              TEXT NOT NULL DEFAULT '',
			ip_address           TEXT NOT NULL DEFAULT '',
			status               TEXT NOT NULL DEFAULT 'registered',
			registered_at        TEXT NOT NULL,
			last_seen            TEXT NOT NULL,
			last_heartbeat_at    TEXT NOT NULL DEFAULT '',
			device_id            TEXT NOT NULL DEFAULT '',
			identity_key_pub     BLOB NOT NULL DEFAULT '',
			key_protection_level TEXT NOT NULL DEFAULT '',
			last_provenance_json TEXT NOT NULL DEFAULT '',
			tenant_id            TEXT NOT NULL DEFAULT '',
			hidden               INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_stewards_status    ON stewards(status)`,
		`CREATE INDEX IF NOT EXISTS idx_stewards_last_seen ON stewards(last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_stewards_device_id ON stewards(device_id)`,
		// Issue #3403: backstop for the tenant-scoped duplicate-device_id guard. The
		// plain index above cannot serialize two concurrent claims asserting one
		// device_id; this partial unique index can. Empty device_id means "not
		// asserted" and is excluded so those rows do not collide with each other.
		`CREATE UNIQUE INDEX IF NOT EXISTS uq_stewards_tenant_device ON stewards(tenant_id, device_id) WHERE device_id <> ''`,

		// Commands — durable command dispatch state (ADR-003 §1 Deficiency #5, Issue #665)
		// Records are append-only for audit purposes; PurgeExpiredRecords removes
		// completed/failed records older than the configured threshold.
		`CREATE TABLE IF NOT EXISTS commands (
			id            TEXT PRIMARY KEY,
			type          TEXT NOT NULL,
			steward_id    TEXT NOT NULL,
			tenant_id     TEXT NOT NULL DEFAULT '',
			payload       TEXT NOT NULL DEFAULT '{}',
			status        TEXT NOT NULL DEFAULT 'pending',
			issued_at     TEXT NOT NULL,
			started_at    TEXT,
			completed_at  TEXT,
			result        TEXT NOT NULL DEFAULT '{}',
			error_message TEXT NOT NULL DEFAULT '',
			issued_by     TEXT NOT NULL DEFAULT '',
			delivery_status TEXT NOT NULL DEFAULT 'pending',
			delivery_detail TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_commands_steward_id  ON commands(steward_id)`,
		`CREATE INDEX IF NOT EXISTS idx_commands_status      ON commands(status)`,
		`CREATE INDEX IF NOT EXISTS idx_commands_issued_at   ON commands(issued_at)`,
		`CREATE INDEX IF NOT EXISTS idx_commands_tenant_id   ON commands(tenant_id)`,
		// Issue #3757: reconnect-drain lookup (ListPendingDeliveries) filters by
		// steward_id + delivery_status together, then narrows the result to the
		// steward's tenant chain (idx_commands_tenant_id above covers that column).
		`CREATE INDEX IF NOT EXISTS idx_commands_steward_delivery ON commands(steward_id, delivery_status)`,

		// Command audit trail — immutable log of each state transition
		`CREATE TABLE IF NOT EXISTS command_transitions (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			command_id    TEXT NOT NULL,
			status        TEXT NOT NULL,
			timestamp     TEXT NOT NULL,
			error_message TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_command_transitions_command_id ON command_transitions(command_id)`,
		`CREATE INDEX IF NOT EXISTS idx_command_transitions_timestamp  ON command_transitions(timestamp)`,

		// Triggers — durable workflow trigger persistence (Issue #1088)
		// Secret material is never stored here; *_ref columns hold pkg/secrets keys.
		`CREATE TABLE IF NOT EXISTS triggers (
			id               TEXT PRIMARY KEY,
			tenant_id        TEXT NOT NULL,
			name             TEXT NOT NULL DEFAULT '',
			type             TEXT NOT NULL DEFAULT '',
			status           TEXT NOT NULL DEFAULT '',
			workflow_name    TEXT NOT NULL DEFAULT '',
			created_at       TEXT NOT NULL,
			updated_at       TEXT NOT NULL,
			webhook_path     TEXT NOT NULL DEFAULT '',
			webhook_method   TEXT NOT NULL DEFAULT '[]',
			bearer_ref       TEXT NOT NULL DEFAULT '',
			hmac_ref         TEXT NOT NULL DEFAULT '',
			apikey_ref       TEXT NOT NULL DEFAULT '',
			basic_user_ref   TEXT NOT NULL DEFAULT '',
			basic_pass_ref   TEXT NOT NULL DEFAULT '',
			payload          BLOB NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_triggers_tenant_id ON triggers(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_triggers_type      ON triggers(type)`,
		`CREATE INDEX IF NOT EXISTS idx_triggers_status    ON triggers(status)`,

		// Push records — durable configuration push state (Issue #1317)
		// Stores pending and in-progress push operations so a new leader can resume
		// after failover. The data column holds the full StewardConfiguration JSON blob.
		`CREATE TABLE IF NOT EXISTS push_records (
			id           TEXT PRIMARY KEY,
			config_id    TEXT NOT NULL,
			tenant_id    TEXT NOT NULL,
			version      TEXT NOT NULL,
			status       TEXT NOT NULL,
			initiated_by TEXT NOT NULL,
			data         BLOB NOT NULL,
			created_at   TEXT NOT NULL,
			updated_at   TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_push_records_status    ON push_records(status)`,
		`CREATE INDEX IF NOT EXISTS idx_push_records_tenant_id ON push_records(tenant_id)`,

		// Pending registrations — durable queue for manual-review approval mode (Issue #1599)
		// Records are created by ManualReviewApprovalHook and acted upon by the CLI approve/deny commands.
		`CREATE TABLE IF NOT EXISTS pending_registrations (
			id           TEXT PRIMARY KEY,
			steward_id   TEXT NOT NULL,
			tenant_id    TEXT NOT NULL,
			source_ip    TEXT NOT NULL DEFAULT '',
			token_prefix TEXT NOT NULL DEFAULT '',
			status       TEXT NOT NULL DEFAULT 'pending',
			deny_reason  TEXT NOT NULL DEFAULT '',
			created_at   TEXT NOT NULL,
			expires_at   TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_registrations_tenant_id  ON pending_registrations(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_registrations_status     ON pending_registrations(status)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_registrations_expires_at ON pending_registrations(expires_at)`,

		// Generate-on-claim pending registrations (Issue #1696)
		// Replaces the in-memory sync.Map registrationQueue with a durable store.
		// No cert bundle is ever stored here — cert generation happens in memory on first approved poll.
		// Device identity columns added by Issue #3403 so the claim step can write a
		// complete StewardRecord without re-contacting the steward.
		`CREATE TABLE IF NOT EXISTS cfgms_pending_registrations (
			pending_id           TEXT PRIMARY KEY,
			steward_id           TEXT NOT NULL DEFAULT '',
			tenant_id            TEXT NOT NULL,
			token_str            TEXT NOT NULL,
			source_ip            TEXT NOT NULL DEFAULT '',
			registered_at        TEXT NOT NULL,
			expires_at           TEXT NOT NULL,
			claimed_at           TEXT,
			status               TEXT NOT NULL DEFAULT 'pending',
			device_id            TEXT NOT NULL DEFAULT '',
			identity_key_pub     BLOB NOT NULL DEFAULT '',
			key_protection_level TEXT NOT NULL DEFAULT '',
			csr_pem              TEXT NOT NULL DEFAULT '',
			hostname             TEXT NOT NULL DEFAULT '',
			platform             TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cfgms_pending_registrations_tenant_id    ON cfgms_pending_registrations(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cfgms_pending_registrations_status       ON cfgms_pending_registrations(status)`,
		`CREATE INDEX IF NOT EXISTS idx_cfgms_pending_registrations_expires_at   ON cfgms_pending_registrations(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_cfgms_pending_registrations_token_str    ON cfgms_pending_registrations(token_str)`,

		// Pending registration-refresh requests (ADR-010, Issue #2093)
		// Records are created by the /refresh/challenge handler and acted upon by
		// the approval flow or auto-accept policy. ClaimBundle is populated by
		// StoreClaimBundle once the steward completes the PoP exchange.
		`CREATE TABLE IF NOT EXISTS pending_refresh_requests (
			pending_id               TEXT PRIMARY KEY,
			device_id                TEXT NOT NULL,
			tenant_id                TEXT NOT NULL,
			source_ip                TEXT NOT NULL DEFAULT '',
			provenance_matched_fields INTEGER NOT NULL DEFAULT 0,
			provenance_total_fields   INTEGER NOT NULL DEFAULT 0,
			claim_bundle             BLOB NOT NULL DEFAULT '',
			status                   TEXT NOT NULL DEFAULT 'pending',
			created_at               TEXT NOT NULL,
			expires_at               TEXT NOT NULL,
			resolved_at              TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_refresh_device_id  ON pending_refresh_requests(device_id)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_refresh_tenant_id  ON pending_refresh_requests(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_refresh_status     ON pending_refresh_requests(status)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_refresh_expires_at ON pending_refresh_requests(expires_at)`,

		// Per-tenant registration-refresh policies (ADR-010 §4, Issue #2093)
		// Absent rows return the default policy: mode=require_approval, max_dormancy_days=NULL.
		`CREATE TABLE IF NOT EXISTS refresh_policies (
			tenant_id         TEXT PRIMARY KEY,
			mode              TEXT NOT NULL DEFAULT 'require_approval',
			max_dormancy_days INTEGER
		)`,

		// Fenced, quorum-equivalent singleton-claim leases (ADR-031 Decision 5,
		// Issue #3756). Release force-expires rather than deletes a row, so
		// token remains a monotonic per-name high-water mark.
		`CREATE TABLE IF NOT EXISTS cfgms_leases (
			name       TEXT PRIMARY KEY,
			holder_id  TEXT NOT NULL,
			token      INTEGER NOT NULL,
			expires_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_leases_expires_at ON cfgms_leases(expires_at)`,

		// Per-tenant assurance-policy overrides (ADR-021, Issue #2845).
		// Each row holds one per-permission override. Absent rows mean global defaults apply.
		`CREATE TABLE IF NOT EXISTS assurance_policy_overrides (
			tenant_id             TEXT NOT NULL,
			permission_id         TEXT NOT NULL,
			min_override          INTEGER,
			require_user_presence INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (tenant_id, permission_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_assurance_policy_overrides_tenant_id ON assurance_policy_overrides(tenant_id)`,

		// Per-tenant blast-radius overrides (Issue #3698). One row per tenant;
		// SetPolicy upserts. Absent rows mean no override at that tenant.
		`CREATE TABLE IF NOT EXISTS blast_radius_policy_overrides (
			tenant_id   TEXT PRIMARY KEY,
			max_targets INTEGER
		)`,

		// Registration-refresh challenge nonces (Issue #3755, ADR-031 amendment to
		// ADR-011). GetAndConsumeNonce deletes the row it reads via DELETE ... RETURNING.
		`CREATE TABLE IF NOT EXISTS refresh_nonces (
			key        TEXT NOT NULL PRIMARY KEY,
			entry      BLOB NOT NULL,
			expires_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_nonces_expires_at ON refresh_nonces(expires_at)`,

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

		// Session token records for pkg/session.Store (Issue #2736 / epic #2735).
		// Key is SHA-256(token) hex — the raw token is NEVER stored here or in any log.
		// Multiple rows can share a session_id: one for the current token and one for
		// the prior-token grace slot produced by Manager.Renew. Both rows hold identical
		// session data; the distinction is maintained only in the Manager's in-memory state.
		//
		// hash_expires_at (nullable): set by StampGraceExpiry after Renew so that prior-token
		// grace slots expire on cluster peers and after controller restarts, bounding the
		// window in which a rotated-away token hash remains a valid credential.
		`CREATE TABLE IF NOT EXISTS session_token_records (
			token_hash            TEXT PRIMARY KEY,
			session_id            TEXT NOT NULL,
			principal_id          TEXT NOT NULL,
			connection_name       TEXT NOT NULL,
			tenant_id             TEXT NOT NULL,
			issued_at             TEXT NOT NULL,
			last_activity         TEXT NOT NULL,
			absolute_expires_at   TEXT NOT NULL,
			hash_expires_at       TEXT,
			assurance             INTEGER NOT NULL DEFAULT 1,
			bound_ip              TEXT    NOT NULL DEFAULT '',
			last_proven_at        TEXT,
			credential_id         BLOB,
			root_scoped           INTEGER NOT NULL DEFAULT 0,
			channel               TEXT    NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_session_token_records_session_id ON session_token_records(session_id)`,

		// Cases — cockpit investigation workspaces (ADR-022 §8, Issue #3602).
		// ticket_json holds the per-field-provenanced Ticket as a JSON object.
		`CREATE TABLE IF NOT EXISTS cases (
			id           TEXT PRIMARY KEY,
			tenant_id    TEXT NOT NULL,
			status       TEXT NOT NULL DEFAULT 'open',
			ticket_json  TEXT NOT NULL DEFAULT '{}',
			created_at   TEXT NOT NULL,
			updated_at   TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cases_tenant_id  ON cases(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_cases_status     ON cases(status)`,

		// Case pins — discriminated graph references attached to cases.
		// ref_kind identifies which ref_* fields are populated (ADR-022 §8).
		`CREATE TABLE IF NOT EXISTS case_pins (
			id                   TEXT PRIMARY KEY,
			case_id              TEXT NOT NULL,
			ref_kind             TEXT NOT NULL,
			ref_eid              TEXT NOT NULL DEFAULT '',
			ref_edge_identity    TEXT NOT NULL DEFAULT '',
			ref_obs_version      TEXT NOT NULL DEFAULT '',
			ref_drift_record     TEXT NOT NULL DEFAULT '',
			ref_subject          TEXT NOT NULL DEFAULT '',
			ref_range_start      TEXT,
			ref_range_end        TEXT,
			annotation           TEXT NOT NULL DEFAULT '',
			author               TEXT NOT NULL DEFAULT '',
			pinned_at            TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_case_pins_case_id ON case_pins(case_id)`,

		// Case content — typed entries: finding, transcript-entry, note (ADR-022 §8).
		`CREATE TABLE IF NOT EXISTS case_content (
			id         TEXT PRIMARY KEY,
			case_id    TEXT NOT NULL,
			kind       TEXT NOT NULL,
			body       TEXT NOT NULL DEFAULT '',
			author     TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_case_content_case_id ON case_content(case_id)`,
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("schema: failed to begin initialization transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("schema statement failed: %w\nSQL: %s", err, stmt)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("schema: failed to commit initialization: %w", err)
	}
	committed = true

	// Record or verify schema version (runs after DDL is committed).
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
