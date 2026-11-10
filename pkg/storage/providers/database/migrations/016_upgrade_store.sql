-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 016: durable steward upgrade records (Issue #5977).
--
-- POST /api/v1/stewards/upgrade keeps each upgrade (and each rollback) in
-- cfgms_upgrade_records so the record, its status and its publisher-signature
-- provenance survive a controller restart and are visible from every node of a
-- cluster: an upgrade dispatched on one node can be read and rolled back by
-- --upgrade-id from another. There is no in-memory fallback.
--
-- Existing per-node SQLite upgrade records (upgrade_records in the node's
-- cfgms.db) are not imported; a controller on this provider no longer reads them.
--
-- bundle_signature is the publisher's Ed25519 signature over the binary's
-- content hash; it is required at creation (the store rejects an empty one) so
-- the audit trail is complete from the moment an upgrade is dispatched.
-- operation_nonce is the caller's replay-defense nonce and may be absent.
--
-- RLS follows command_records and cfgms_rollout_records: reads are permissive
-- without a tenant context (by-ID lookup, using the NULL-safe form from
-- migration 010) and filtered when one is set; writes require the caller's
-- tenant and fail closed otherwise.
--
-- Applied in code by DatabaseSchemas.CreateUpgradeRecordsTable, called from
-- NewDatabaseUpgradeStore on every startup (every statement is idempotent).
-- This file documents the change for operators; it is not executed by a
-- migration runner.

CREATE TABLE IF NOT EXISTS cfgms_upgrade_records (
    id                       TEXT NOT NULL PRIMARY KEY,
    steward_id               TEXT NOT NULL,
    tenant_id                TEXT NOT NULL,
    version                  TEXT NOT NULL,
    platform                 TEXT NOT NULL,
    arch                     TEXT NOT NULL,
    sha256                   TEXT NOT NULL,
    status                   TEXT NOT NULL,
    initiated_by_subject     TEXT NOT NULL,
    initiated_by_tenant      TEXT NOT NULL,
    initiated_by_auth_method TEXT NOT NULL,
    publisher                TEXT NOT NULL,
    signature_digest         TEXT NOT NULL,
    bundle_signature         BYTEA NOT NULL,
    created_at               TIMESTAMP WITH TIME ZONE NOT NULL,
    operation_nonce          BYTEA,
    dispatched_at            TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at             TIMESTAMP WITH TIME ZONE,
    error_message            TEXT NOT NULL DEFAULT ''
);

-- Per-steward listing (and the non-terminal-upgrade check that reads it) and
-- per-tenant listing, newest first.
CREATE INDEX IF NOT EXISTS idx_upgrade_records_steward_created ON cfgms_upgrade_records(steward_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_upgrade_records_tenant_created ON cfgms_upgrade_records(tenant_id, created_at DESC);

ALTER TABLE cfgms_upgrade_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE cfgms_upgrade_records FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_read   ON cfgms_upgrade_records;
DROP POLICY IF EXISTS rls_write  ON cfgms_upgrade_records;
DROP POLICY IF EXISTS rls_update ON cfgms_upgrade_records;
DROP POLICY IF EXISTS rls_delete ON cfgms_upgrade_records;

CREATE POLICY rls_read ON cfgms_upgrade_records FOR SELECT USING (
    coalesce(current_setting('app.current_tenant', true), '') = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);
CREATE POLICY rls_write ON cfgms_upgrade_records FOR INSERT WITH CHECK (
    tenant_id = current_setting('app.current_tenant', true)
);
CREATE POLICY rls_update ON cfgms_upgrade_records FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
CREATE POLICY rls_delete ON cfgms_upgrade_records FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true));
