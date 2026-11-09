-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 015: durable ring-advance rollout records (Issue #5976).
--
-- POST /api/v1/rollout keeps its orchestration state in cfgms_rollout_records
-- so a rollout, its ring progress, halt metadata and deferred-steward list
-- survive a controller restart and are visible from every node of a cluster.
--
-- owner_node_id is the ID of the controller node advancing the rollout. At
-- startup a node halts the in-progress rollouts it owned itself (their advancing
-- goroutine died with the previous process); rollouts owned by a peer are never
-- touched. An empty owner means the controller ran without an HA manager.
--
-- RLS follows command_records: reads are permissive without a tenant context
-- (by-ID lookup and the cross-tenant startup sweep, using the NULL-safe form from
-- migration 010) and filtered when one is set; writes require the caller's
-- tenant and fail closed otherwise.
--
-- Applied in code by DatabaseSchemas.CreateRolloutRecordsTable, called from
-- NewDatabaseRolloutStore on every startup (every statement is idempotent).
-- This file documents the change for operators; it is not executed by a
-- migration runner.

CREATE TABLE IF NOT EXISTS cfgms_rollout_records (
    id                TEXT NOT NULL PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    initiated_by      TEXT NOT NULL DEFAULT '',
    target_version    TEXT NOT NULL DEFAULT '',
    current_ring      TEXT NOT NULL DEFAULT '',
    rings_completed   INTEGER NOT NULL DEFAULT 0,
    rings_total       INTEGER NOT NULL DEFAULT 0,
    status            TEXT NOT NULL,
    started_at        TIMESTAMP WITH TIME ZONE NOT NULL,
    halted_at         TIMESTAMP WITH TIME ZONE,
    error_message     TEXT NOT NULL DEFAULT '',
    owner_node_id     TEXT NOT NULL DEFAULT '',
    deferred_stewards JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_rollout_records_tenant_id ON cfgms_rollout_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rollout_records_in_progress ON cfgms_rollout_records(owner_node_id) WHERE status = 'in-progress';

ALTER TABLE cfgms_rollout_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE cfgms_rollout_records FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_read   ON cfgms_rollout_records;
DROP POLICY IF EXISTS rls_write  ON cfgms_rollout_records;
DROP POLICY IF EXISTS rls_update ON cfgms_rollout_records;
DROP POLICY IF EXISTS rls_delete ON cfgms_rollout_records;

CREATE POLICY rls_read ON cfgms_rollout_records FOR SELECT USING (
    coalesce(current_setting('app.current_tenant', true), '') = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);
CREATE POLICY rls_write ON cfgms_rollout_records FOR INSERT WITH CHECK (
    tenant_id = current_setting('app.current_tenant', true)
);
CREATE POLICY rls_update ON cfgms_rollout_records FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true));
CREATE POLICY rls_delete ON cfgms_rollout_records FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true));
