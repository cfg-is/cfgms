-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 009: Add cfgms_tenant_pending_deletions table for ADR-027 Decisions 3-4
-- (Issue #3182).
--
-- Why this table exists:
--   Decisions 3-4 of ADR-027 describe a Suspend → Hold → Delete pipeline. A fully
--   suspended subtree can only be hard-deleted after an operator has submitted a
--   deletion request (which records membership and starts a hold timer), the hold
--   period has elapsed, and a second operator has approved the deletion (dual-control).
--   This table persists the in-flight record between those steps.
--
--   subtree_root_id   — the top of the subtree entering the pipeline.
--   requested_by      — principal who called RequestTenantDeletion.
--   requested_at      — timestamp of the request.
--   eligible_at       — earliest timestamp at which ApproveTenantDeletion may proceed.
--   state             — 'hold' (waiting for hold period) or 'eligible' (approvable).
--   pinned_member_ids — JSON array of tenant IDs in the subtree at request time.
--                       ApproveTenantDeletion requires the current subtree to match
--                       this set exactly (defense in depth against membership changes).
--
-- The controller applies these changes automatically at startup via
-- DatabaseSchemas.CreatePendingDeletionsTable (schemas.go). This file is for
-- operators who provision schema out-of-band. CREATE TABLE IF NOT EXISTS is
-- idempotent on Postgres 9.6+.

CREATE TABLE IF NOT EXISTS cfgms_tenant_pending_deletions (
    subtree_root_id   VARCHAR(255) PRIMARY KEY,
    requested_by      VARCHAR(255) NOT NULL,
    requested_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    eligible_at       TIMESTAMP WITH TIME ZONE NOT NULL,
    state             VARCHAR(50)  NOT NULL DEFAULT 'hold',
    pinned_member_ids JSONB        NOT NULL DEFAULT '[]'
);
