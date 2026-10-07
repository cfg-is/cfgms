-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 011: add outbox delivery-lifecycle columns to command_records
-- (Issue #3757, ADR-031 Decision 2).
--
-- A command/notification row destined for a steward now carries its own
-- delivery lifecycle (pending -> delivered -> acknowledged, terminal failures
-- recorded distinctly) independent of the existing `status` column, which
-- tracks the steward's execution of the command, not the controller's
-- delivery of it.
--
-- delivery_status: pending | delivered | acknowledged | failed. Defaults to
--                  'pending' so pre-existing rows (dispatched by the retired
--                  fire-and-forget goroutine, whose actual delivery outcome is
--                  unknown) are drained rather than silently treated as done.
-- delivery_detail: human-readable reason for the current delivery_status
--                  (e.g. a sanitized transport error). Empty until set.
--
-- Applied in code by DatabaseSchemas.BackfillCommandRecordsDeliveryStatus,
-- called from DatabaseCommandStore.initializeSchema on every startup (ADD
-- COLUMN IF NOT EXISTS is idempotent on Postgres). This file documents the
-- change for operators; it is not executed by a migration runner.

ALTER TABLE command_records ADD COLUMN IF NOT EXISTS delivery_status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE command_records ADD COLUMN IF NOT EXISTS delivery_detail TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_command_records_steward_delivery ON command_records(steward_id, delivery_status);
