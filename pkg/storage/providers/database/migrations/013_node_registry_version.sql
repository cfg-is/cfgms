-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 013: Add version and started_at to cfgms_node_registry (Issue #4514).
--
-- The failover monitor and GET /api/v1/ha/cluster read each live node's version and
-- start time from the shared node registry. last_seen is the existing updated_at.
-- The controller applies the same statements at startup via
-- DatabaseSchemas.CreateNodeRegistryTable (schemas.go). This file is for operators
-- who provision schema out-of-band. Every statement is idempotent.

ALTER TABLE cfgms_node_registry ADD COLUMN IF NOT EXISTS version TEXT NOT NULL DEFAULT '';
ALTER TABLE cfgms_node_registry ADD COLUMN IF NOT EXISTS started_at TIMESTAMP WITH TIME ZONE;
