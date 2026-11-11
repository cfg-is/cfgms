-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 018: Add the schema range to cfgms_node_registry.
--
-- Each controller node reports the schema version it requires and the oldest it
-- tolerates, so the mixed-version state of a rolling deploy can be read from the
-- registry and GET /api/v1/ha/cluster. The controller applies the same statements
-- at startup via DatabaseSchemas.CreateNodeRegistryTable (schemas.go). This file is
-- for operators who provision schema out-of-band. Every statement is idempotent.
--
-- Expand-only: a node that predates these columns never writes them, so its row
-- keeps the default 0. A later contract step reads 0 as "unknown" and blocks
-- (fail closed).

ALTER TABLE cfgms_node_registry ADD COLUMN IF NOT EXISTS schema_required INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cfgms_node_registry ADD COLUMN IF NOT EXISTS schema_min_tolerated INTEGER NOT NULL DEFAULT 0;
