-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 017: Record the applied schema version in cfgms_schema_version (Issue #6092).
--
-- The controller applies the same statements at startup via checkSchemaVersion
-- (schema_version.go), which refuses to start against a database whose recorded
-- version is outside the range the controller tolerates. This file is for operators
-- who provision schema out-of-band. Every statement is idempotent.
--
-- The table holds no tenant data and has no row-level security.

CREATE TABLE IF NOT EXISTS cfgms_schema_version (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    version              INTEGER NOT NULL,
    min_node_version     INTEGER NOT NULL DEFAULT 0,
    contract_applied     INTEGER NOT NULL DEFAULT 0,
    recent_gate_required INTEGER,
    recent_gate_at       TIMESTAMPTZ,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO cfgms_schema_version (id, version) VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;
