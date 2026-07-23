-- SPDX-License-Identifier: AGPL-3.0-only
-- Copyright 2026 Jordan Ritz
--
-- PostgreSQL schema for the CFGMS entity graph database provider (ADR-022).
-- Mirrors the SQLite provider tables (eg_ prefix) using PostgreSQL syntax:
-- BIGSERIAL primary keys, $N placeholders (in Go), TEXT RFC3339 timestamps for
-- cross-provider portability, and ON CONFLICT upserts.

CREATE TABLE IF NOT EXISTS eg_payload_content (
    content_hash TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS eg_observation_log (
    id              BIGSERIAL PRIMARY KEY,
    subject         TEXT NOT NULL,
    source          TEXT NOT NULL,
    source_class    TEXT NOT NULL DEFAULT '',
    observed_at     TEXT NOT NULL,
    recorded_at     TEXT NOT NULL,
    kind            TEXT NOT NULL,
    confidence      TEXT NOT NULL DEFAULT '',
    claim_scope_key TEXT NOT NULL DEFAULT '',
    payload_hash    TEXT NOT NULL,
    tenant_path     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_eg_log_subject  ON eg_observation_log(subject);
CREATE INDEX IF NOT EXISTS idx_eg_log_source   ON eg_observation_log(source);
CREATE INDEX IF NOT EXISTS idx_eg_log_tenant   ON eg_observation_log(tenant_path);
CREATE INDEX IF NOT EXISTS idx_eg_log_subj_src ON eg_observation_log(subject, source);

CREATE TABLE IF NOT EXISTS eg_entity_current (
    subject         TEXT NOT NULL,
    source          TEXT NOT NULL,
    source_class    TEXT NOT NULL DEFAULT '',
    kind            TEXT NOT NULL,
    confidence      TEXT NOT NULL DEFAULT '',
    observed_at     TEXT NOT NULL,
    recorded_at     TEXT NOT NULL,
    payload_hash    TEXT NOT NULL,
    tenant_path     TEXT NOT NULL DEFAULT '',
    log_seq         BIGINT NOT NULL,
    PRIMARY KEY (subject, source)
);

CREATE INDEX IF NOT EXISTS idx_eg_cur_subject ON eg_entity_current(subject);
CREATE INDEX IF NOT EXISTS idx_eg_cur_tenant  ON eg_entity_current(tenant_path);

CREATE TABLE IF NOT EXISTS eg_entity_index (
    subject          TEXT PRIMARY KEY,
    entity_kind      TEXT NOT NULL DEFAULT '',
    owning_tenant    TEXT NOT NULL DEFAULT '',
    hostname         TEXT NOT NULL DEFAULT '',
    mac_addrs        TEXT NOT NULL DEFAULT '',
    machine_sid      TEXT NOT NULL DEFAULT '',
    dir_object_guid  TEXT NOT NULL DEFAULT '',
    serial_number    TEXT NOT NULL DEFAULT '',
    cloud_object_id  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_eg_idx_kind   ON eg_entity_index(entity_kind);
CREATE INDEX IF NOT EXISTS idx_eg_idx_tenant ON eg_entity_index(owning_tenant);

CREATE TABLE IF NOT EXISTS eg_edge_projection (
    from_subject TEXT NOT NULL,
    to_subject   TEXT NOT NULL,
    edge_type    TEXT NOT NULL,
    source       TEXT NOT NULL,
    source_class TEXT NOT NULL DEFAULT '',
    observed_at  TEXT NOT NULL DEFAULT '',
    payload_hash TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (from_subject, to_subject, edge_type, source)
);

-- Story-3: add observed_at to databases created before it existed.
ALTER TABLE eg_edge_projection ADD COLUMN IF NOT EXISTS observed_at TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_eg_edge_from ON eg_edge_projection(from_subject);
CREATE INDEX IF NOT EXISTS idx_eg_edge_to   ON eg_edge_projection(to_subject);

CREATE TABLE IF NOT EXISTS eg_drift_projection (
    subject          TEXT PRIMARY KEY,
    detected_at      TEXT NOT NULL,
    fields_json      TEXT NOT NULL DEFAULT '[]',
    config_revision  TEXT NOT NULL DEFAULT '',
    lifecycle_status TEXT NOT NULL DEFAULT 'detected'
);

CREATE TABLE IF NOT EXISTS eg_claim_scope_prior (
    source          TEXT NOT NULL,
    claim_scope_key TEXT NOT NULL,
    subject         TEXT NOT NULL,
    PRIMARY KEY (source, claim_scope_key, subject)
);
