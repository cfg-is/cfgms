-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 006: Add device-continuity columns to session_token_store (Issue #2788).
--
-- ADR-021 Decision 3 (silent continuity) and Decision 5 (IP-change downgrade) require
-- durable storage of per-session assurance state so that:
--   - A session's AssuranceStrong survives rolling restarts and node failovers without
--     downgrading every session on restart (the failover-looks-like-device-change problem
--     that the ADR Sequencing section describes as the reason #2775 must precede this story).
--   - The IP-change detection compares the stored BoundIP against the current request IP;
--     the comparison must work on any node, so BoundIP must be in the shared store.
--
-- Column semantics:
--   assurance:      AssuranceLevel numeric value (0=Machine, 1=Basic, 2=Strong).
--                   Defaults to 1 (AssuranceBasic) — all pre-existing rows are human sessions.
--   bound_ip:       Source IP at last successful strong-factor proof. Empty until first proof.
--   last_proven_at: Wall-clock time of last proof. NULL until first proof.
--   credential_id:  WebAuthn credential ID (BYTEA) that established AssuranceStrong.
--                   NULL when no device-bound proof has been recorded.

ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS assurance      INTEGER NOT NULL DEFAULT 1;
ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS bound_ip       TEXT    NOT NULL DEFAULT '';
ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS last_proven_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS credential_id  BYTEA;
