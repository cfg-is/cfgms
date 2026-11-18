-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 019: Add csrf_token_hash to session_token_store (Issue #6321).
--
-- csrf_token_hash is the hex SHA-256 of a web session's session-bound CSRF token,
-- so every controller node accepts the token for the session's whole lifetime
-- (restarts, rolling deploys, fail-over). The raw token is never stored. The
-- controller applies the same statement at startup via
-- DatabaseSchemas.BackfillSessionTokenStoreContinuity (schemas.go). This file is
-- for operators who provision schema out-of-band. The statement is idempotent.
--
-- Expand-only: a node that predates this column never names it, so its upserts
-- leave the stored value untouched. Rows without a hash (sessions issued by such a
-- node, and CLI sessions) read as the default '' and are refused on unsafe web
-- methods until the user logs in again.

ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS csrf_token_hash TEXT NOT NULL DEFAULT '';
