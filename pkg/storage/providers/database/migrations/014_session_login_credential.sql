-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 014: Add login_credential_id to session_token_store (Issue #5166).
--
-- login_credential_id is the WebAuthn credential ID of the first elevation of a
-- session (the passkey that logged a web session in). It is set once and never
-- changed by a later step-up, so revoking that passkey can end the session.
-- NULL for sessions that predate this column.

ALTER TABLE session_token_store ADD COLUMN IF NOT EXISTS login_credential_id BYTEA;
