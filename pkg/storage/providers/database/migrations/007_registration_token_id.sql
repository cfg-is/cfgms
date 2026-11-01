-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 007: Add the stable, non-secret `id` column to cfgms_registration_tokens
-- (Issue #2970).
--
-- Why the column exists:
--   The web UI never holds a registration token secret — list and get responses are
--   redacted to a 6-character prefix. To revoke or delete a token it addresses the
--   token by a stable UUID (`token_id` in API responses, `id` here), which the
--   handlers resolve through GetTokenByID.
--
-- Why existing rows must be back-filled:
--   A row with a NULL id reports token_id: "" to the web UI, which then has no value
--   to address the token with — the token can never be revoked or deleted from the
--   UI. That would fail on exactly the tokens most likely to need revoking: the
--   pre-existing ones. Every row therefore receives a UUID.
--
-- The controller applies this migration automatically at startup via
-- DatabaseSchemas.BackfillRegistrationTokenIDs (schemas.go), which generates the
-- UUIDs in Go and therefore carries no minimum Postgres version. This file is for
-- operators who provision schema out-of-band; gen_random_uuid() requires Postgres 13+
-- (or the pgcrypto extension on older servers).

ALTER TABLE cfgms_registration_tokens ADD COLUMN IF NOT EXISTS id VARCHAR(36);

UPDATE cfgms_registration_tokens
SET id = gen_random_uuid()::text
WHERE id IS NULL OR id = '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_cfgms_reg_tokens_id
    ON cfgms_registration_tokens(id);
