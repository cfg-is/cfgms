-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 012: Add the opaque tenant billing label to cfgms_tenants (Issue #4645,
-- ADR-025 Amendment 6 A6.2).
--
-- The label is random, stable for the tenant's whole life, and never derived from the
-- tenant name or ID. Existing rows are filled with random values (not a hash of any
-- column), then a unique index is added.
--
-- The controller applies the same steps at startup via
-- DatabaseSchemas.BackfillTenantBillingLabel (schemas.go). This file is for operators
-- who provision schema out-of-band. Every statement is idempotent.

ALTER TABLE cfgms_tenants ADD COLUMN IF NOT EXISTS billing_label VARCHAR(64);

-- 80 random bits per label: 12 + 8 hex characters from two independent v4 UUIDs,
-- skipping the fixed version/variant nibbles.
UPDATE cfgms_tenants
SET billing_label = 'bl-' ||
    substr(replace(gen_random_uuid()::text, '-', ''), 1, 12) ||
    substr(replace(gen_random_uuid()::text, '-', ''), 25, 8)
WHERE billing_label IS NULL OR billing_label = '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_cfgms_tenants_billing_label ON cfgms_tenants(billing_label);
