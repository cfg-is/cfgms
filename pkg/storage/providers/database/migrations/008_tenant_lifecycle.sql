-- SPDX-License-Identifier: AGPL-3.0-only
-- Migration 008: Add ADR-027 Decision 2 suspension provenance columns to cfgms_tenants
-- (Issue #3158).
--
-- Why these columns exist:
--   Suspending a tenant cascades to its entire subtree (ADR-027 Decision 1). Decision 2
--   requires tracking *why* each tenant is suspended: directly targeted, cascade effect
--   of an ancestor's suspend, or both simultaneously. This distinction is what lets
--   RestoreTenant only lift the cascade effect without overriding an independent suspension.
--
--   directly_suspended    — this tenant was the direct target of a SuspendTenant call.
--   cascade_suspended_from — the ancestor tenant ID whose suspend cascaded to this tenant
--                            (NULL when the tenant is not cascade-suspended).
--
-- Both columns can be set simultaneously (a tenant independently suspended that is also
-- cascade-suspended by an ancestor).
--
-- The controller applies these changes automatically at startup via
-- DatabaseSchemas.BackfillTenantLifecycle (schemas.go). This file is for operators
-- who provision schema out-of-band. ADD COLUMN IF NOT EXISTS is idempotent on Postgres 9.6+.

ALTER TABLE cfgms_tenants ADD COLUMN IF NOT EXISTS directly_suspended BOOLEAN DEFAULT false;
ALTER TABLE cfgms_tenants ADD COLUMN IF NOT EXISTS cascade_suspended_from VARCHAR(255);
