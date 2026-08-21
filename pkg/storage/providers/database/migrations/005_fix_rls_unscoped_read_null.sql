-- Fix RLS unscoped-read branch (NULL vs empty string) on sessions,
-- steward_records, and command_records.
--
-- Problem: current_setting('app.current_tenant', true) returns NULL when the
-- setting has never been applied in the session. The comparison NULL = '' yields
-- NULL (not true), so the permissive "read all" branch never fires. Unscoped
-- callers see zero rows instead of all rows.
--
-- Evidence (measured live, 2026-08-20):
--   app.current_tenant unset → 0 rows
--   set app.current_tenant = '' → 2 rows
--   set app.current_tenant = '<tenant>' → 2 rows
--   as superuser (RLS bypassed) → 2 rows
--
-- Fix: COALESCE to '' so NULL and empty string both match the permissive branch.

DROP POLICY IF EXISTS rls_read ON sessions;
CREATE POLICY rls_read ON sessions FOR SELECT USING (
    COALESCE(current_setting('app.current_tenant', true), '') = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);

DROP POLICY IF EXISTS rls_read ON steward_records;
CREATE POLICY rls_read ON steward_records FOR SELECT USING (
    COALESCE(current_setting('app.current_tenant', true), '') = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);

DROP POLICY IF EXISTS rls_read ON command_records;
CREATE POLICY rls_read ON command_records FOR SELECT USING (
    COALESCE(current_setting('app.current_tenant', true), '') = ''
    OR tenant_id = current_setting('app.current_tenant', true)
);
