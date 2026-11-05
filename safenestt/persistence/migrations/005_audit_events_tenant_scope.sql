-- 005_audit_events_tenant_scope.sql
--
-- Corrective migration. Does NOT touch historical migrations (001-004).
--
-- WHY THIS EXISTS
--   Agent-authorization audit events were written WITHOUT a tenant_id, and the
--   audit_events RLS policy scoped tenant isolation only indirectly, through
--   investigation_id. Authorization checks that are not tied to a single
--   investigation (PermissionManager.authorize) produce audit rows with
--   investigation_id IS NULL, which the old policy could not scope to a tenant
--   -- so those writes failed (InsufficientPrivilege) and, structurally, audit
--   rows were not tenant-isolated in their own right.
--
--   The fix makes audit_events tenant-scoped directly:
--     * audit_events gains a NOT NULL tenant_id column (see models.py).
--     * PersistentAuditLogger sets tenant context before every write, and
--       repositories.AuditEventRepository.record() populates tenant_id and
--       fails loud if get_current_tenant() is NULL.
--     * audit_events_policy keys on tenant_id directly and still forbids binding
--       an event to an investigation owned by a different tenant.
--
--   On a FRESH database this is handled entirely by models.py (create_all adds
--   the column) and rls.py::apply_rls_policies (creates the policy). This file
--   is ONLY for EXISTING databases, where create_all never alters a table that
--   already exists and would leave audit_events without tenant_id -- at which
--   point the corrected policy, which references tenant_id, cannot be created.
--
-- ORDERING (IMPORTANT)
--   Apply this migration to any existing database BEFORE running migrate.py /
--   apply_rls_policies again. It adds and backfills the column the corrected
--   audit_events_policy depends on.
--
-- WHAT THIS DOES
--   1. Adds audit_events.tenant_id (TEXT), initially nullable.
--   2. Backfills tenant_id from investigations for every row carrying an
--      investigation_id.
--   3. Rows that cannot be attributed (investigation_id IS NULL, or pointing at
--      a missing investigation) are counted and the migration ABORTS, so an
--      operator resolves orphan audit rows explicitly rather than have a tenant
--      silently invented for tamper-evident audit history.
--   4. Sets tenant_id NOT NULL and creates ix_audit_events_tenant_id (matching
--      models.py: tenant_id, index=True).
--   5. Re-applies the corrected, tenant-keyed audit_events_policy, identical to
--      rls.py::apply_rls_policies.
--
-- SAFETY
--   Idempotent. Adds and backfills a column; performs no DELETE or TRUNCATE.
--   Runs in a single transaction -- if orphan rows remain it rolls back whole,
--   leaving the database exactly as before. Migrations 001-004 are untouched.

BEGIN;

-- 1. Add the column, nullable for now so existing rows survive the ALTER.
ALTER TABLE public.audit_events ADD COLUMN IF NOT EXISTS tenant_id TEXT;

-- 2. Backfill from the owning investigation.
UPDATE public.audit_events a
   SET tenant_id = i.tenant_id
  FROM public.investigations i
 WHERE a.investigation_id = i.investigation_id
   AND a.tenant_id IS NULL;

-- 3. Fail loud on any row we could not attribute to a tenant. Audit history is
--    tamper-evident; we do not invent a tenant for it.
DO $$
DECLARE orphan_count BIGINT;
BEGIN
    SELECT count(*) INTO orphan_count
      FROM public.audit_events
     WHERE tenant_id IS NULL;

    IF orphan_count > 0 THEN
        RAISE EXCEPTION
            'audit_events: % row(s) have no derivable tenant_id (investigation_id is NULL or points to a missing investigation). Resolve these rows explicitly before applying this migration; refusing to invent a tenant for audit history.',
            orphan_count;
    END IF;
END $$;

-- 4. Enforce NOT NULL and index, matching models.py.
ALTER TABLE public.audit_events ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_id ON public.audit_events (tenant_id);

-- 5. Corrected, tenant-keyed policy. Identical to rls.py::apply_rls_policies.
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_events_tenant_isolation ON public.audit_events;
DROP POLICY IF EXISTS audit_events_insert ON public.audit_events;
DROP POLICY IF EXISTS audit_events_update ON public.audit_events;
DROP POLICY IF EXISTS audit_events_delete ON public.audit_events;
DROP POLICY IF EXISTS audit_events_policy ON public.audit_events;

CREATE POLICY audit_events_policy ON public.audit_events FOR ALL
    USING (tenant_id = get_current_tenant())
    WITH CHECK (
        tenant_id = get_current_tenant()
        AND (
            investigation_id IS NULL
            OR investigation_id IN (
                SELECT investigation_id FROM investigations
                WHERE tenant_id = get_current_tenant()
            )
        )
    );

COMMIT;
