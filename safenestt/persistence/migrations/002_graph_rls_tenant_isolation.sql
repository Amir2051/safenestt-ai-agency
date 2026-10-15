-- =====================================================================
-- 002_graph_rls_tenant_isolation.sql
--
-- SECURITY-ONLY migration. Additive: enables RLS and adds policies on the
-- two graph tables. It does NOT create, alter, rewrite, or delete any row,
-- column, constraint, or index.
--
-- WHY
-- ---
-- A completed end-to-end investigation produced 21 graph_nodes and 15
-- graph_edges, and a foreign tenant reading under its own valid tenant
-- context could see all of them. pg_class confirmed the cause:
--
--   graph_nodes | relrowsecurity = false | relforcerowsecurity = false
--   graph_edges | relrowsecurity = false | relforcerowsecurity = false
--
-- Every other investigation-owned table (investigations, evidence, findings,
-- reports, agent_runs) already had RLS enabled and forced, so the graph
-- tables were the single remaining isolation gap. investigation_id secrecy
-- and UUID unpredictability are explicitly NOT treated as authorization.
--
-- TENANT AUTHORITY
-- ---------------
-- investigations.tenant_id is the single source of truth, resolved through
-- get_current_tenant(). This matches the established child-table pattern:
--
--   child.investigation_id IN (
--       SELECT investigation_id FROM investigations
--       WHERE tenant_id = get_current_tenant())
--
-- There is no organizations/cases table and no auth.uid() in this schema.
--
-- FAIL-CLOSED BEHAVIOUR
-- --------------------
-- get_current_tenant() returns '' when no context is established. No
-- investigation row has tenant_id = '', so the subquery yields no rows and
-- the predicate is false for every row: a request with no tenant context
-- sees zero graph rows and can write none.
--
-- SERVICE ROLE
-- -----------
-- postgres is the owner and a superuser; superusers and table owners bypass
-- RLS unless FORCE is applied. FORCE ROW LEVEL SECURITY is enabled below so
-- the owner is subject to policy too, and app-level tenant validation in
-- PersistentInvestigationStore remains the control for service-role writes.
-- =====================================================================

BEGIN;

-- ---------------------------------------------------------------------
-- graph_nodes
-- ---------------------------------------------------------------------
ALTER TABLE public.graph_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.graph_nodes FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS graph_nodes_tenant_isolation ON public.graph_nodes;
CREATE POLICY graph_nodes_tenant_isolation
    ON public.graph_nodes
    FOR ALL
    USING (
        investigation_id IN (
            SELECT investigations.investigation_id
            FROM investigations
            WHERE investigations.tenant_id = get_current_tenant()
        )
    )
    WITH CHECK (
        investigation_id IN (
            SELECT investigations.investigation_id
            FROM investigations
            WHERE investigations.tenant_id = get_current_tenant()
        )
    );

-- Explicit INSERT policy.
-- WITH CHECK is required so a row cannot be INSERTed into an investigation
-- belonging to another tenant, and so a row cannot be INSERTed when no
-- tenant context is established.
DROP POLICY IF EXISTS graph_nodes_insert ON public.graph_nodes;
CREATE POLICY graph_nodes_insert
    ON public.graph_nodes
    FOR INSERT
    WITH CHECK (
        investigation_id IN (
            SELECT investigations.investigation_id
            FROM investigations
            WHERE investigations.tenant_id = get_current_tenant()
        )
    );

-- ---------------------------------------------------------------------
-- graph_edges
-- ---------------------------------------------------------------------
ALTER TABLE public.graph_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.graph_edges FORCE  ROW LEVEL SECURITY;

DROP POLICY IF EXISTS graph_edges_tenant_isolation ON public.graph_edges;
CREATE POLICY graph_edges_tenant_isolation
    ON public.graph_edges
    FOR ALL
    USING (
        investigation_id IN (
            SELECT investigations.investigation_id
            FROM investigations
            WHERE investigations.tenant_id = get_current_tenant()
        )
    )
    WITH CHECK (
        investigation_id IN (
            SELECT investigations.investigation_id
            FROM investigations
            WHERE investigations.tenant_id = get_current_tenant()
        )
    );

DROP POLICY IF EXISTS graph_edges_insert ON public.graph_edges;
CREATE POLICY graph_edges_insert
    ON public.graph_edges
    FOR INSERT
    WITH CHECK (
        investigation_id IN (
            SELECT investigations.investigation_id
            FROM investigations
            WHERE investigations.tenant_id = get_current_tenant()
        )
    );

COMMIT;

-- =====================================================================
-- NOT applied here: cross-investigation edge integrity.
--
-- graph_edges has NO foreign key tying source_node_id / target_node_id to
-- graph_nodes(investigation_id, node_key), so an edge can name nodes that
-- do not exist or belong to a different investigation. Today that is caught
-- only in application code (PersistentInvestigationStore.add_graph_edge).
--
-- Adding a composite FK would require a unique index on
-- graph_nodes(investigation_id, node_key) -- which already exists as
-- uq_graph_nodes_inv_key -- so the constraint is technically feasible.
-- It is deliberately NOT added in this migration: it is a schema constraint
-- change, not a security-policy change, and existing rows would have to be
-- validated against it first. Tracked as a separate follow-up.
-- =====================================================================