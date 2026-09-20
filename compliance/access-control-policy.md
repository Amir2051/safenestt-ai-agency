# Access Control Policy — SafeNestT

**Status:** Draft — review before adoption.

## Purpose

Defines how access to SafeNestT systems and data is granted, enforced, reviewed, and revoked.

## Principles

- **Least privilege:** Every identity (human or service) gets the minimum access needed for its
  function, nothing more.
- **Tenant isolation is a hard boundary:** No client, employee, or service account may access data
  belonging to a tenant it isn't scoped to, enforced at the database layer via Row Level Security,
  not only in application logic. (Current status: **Not Met** — see `gap-analysis.md`; the
  `safenestt_app` role can currently override `app.current_tenant_id`. This must be closed before
  this policy can be represented as implemented.)
- **Separation of duties:** The role used by the running API must never hold database-owner
  privileges. A separate, more privileged role is used only for migrations, run outside the
  request path.

## Database roles

| Role | Privileges | Used by |
|---|---|---|
| `safenestt_app` | Row-level-scoped SELECT/INSERT/UPDATE per RLS policy; INSERT-only on `audit_events` (no UPDATE/DELETE) | Running API service |
| Owner/migration role | Full schema privileges | Migration process only, never the live API |

## API key management

- Keys are issued per tenant/client.
- Keys must be hashed at rest and compared using a timing-safe method — **currently not met**; see
  `gap-analysis.md`. Do not adopt this policy as "in effect" until the underlying comparison is
  fixed.
- Revoked keys are marked revoked and rejected, never left readable in cleartext.
- Keys carry an expiry and can be rotated without downtime.
- Rate limits are enforced per key; limits must hold across all worker processes, not reset per
  process (**currently partial** — see `gap-analysis.md`).

## Provisioning and deprovisioning

- Access is granted only after a documented request/approval (even informal, e.g. a written note
  or ticket, for a small team — the point is a record exists).
- Access is revoked immediately on role change or departure; API keys tied to a departing
  client/employee are revoked, not merely deactivated by convention.

## Access review

- Review who/what has standing production access at least quarterly.
- Review the list of active API keys and their scopes at the same cadence.

## Enforcement evidence

Access control effectiveness is demonstrated through:
- Automated tests: `tests/test_tenant_isolation.py`, `tests/test_api_key_lifecycle.py`,
  `tests/test_rate_limiting.py`.
- The tamper-evident audit log (`audit_events` table, hash-chained).
- RabbitCode's independent re-verification results, tracked in `gap-analysis.md`.

**Owner:** Ronzoro (Moussa Adam), SafeNestT
**Next review date:** _fill in_
