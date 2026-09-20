# Risk Assessment — SafeNestT

**Status:** Draft — review and re-score before adoption. Likelihood/impact ratings below are a
starting point, not a final assessment.

## Purpose

Identifies and prioritizes risks specific to a multi-tenant platform handling real fraud
investigation data, PII, and financial identifiers for individual clients, law firms, and banks.

## Risk register

| Risk | Likelihood | Impact | Current mitigation | Residual risk |
|---|---|---|---|---|
| Cross-tenant data exposure via the confirmed `app.current_tenant_id` bypass | High (confirmed exploitable path exists today) | Critical — direct breach of client fraud case data across tenants, including banks/law firms | RLS policies exist at DB level but the bypass defeats them; app-layer checks are not sufficient on their own | **Critical — treat as the top open risk until closed** |
| Encryption key compromise or weak-key acceptance | Medium | Critical — all Restricted-classification data readable | Fernet encryption implemented, but weak/default keys are still accepted in production | High until key validation is fixed |
| API key compromise | Medium | High — impersonation of a tenant/client, potential access to that tenant's cases | Keys exist, but hashing/timing-safe comparison and cleartext-revoked-key issues are unresolved | High |
| Multi-worker rate-limit bypass enabling abuse or credential stuffing | Medium | Medium | Per-key limiting exists but is process-local | Medium |
| Free-tier LLM vendor (OpenRouter) data retention beyond SafeNestT's control | Medium | Medium–High depending on retention terms, since investigation inputs pass through it | No documented DPA yet | Medium — see `vendor-management.md` |
| Broken CI vulnerability scanning (pip-audit not actually enforced, packaging broken) | Medium | Medium — known-vulnerable dependencies could ship undetected | pip-audit configured but not currently reliable | Medium |
| No documented backup/restore process | Medium | High — case data loss for active fraud investigations with real financial and legal stakes | None documented | High until backups are tested |
| Single point of accountability (small team) for incident response and security ownership | Low–Medium | Medium | Documented in `incident-response-plan.md` | Acceptable for current scale; revisit as team grows |

## Risk-specific context

SafeNestT is not a typical SaaS risk profile: the data involved is used in active IC3/FBI
submissions and real financial recovery cases, and clients include banks and law firms with their
own regulatory obligations (e.g., GLBA for banking clients). A breach here has legal and
reputational consequences beyond the usual SaaS calculus — this should weight prioritization toward
closing the tenant-isolation and encryption gaps before anything else, including before spending
further time on audit logistics.

## Review cadence

Re-score this register whenever a `gap-analysis.md` item changes status, and at minimum annually.

**Owner:** Ronzoro (Moussa Adam), SafeNestT
**Next review date:** _fill in_
