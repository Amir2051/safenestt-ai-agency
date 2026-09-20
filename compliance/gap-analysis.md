# SOC 2 Gap Analysis — SafeNestT AI Engine

**Last updated:** 2026-09-20
**Source of truth for status:** RabbitCode independent cold-read verification, not Hermes
self-reports. Hermes has produced "VERIFIED" claims in three consecutive rounds that RabbitCode's
independent re-check found substantially overstated — so this tracker only marks something Met
once RabbitCode has confirmed it against the actual pushed commit.

Status legend: **Met** (independently confirmed) · **Partial** (implemented but with a known
bypass or untested path) · **Not Met** (claimed but disproven, or not attempted) · **Not Started**

## Security (CC — Common Criteria)

| Control | SOC 2 Criteria | Status | Evidence / Gap |
|---|---|---|---|
| Tenant data isolation | CC6.1 Logical Access | **Not Met** | DB-level RLS policies exist, but the `safenestt_app` role can arbitrarily set `app.current_tenant_id`, allowing cross-tenant reads/writes. This is the single highest-priority item — it's the core promise of a multi-tenant platform. |
| Encryption at rest | CC6.1, CC6.7 | **Partial** | Fernet encryption implemented on all sensitive columns (`investigations.target`, `agent_runs.inputs/outputs`, `findings.claim`, `evidence.data`, `reports.draft`). Production still accepts weak/default/all-zero/repeated-byte encryption keys — key validation needs to actually reject these, not just claim to. |
| Encryption in transit | CC6.7 | **Partial** | Code supports `sslmode=verify-full`. Live PostgreSQL instance has no SSL enabled; the SSL-enabled docker-compose stack has commented-out volume mounts and isn't actually startable. |
| Authentication (API keys) | CC6.1, CC6.6 | **Not Met** | Claimed as hashed-at-rest with timing-safe comparison; verified to actually use plain dict membership, with revoked keys stored in cleartext. |
| Rate limiting | CC6.6, CC7.2 | **Partial** | Per-key limiting confirmed, but counters are process-local — ineffective the moment the app runs multi-worker, which production will. |
| Audit logging (tamper evidence) | CC7.2, CC7.3 | **Likely Met — re-verify after latest changes** | Hash-chain design (`chain_hash = SHA256(previous_hash + event_data)`), insert-only DB role with UPDATE/DELETE revoked. Structurally sound at last independent look; re-confirm against current commit before relying on it. |
| Dependency / vulnerability management | CC7.1 | **Not Met** | `pip-audit` added to CI but packaging is broken: missing declared dependencies (`ddgs`, `starlette`), lockfile references the wrong commit via SSH, Docker build fails. A broken build pipeline means the vulnerability scan isn't actually running against what ships. |
| Privileged access separation | CC6.1, CC6.3 | **Not Met** | API containers were found retaining DB-owner credentials, which can bypass RLS entirely — the fix (separate `migrate` service as owner, API restricted to `safenestt_app`) was claimed but not yet independently confirmed on the latest commit. |
| Change management | CC8.1 | **Exists informally — needs to be written up** | The Hermes-builds / RabbitCode-independently-verifies loop is a real control and good practice, but it isn't documented as a formal policy anywhere. Auditors want to see the process on paper, not just observe it happening. |

## Availability (A)

| Control | Status | Gap |
|---|---|---|
| Backup and recovery | **Not Started** | No documented backup schedule, retention policy, or restore test on record. |
| Monitoring / alerting | **Not Started** | No alerting specifically on the tenant-isolation boundary or on repeated auth failures. |

## Confidentiality (C)

| Control | Status | Gap |
|---|---|---|
| Data classification | **Not Started** | No written classification of what counts as sensitive (case data, PII, financial identifiers) vs. non-sensitive. |
| Subprocessor/vendor review | **Not Started** | OpenRouter, DeHashed, and the VPS host have no documented due-diligence or data-handling review. See `vendor-management.md`. |

## Organizational (CC1 — Control Environment)

| Control | Status | Gap |
|---|---|---|
| Written information security policy | **Not Started** | Draft in `information-security-policy.md` — needs review and adoption. |
| Access provisioning/deprovisioning procedure | **Not Started** | Draft in `access-control-policy.md`. |
| Incident response plan | **Not Started** | Draft in `incident-response-plan.md`. |
| Risk assessment | **Not Started** | Draft in `risk-assessment.md`. |

## Priority order

1. Tenant isolation bypass (`app.current_tenant_id`) — this alone would fail an audit and is a live
   data-breach risk today, not just a paperwork gap.
2. Encryption key validation (reject weak/default keys in production).
3. API key storage and verification (hash at rest, timing-safe compare, no cleartext revoked keys).
4. Fix the packaging/build pipeline so CI's `pip-audit` is actually scanning what ships.
5. Privileged DB credential separation (confirm API containers never hold owner creds).
6. Everything else in this table, then the five policy documents.
