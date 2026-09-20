# Information Security Policy — SafeNestT

**Status:** Draft — review before adoption. Do not represent any control below as "in place" to an
auditor, client, or partner until it matches `gap-analysis.md`.

## Purpose

This policy establishes SafeNestT's approach to protecting the confidentiality, integrity, and
availability of client fraud-investigation data, case evidence, and personal information handled
by the platform.

## Scope

Applies to the SafeNestT AI Engine (multi-tenant investigation platform), its infrastructure (VPS
hosting, PostgreSQL, Docker), and any personnel or automated agents (including Hermes) with access
to production systems or data.

## Data classification

- **Restricted:** Case evidence, investigation targets, fraud victim PII, financial identifiers,
  crypto wallet/transaction data tied to a specific investigation.
- **Confidential:** Client account information, API keys, encryption keys, audit logs.
- **Internal:** Architecture documentation, non-production configuration.
- **Public:** Marketing materials, published documentation.

Restricted and Confidential data must be encrypted at rest and in transit (see Encryption below)
and must never appear in logs, error messages, or version control.

## Access control

Governed in detail by `access-control-policy.md`. Summary principles:

- Access is granted on a least-privilege, need-to-know basis per tenant.
- Tenant isolation is enforced at the database layer (Row Level Security), not only in application
  code — see `gap-analysis.md` for current status of this control.
- All production access is logged in the tamper-evident audit chain.

## Encryption

- Restricted-classification data is encrypted at rest (Fernet symmetric encryption).
- Encryption keys are managed via environment variables today, with a documented upgrade path to
  Docker secrets → AWS SSM → GCP Secret Manager as the platform scales.
- Weak, default, or predictable encryption keys must be rejected outright in production — this is
  a currently open gap, not yet a met control.
- Database connections use TLS (`sslmode=verify-full` in code); production infrastructure must
  actually have SSL enabled to match.

## Change management

- All production changes go through the standing build/verify loop: Hermes implements, RabbitCode
  independently re-verifies from a cold read of the actual pushed commit before any change is
  considered done.
- No change is marked complete based on a self-report alone.

## Vulnerability management

- Dependency vulnerabilities are scanned via `pip-audit` in CI.
- CI must fail the build on a detected vulnerability (not silently continue) — see `gap-analysis.md`
  for current status.

## Incident response

Governed by `incident-response-plan.md`.

## Personnel

- SafeNestT is currently operated by a small team; this policy applies equally regardless of team
  size. As headcount grows, add role-based training and onboarding/offboarding checklists here.

## Policy review

This policy is reviewed and updated at minimum annually, or after any material change to the
platform's architecture, data handling, or a security incident.

**Owner:** Ronzoro (Moussa Adam), SafeNestT
**Next review date:** _fill in_
