# Incident Response Plan — SafeNestT

**Status:** Draft — review before adoption.

## Purpose

Defines how SafeNestT detects, contains, investigates, and reports security incidents, including
any that involve client fraud-case data or personal information.

## What counts as an incident

- Unauthorized access to, or disclosure of, Restricted or Confidential data (see
  `information-security-policy.md` for classification).
- Cross-tenant data exposure of any kind, including near-misses caught in testing.
- Compromise of encryption keys, API keys, or database credentials.
- Any finding from independent verification (RabbitCode) that identifies a live exploitable gap
  rather than a code-quality issue — these should trigger this plan's containment steps, not just
  a backlog ticket, until the exploitability is ruled out.

## Response phases

### 1. Detection
- Sources: audit log anomalies, RabbitCode findings, automated test failures on
  `test_tenant_isolation.py` / `test_encryption.py` / `test_api_key_lifecycle.py`, direct report.

### 2. Triage and containment
- Determine scope: which tenant(s), what data classification, how long the exposure window was.
- If a live exploitable gap (e.g., the current tenant-isolation bypass) is confirmed in production,
  contain first — restrict the affected access path or take the affected endpoint offline — before
  continuing investigation.

### 3. Investigation
- Use the audit log's hash-chain to establish what actually happened (its tamper-evidence is the
  reason this control matters for incident response specifically, not just compliance checkbox).
- Identify root cause and whether it was previously flagged (check `gap-analysis.md` history).

### 4. Notification
- Determine legal notification obligations: state breach-notification laws apply given SafeNestT
  holds real PII and financial data; bank/institutional clients may have contractual notification
  windows tighter than statutory minimums. Get counsel involved before external notification for
  anything beyond a contained internal near-miss.
- Notify affected tenants per contractual SLA once scope is confirmed.

### 5. Remediation and post-incident review
- Fix must be independently re-verified (RabbitCode) before being considered closed — self-report
  alone does not close an incident, consistent with the standing change-management process.
- Update `gap-analysis.md` and this plan with what was learned.

## Roles

- **Incident owner:** Ronzoro (Moussa Adam) — single point of accountability given current team
  size. Revisit as the team grows.

## Testing this plan

- Review annually, or after any incident, or after any material architecture change.
- A tabletop walkthrough (even solo, working through "what would I actually do if X happened")
  counts as a documented test for audit purposes — record the date and scenario when done.

**Owner:** Ronzoro (Moussa Adam), SafeNestT
**Next review date:** _fill in_
