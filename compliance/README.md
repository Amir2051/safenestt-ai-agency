# SafeNestT Compliance Program

This directory tracks SafeNestT's path to SOC 2 (and adjacent regulatory) readiness. It exists
alongside the code, not instead of it — SOC 2 auditors test whether these policies match what the
system actually does, so every claim in here has to stay in sync with the verified state of the
platform (see `gap-analysis.md`, which is sourced from the RabbitCode independent-verification
findings, not from self-reported "VERIFIED" status).

## Files in this directory

| File | Purpose |
|---|---|
| `gap-analysis.md` | Control-by-control tracker mapped to SOC 2 Trust Services Criteria. Status reflects independently-verified state, not developer self-report. |
| `information-security-policy.md` | The top-level written policy SOC 2 requires — access control, encryption, data classification, acceptable use. |
| `access-control-policy.md` | Who can access what, how access is granted/revoked, and how that's enforced technically (RLS, API keys). |
| `incident-response-plan.md` | What happens when something goes wrong — detection, containment, notification obligations. |
| `vendor-management.md` | Subprocessor list (OpenRouter, DeHashed, hosting) and what due diligence exists for each. |
| `risk-assessment.md` | Documented risks specific to a fraud-investigation platform handling PII and financial data. |

## Scope decision

- **Trust Services Criteria in scope:** Security (mandatory), Confidentiality (given fraud case
  data and client PII), Privacy (recommended given individual consumer fraud victims as data
  subjects — decide once counsel weighs in).
- **Type I vs Type II:** Target Type I first (point-in-time control design). Type II requires the
  controls to operate correctly for a 3–6 month observation window, so that clock starts only once
  the gap analysis shows everything closed, not partial.
- **Adjacent frameworks to track alongside SOC 2:** GLBA Safeguards Rule (relevant because bank
  clients will expect it — overlaps heavily with SOC 2 Security), and state breach-notification
  laws (apply regardless of certification status).

## How to use this

1. Read `gap-analysis.md` first. Anything marked "Not Met" or "Partial" blocks a real audit —
   treat those as the backlog, not the policy docs.
2. The policy documents (`information-security-policy.md`, `access-control-policy.md`,
   `incident-response-plan.md`, `vendor-management.md`, `risk-assessment.md`) are drafts based on
   what's actually built. Review and edit them — a policy that overstates reality is worse than no
   policy, since an auditor tests the gap between the two directly.
3. Once RabbitCode confirms a gap-analysis item is closed, update its status and evidence pointer
   in `gap-analysis.md` in the same commit as the fix — that pairing is itself useful audit
   evidence of a working change-management process.
