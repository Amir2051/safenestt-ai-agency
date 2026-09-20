# Vendor / Subprocessor Management — SafeNestT

**Status:** Draft — review before adoption. Fill in the blanks below with actual due-diligence
findings before treating this as a completed control.

## Purpose

Tracks third parties that process, store, or could access SafeNestT data, and the review applied
to each — a required control area for SOC 2 (vendors are in scope because a breach at a
subprocessor is a breach of your data too).

## Current subprocessors

| Vendor | Role | Data exposure | Data Processing Agreement on file? | Notes |
|---|---|---|---|---|
| OpenRouter | LLM inference for investigation agents | Investigation inputs/outputs pass through their API (currently free-tier models) | _fill in_ | Plan to move to paid models once SafeNestT has paying clients on this engine — revisit vendor terms at that transition, since paid tiers often have different data-retention terms than free tiers. |
| DeHashed | Breach-data lookups for OSINT | Search queries (may include investigation targets) | _fill in_ | Integration is designed to gracefully skip when unavailable — confirm this also means no query is sent/logged on skip. |
| VPS host | Infrastructure hosting the monorepo, database, and application | Full access to encrypted-at-rest and (briefly) decrypted data in memory during processing | _fill in_ | Confirm host's own security posture, backup practices, and data-center jurisdiction. |
| Future: KMS provider (AWS SSM / GCP Secret Manager) | Encryption key management, per the documented upgrade path | Encryption keys | Not yet in use | Evaluate when moving off env-var key storage. |

## Review process

- Before onboarding a new vendor with access to Restricted or Confidential data, confirm: (1) they
  have a written security policy or SOC 2/ISO certification of their own, (2) a data processing
  agreement is signed, (3) their data retention and deletion terms are compatible with SafeNestT's
  obligations to tenants.
- Review this list at least annually, and immediately after any vendor's own publicized security
  incident.

## Notes on free-tier services specifically

Free-tier API services (currently OpenRouter) often have looser data-retention and logging
guarantees than paid tiers. Before scaling client volume on any free-tier dependency, confirm in
writing what the provider does and doesn't retain — this is worth resolving before, not after, the
first paying client's real case data flows through it.

**Owner:** Ronzoro (Moussa Adam), SafeNestT
**Next review date:** _fill in_
