# TrustVault — AI Usage Log & Engineering Prompts

This document tracks AI-assisted development across the 7-day delivery lifecycle of **TrustVault**.
In compliance with project specifications, all logged entries reflect genuine development discoveries, security reviews, and corrections. No mistakes or tests are fabricated.

---

## Reusable System Instructions & Guardrails

When collaborating with AI on TrustVault, the following engineering prompts and constraints are enforced:

1. **Security-First Authority**: The backend is the sole source of truth for authorization. Never trust client-supplied roles, user IDs, or frontend permissions.
2. **Default Deny**: Reject any request unless an explicit ownership or unrevoked grant exists.
3. **Audit Trail Integrity**: Every state-changing and access-evaluation action must record an immutable audit event before returning a response.
4. **Zero Unguessable-ID Relying Security**: Obscurity is not authorization. Even if a document ID is a UUID, full authorization must execute before returning bytes or metadata.
5. **Private Storage Isolation**: Keep stored files strictly outside the web root. Use randomly generated 256-bit keys and enforce path traversal checks.

---

## AI Interaction Log

### Entry 1 (Day 1 — 2026-10-19): Audit Hash Chaining Serialization Failure Across Database Dialects
- **Category**: Cryptographic Audit Integrity / Data Serialization
- **Prompt Summary**: 
  "Implement a tamper-evident audit service using SHA-256 hash chaining (`AuditService.log_event` and `AuditService.verify_chain_integrity`) that calculates record hashes based on sequence, timestamp, actor, action, resource, outcome, request_id, details, and previous_hash."
- **What the AI Produced**:
  An initial implementation of `AuditService.calculate_hash()` that converted timestamps to strings using `datetime.isoformat()`. During record creation, `datetime.now(timezone.utc).isoformat()` generated a timezone-aware ISO string (e.g. `2026-10-19T07:47:53.123456+00:00`).
- **What was Specifically Wrong or Incomplete**:
  When the integration test `test_audit_service_initialization_and_verification` executed, `verify_chain_integrity()` loaded the committed `AuditEvent` back from the database. The database engine (SQLite during local testing, and standard SQL DateTime columns without custom type decorators) returns timestamps as timezone-naive datetime objects. Calling `.isoformat()` on the retrieved object yielded `2026-10-19T07:47:53.123456` (lacking the `+00:00` suffix). This produced an unexpected hash mismatch, erroneously triggering a false-positive `Record tampering detected at sequence 1` assertion failure.
- **What was Changed and How Verified**:
  Created a dedicated, deterministic canonical formatter `AuditService.format_timestamp(dt: datetime) -> str`. It inspects `dt.tzinfo`: if naive, it assigns UTC; if aware, it converts to UTC, and formats explicitly with `%Y-%m-%dT%H:%M:%S.%fZ`. Both `log_event()` and `verify_chain_integrity()` now pass `datetime` objects to `calculate_hash()`, ensuring byte-for-byte serialization identity regardless of database driver quirks. Verified by running `pytest -v`, where both `test_audit_service_initialization_and_verification` and `test_audit_service_detects_tampering` passed successfully.
- **Git Commit**: Commit `631a034` ("feat(core): initialize Day 1 foundation, health check, schema models, and tamper-evident audit service").

---

### [Upcoming Entries for Days 2–7]
- **Entry 2 (Day 2)**: Centralized authorization policy and cross-user grant resolution.
- **Entry 3 (Day 3)**: Private storage streaming size validation and magic byte content sniffing.
- **Entry 4 (Day 4)**: Immediate revocation propagation and race-free permission grants.
- **Entry 5 (Day 5)**: React frontend state synchronization, CSRF cookie handling, and admin activity filtering.
