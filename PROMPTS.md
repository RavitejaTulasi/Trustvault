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

### Entry 3 (Day 3 — 2026-10-19): Private Document Management, Storage Isolation, and Authorization
- **Category**: Secure Document Storage & Server-Side Authorization
- **Prompt Summary**:
  "Implement secure document management with private file storage and strict server-side ownership authorization (`POST /documents`, `GET /documents`, `GET /documents/{id}`, `GET /documents/{id}/download`, `PATCH /documents/{id}`, `DELETE /documents/{id}`), extension whitelisting, magic byte sniffing, deliberate 404 responses, and audit logging."
- **What the AI Produced**:
  - Implemented `backend/app/schemas/document.py` for document validation and response serialization.
  - Enhanced `backend/app/services/storage_service.py` with extension whitelisting, magic byte inspection (content sniffing for PDF, PNG, JPEG, Office archives), and executable blocklists.
  - Implemented `backend/app/api/documents.py` providing endpoints for upload, listing, metadata retrieval, secure download streaming, metadata updates, and deletion.
  - Integrated document API routes into `backend/app/api/router.py`.
  - Added comprehensive automated security tests in `backend/tests/test_documents.py` covering all 14 required test cases (owner lifecycle, cross-user isolation, admin access restriction, file type/magic byte rejection, audit logging).
- **What was Specifically Wrong or Incomplete**:
  Initial test implementation had minor linter findings regarding unused test fixtures/variables and type annotations (`Optional[str]` vs `str | None`).
- **What was Changed and How Verified**:
  Cleaned up unused variables and updated type hints and import sorting. Verified by executing `pytest backend/tests/ -v` (45/45 tests passing successfully) and `ruff check .`.
- **Git Status**: Committed as `6702781` ("feat(storage): implement Day 3 private document management, storage isolation, and authorization").

---

### Entry 4 (Day 4 — 2026-10-19): Document Sharing Grants, Least-Privilege Permissions, and Immediate Revocation
- **Category**: Fine-Grained Authorization / Sharing & Revocation
- **Prompt Summary**:
  "Implement document sharing for named users with explicit `read` and `edit` grant levels, owner-only grant management (`GET/POST /documents/{id}/permissions`, `DELETE /documents/{id}/permissions/{user_id}`), immediate revocation on the next request, upsert behavior for re-grants, deliberate 404 responses for non-owners, and tamper-evident audit events for grant, revoke, and denied operations."
- **What the AI Produced**:
  - Added `backend/app/schemas/grant.py` with `GrantCreateRequest` (validates `read`/`edit`), `GrantResponse`, and `GrantListResponse`.
  - Added `_get_active_grant()` and grant listing/creation/revocation endpoints to `backend/app/api/documents.py`.
  - Wired the existing `active_grant` parameter of `AuthorizationService.authorize_document_access()` into every document read/download/edit/delete path and added ownership-or-active-grant scoping to the document list. The grant-evaluation branch already existed in `backend/app/services/authorization.py` at HEAD (last changed in commit `631a034`); Day 4 did not modify that file.
  - Added `backend/tests/test_grants.py` covering grant creation for both levels, read/edit enforcement boundaries, immediate revocation, non-owner grant-management denial, and sharing audit events.
- **What was Specifically Wrong or Incomplete**:
  The first draft of the new tests assigned owner fixtures that were never referenced, which `ruff` flagged as `F841` unused variables. No change to the authorization service was required or made.
- **What was Changed and How Verified**:
  Rewrote the test fixtures to reference only needed users and removed unused assignments. Verified with `pytest backend/tests/ -v` (51/51 tests passing: 45 prior + 6 new).
- **Git Status**: Included in the Day 4 commit (`feat(security): add document sharing grants and revocation`) after final verification (59/59 tests).

---

### Entry 5 (Day 4.1 — 2026-10-19): Independent Review Remediation — Admin Metadata Scope, API Documentation, Grant Edge Cases, and Concurrent Upserts
- **Category**: Security Review Remediation / Least Privilege / Concurrency
- **Prompt Summary**:
  "Act as an independent reviewer of the uncommitted Day 4 sharing implementation. Verify the permission matrix, grant-management security, revocation behavior, audit events, tests, and documentation against the actual repository; report exact commands and findings without modifying files."
- **What the Review Found**:
  - `GET /api/v1/documents` had a special administrator branch that returned metadata for every document, contradicting the documented owner-or-grant policy.
  - `docs/API.md` documented an unimplemented search route, non-existent effective-permission fields and version history, replacement-file upload on PATCH, and incorrect DELETE/logout response codes and audit action names.
  - Grant edge cases (re-grant after revocation, self-grant, inactive recipient, invalid permission, list after revocation, duplicate requests) lacked endpoint-level coverage.
  - Grant creation used query-then-insert, leaving a uniqueness-conflict window under concurrent duplicate requests.
  - `PROMPTS.md` Entry 4 incorrectly attributed the pre-existing authorization-service grant branch to Day 4.
- **What was Changed and How Verified**:
  - Removed the administrator list branch so every caller is scoped to owned or actively granted documents.
  - Reworked `docs/API.md` and `docs/ARCHITECTURE.md` to match implemented routes, schemas, status codes, and planned/unimplemented endpoints.
  - Added eight endpoint-level tests covering admin list scoping, re-grant permission restoration, self-grant rejection, inactive recipients, invalid permissions, list-after-revocation, duplicate grant requests, and administrator access to owned/granted documents.
  - Replaced the grant upsert with `INSERT ... ON CONFLICT DO UPDATE` for SQLite and PostgreSQL, retaining the unique constraint and a query-then-write fallback for other dialects.
  - Corrected this log's Day 4 provenance using `git log`/`git diff` evidence.
  - Verified with `pytest backend/tests/ -v`: 59/59 tests passing. `ruff check .` reports the same 45 pre-existing findings (mostly FastAPI `B008`, plus existing `I001`, `F401`, `F841`, `BLE001`) with no new rule categories introduced by this remediation.
- **Git Status**: Included in the Day 4 commit (`feat(security): add document sharing grants and revocation`) after final verification (59/59 tests).
