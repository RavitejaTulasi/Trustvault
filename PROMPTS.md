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

---

### Entry 6 (Day 5 — 2026-10-19): Secure Document Search, Filtering, and Effective-Permission Visibility
- **Category**: Secure Search / Authorization-Scoped Filtering / Effective Permissions
- **Prompt Summary** (abridged from the actual Day 5 prompt):
  "Implement Day 5 secure document search, filtering, and effective-permission visibility. Extend the existing document-list endpoint with title/filename search plus category, owner, and created-date filters; preserve pagination and sorting; enforce owner-or-active-grant visibility before filtering; validate invalid date ranges and malformed parameters; expose a server-derived `owner`/`edit`/`read` effective permission; add security and regression tests; and update API, architecture, threat-model, and prompt-history documentation."
- **What the AI Produced**:
  - Extended `GET /api/v1/documents` with `q`, `category`, `owner_id`, `created_from`, and `created_to` query parameters. Search matches `title` and `original_filename` case-insensitively with parameterized SQLAlchemy expressions.
  - Preserved `created_at` descending sort and existing `page`/`page_size` behavior, with validation for pagination, blank/oversized string filters, malformed datetimes, and reversed date ranges.
  - Applied the owner-or-active-grant visibility scope before all optional filters, so filters can only narrow results. Admin role does not widen visibility.
  - Added `DocumentListItem` with server-derived `effective_permission` (`owner`, `edit`, or `read`) and batched the active-grant lookup for the current page to avoid per-document queries.
  - Added `backend/tests/test_search.py` with 10 tests covering title/filename search, SQL wildcard escaping and injection payloads, category, owner isolation, date ranges, combined filters, effective permissions, revoked/deleted exclusion, admin scope, empty results, and malformed parameters.
  - Updated `docs/API.md`, `docs/ARCHITECTURE.md`, and `THREATS.md`.
- **Issues Discovered and Corrections Made**:
  - `docs/API.md` and the architecture matrix still described search as a separate planned route; corrected to document search on the existing list endpoint and removed the nonexistent `/documents/search` route.
  - Adding `effective_permission` directly to `DocumentResponse` would have changed upload/get/update response contracts unnecessarily; introduced a list-specific `DocumentListItem` schema instead.
  - Raw LIKE input would have treated `%` and `_` as wildcards; escaped them so search terms are literal.
  - Mixed timezone-aware and naive datetimes could fail comparison; normalized both bounds to UTC before validating and querying.
  - No model or migration change was required because `title`, `original_filename`, `category`, `owner_id`, and `created_at` already exist.
- **What was Changed and How Verified**:
  Verified with `pytest backend/tests/ -v`: 69/69 tests passing (59 prior + 10 new). `ruff check .` still reports the same 45 pre-existing findings (38 `B008`, 3 `I001`, 2 `F401`, 1 `BLE001`, 1 `F841`) with no new findings or rule categories.
- **Git Status**: Committed and pushed as [`650acd63d930966d2d2254d3e0dfaeb8a104d9c8`](https://github.com/RavitejaTulasi/Trustvault/commit/650acd63d930966d2d2254d3e0dfaeb8a104d9c8) — "feat(security): add secure document search and effective permissions".

---

### Entry 7 (Day 6 — 2026-10-19): Administrator Audit Inspection, Document Activity, and Hash-Chain Verification APIs
- **Category**: Administrative Audit Visibility / API Security / Integrity Verification
- **Prompt Summary** (abridged from the actual Day 6 prompt):
  "Implement the Day 6 administrator audit-event and document activity-history APIs. Expose a filtered, paginated audit query, a read-only hash-chain verification endpoint, and a document-focused activity endpoint. Restrict all three endpoints to administrators, keep responses free of hash-chain internals and sensitive credentials, validate filters and date ranges, add security and tamper-detection tests, and update the API, architecture, threat-model, and prompt-history documentation. Leave the work uncommitted for review."
- **Final Review Prompt Summary** (abridged):
  "Independently review the uncommitted Day 6 changes for security, correctness, test adequacy, and documentation accuracy. Inspect every change, run the full test suite with warnings as errors, and verify authorization, response shaping, hash verification, caching, and audit coverage claims against the actual repository. If a defect is found, make only a narrow, tested correction. Do not commit or push, and do not start Day 7."
- **What the AI Produced**:
  - Added `backend/app/schemas/audit.py` with `AuditEventResponse`, `AuditEventListResponse`, and `AuditVerificationResponse`.
  - Added `backend/app/api/audit.py` with:
    - `GET /api/v1/admin/audit` for exact actor/action/resource/outcome/time filters and newest-first pagination.
    - `GET /api/v1/admin/audit/verify` as a read-only wrapper around `AuditService.verify_chain_integrity()`.
    - `GET /api/v1/admin/documents/activity` restricted to `document` and `document_grant` events with document, actor, action, outcome, and time filters.
  - Added `Cache-Control: no-store` and `Pragma: no-cache` to all three read-only responses.
  - Wired the router into `backend/app/api/router.py` and exported the schemas from `backend/app/schemas/__init__.py`.
  - Added `backend/tests/test_audit_api.py` with 16 tests covering 401/403 access control, safe response shaping and cache prevention, pagination and ordering, combined and invalid filters, SQL-injection/wildcard handling, document/grant activity correlation, malformed details, default-deny detail redaction, valid and tampered chain verification, altered record hashes, broken previous-hash links, sequence gaps, and separation from document-content authorization.
  - No model or migration change was required because the existing `audit_events` fields and indexes support every new query.
  - Updated `docs/API.md`, `docs/ARCHITECTURE.md`, and `THREATS.md` with the implemented endpoints, actual audit coverage, known gaps, and TV-19.
- **Issues Discovered and Corrections Made**:
  - Grant audit events use the grant row ID as `resource_id`, not the document ID. A document activity filter based only on `resource_id` would omit grant/revoke history; added an OR condition matching the recorded `details.document_id`.
  - `details` is stored as JSON text on the ORM model. The response schema now parses it into an object and returns `null` for malformed or non-object values so a bad row cannot break the endpoint.
  - A raw LIKE pattern for activity correlation would treat `%` and `_` in a supplied document ID as wildcards; escaped all LIKE metacharacters before matching.
  - The first test run emitted Starlette deprecation warnings for `HTTP_422_UNPROCESSABLE_ENTITY`; used a literal `422` status in the new endpoints to avoid the warning without depending on a newly added Starlette constant.
  - `AuditService.verify_chain_integrity()` embeds the stored and computed 64-character hashes in tamper failure messages. Returning that diagnostic verbatim would contradict the endpoint's no-hash-exposure boundary; added full-hash redaction while preserving sequence numbers and failure type.
  - The final independent review found that parsed audit `details` could expose historical document titles, filenames, categories, sizes, and MIME types from upload/delete events through the admin audit and activity endpoints, contradicting the documented no-metadata boundary. Added a default-deny `details` allowlist to `AuditEventResponse`; safe correlation/account-management keys are preserved and every other key, including storage paths/keys, passwords, and tokens, is returned as `[redacted]`. Raw audit rows are unchanged. Added a regression test covering safe, unsafe, nested, and secret-like keys.
  - The same review found that direct service tests did not explicitly cover an altered record hash, a broken previous-hash link, or a sequence gap, although the verifier implements each check and empty-chain/altered-event cases already existed. Added three focused service tests; all now pass.
  - Audit API reads were deliberately not made to append audit events: doing so would create side effects on GET requests, inflate the chain during investigations, and make verification counts unstable. The resulting administrative-read coverage gap is documented instead of claiming complete read auditing.
  - Used `Annotated` FastAPI dependencies in the new endpoints to avoid adding new `B008` lint findings.
- **What was Changed and How Verified**:
  Verified with `pytest backend/tests/ -q`: 85/85 tests passing (69 prior + 16 Day 6 tests: 12 initial + 4 final-review tests). `pytest backend/tests/ -q -W error` also passed 85/85. `ruff check .` still reports the same 45 pre-existing findings (38 `B008`, 3 `I001`, 2 `F401`, 1 `BLE001`, 1 `F841`) with no new findings or rule categories. `git diff --check` reported no whitespace errors, only Git's CRLF conversion warnings.
- **Git Status**: Day 6 changes remain uncommitted and unpushed pending review. No commit hash is recorded because no commit has been created.

---

### Entry 8 (Day 6.1 — 2026-10-19): Bounded Audit-Chain Verification and Abuse Resistance
- **Category**: Resource Exhaustion Protection / Audit Integrity Verification
- **Prompt Summary** (abridged from the actual Day 6.1 prompt):
  "Harden `GET /api/v1/admin/audit/verify` against CPU, memory, database, and request exhaustion while preserving complete and trustworthy integrity verification. Use bounded batching, configurable limits, administrator-scoped rate limiting, explicit incomplete results, and regression tests. Do not change the hash format or historical audit data, and leave all changes uncommitted."
- **Baseline Inspected Before Changes**:
  - HEAD and `origin/main` were both `b8f1992`; the Day 6 changes were still staged and uncommitted.
  - `AuditService.verify_chain_integrity()` executed `list(db.execute(select(AuditEvent).order_by(...)).scalars().all())`, materializing the entire audit chain as ORM objects before hashing any record.
  - The verification endpoint had no record limit, timeout, or request rate limiting, and was protected only by the administrator role check.
  - The existing rate limiter was an in-memory, process-local login limiter keyed by IP and email. No shared/distributed limiter existed.
  - Baseline test result: 85 passed.
- **What the AI Produced**:
  - Added `AuditService.verify_chain_integrity_bounded()`, which captures the current maximum `sequence_number` as a high-water mark and verifies records in ascending keyset batches. Batches select only the columns required for hashing, so the ORM identity map and full chain are not materialized.
  - Added `AuditVerificationResult` with three outcomes: `VALID`, `INVALID`, and `INCOMPLETE`. `VALID` is returned only after every sequence from 1 through the high-water mark is examined.
  - Added configurable limits: `AUDIT_VERIFY_MAX_RECORDS` (default 100000), `AUDIT_VERIFY_BATCH_SIZE` (default 1000), `AUDIT_VERIFY_TIMEOUT_SECONDS` (default 30), `AUDIT_VERIFY_RATE_LIMIT_MAX_REQUESTS` (default 5), and `AUDIT_VERIFY_RATE_LIMIT_WINDOW_SECONDS` (default 60).
  - Added `SlidingWindowRateLimiter`, keyed by administrator user ID, and applied it to the verification endpoint. Rate-limited requests receive `429 Too Many Requests` with `Retry-After` and no-cache headers.
  - Extended `AuditVerificationResponse` with an explicit `status` field while retaining `is_valid`, `records_verified`, and `failure_reason` for compatibility.
  - Kept the existing `verify_chain_integrity()` tuple API as a bounded wrapper so existing service callers and tests retain their contract.
  - Added six tests: empty chain, bounded multi-batch traversal, out-of-range low sequence detection, timeout-driven incomplete verification, chain-exceeds-record-limit incomplete verification, and per-administrator verification rate limiting.
  - Updated `.env.example`, `docs/API.md`, `docs/ARCHITECTURE.md`, and `THREATS.md`.
- **Issues Discovered and Corrections Made**:
  - Loading a full batch and checking the deadline only at the top of the loop could report `INCOMPLETE` after the final batch had already verified the high-water mark. Added an immediate `VALID` return when the last verified sequence reaches the high-water mark.
  - Setting cache headers on the injected `Response` before raising `HTTPException` would not reliably preserve them on the 429 response. Added `Cache-Control: no-store` and `Pragma: no-cache` directly to the rate-limit exception headers.
  - The existing API contract had only `is_valid`, which cannot distinguish tampering from a resource-limited pass. Added `status` rather than overloading `is_valid`; both `INVALID` and `INCOMPLETE` return `is_valid: false`, but only `INVALID` represents an integrity failure.
  - The initial keyset query started after sequence 0, so a tampered row with a non-positive `sequence_number` would never be fetched and could escape detection even though the previous verifier caught it as a sequence gap. Captured `MIN(sequence_number)` alongside the high-water mark and reject any minimum below 1 before batching; added a regression test.
  - The verifier cannot detect deletion of the current tail record when that deletion occurs before the high-water mark is captured, because no external anchor commits to the chain length. This pre-existing hash-chain limitation remains documented as a residual risk rather than being hidden.
  - The new limiter is intentionally process-local. Documentation states that multiple workers or instances multiply the effective limit and that distributed enforcement requires a shared limiter such as Redis.
  - Batch reads use a high-water mark rather than a database-wide repeatable-read snapshot. Concurrent tampering between batch reads may require a re-run during a quiet window; this limitation is documented instead of claiming a fully consistent snapshot.
- **What was Changed and How Verified**:
  - `python -m pytest backend/tests/ -q`: 91 passed (85 prior + 6 new).
  - `python -m pytest backend/tests/ -q -W error`: 91 passed.
  - `python -m ruff check . --statistics`: 45 findings, unchanged from baseline (38 `B008`, 3 `I001`, 2 `F401`, 1 `BLE001`, 1 `F841`).
  - `git diff --check`: no whitespace errors; only Git's expected CRLF conversion warnings.
- **Git Status**: Day 6.1 changes remain uncommitted and unpushed. Day 6 remains staged; no commit hash is recorded because no commit was created.

---

### Entry 9 (Day 6.2 — 2026-10-19): Audit Coverage Completion for Administrative Reads and Upload Denials
- **Category**: Audit Coverage / Security Observability
- **Prompt Summary** (abridged from the actual Day 6.2 prompt):
  "Audit the implementation for security-relevant actions that are not actually covered by audit events. Build a coverage matrix from real code, then implement only the minimum safe changes needed to close the genuine gaps. Do not fabricate coverage claims, do not change the hash format or historical records, do not add external anchoring or frontend work, and leave all changes uncommitted and unpushed pending review."
- **Baseline Inspected Before Changes**:
  - HEAD and `origin/main` were both `ab3a702` (Day 6 `a56d7ac` and Day 6.1 `ab3a702` already pushed). Working tree was clean.
  - Baseline: 91 tests passing; `ruff check . --statistics` reported 45 findings (38 `B008`, 3 `I001`, 2 `F401`, 1 `BLE001`, 1 `F841`).
  - Every `AuditService.log_event` call site was enumerated across `auth.py`, `documents.py`, `users.py`, and `audit.py` and mapped against the review matrix's action list.
- **Coverage Matrix Result**:
  - Covered: authentication (`user.register`, `user.login`, `user.login_failed`, `user.login_rate_limited`, `user.logout`, `user.update`), admin user management (`user.role_change`, `user.deactivate`, `user.reactivate`, `user.sessions_revoked`), document lifecycle success paths (`document.upload`, `document.read`, `document.download`, `document.edit`, `document.delete`), authorization denials on read/download/edit/delete, and sharing (`permission.grant`, `permission.revoke`, `permission.list_denied`).
  - Genuine gaps closed: the three administrator audit/activity reads appended no events, and rejected uploads (role denial, missing filename, invalid extension/magic bytes, empty/oversized files) appended no events.
  - Remaining documented gaps (unchanged, accepted for this milestone): document list/search reads, successful `GET /documents/{id}/permissions` reads, administrative user-list/profile reads, and request-validation failures that occur before an audit call.
- **What the AI Produced**:
  - Added `_record_admin_audit_read()` in `backend/app/api/audit.py`: appends the read event, commits, and fails closed with `503 Audit trail unavailable` (plus no-store headers) on `SQLAlchemyError`, so an administrative read is never served without a persisted audit record.
  - Instrumented the three endpoints: `audit.read` for `GET /admin/audit`, `audit.verify` for `GET /admin/audit/verify` (details record the allowlisted `verification_status`), and `audit.activity_read` for `GET /admin/documents/activity`. All use `resource_type` `audit`, the admin's actor ID, client IP, user agent, and request ID.
  - Instrumented rejected uploads in `backend/app/api/documents.py` as `document.upload` with `DENIED` and an allowlisted `details.reason`: `insufficient_role`, `missing_filename`, `invalid_upload`, or `size_limit_exceeded`.
  - Added `verification_status` to the `SAFE_DETAIL_KEYS` allowlist in `backend/app/schemas/audit.py`; nothing else in the allowlist changed.
  - Added seven tests and extended six existing ones: administrative reads audited exactly once with correct actor/outcome/resource type; `verification_status` visible through the API allowlist; all three endpoints fail closed per-path when audit persistence fails; a flushed-but-uncommitted read event is rolled back after a simulated persistence failure and the session remains usable; viewer upload denial audited without a false success; invalid and empty uploads now assert exactly one `DENIED` event each with no `SUCCESS` upload event; tamper, incomplete, rate-limit, and non-admin tests now assert event counts and outcomes, including that `429` responses append nothing and the tamper test still proves the chain is never repaired.
  - Updated `docs/API.md`, `docs/ARCHITECTURE.md`, and `THREATS.md` (TV-12, TV-13, TV-19) and this entry. `THREATS.md` TV-12 notes the read-event tradeoff honestly, and TV-19's residual risk now states that read auditing increases audit-log volume during investigations.
- **Issues Discovered and Corrections Made**:
  - Day 6 deliberately avoided appending audit events from audit GET endpoints because it could inflate the chain during investigations. Day 6.2 reverses that decision only for read auditing, with an explicit fail-closed policy, explicit documentation of the log-volume tradeoff, and tests proving rate-limited and denied requests append nothing.
  - The `audit.verify` read event is appended only after a verification pass completes, so it can never inflate that pass's `records_verified`; the valid-chain test still expects `records_verified == total` with no change.
  - The tamper test previously asserted an exact audit-row count. It now expects `+1` (the single `audit.verify` read event), still refreshes the tampered row, and keeps the no-repair invariant, rather than deleting the count assertion.
  - Touching `status.HTTP_413_REQUEST_ENTITY_TOO_LARGE` in the new upload-denial path emitted a Starlette deprecation warning; used `HTTP_413_CONTENT_TOO_LARGE` (same code) instead.
  - The fail-closed `HTTPException` cannot inherit the endpoint's injected `Response` headers, so the `503` carries its own `Cache-Control: no-store` and `Pragma: no-cache` headers, consistent with the Day 6.1 rate-limit fix.
  - The fail-closed tests trigger a real session `rollback()` in the request path, which surfaced `SAWarning: transaction already deassociated from connection` at fixture teardown. Root cause: the test fixture joins its session to a pre-existing connection transaction using the effective `rollback_only` mode, so a legitimate application rollback ends that shared transaction and deactivates the fixture's `Transaction` handle; teardown then rolled back the deactivated handle. This is a test-fixture artifact, not a production transaction-management defect, because production `get_db` uses a fresh session per request. Fixed in `backend/tests/conftest.py` by making the join mode explicit and rolling back only when the fixture transaction is still active. An initial attempt to use `create_savepoint` made isolation worse: with pysqlite's legacy transactional mode and the StaticPool test engine, no explicit `BEGIN` precedes `SAVEPOINT`, so releasing the outermost savepoint commits and data leaked across tests; that change was reverted.
- **What was Changed and How Verified**:
  - `python -m pytest backend/tests/ -q`: 98 passed (91 prior + 7 new).
  - `python -m pytest backend/tests/ -q -W error`: 98 passed with no warnings.
  - `python -m ruff check . --statistics`: 45 findings, unchanged from baseline with no new rules or categories.
  - `git diff --check`: no whitespace errors; only Git's expected CRLF conversion warnings.
- **Git Status**: Committed as `1ab85ab` (`feat(security): audit administrative reads and rejected uploads (Day 6.2)`) and pushed to `origin/main` on 2026-10-19 (`ab3a702..1ab85ab`).
