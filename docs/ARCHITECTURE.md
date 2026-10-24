# TrustVault — Architecture & Security Specification

TrustVault is a secure document sharing platform designed with a primary focus on authorization correctness, private storage isolation, and a verifiable, tamper-evident audit trail.

---

## 1. System Overview & Core Principles

TrustVault is engineered around five mandatory security pillars:

1. **Default-Deny Authorization**: Every protected operation denies access unless an explicit ownership relation or active, unrevoked grant is confirmed in the current transaction.
2. **Server-Side Trust Boundary**: Frontend checks exist solely for user interface ergonomics. The backend is the sole authority; client-supplied role parameters or user IDs are rejected.
3. **Storage Decoupling**: Stored files are kept strictly outside the web server root. Physical file paths are generated via 256-bit unguessable random keys and are never exposed to clients.
4. **Immediate Revocation**: No cached authorization tokens or long-lived download URLs are used. When an access grant is revoked, the very next download or read attempt is blocked.
5. **Tamper-Evident Auditability**: Every instrumented authentication, state-changing, document access, access-denial, and administrative audit-read action produces a cryptographically hash-chained audit record. HMAC-protected local-file checkpoints record verified chain heads, but share the application host and are not independent. The exact recorded actions and the remaining gaps are listed in Section 5.

---

## 2. Role & Permission Matrix

TrustVault enforces three distinct roles, with fine-grained document-level permission overrides.

### Role Definitions

- **Administrator**: Responsible for platform governance, user lifecycle management, and security audit investigations.
  * *Critical Rule*: Administrators are **NOT** superusers with automatic bypass to document metadata or contents. Administrators see only documents they own or are explicitly granted by an owner, and they cannot read or download other users' documents without such a grant.
- **Document Owner**: Users who upload documents. Document owners have exclusive control over their documents (read, download, edit, delete, grant permissions, revoke permissions, and view document-specific audit history).
- **Viewer**: Read-only or read/edit participants who have been explicitly granted access to specific documents. Viewers cannot upload documents, delete documents, or grant permissions to others.

### Complete Permission Matrix

| Operation / Capability | Administrator | Document Owner (Own Docs) | Viewer (Granted 'edit') | Viewer (Granted 'read') | Unrelated User / Public |
|---|---|---|---|---|---|
| **System Health (`GET /health`)** | Yes | Yes | Yes | Yes | Yes (Public probe) |
| **User Authentication (`POST /auth/login`, `logout`)** | Yes | Yes | Yes | Yes | Yes (Public endpoint) |
| **Manage Users (`GET/PATCH /admin/users`, revoke sessions)** | **Yes** | No (403 Forbidden) | No (403 Forbidden) | No (403 Forbidden) | No (401 Unauthorized) |
| **System-wide Audit Trail (`GET /admin/audit`)** | **Yes** (read-only) | No (403 Forbidden) | No (403 Forbidden) | No (403 Forbidden) | No (401 Unauthorized) |
| **Verify Audit Hash Chain (`GET /admin/audit/verify`)** | **Yes** (read-only) | No (403 Forbidden) | No (403 Forbidden) | No (403 Forbidden) | No (401 Unauthorized) |
| **Document Activity History (`GET /admin/documents/activity`)** | **Yes** (read-only) | No (403 Forbidden) | No (403 Forbidden) | No (403 Forbidden) | No (401 Unauthorized) |
| **Create/Inspect Audit Checkpoints (`POST/GET /admin/audit/checkpoints`)** | **Yes** | No (403 Forbidden) | No (403 Forbidden) | No (403 Forbidden) | No (401 Unauthorized) |
| **Verify Audit Checkpoint (`GET /admin/audit/checkpoints/verify`)** | **Yes** (read-only) | No (403 Forbidden) | No (403 Forbidden) | No (403 Forbidden) | No (401 Unauthorized) |
| **Upload New Document (`POST /documents`)** | **Yes** (creates an admin-owned document) | **Yes** | No (403 Forbidden) | No (403 Forbidden) | No (401 Unauthorized) |
| **List Documents (`GET /documents`)** | Own/granted only | Own docs only | Granted docs only | Granted docs only | No (401 Unauthorized) |
| **Read Document Metadata (`GET /documents/{id}`)** | Own/granted only | **Yes** | **Yes** | **Yes** | No (401/404 Deliberate) |
| **Download Document Bytes (`GET /documents/{id}/download`)** | Own/granted only | **Yes** | **Yes** | **Yes** | No (401/404 Deliberate) |
| **Edit Document Metadata (`PATCH /documents/{id}`)** | Own/granted only | **Yes** | **Yes** | No (404 Deliberate) | No (401/404 Deliberate) |
| **Delete Document (`DELETE /documents/{id}`)** | Own only | **Yes** (Owner only) | No (404 Deliberate) | No (404 Deliberate) | No (401/404 Deliberate) |
| **Grant Access to Named User (`POST /documents/{id}/permissions`)**| Own only | **Yes** (Owner only) | No (404 Deliberate) | No (404 Deliberate) | No (401/404 Deliberate) |
| **Revoke Access (`DELETE /documents/{id}/permissions/{user_id}`)** | Own only | **Yes** (Owner only) | No (404 Deliberate) | No (404 Deliberate) | No (401/404 Deliberate) |
| **View Document Permissions (`GET /documents/{id}/permissions`)** | Own only | **Yes** (Owner only) | No (404 Deliberate) | No (404 Deliberate) | No (401/404 Deliberate) |
| **Search/Filter Documents (`GET /documents?q=...`)** | Own/granted only | **Yes** (own docs) | **Yes** (granted docs) | **Yes** (granted docs) | No (401 Unauthorized) |

Search, category, owner, and created-date filters are AND-combined and are applied only after the ownership/active-grant visibility condition. A filter can narrow the result set but cannot widen document access. Each list item includes a server-derived `effective_permission` of `owner`, `edit`, or `read`; revoked grants do not confer access or permission.

**Note on Administrative Access**: If an administrator needs access to a document for legal discovery, an explicitly logged owner grant is currently required. A dedicated administrative delegation/reassignment workflow is not implemented in the current build. Administrators cannot silently browse or download user documents through the admin role.

### Sharing and Revocation Semantics

Grant rows carry an internal, monotonic `revocation_version` that only revocation increments. Grant creation captures the recipient's current generation before authorization, then performs a conditional upsert (`ON CONFLICT DO UPDATE ... WHERE revocation_version = :expected`). Zero affected rows means the generation changed while the request was in flight, so the request returns `409 Conflict` and records `permission.grant` with `FAILURE` and an allowlisted `reason` (`revoked_concurrently`, or `concurrent_update` when the row disappeared). This makes revocation win against a grant request that began before it, even when a later re-grant has already made the row active again.

Concurrent grant requests with no intervening revocation remain last-writer-wins, and the `(document_id, user_id)` unique constraint still guarantees a single row. The generation is not exposed by the API. The SQLite and PostgreSQL paths use the same conditional upsert; unsupported dialects use a conditional `UPDATE ... WHERE revocation_version = :expected` fallback. The opt-in PostgreSQL suite exercises the stale-grant, stale-re-grant, and concurrent-revoke cases with real row locking.

---

## 3. Technology Stack & Component Architecture

```
+-------------------------------------------------------------------------+
|                              Client Browser                             |
|        (React 18 + Vite SPA, Vanilla CSS Design System, CSRF Headers)   |
+-------------------------------------------------------------------------+
                                     |
                                     | HTTPS / HTTP-Only Cookies / CSRF Tokens
                                     v
+-------------------------------------------------------------------------+
|                             FastAPI Backend                             |
|  - Request ID, Metadata Validation & Security Headers (nosniff, DENY)   |
|  - Request Body Limits (declared and streamed)                          |
|  - Session Authentication Middleware (Argon2, Server-side sessions)    |
|  - Rate Limiter (Shared database-backed fixed window on login)          |
+-------------------------------------------------------------------------+
       |                                          |
       v                                          v
+----------------------------------+   +----------------------------------+
| Central Authorization Service    |   | Private Persistent Storage       |
| (backend/app/services/           |   | (Outside Web Root)               |
|  authorization.py)               |   | - 256-bit unguessable keys       |
|  - Evaluates active session      |   | - Path traversal containment     |
|  - Evaluates document ownership  |   | - Chunked stream validation      |
|  - Evaluates active grant status |   | - Private staging + atomic rename|
+----------------------------------+   | - Startup reconciliation         |
                                       +----------------------------------+
       |
       v
+-------------------------------------------------------------------------+
|                  Database Layer (SQLAlchemy 2.0 + Alembic)              |
|                      Managed PostgreSQL / psycopg 3                     |
|  - users, sessions, documents, document_versions, document_grants        |
|  - storage_objects (global key owner + lifecycle state)                  |
|  - upload_requests (durable idempotency result)                           |
|  - audit_chain_state (serialized append sequence and chain head)        |
|  - login_rate_limit_buckets (shared, expiring login counters)           |
|  - storage_quota_state (serialized upload admission)                    |
|  - Versioned SHA-256 hash chain; actor identity locked by RESTRICT      |
+-------------------------------------------------------------------------+
       |
       v
+-------------------------------------------------------------------------+
|       Independent Audit Anchor (separate PostgreSQL service)            |
|  - HMAC-SHA256 checkpoints bound to stream + sequence                    |
|  - application role has SELECT/INSERT only on provisioned table          |
|  - scheduled creation with observable state in /health                  |
+-------------------------------------------------------------------------+
```

### Storage and Request Boundaries

Uploads are streamed to a private `.staging` directory on the same filesystem, validated against the extension/magic-byte policy, counted against `MAX_FILE_SIZE_BYTES`, fsynced, and atomically renamed to a 64-character lowercase hex storage key before the document row commits for local storage. A crash between rename and commit can leave an unreferenced file.

`storage_objects` is the canonical, durable owner and lifecycle record for each key. Insert triggers atomically claim a registry row for exactly one document or version and reject a second owner, a missing key, or a key outside the `active` state. Storage-key reassignment is rejected; owner metadata is retained as a tombstone even if a document row is later removed. Remote deletion first moves the registry row to `deleting` in the same transaction as the document soft-delete and durable delete intent. The worker verifies no active document or version reference exists, commits and releases database locks, then calls the provider. It only marks the registry key `deleted` in the same fenced transaction that completes the operation. Ambiguous or failed provider outcomes leave the key fenced for retry or review.

The `upload_requests` table scopes required `Idempotency-Key` values to an owner and persists a digest of the exact file and metadata. The upload response is saved in the same commit as the document, audit event, active registry ownership, and `UPLOAD_COMMITTED` operation state. Retries with the same payload replay the original response; payload changes and unresolved requests return `409`. The browser keeps an unresolved key in `sessionStorage` so a page reload does not silently create a second document. Keys and idempotency records are retained as ownership tombstones; downgrades refuse to remove them when any such history exists.

Startup reconciliation removes finalized files belonging to soft-deleted documents after the soft-delete is committed. It preserves unreferenced finalized files and `.part` staging files because local uploads have no durable lease for distinguishing an abandoned file from a slow in-flight upload; a grace period alone cannot prove that the request stopped. Active files are never removed, and missing active files are counted and logged rather than recreated. Orphaned-file cleanup requires a future durable ownership/lease mechanism. The filesystem and database do not share an atomic transaction; this is a recoverable-ordering design, not a distributed transaction.

Upload admission updates the singleton `storage_quota_state` row at the start of the document transaction, then checks active per-user document count and bytes plus platform-wide bytes. PostgreSQL holds the row lock and SQLite holds its write lock until the caller commits or rolls back, so concurrent workers cannot both admit uploads against the same stale usage snapshot. Count-limit rejection returns `409`; byte-limit rejection returns `413`. The opt-in PostgreSQL suite verifies both per-user count admission and cross-owner global byte admission with four concurrent uploaders.

A pure-ASGI middleware enforces request-body limits before multipart/JSON parsing. Declared `Content-Length` values above `MAX_FILE_SIZE_BYTES + MAX_MULTIPART_OVERHEAD_BYTES` for multipart requests, or above `MAX_JSON_BODY_BYTES` for other requests, are rejected immediately. Bodies without a trusted length are counted as they stream. Request IDs, user agents, client IPs, filenames, and MIME types are validated against their database column bounds before persistence; overlong values are rejected rather than truncated.

The online audit hash chain is retained indefinitely because checkpoint and chain verification require it. `AUDIT_RETENTION_DAYS` is an objective for independently held archive copies, not an online-deletion schedule, and `AUDIT_RETENTION_AUTO_DELETE=true` is rejected at startup.

---

## 4. Tamper-Evident Audit Chaining Design

Audit records form a cryptographic hash chain. Version 2 records bind the stable event identity and request metadata in addition to the original chain fields:

$$RecordHash_i = \text{SHA256}_{v2}(Seq_i \parallel Timestamp_i \parallel Actor_i \parallel Action_i \parallel ResourceType_i \parallel ResourceId_i \parallel Outcome_i \parallel RequestId_i \parallel Details_i \parallel PreviousHash_i \parallel EventId_i \parallel IP_i \parallel UserAgent_i)$$

Where:
- $PreviousHash_1 = \text{"000...000"}_{64}$ (Genesis Hash)
- $PreviousHash_i = RecordHash_{i-1}$ for $i > 1$
- `hash_version` records which canonical payload produced each hash. Version 1 preserves the original delimiter-separated payload byte-for-byte, so records and checkpoints created before the upgrade continue to verify. New events use version 2 canonical JSON, which includes `id`, `ip_address`, and `user_agent`.

### Verification Mechanism
`AuditService.verify_chain_integrity_bounded(db, ...)` verifies the chain from index 1 through a high-water mark captured at the start of the pass. Records are fetched in ascending keyset batches (bounded by `AUDIT_VERIFY_BATCH_SIZE`) using selected columns rather than materializing ORM entities or the full chain. For every record it:
1. Validates strictly ascending sequence numbers without gaps.
2. Validates that `event.previous_hash == previous_event.record_hash`.
3. Canonicalizes timestamps into UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
4. Recomputes the hash using the record's `hash_version` and asserts exact equality against `event.record_hash`. Unknown hash versions are `INVALID`.

### Append Serialization and Transaction Boundary
`AuditService.log_event()` allocates sequence numbers through the singleton `audit_chain_state` row. An atomic increment obtains the row write lock, which is held until the caller commits or rolls back; the event insert and chain-head hash update are part of that same transaction. This prevents two concurrent writers from selecting the same sequence or previous hash on PostgreSQL and SQLite.

- **PostgreSQL**: concurrent appends wait on the chain-state row and then reread the committed head under READ COMMITTED. A deadlock or serialization failure aborts the entire transaction, including the business operation; the transaction is never partially committed. The application does not automatically retry inside an aborted transaction because that would discard or duplicate caller state. Retry the complete request at the caller/API boundary.
- **SQLite**: the row update takes the database write lock; `busy_timeout` bounds lock waits. The offline test suite uses a file-backed four-session test to check unique contiguous allocation, but that is a portability check, not PostgreSQL verification.
- **PostgreSQL verification**: the opt-in suite covers eight concurrent first appends (the chain-state row is seeded once), a rolled-back append whose sequence is reused by the next commit, a concurrent commit/rollback pair that leaves exactly one event, and a bounded verification pass whose high-water mark excludes an append committed mid-pass.
- **Actor lifecycle**: `audit_events.actor_id` uses `ON DELETE RESTRICT`/`ON UPDATE RESTRICT`. A referenced user cannot be hard-deleted, which would otherwise null or change a hash-covered actor identity. The supported lifecycle is deactivation through `is_active`; deactivation preserves the audit reference. The ORM relationship uses `passive_deletes=True` so SQLAlchemy does not try to null the audit rows before the database constraint runs.
- **Migration**: revision `c3d4e5f6a7b8` adds `hash_version`, creates and seeds
`audit_chain_state` from the existing head, and replaces the actor foreign key. Existing rows are marked version 1,
and historical checkpoint comparisons continue to use their stored record hashes unchanged. Revision
`b6f1c8e9a2d4` creates the shared login rate-limit table including the `denial_audit_recorded` marker used to bound
login-denial audit events, revision `d4e5f6a7b8c9` adds `storage_quota_state`, and revision `e5f6a7b8c9d0` adds the
grant `revocation_version`. The full chain was upgraded, downgraded one revision, and re-upgraded on PostgreSQL 16;
the downgrade of `c3d4e5f6a7b8` remains conditionally refused when version 2 records exist.
- **Downgrade policy**: forward upgrades are supported. Downgrading below `c3d4e5f6a7b8` is refused while any
version 2 audit record exists: the legacy schema cannot store `hash_version`, so a downgrade followed by a
re-upgrade would silently relabel those rows as version 1 and verification would then report a broken chain. The
migration raises an error before dropping the column, so `hash_version`, `audit_chain_state`, and every record hash
remain intact. Alembic applies revisions stepwise: on a chain downgrade, the Phase 5 revision above it may already be
reverted before the refusal, leaving the database at the consistent `c3d4e5f6a7b8` schema (with the version 2 rows
untouched); PostgreSQL may roll the whole command back where migration DDL is transactional, which is not verified in
this build. Recovery from a failed release is restoration from a database snapshot taken before version 2 records
were written, or continued operation on the current schema; audit rows must not be deleted or rewritten to force a
downgrade. Chains containing only version 1 records downgrade and re-upgrade normally, because every row is
backfilled as version 1 and the rebuilt chain state is seeded from the existing head.

The pass is bounded by `AUDIT_VERIFY_MAX_RECORDS` and `AUDIT_VERIFY_TIMEOUT_SECONDS`. The result distinguishes three outcomes:

- `VALID`: all records through the high-water mark were examined and passed.
- `INVALID`: an integrity failure was detected; the reported count stops before the failing record.
- `INCOMPLETE`: the record limit or time budget prevented complete verification. `is_valid` is `false`, and the result explicitly states that the pass was incomplete. A partial pass is never reported as full-chain success.

Administrators can invoke this verification through the read-only `GET /api/v1/admin/audit/verify` endpoint. The endpoint reports the status, the number of records verified, and a failure reason with full hash values redacted. It never rewrites a record, appends an event, truncates the chain, or returns stored hash-chain fields. Verification requests are limited per administrator by a process-local sliding-window limiter (`AUDIT_VERIFY_RATE_LIMIT_MAX_REQUESTS` per `AUDIT_VERIFY_RATE_LIMIT_WINDOW_SECONDS`, default 5 per 60 seconds); excess requests receive `429 Too Many Requests` with `Retry-After`.

### Verification Consistency and Limits
The high-water mark prevents verification from chasing audit writes that are appended during the pass: only records at or below the maximum sequence observed at the start are examined. This is not a single repeatable-read database snapshot. A record modified between batch reads can cause a mixed read, and a modification made after a record was already examined is not re-checked until the next run. For a stronger point-in-time result, run verification during a quiet window or against a database snapshot/read replica. The rate limiter is process-local and is not shared across workers or instances; deployment-level or Redis-backed enforcement is required to bound aggregate concurrency. If the chain exceeds the configured record limit or the time budget expires, the endpoint returns an explicit `INCOMPLETE` result rather than a partial success.

### Audit Checkpoints

Hash chaining alone cannot detect a database-level attacker who rewrites the entire chain from an arbitrary sequence forward or truncates the current tail before a pass begins. TrustVault stores HMAC-protected checkpoints in a separately administered PostgreSQL service configured by `AUDIT_ANCHOR_DATABASE_URL`. Its `trustvault_audit_anchor.checkpoints` table is provisioned separately by `backend/scripts/provision_audit_anchor.sql`; the runtime role receives only `SELECT` and `INSERT` permissions. It is not the owner of the schema or table.

- A checkpoint records the audit stream identifier (`trustvault.audit`), the highest verified sequence number and record hash, a format version, a creation timestamp, and the previous checkpoint's HMAC tag. The document is protected by an HMAC-SHA256 integrity tag derived from `AUDIT_ANCHOR_HMAC_KEY`.
- Creation (`POST /admin/audit/checkpoints`) verifies the bounded audit chain, refuses invalid or incomplete chains, and writes checkpoints monotonically. Repeating creation for the current chain head is idempotent; rollback and conflicting writes are rejected.
- The checkpoint covers only the verified prefix. The `audit.checkpoint_created` event is appended afterward, so a checkpoint never binds its own creation event.
- Verification (`GET /admin/audit/checkpoints/verify`) compares the bounded chain with the latest stored checkpoint. Invalid or mismatched history reports `INVALID`; a missing or genesis-only checkpoint reports `INCOMPLETE`; an unavailable store reports `UNAVAILABLE`.
- The in-process scheduler creates a checkpoint at startup and every `AUDIT_CHECKPOINT_INTERVAL_SECONDS`. Scheduled and administrator-triggered writes share a PostgreSQL advisory lock within the anchor database. Scheduler health and checkpoint age are exposed through `GET /health`.

### Independence Boundary
Production configuration requires the anchor URL to use a host distinct from the application database host and rejects local-file anchoring. This is a configuration guard, not proof that DNS names identify separate physical clusters, providers, administrators, backups, or credentials. Operators must verify these boundaries and keep anchor administration outside the application deployment account. The HMAC key is available to the application, so a compromised application runtime can forge checkpoints. A privileged administrator of the anchor database can also rewrite its contents. The design therefore protects against an application-database-only rewrite, not compromise of every system holding the evidence. `GET /health` reports configured PostgreSQL anchoring but sets `independence_verified=false` pending operator verification.

`local_file` remains available for development and is never considered independent. Production startup rejects it.

## 5. Administrative Audit API and Coverage

### API Surface
All six endpoints require the authenticated `admin` role and are registered under `/api/v1`:

- `GET /admin/audit`: filtered, paginated audit-event inspection across all actors and resources.
- `GET /admin/audit/verify`: bounded hash-chain verification with explicit `VALID`, `INVALID`, or `INCOMPLETE` outcomes and per-administrator rate limiting.
- `GET /admin/documents/activity`: filtered, paginated document and document-grant activity.
- `POST /admin/audit/checkpoints`: verifies the committed chain and stores a checkpoint through the configured `CheckpointStore`; returns `201 CREATED` or `200 ALREADY_PRESENT`, `409` for an invalid/incomplete chain or a rejected rollback/conflict, and `503` when no anchor is configured or the local store is unavailable.
- `GET /admin/audit/checkpoints`: returns checkpoint metadata (stream ID, sequence number, created-at, format version, anchor mode, availability) without hash values, HMAC tags, keys, or paths; reports `available: false` when no checkpoint is stored (including when anchoring is disabled).
- `GET /admin/audit/checkpoints/verify`: bounded chain verification compared against the stored checkpoint with explicit `VALID`, `INVALID`, `INCOMPLETE`, or `UNAVAILABLE` outcomes and a separate per-administrator rate limiter.

The audit and activity response schemas expose only `id`, `sequence_number`, `timestamp`, `actor_id`, `action`, `resource_type`, `resource_id`, `outcome`, `request_id`, `ip_address`, `user_agent`, and sanitized `details`. `previous_hash` and `record_hash` are deliberately excluded, as are credential fields and checkpoint HMAC tags. `details` uses a default-deny allowlist that preserves correlation, account-management, and checkpoint keys (`document_id`, `recipient_id`, `target_user_id`, `permission`, `reason`, `changed_fields`, `role`, `from_role`, `to_role`, `email`, `sessions_revoked`, `verification_status`, `already_present`, and `checkpoint_sequence`) and returns `[redacted]` for every other key, including document title, filename, size, category, MIME type, storage path/key, password, and token values. Raw audit rows are unchanged. Verification and checkpoint failure diagnostics redact full hash values. All audit, activity, and checkpoint endpoints also return `Cache-Control: no-store` and `Pragma: no-cache`. String filters are trimmed, length-bounded, and exact-matched through bound SQLAlchemy expressions. `document_id` activity filtering matches direct document events by `resource_id` and grant events by the recorded `details.document_id`; LIKE metacharacters in the supplied ID are escaped.

These endpoints are read-only. They do not return document metadata values or bytes and do not create an alternative path to document access. An administrator querying audit data remains subject to the same owner-or-active-grant policy on document routes.

### Administrative Read Auditing
Each successful administrative read appends its own audit event with `resource_type` set to `audit` and no resource ID: `audit.read` for `GET /admin/audit`, `audit.verify` for `GET /admin/audit/verify` (with allowlisted `details.verification_status` recording `VALID`, `INVALID`, or `INCOMPLETE`), `audit.activity_read` for `GET /admin/documents/activity`, `audit.checkpoint_read` for `GET /admin/audit/checkpoints`, and `audit.checkpoint_verify` for `GET /admin/audit/checkpoints/verify` (with allowlisted `details.verification_status` recording `VALID`, `INVALID`, `INCOMPLETE`, or `UNAVAILABLE`). Scheduled creation records `audit.checkpoint_scheduled` with `already_present` and `checkpoint_sequence`. Checkpoint creation records `audit.checkpoint_created` (outcome `SUCCESS` with allowlisted `details.already_present` and `details.checkpoint_sequence`, or `FAILURE` with an allowlisted `details.reason`) after the anchor write. The event is committed before the response is returned; if the event cannot be durably persisted, the endpoint returns `503 Audit trail unavailable` with `Cache-Control: no-store` instead of serving an unaudited response. Rate-limited (`429`) and non-administrator (`403`) requests do not create read events because no audit data is served. Verification still inspects only records at or below the high-water mark observed before its own read event is appended, so the read event never inflates `records_verified` for that pass.

### Recorded Audit Actions
The current build records the following events:

- Authentication and self-service: `user.register`, `user.login`, `user.login_failed`, `user.login_rate_limited`, `user.logout`, `user.update`.
- Administrative user management: `user.role_change`, `user.deactivate`, `user.reactivate`, `user.sessions_revoked`.
- Administrative audit inspection and anchoring: `audit.read`, `audit.verify`, `audit.activity_read`, `audit.checkpoint_read`, `audit.checkpoint_verify`, `audit.checkpoint_created`, `audit.checkpoint_scheduled`.
- Documents: `document.upload`, `document.read`, `document.download`, `document.edit`, `document.delete`, including success and authorization-denial outcomes. Rejected uploads are recorded as `document.upload` with `DENIED` and an allowlisted `details.reason` (`insufficient_role`, `missing_filename`, `invalid_upload`, or `size_limit_exceeded`).
- Sharing: `permission.grant`, `permission.revoke`, and `permission.list_denied`.

### Known Coverage Gaps
The following operations are not currently recorded as audit events:

- Document list/search/read-metadata enumeration through `GET /documents`.
- Successful `GET /documents/{id}/permissions` reads (denied attempts are recorded as `permission.list_denied`).
- Administrative user-list/profile reads.
- Request-validation failures that occur before an audit call (for example, malformed multipart uploads or invalid pagination parameters); a syntactically valid but rejected upload is audited as described above.

These gaps mean the architecture does not claim that every read or every administrative query is audited. State-changing administrative actions and the document access paths listed above are audited; expanding read coverage would require a separate, explicit event-volume and privacy decision.
