# TrustVault — Architecture & Security Specification

TrustVault is a secure document sharing platform designed with a primary focus on authorization correctness, private storage isolation, and a verifiable, tamper-evident audit trail.

---

## 1. System Overview & Core Principles

TrustVault is engineered around five mandatory security pillars:

1. **Default-Deny Authorization**: Every protected operation denies access unless an explicit ownership relation or active, unrevoked grant is confirmed in the current transaction.
2. **Server-Side Trust Boundary**: Frontend checks exist solely for user interface ergonomics. The backend is the sole authority; client-supplied role parameters or user IDs are rejected.
3. **Storage Decoupling**: Stored files are kept strictly outside the web server root. Physical file paths are generated via 256-bit unguessable random keys and are never exposed to clients.
4. **Immediate Revocation**: No cached authorization tokens or long-lived download URLs are used. When an access grant is revoked, the very next download or read attempt is blocked.
5. **Tamper-Evident Auditability**: Every instrumented authentication, state-changing, document access, access-denial, and administrative audit-read action produces a cryptographically hash-chained audit record, and independently stored HMAC-protected checkpoints anchor the chain outside the audit database (adapter-based; a development-only local file adapter and an external S3 adapter are implemented, but no live production provider has been configured or verified). The exact recorded actions and the remaining gaps are listed in Section 5.

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
|  - users, sessions, documents, document_grants, audit_events            |
|  - audit_chain_state (serialized append sequence and chain head)        |
|  - login_rate_limit_buckets (shared, expiring login counters)           |
|  - storage_quota_state (serialized upload admission)                    |
|  - Versioned SHA-256 hash chain; actor identity locked by RESTRICT      |
+-------------------------------------------------------------------------+
       |
       v
+-------------------------------------------------------------------------+
|             Audit Checkpoint Anchor (CheckpointStore adapter)           |
|  - HMAC-SHA256 protected checkpoints bound to stream + sequence         |
|  - scheduled creation with observable state in /health                  |
|  - local_file = development only; production requires s3                |
+-------------------------------------------------------------------------+
```

### Storage and Request Boundaries

Uploads are streamed to a private `.staging` directory on the same filesystem, validated against the extension/magic-byte policy, counted against `MAX_FILE_SIZE_BYTES`, fsynced, and atomically renamed to a 64-character lowercase hex storage key before the document row commits. If the transaction or finalization fails, both staged and final paths are removed. A crash between rename and commit can leave an unreferenced file.

Startup reconciliation removes files belonging to soft-deleted documents immediately. It removes other unreferenced files and stale `.part` staging files only after `STORAGE_ORPHAN_GRACE_SECONDS`, so another worker's in-flight upload is not deleted. Active files are never removed, and missing active files are counted and logged rather than recreated. The filesystem and database do not share an atomic transaction; this is a recoverable-ordering design, not a distributed transaction.

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

### Independently Stored Checkpoints
Hash chaining alone cannot detect a database-level attacker who rewrites the entire chain from an arbitrary sequence forward, or who truncates the current tail before a pass begins. To detect those cases, TrustVault anchors the chain in independently stored checkpoints through a `CheckpointStore` adapter (`backend/app/services/checkpoint_store.py`):

- A checkpoint records the audit stream identifier (`trustvault.audit`), the highest verified sequence number, that record's hash, a format version, a creation timestamp, and the previous checkpoint's HMAC tag, and is protected by an HMAC-SHA256 integrity tag computed with the configured `AUDIT_ANCHOR_HMAC_KEY`.
- Creation (`POST /admin/audit/checkpoints`) runs the bounded chain verification first and refuses to anchor an invalid or incompletely verified chain. It then reads the latest stored checkpoint, refuses to move backwards (rollback) or to silently overwrite a conflicting checkpoint at the same sequence, and writes through compare-and-swap semantics. Repeating creation for the current chain head is idempotent and reports `ALREADY_PRESENT`; extending the chain and retrying advances the checkpoint.
- The checkpoint covers the verified prefix only. The `audit.checkpoint_created` event is appended after the checkpoint is stored, so a checkpoint never binds its own creation record, and a failure to append that event does not invalidate or roll back the checkpoint (retrying is safe).
- Verification (`GET /admin/audit/checkpoints/verify`) re-verifies the bounded chain and compares it with the stored checkpoint. A rewritten hash, a missing checkpointed sequence, a corrupt/invalid checkpoint, or a checkpoint that does not match the chain reports `INVALID`; no stored checkpoint or the bounded-verification `INCOMPLETE` outcome reports `INCOMPLETE`; an unconfigured anchor or an unreachable/access-denied provider reports `UNAVAILABLE`. None of those states is ever reported as `VALID`. The chain may legitimately extend beyond the checkpoint without affecting validity. A genesis-only checkpoint (`sequence_number=0`) is always `INCOMPLETE`, because it cannot distinguish an empty chain from truncation to zero.
- When anchoring is enabled, an in-process `CheckpointScheduler` (`backend/app/services/checkpoint_runtime.py`) creates a checkpoint at startup and then every `AUDIT_CHECKPOINT_INTERVAL_SECONDS`. Scheduled creation uses the same bounded verification and conditional-write path, takes a transaction-scoped PostgreSQL advisory lock so only one worker attempts a write at a time, and records its last attempt/success/failure, checkpoint sequence, checkpoint age, and next run in process-local state exposed by `GET /health`. Administrator-triggered creation acquires the same lock, so scheduled and manual writers cannot overlap across workers; the store's conditional writes remain the final guard. A successful creation appends `audit.checkpoint_scheduled`; if that audit write fails, the checkpoint remains stored, the failure is logged, and the next run anchors the current head. The scheduler does not replace administrator-triggered creation.

Two adapters are implemented behind this interface:

- `LocalFileCheckpointStore` (`AUDIT_ANCHOR_MODE=local_file`) writes HMAC-signed checkpoint documents to `AUDIT_ANCHOR_DIR`. It shares the application's host and filesystem failure domain and is explicitly **not** independent production anchoring; the settings validator rejects it in `ENVIRONMENT=production`, and it must only be used for local development and testing.
- `S3CheckpointStore` (`AUDIT_ANCHOR_MODE=s3`) writes the same checkpoint document format to Amazon S3 or an S3-compatible bucket using conditional writes (`If-None-Match: *`), `list_objects_v2` pagination, bounded request timeouts, standard-mode retries, the AWS default credential chain (the application never reads or stores credentials itself), and optional KMS encryption and Object Lock retention. It requires AWS-compatible conditional-write and read-after-write consistency semantics; an S3-compatible service must be verified to honor them before it can be trusted as an anchor. Provider failures are mapped to fixed checkpoint errors; an access denial never becomes a valid result, and there is no fallback to local-file storage. The adapter validates only the highest visible checkpoint object and its HMAC/format, verifies that the object key matches the embedded checkpoint sequence, and treats malformed, repeated, or excessive pagination tokens as failures; it does not enumerate and validate the full checkpoint history.

With `AUDIT_ANCHOR_MODE=disabled` (the non-production default), no adapter is configured: checkpoint creation fails closed with `503`, checkpoint verification reports `UNAVAILABLE`, and the scheduler does not start. Production startup rejects `disabled` and requires `AUDIT_ANCHOR_MODE=s3`; it also fails if the S3 adapter cannot initialize. **This repository ships no bucket, credentials, endpoint, or deployment configuration, and the S3 adapter has not been exercised against a live bucket.** It becomes production anchoring only after an operator provisions an independently controlled destination, grants least-privilege access, verifies reachability, and confirms checkpoint creation and verification. The `CheckpointStore` interface remains the extension point for other providers (for example a separately administered anchor service or an RFC 3161 timestamp authority).

### Limitation & Production Anchoring
Hash chaining reliably detects unauthorized modification, insertion, or deletion of individual records within the observed chain, and stored checkpoints extend that detection to whole-chain rewrites and tail truncation at or below the checkpointed sequence — provided the checkpoint store and HMAC key are outside the database attacker's control. The following boundaries remain and are not solved by this build:

- A local `local_file` checkpoint store sits on the same host as the application; an attacker who compromises both the database and the anchor directory (or the HMAC key) can rewrite or roll back checkpoints. The local adapter cannot prevent deletion of its own files.
- The external `s3` adapter is implemented but has not been deployed or verified against a live, independently controlled bucket in this build. Provider-side resistance also depends on configuration the adapter cannot enforce (an identity without delete/retention rights, versioning, and Object Lock). Production startup now fails closed unless this adapter is configured and initializable, but a syntactically valid configuration is not proof that the provider is reachable, honors conditional writes, or retains checkpoints.
- The adapter cannot detect deletion, overwrite, or rollback of checkpoint objects when the provider permits them or when a provider returns stale/incomplete listings with a success status. It reads the highest visible checkpoint; if newer objects are removed, verification compares the chain against the older checkpoint and may still report `VALID`. Only provider controls resist this: versioning, Object Lock (Compliance mode), withholding delete and retention-bypass permissions from the workload, a separately administered account, and monitoring version history. The application-layer adapter does not and cannot enforce them.
- Conditional writes protect a given sequence key from replacement, but writers anchoring different chain heads write different keys. The highest sequence becomes the latest checkpoint and lower concurrent branches are ignored, leaving orphaned anchors. The adapter does not validate the full branch history; serialize checkpoint creation through a single writer or idempotent schedule to avoid forks, and monitor the prefix for unexpected objects.
- Some S3-compatible services may reject, ignore, or only partially implement `PutObject` conditional writes, or may not provide strong read-after-write listing consistency. The adapter cannot detect a provider that ignores the precondition or returns an incomplete listing as success. Before relying on such a service, perform a preflight with concurrent writes to the same key and verify that exactly one succeeds (`412 PreconditionFailed` for the loser).
- The adapter trusts a successful `PutObject` response and does not read the object back after writing. A provider that acknowledges a write but does not durably store it can make checkpoint creation appear successful; verification still requires a retrievable, HMAC-valid checkpoint and will report `INCOMPLETE` if none is available. Provider durability is an operational assumption, not something the application verifies.
- History rewritten strictly after the latest checkpoint is not detected by the checkpoint comparison alone; it is caught only by the ordinary full-chain verification, and the high-water mark still derives from the remaining rows.

For high-assurance production environments, configure the implemented `s3` adapter against a bucket in a separately administered account with versioning and Object Lock (Compliance mode) enabled, and create checkpoints on a regular schedule so the unanchored window stays small.

### External Provider Setup & Operations (Amazon S3)
Amazon S3 (or an S3-compatible service) was selected because it provides a separate credential/account boundary, conditional writes for compare-and-swap checkpoint creation, versioning and Object Lock for tamper resistance, and provider-managed encryption. **No bucket or credentials exist in this repository, and no live deployment has been verified.**

Required configuration (`AUDIT_ANCHOR_MODE=s3`):

- `AUDIT_ANCHOR_S3_BUCKET` and `AUDIT_ANCHOR_S3_REGION` are required; `AUDIT_ANCHOR_S3_PREFIX` selects the checkpoint key prefix (default `trustvault-audit-checkpoints`).
- `AUDIT_ANCHOR_HMAC_KEY` must be at least 32 characters, generated from a cryptographic random source, and stored in a secret manager.
- `AUDIT_CHECKPOINT_INTERVAL_SECONDS` defaults to `3600`; `AUDIT_CHECKPOINT_MAX_AGE_SECONDS` defaults to `7200` and must be at least the interval. The maximum age is the health-alert threshold for the last successful scheduled checkpoint.
- `AUDIT_ANCHOR_S3_ENDPOINT_URL` is optional for S3-compatible services and must use HTTPS in production.
- `AUDIT_ANCHOR_S3_KMS_KEY_ID`, `AUDIT_ANCHOR_S3_OBJECT_LOCK_MODE` (GOVERNANCE/COMPLIANCE), `AUDIT_ANCHOR_S3_OBJECT_LOCK_DAYS`, `AUDIT_ANCHOR_S3_CONNECT_TIMEOUT_SECONDS`, `AUDIT_ANCHOR_S3_READ_TIMEOUT_SECONDS`, and `AUDIT_ANCHOR_S3_MAX_ATTEMPTS` are optional operational settings.

Provider setup:

1. Create the bucket in a separately administered account (or at minimum a separate credential boundary) with Block Public Access enabled, versioning enabled, and Object Lock enabled at bucket creation if WORM retention is required.
2. Run the application with a workload identity (instance/task role or OIDC) holding only the permissions needed for the configured prefix. Never embed access keys in the repository, `.env.example`, tests, or logs. Example least-privilege policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "arn:aws:s3:::EXAMPLE-BUCKET",
      "Condition": {"StringLike": {"s3:prefix": ["trustvault-audit-checkpoints/*"]}}
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/trustvault-audit-checkpoints/*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:PutObjectRetention"],
      "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/trustvault-audit-checkpoints/*"
    }
  ]
}
```

Add `kms:GenerateDataKey` and `kms:Decrypt` for the configured KMS key when SSE-KMS is enabled. Do not grant delete permissions to the application identity; versioning/Object Lock and a separate administration path are the recovery boundary.

Verification, rotation, and failure behavior:

- After configuring the provider, have an administrator call `POST /admin/audit/checkpoints` followed by `GET /admin/audit/checkpoints/verify`. `VALID` confirms connectivity and a matching non-genesis anchor; `INCOMPLETE` or `UNAVAILABLE` means anchoring is not usable and must be treated as a failure, not a success.
- Scheduled creation runs at startup and every `AUDIT_CHECKPOINT_INTERVAL_SECONDS`, so the unanchored window is bounded without a manual task. Verify that the scheduler's first attempt succeeds and monitor `/health`; creation still occurs through the same conditional-write path if multiple workers are running.
- In-place HMAC key rotation is not supported: checkpoint links bind each document to the preceding checkpoint's HMAC, so rotation requires a planned re-anchoring procedure. Keep the key in a secret manager with restricted access.
- AWS credentials and KMS keys rotate through the provider/identity layer; TrustVault does not store either.
- Recovery relies on bucket versioning and Object Lock; the application identity must not be able to delete anchor objects, and restore operations belong to the separately administered provider account.
- Timeouts, throttling, missing buckets, missing credentials, SDK validation failures, and other provider failures become `anchor_unavailable`; permission failures become `anchor_access_denied`. Both fail closed with `503` on creation and `UNAVAILABLE` (never `VALID`) on verification. An identical conditional-write retry is idempotent; a different checkpoint at the same sequence becomes `409`/`anchor_conflict`, and rollback attempts are refused. AWS `409 ConditionalRequestConflict` (for example a concurrent delete/create) is surfaced as unavailability and must be retried; it is never treated as success. The adapter never falls back to local-file storage.
- KMS key existence and permissions, bucket Object Lock enablement, retention mode, and policy enforcement are provider-side responsibilities; the adapter only requests these settings and fails closed if the provider rejects them. Object Lock in `GOVERNANCE` mode can be bypassed by principals holding `s3:BypassGovernanceRetention`; withhold that permission from the workload and prefer `COMPLIANCE` for the anchor prefix.
- `GET /health` reports scheduler evidence under `components.audit_anchor`: `status` (`starting`, `ok`, `overdue`, `invalid`, `incomplete`, `unavailable`, `error`, or `scheduler_stopped`), last checkpoint sequence/age, failure reason, and `overdue`. It does not probe the provider on each request. `independent: true` reflects `AUDIT_ANCHOR_MODE=s3`; only a recent successful scheduled checkpoint yields `status=ok`. Top-level health becomes `degraded` for any unhealthy anchor while core database/storage remain available.
- An opt-in real-AWS integration suite (`backend/tests/test_checkpoint_s3_integration.py`) exists for operators with an explicitly approved test bucket. It is skipped by default, never falls back to a fake client, and has not been run against a live bucket in this build. Prerequisites, least-privilege permissions, exact commands, cleanup, and limits are documented in [`docs/AWS_INTEGRATION_TESTING.md`](AWS_INTEGRATION_TESTING.md).

---

## 5. Administrative Audit API and Coverage

### API Surface
All six endpoints require the authenticated `admin` role and are registered under `/api/v1`:

- `GET /admin/audit`: filtered, paginated audit-event inspection across all actors and resources.
- `GET /admin/audit/verify`: bounded hash-chain verification with explicit `VALID`, `INVALID`, or `INCOMPLETE` outcomes and per-administrator rate limiting.
- `GET /admin/documents/activity`: filtered, paginated document and document-grant activity.
- `POST /admin/audit/checkpoints`: verifies the committed chain and stores a checkpoint through the configured `CheckpointStore`; returns `201 CREATED` or `200 ALREADY_PRESENT`, `409` for an invalid/incomplete chain or a rejected rollback/conflict, and `503` when no anchor is configured, the provider is unavailable, or provider access is denied.
- `GET /admin/audit/checkpoints`: returns checkpoint metadata (stream ID, sequence number, created-at, format version, anchor mode, availability) without hash values, HMAC tags, keys, paths, or provider configuration; reports `available: false` when no checkpoint is stored (including when anchoring is disabled).
- `GET /admin/audit/checkpoints/verify`: bounded chain verification compared against the stored checkpoint with explicit `VALID`, `INVALID`, `INCOMPLETE`, or `UNAVAILABLE` outcomes and a separate per-administrator rate limiter.

The audit and activity response schemas expose only `id`, `sequence_number`, `timestamp`, `actor_id`, `action`, `resource_type`, `resource_id`, `outcome`, `request_id`, `ip_address`, `user_agent`, and sanitized `details`. `previous_hash` and `record_hash` are deliberately excluded, as are any credential fields, checkpoint HMAC tags, and provider configuration (bucket names, prefixes, and endpoint URLs). `details` uses a default-deny allowlist that preserves correlation, account-management, and checkpoint keys (`document_id`, `recipient_id`, `target_user_id`, `permission`, `reason`, `changed_fields`, `role`, `from_role`, `to_role`, `email`, `sessions_revoked`, `verification_status`, `already_present`, and `checkpoint_sequence`) and returns `[redacted]` for every other key, including document title, filename, size, category, MIME type, storage path/key, password, and token values. Raw audit rows are unchanged. Verification and checkpoint failure diagnostics redact full hash values. All audit, activity, and checkpoint endpoints also return `Cache-Control: no-store` and `Pragma: no-cache`. String filters are trimmed, length-bounded, and exact-matched through bound SQLAlchemy expressions. `document_id` activity filtering matches direct document events by `resource_id` and grant events by the recorded `details.document_id`; LIKE metacharacters in the supplied ID are escaped.

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
