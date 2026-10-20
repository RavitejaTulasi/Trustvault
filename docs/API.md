# TrustVault — REST API Specification

This document details the complete API contract for TrustVault, including authentication requirements, role restrictions, authorization policies, validation rules, and error codes.

---

## Standard Response Standards & Error Conventions

### Status Codes
- `200 OK`: Request succeeded.
- `201 Created`: Resource successfully created.
- `204 No Content`: Resource successfully deleted or updated without body response.
- `400 Bad Request`: Validation failure, invalid payload, or malformed parameter.
- `401 Unauthorized`: Authentication required or invalid/expired session cookie.
- `403 Forbidden`: Authenticated identity lacks the required platform role (for example, an admin-only endpoint).
- `404 Not Found`: Deliberate 404 returned for inaccessible or non-existent documents to prevent existence discovery, or a non-existent endpoint/resource.
- `409 Conflict`: The audit chain could not be anchored because it is invalid or incompletely verified, or the stored checkpoint rejected a rollback or conflicting write.
- `413 Payload Too Large`: Upload exceeds maximum allowed file size (10MB).
- `422 Unprocessable Entity`: Malformed query parameter, invalid filter value, or invalid date range.
- `429 Too Many Requests`: Rate limit exceeded (e.g. login brute-force throttle).
- `503 Service Unavailable`: Database or storage health failure, or the configured checkpoint provider is unreachable or denies access.

### Security Headers on Every Response
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-Request-ID: <uuid>`

---

## 0. Health & Readiness

### `GET /health`
- **Authentication**: None (Public)
- **Action**: Checks database connectivity and private-storage writability, and reports the checkpoint scheduler's last attempt, last success, last failure, latest checkpoint sequence/age, and overdue state. It does not contact the external checkpoint provider on every request.
- **Response `200 OK`**: `status` is `healthy` when core services and anchoring are healthy, or `degraded` when core services are healthy but `components.audit_anchor` is not. The audit-anchor `status` is one of `not_configured`, `local_development_only`, `scheduler_stopped`, `starting`, `overdue`, `ok`, `invalid`, `incomplete`, `unavailable`, or `error`.
- **Response `503 Service Unavailable`**: Database or private storage is unavailable; `status` is `unhealthy`.
- **Operational Note**: Alert on top-level `degraded` and on anchor failures/overdue conditions. A `local_development_only` anchor is non-independent and is never accepted in production.

---

## 1. Authentication Endpoints

### `POST /api/v1/auth/login`
- **Authentication**: None (Public)
- **Rate Limit**: 5 failed attempts per 5 minutes per IP and per IP+email. Counters are stored in the shared application database, reserved atomically before password verification, and expire automatically. A successful login clears the IP+email bucket and releases its own IP slot without clearing earlier IP-wide failures. A limiter storage failure returns `503` rather than falling back to process-local state. At most one `user.login_rate_limited` audit event is written per IP window; repeated denied requests, including attempts that rotate the email address, do not multiply audit rows. A failure to persist the aggregate event fails closed with `503`.
- **Client IP**: The immediate peer address is used unless it matches `TRUSTED_PROXY_IPS`. Only then is `X-Forwarded-For` walked right-to-left, stopping at the first non-proxy address. Malformed, oversized, or excessive-hop headers fall back to the peer. `0.0.0.0/0` and `::/0` are rejected at startup.
- **Request Body**:
  ```json
  {
    "email": "user@trustvault.local",
    "password": "SecurePassword123!"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "id": "u_984f1b...",
    "email": "user@trustvault.local",
    "full_name": "Alice Smith",
    "role": "owner",
    "is_active": true,
    "created_at": "2026-10-19T10:00:00.000000Z",
    "updated_at": "2026-10-19T10:00:00.000000Z"
  }
  ```
- **Cookies Set**:
  - `trustvault_session`: HttpOnly, SameSite=Lax, Secure (in production).
  - `trustvault_csrf`: SameSite=Lax (readable by frontend for inclusion in `X-CSRF-Token` headers).
- **Audit Events**: `user.login`, `user.login_failed`, or `user.login_rate_limited`

### `POST /api/v1/auth/logout`
- **Authentication**: Required (`SessionCookie`)
- **Action**: Revokes session in database, clears session cookies.
- **Response `204 No Content`**: Empty body.
- **Audit Event**: `user.logout`

### `GET /api/v1/auth/me`
- **Authentication**: Required
- **Response `200 OK`**: Current user profile and assigned role.

---

## 2. Document Endpoints

### `POST /api/v1/documents`
- **Authentication**: Required
- **Role Requirement**: Document Owner or Admin (Viewers receive `403 Forbidden`)
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `file`: UploadFile (binary, max 10MB, validated extension & magic bytes)
  - `title`: string (1-255 chars)
  - `category`: string (optional, default: "General")
- **Response `201 Created`**:
  ```json
  {
    "id": "doc_a1b2c3...",
    "title": "Quarterly Financial Audit",
    "original_filename": "q3_audit.pdf",
    "file_size_bytes": 1048576,
    "mime_type": "application/pdf",
    "category": "Financial",
    "owner_id": "u_984f1b...",
    "is_deleted": false,
    "created_at": "2026-10-19T10:00:00.000000Z",
    "updated_at": "2026-10-19T10:00:00.000000Z"
  }
  ```
- **Audit Event**: `document.upload` (Outcome: `SUCCESS`, or `DENIED` with an allowlisted `details.reason` of `insufficient_role`, `missing_filename`, `invalid_upload`, or `size_limit_exceeded` when an upload attempt is rejected)

### `GET /api/v1/documents`
- **Authentication**: Required
- **Authorization Rule**: Returns only documents owned by the caller OR documents where the caller has an active, non-revoked grant. This scope is applied before any search or filter and applies equally to administrators; admin role alone does not expose other users' document metadata.
- **Query Parameters**:
  - `page`: integer, minimum 1 (default: 1).
  - `page_size`: integer, 1-100 (default: 25).
  - `q`: optional string, 1-255 characters. Case-insensitive literal substring match against `title` and `original_filename`. SQL LIKE wildcards (`%`, `_`) are escaped and matched literally.
  - `category`: optional string, 1-100 characters. Exact category match.
  - `owner_id`: optional string, 1-64 characters. Exact owner ID match, evaluated inside the caller's authorized scope. Filtering by another user's ID returns only the caller's visible matches (normally an empty result); it cannot expand access.
  - `created_from`: optional ISO-8601 datetime. Inclusive lower bound on `created_at`. Naive datetimes are interpreted as UTC; timezone offsets are normalized to UTC.
  - `created_to`: optional ISO-8601 datetime. Inclusive upper bound on `created_at`. Naive datetimes are interpreted as UTC; timezone offsets are normalized to UTC.
- **Validation**: Invalid pagination, blank/oversized string filters, malformed datetimes, or `created_from > created_to` return `422 Unprocessable Entity`.
- **Sorting**: `created_at` descending. Pagination and sorting match the previous list behavior.
- **Response `200 OK`**:
  ```json
  {
    "documents": [
      {
        "id": "doc_a1b2c3...",
        "title": "Quarterly Financial Audit",
        "original_filename": "q3_audit.pdf",
        "file_size_bytes": 1048576,
        "mime_type": "application/pdf",
        "category": "Financial",
        "owner_id": "u_984f1b...",
        "is_deleted": false,
        "created_at": "2026-10-19T10:00:00.000000Z",
        "updated_at": "2026-10-19T10:00:00.000000Z",
        "effective_permission": "owner"
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 25
  }
  ```
- **Effective Permission**: Calculated server-side from the current database state for each visible document: `owner` (caller owns it), `edit` (active edit grant), or `read` (active read grant). It is never accepted from the client. Revoked grants are excluded.
- **Notes**: Search and filtering are provided by this endpoint; there is no separate `/documents/search` route.

### `GET /api/v1/documents/{id}`
- **Authentication**: Required
- **Authorization Rule**: Must be owner or have an active grant. All other callers receive `404 Not Found`.
- **Response `200 OK`**: Document metadata (no version-history field is exposed by the current schema).
- **Audit Event**: `document.read` (Outcome: SUCCESS or DENIED)

### `GET /api/v1/documents/{id}/download`
- **Authentication**: Required
- **Authorization Rule**: Must be owner or have active grant with `read` or `edit`.
- **Response `200 OK`**: Binary byte stream with `Content-Disposition: attachment; filename="..."`.
- **Audit Event**: `document.download` (Outcome: SUCCESS or DENIED)

### `PATCH /api/v1/documents/{id}`
- **Authentication**: Required
- **Authorization Rule**: Owner or active grant with `edit`. Other callers receive `404 Not Found`.
- **Request Body**: Editable metadata only (`title`, `category`). Replacement-file upload is **not implemented** on this endpoint.
- **Response `200 OK`**: Updated document metadata.
- **Audit Event**: `document.edit` (SUCCESS when fields change; DENIED on unauthorized attempts)

### `DELETE /api/v1/documents/{id}`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY. Viewers, editors, and administrators cannot delete another user's document.
- **Response `204 No Content`**: Empty body; the document is soft-deleted and the physical file is removed.
- **Audit Event**: `document.delete` (Outcome: SUCCESS or DENIED)

---

## 3. Permission & Sharing Endpoints

### `GET /api/v1/documents/{id}/permissions`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY. Non-owners (including active grantees) receive `404 Not Found` to avoid disclosing sharing relationships.
- **Response `200 OK`**:
  ```json
  {
    "grants": [
      {
        "id": "gr_5c9d...",
        "document_id": "doc_a1b2c3...",
        "user_id": "u_recipient_123",
        "permission": "read",
        "granted_by_id": "u_owner_456",
        "is_revoked": false,
        "created_at": "2026-10-19T10:00:00.000000Z",
        "updated_at": "2026-10-19T10:00:00.000000Z"
      }
    ]
  }
  ```
- **Notes**: Includes revoked grants so owners can see historical sharing state.
- **Audit Event**: `permission.list_denied` on unauthorized attempts.

### `POST /api/v1/documents/{id}/permissions`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY. Non-owners receive `404 Not Found`.
- **Request Body**:
  ```json
  {
    "user_id": "u_recipient_123",
    "permission": "read"
  }
  ```
- **Validation**: `permission` must be `read` or `edit`; recipient must exist and be active; granting to the owner is rejected with `400 Bad Request`.
- **Upsert Semantics**: Re-granting to a previously revoked user reactivates the existing grant row, updates `granted_by_id`/`permission`, and clears `is_revoked`. The write uses the database `(document_id, user_id)` unique constraint with `ON CONFLICT DO UPDATE` on SQLite and PostgreSQL, so duplicate/concurrent requests leave exactly one grant row and apply the latest requested permission.
- **Response `201 Created`**: Grant representation (same shape as list items).
- **Audit Event**: `permission.grant` (Outcome: SUCCESS or DENIED)

### `DELETE /api/v1/documents/{id}/permissions/{user_id}`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY. Non-owners receive `404 Not Found`.
- **Action**: Immediately sets `is_revoked = True` in the current database transaction. There are no cached tokens or pre-signed URLs, so the very next request from the recipient is denied.
- **Response `200 OK`**: `{"detail": "Permission successfully revoked"}`
- **Error**: `404 Not Found` when no active grant exists for that recipient.
- **Audit Event**: `permission.revoke` (Outcome: SUCCESS or DENIED)

---

## 4. Administration Endpoints

All endpoints in this section require the Administrator role (`UserRole.ADMIN`).

### `GET /api/v1/admin/users`
- **Authentication**: Required
- **Query Parameters**: `page`, `page_size`
- **Response `200 OK`**: Paginated user list (`users`, `total`, `page`, `page_size`).

### `GET /api/v1/admin/users/{user_id}`
- **Authentication**: Required
- **Response `200 OK`**: User profile.
- **Error**: `404 Not Found` for an unknown user.

### `PATCH /api/v1/admin/users/{user_id}`
- **Authentication**: Required
- **Request Body**: `role` (`admin`, `owner`, or `viewer`) and/or `is_active`.
- **Response `200 OK`**: Updated user profile.
- **Errors**: `400 Bad Request` when an administrator attempts to remove their own admin role; `404 Not Found` for an unknown user.
- **Audit Events**: `user.role_change`, `user.deactivate`, or `user.reactivate`
- **Identity Lifecycle**: There is no user hard-delete endpoint. Referenced audit actors are protected by `ON DELETE RESTRICT`/`ON UPDATE RESTRICT`; deactivation is the supported lifecycle operation and preserves the actor identity covered by the audit hash.

### `POST /api/v1/admin/users/{user_id}/revoke-sessions`
- **Authentication**: Required
- **Action**: Immediately invalidates all active sessions for the target user.
- **Response `200 OK`**: `{"user_id": "...", "sessions_revoked": N}`
- **Audit Event**: `user.sessions_revoked`

### `GET /api/v1/admin/audit`
- **Authentication**: Required
- **Authorization Rule**: Administrator role only (`403 Forbidden` for owners/viewers).
- **Action**: Returns a filtered, paginated view of the tamper-evident audit log, sorted by `sequence_number` descending.
- **Query Parameters**:
  - `page`: integer, minimum 1 (default: 1).
  - `page_size`: integer, 1-100 (default: 25).
  - `actor_id`: optional exact actor user ID (1-36 characters).
  - `action`: optional exact action name (1-100 characters), for example `document.read`.
  - `resource_type`: optional exact resource type (1-50 characters), for example `document` or `document_grant`.
  - `resource_id`: optional exact resource ID (1-100 characters).
  - `outcome`: optional exact outcome, one of `SUCCESS`, `DENIED`, or `FAILURE`.
  - `timestamp_from`: optional ISO-8601 inclusive lower bound. Naive datetimes are interpreted as UTC; timezone offsets are normalized to UTC.
  - `timestamp_to`: optional ISO-8601 inclusive upper bound. Naive datetimes are interpreted as UTC; timezone offsets are normalized to UTC.
- **Validation**: Invalid pagination, blank/oversized filters, invalid outcomes, malformed datetimes, or `timestamp_from > timestamp_to` return `422 Unprocessable Entity`.
- **Response `200 OK`**:
  ```json
  {
    "events": [
      {
        "id": "ae_5c9d...",
        "sequence_number": 42,
        "timestamp": "2026-10-19T10:00:00.000000Z",
        "actor_id": "u_984f1b...",
        "action": "document.read",
        "resource_type": "document",
        "resource_id": "doc_a1b2c3...",
        "outcome": "SUCCESS",
        "request_id": "5f42...",
        "ip_address": "127.0.0.1",
        "user_agent": "Mozilla/5.0...",
        "details": {"changed_fields": ["title"]}
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 25
  }
  ```
- **Response Safety**: Only the fields shown above are exposed. Internal hash-chain fields (`previous_hash`, `record_hash`) and user credential fields are never returned. Verification diagnostics redact full hash values before returning a failure reason. Stored JSON `details` is parsed into an object; malformed or non-object details are returned as `null`.
- **Detail Redaction**: `details` uses a default-deny key allowlist for `already_present`, `changed_fields`, `checkpoint_sequence`, `document_id`, `email`, `from_role`, `permission`, `reason`, `recipient_id`, `role`, `sessions_revoked`, `target_user_id`, `to_role`, and `verification_status`. Every other key is returned as `[redacted]`, including document title, filename, size, category, MIME type, storage path/key, password, and token values. Redaction applies only to API serialization; stored audit records remain unchanged.
- **Caching**: Responses set `Cache-Control: no-store` and `Pragma: no-cache` on all audit, activity, and checkpoint endpoints.
- **Read Auditing**: Each successful read of these endpoints is itself recorded as an audit event (`audit.read`, `audit.verify`, `audit.activity_read`, `audit.checkpoint_read`, or `audit.checkpoint_verify`, with `resource_type` `audit`). The event commits before the response is sent; if it cannot be persisted, the endpoint returns `503` with detail `Audit trail unavailable` instead of serving an unaudited response. Requests denied by role (`403`) or rate limiting (`429`) do not create read events.
- **Filtering Safety**: All filters use parameterized SQLAlchemy expressions. String filters are trimmed and exact-matched; document activity uses escaped literal matching where text search is required.

### `GET /api/v1/admin/audit/verify`
- **Authentication**: Required
- **Authorization Rule**: Administrator role only (`403 Forbidden` for owners/viewers).
- **Action**: Performs a bounded, read-only validation of audit sequence continuity, previous-hash links, and recomputed SHA-256 record hashes. It does not modify, repair, append, or truncate audit records.
- **Hash Coverage**: Each record is recomputed with its stored `hash_version`. Version 2 hashes bind the event `id`, `ip_address`, and `user_agent` in addition to sequence, timestamp, actor, action, resource, outcome, request ID, details, and previous hash; these fields are therefore tamper-evident through the verification API. Version 1 preserves the original payload for historical records and checkpoints. An unrecognized hash version is `INVALID`.
- **Consistency Boundary**: The endpoint first reads the current maximum `sequence_number` as a high-water mark, then verifies records in ascending keyset batches with `sequence_number <= high_water_mark`. Records committed after the high-water mark are outside that verification pass. VALID is returned only when every sequence from 1 through the high-water mark was examined without an integrity failure.
- **Resource Limits** (configurable through environment variables):

  | Setting | Default | Purpose |
  |---|---|---|
  | `AUDIT_VERIFY_MAX_RECORDS` | `100000` | Maximum chain length accepted for a complete pass. A larger chain returns `INCOMPLETE` without examining records. |
  | `AUDIT_VERIFY_BATCH_SIZE` | `1000` | Rows fetched per indexed batch. Prevents loading the entire chain into memory. |
  | `AUDIT_VERIFY_TIMEOUT_SECONDS` | `30` | Wall-clock budget for the pass. Expiry returns `INCOMPLETE` with the verified count. |
  | `AUDIT_VERIFY_RATE_LIMIT_MAX_REQUESTS` | `5` | Verification requests allowed per administrator per sliding window. |
  | `AUDIT_VERIFY_RATE_LIMIT_WINDOW_SECONDS` | `60` | Sliding-window duration for verification rate limiting. |

- **Response `200 OK`**:
  ```json
  {
    "status": "VALID",
    "is_valid": true,
    "records_verified": 42,
    "failure_reason": null
  }
  ```
- **Status Semantics**:
  - `VALID`: every record from sequence 1 through the high-water mark was examined and passed. `is_valid` is `true`.
  - `INVALID`: an altered record, altered record hash, v2 event identity or request-metadata tampering, unknown hash version, broken previous-hash link, or sequence gap was detected. `is_valid` is `false`, and `records_verified` is the number of records successfully verified before the failure.
  - `INCOMPLETE`: complete verification could not be performed because the chain exceeded the configured record limit or the time budget expired. `is_valid` is `false`, `records_verified` reports only records actually verified, and `failure_reason` explicitly states that verification was incomplete. An `INCOMPLETE` response never represents full-chain success.
- **Failure Response**: Integrity failures and incomplete passes both return `200 OK` with the status fields above. Full 64-character hash values in the underlying diagnostic are redacted as `[redacted]`; sequence numbers and failure type remain available.
- **Rate Limit Response**: Exceeding the per-administrator verification limit returns `429 Too Many Requests` with a `Retry-After` header in seconds and a generic error detail. Rate-limit responses also set `Cache-Control: no-store` and `Pragma: no-cache`. Query parameters cannot bypass the limit because the endpoint accepts none and every admitted or rejected request is evaluated against the same administrator identity.
- **Limiter Scope**: The limiter is in-memory and process-local. It is not shared across multiple workers or application instances, so the effective limit can be multiplied by the number of processes. Distributed enforcement requires an external shared limiter such as Redis.
- **Concurrency Limitation**: The high-water mark excludes later writes and prevents an endless verification chase, but the batch reads are not a single repeatable-read snapshot. A tampering write that lands between batch reads may not be reflected consistently in one pass; re-run verification after writes are quiesced for a stronger point-in-time check.
- **Caching**: Responses set `Cache-Control: no-store` and `Pragma: no-cache`.

### Checkpoint Anchoring Configuration
Checkpoint endpoints use the adapter selected by `AUDIT_ANCHOR_MODE`:

- `disabled` (default outside production): no anchoring; creation returns `503` and verification returns `UNAVAILABLE`. Production startup rejects this mode.
- `local_file`: development-only local directory (`AUDIT_ANCHOR_DIR`); rejected at startup in `ENVIRONMENT=production`.
- `s3`: external Amazon S3 or S3-compatible bucket (`AUDIT_ANCHOR_S3_*`), using the AWS default credential chain. Checkpoint documents use the same HMAC-protected format and conditional writes as the local adapter. The adapter ships in code but no provider configuration or credentials exist in this repository.

When anchoring is enabled, an in-process scheduler attempts a checkpoint every `AUDIT_CHECKPOINT_INTERVAL_SECONDS` and records the last attempt, success, failure reason, and checkpoint metadata in `GET /health` under `components.audit_anchor`. A successful attempt also appends `audit.checkpoint_scheduled` to the audit trail. Alert on `components.audit_anchor.status` other than `ok`/`local_development_only` and on top-level `status=degraded`. `AUDIT_CHECKPOINT_MAX_AGE_SECONDS` controls when the last successful checkpoint is reported as overdue and must be at least the interval.

### `POST /api/v1/admin/audit/checkpoints`
- **Authentication**: Required
- **Authorization Rule**: Administrator role only (`403 Forbidden` for owners/viewers).
- **Action**: Runs the same bounded chain verification as `GET /api/v1/admin/audit/verify` and, only if the committed chain is valid, stores a checkpoint through the configured checkpoint anchor adapter. A checkpoint binds the audit stream ID (`trustvault.audit`), the highest verified `sequence_number`, that record's hash, the checkpoint format version, a creation timestamp, and the preceding checkpoint's HMAC tag, protected by an HMAC-SHA256 integrity tag. The `audit.checkpoint_created` event is appended after the checkpoint is stored, so the checkpoint always covers a prefix that does not include its own creation event.
- **Request Body**: None.
- **Idempotency and Monotonicity**: Repeating the call for the current chain head is idempotent and returns the existing checkpoint. The anchor store rejects backwards writes (rollback) and conflicting checkpoints at the same sequence; extending the chain and calling again advances the checkpoint.
- **Response `201 Created`** (new checkpoint) or **`200 OK`** (checkpoint for this head already present):
  ```json
  {
    "status": "CREATED",
    "stream_id": "trustvault.audit",
    "sequence_number": 42,
    "created_at": "2026-10-19T10:00:00.000000Z",
    "anchor_mode": "local_file"
  }
  ```
  `status` is `CREATED` or `ALREADY_PRESENT`. `anchor_mode` is the configured adapter (`local_file` or `s3`). Response fields never include record hashes, HMAC tags, signing keys, filesystem paths, bucket names, object prefixes, endpoints, or provider error details.
- **Refusal `409 Conflict`**: Returned when the chain fails verification (altered record, broken link, gap), when the bounded pass was incomplete, when the stored checkpoint is ahead of the chain, or when the anchor store rejects a rollback or conflicting write. The detail is a generic message; the stored `audit.checkpoint_created` failure event records an allowlisted `reason` such as `chain_invalid`, `chain_incomplete`, `anchor_ahead_of_chain`, `anchor_chain_mismatch`, `anchor_rollback_detected`, or `anchor_conflict`.
- **Unavailable `503 Service Unavailable`**: Returned with a generic detail when no anchor adapter is configured (`AUDIT_ANCHOR_MODE=disabled`), the configured adapter is not reachable, or the provider denies access. The failure is recorded as `audit.checkpoint_created` with outcome `FAILURE` and `reason: anchor_unavailable` or `anchor_access_denied` where the audit trail is available. Provider error payloads, credentials, bucket names, prefixes, and endpoints are never returned. Other refusal reasons (`anchor_integrity_failure`, `anchor_format_unsupported`, `anchor_stream_mismatch`, `anchor_ahead_of_chain`, `anchor_chain_mismatch`, `anchor_rollback_detected`, `anchor_conflict`) return `409 Conflict`.
- **Rate Limit Response**: Checkpoint creation shares a separate per-administrator limiter from hash-chain verification. Exceeding `AUDIT_CHECKPOINT_RATE_LIMIT_MAX_REQUESTS` per `AUDIT_CHECKPOINT_RATE_LIMIT_WINDOW_SECONDS` returns `429` with `Retry-After`.
- **Audit Event**: `audit.checkpoint_created` (SUCCESS with allowlisted `details.already_present` and `details.checkpoint_sequence`; FAILURE with allowlisted `details.reason`). The chain verification and anchor comparison inspect only records committed before the event is appended.
- **Caching**: Responses set `Cache-Control: no-store` and `Pragma: no-cache`.

### `GET /api/v1/admin/audit/checkpoints`
- **Authentication**: Required
- **Authorization Rule**: Administrator role only (`403 Forbidden` for owners/viewers).
- **Action**: Returns metadata for the latest stored checkpoint without running chain verification. It does not return record hashes, HMAC tags, signing keys, or filesystem paths.
- **Response `200 OK`**:
  ```json
  {
    "available": true,
    "anchor_mode": "local_file",
    "stream_id": "trustvault.audit",
    "sequence_number": 42,
    "created_at": "2026-10-19T10:00:00.000000Z",
    "format_version": 1
  }
  ```
  When no anchor adapter is configured (`AUDIT_ANCHOR_MODE=disabled`), the endpoint returns `200 OK` with `available: false` and `null` checkpoint fields instead of failing. If the adapter is configured but no checkpoint has been written yet, it returns `200 OK` with `available: false`. Provider configuration (bucket, prefix, endpoint) is never returned.
- **Unavailable `503 Service Unavailable` / Conflict `409 Conflict`**: `503` is returned when a configured adapter cannot be reached; `409` is returned when the stored checkpoint fails its integrity check. The details are generic.
- **Audit Event**: `audit.checkpoint_read` (with `resource_type` `audit`). If the event cannot be persisted, the endpoint returns `503` with detail `Audit trail unavailable` instead of serving an unaudited response.
- **Caching**: Responses set `Cache-Control: no-store` and `Pragma: no-cache`.

### `GET /api/v1/admin/audit/checkpoints/verify`
- **Authentication**: Required
- **Authorization Rule**: Administrator role only (`403 Forbidden` for owners/viewers).
- **Action**: Runs the same bounded chain verification as `GET /api/v1/admin/audit/verify`, then compares the verified chain against the latest stored checkpoint. The chain is verified first, so integrity failures take precedence over anchor state.
- **Status Semantics**:
  - `VALID`: the bounded chain verification passed, a checkpoint exists at a non-genesis sequence, and the record hash at the checkpointed sequence equals the checkpoint's stored hash. The chain may legitimately extend beyond the checkpoint; `chain_head_sequence` reports the verified head. `is_valid` is `true`. `VALID` describes the chain and the latest checkpoint object the provider returned; it does not prove that the provider retained newer checkpoints or resisted deletion/rollback. Those guarantees depend on provider versioning, Object Lock, and permissions (see `docs/ARCHITECTURE.md`).
  - `INVALID`: the chain failed verification, the checkpointed sequence no longer exists (tail truncation), the chain's hash at that sequence no longer matches the checkpoint (history rewrite), or the stored checkpoint fails its HMAC integrity check. `is_valid` is `false`.
  - `INCOMPLETE`: the chain passed verification but no checkpoint has been stored yet, the bounded pass hit the record limit or time budget, or the latest checkpoint is genesis-only (`sequence_number=0`). A genesis-only checkpoint cannot distinguish a legitimately empty chain from truncation to zero, so it is never reported as `VALID`. `is_valid` is `false` and `failure_reason` states why a complete comparison could not be made.
  - `UNAVAILABLE`: the anchor is not configured (`AUDIT_ANCHOR_MODE=disabled`) or the configured provider is unreachable or denies access. `is_valid` is `false` and `checkpoint_sequence` is `null`. This is an operational availability state, not evidence that the audit chain is valid.
- **Response `200 OK`**:
  ```json
  {
    "status": "VALID",
    "is_valid": true,
    "records_verified": 42,
    "checkpoint_sequence": 40,
    "chain_head_sequence": 42,
    "failure_reason": null,
    "anchor_mode": "local_file"
  }
  ```
- **Resource Limits**: Uses the same `AUDIT_VERIFY_*` settings as `GET /api/v1/admin/audit/verify`. Full 64-character hash values in the underlying diagnostic are redacted as `[redacted]`.
- **Rate Limit Response**: Exceeding `AUDIT_CHECKPOINT_RATE_LIMIT_MAX_REQUESTS` per `AUDIT_CHECKPOINT_RATE_LIMIT_WINDOW_SECONDS` returns `429` with `Retry-After`. This limiter is separate from the hash-chain verification limiter.
- **Audit Event**: `audit.checkpoint_verify` (with allowlisted `details.verification_status` recording `VALID`, `INVALID`, `INCOMPLETE`, or `UNAVAILABLE`). The event commits before the response is sent; if it cannot be persisted, the endpoint returns `503` with detail `Audit trail unavailable`.
- **Caching**: Responses set `Cache-Control: no-store` and `Pragma: no-cache`.

### `GET /api/v1/admin/documents/activity`
- **Authentication**: Required
- **Authorization Rule**: Administrator role only (`403 Forbidden` for owners/viewers).
- **Action**: Returns a filtered, paginated activity history restricted to `document` and `document_grant` audit resources, sorted by `sequence_number` descending.
- **Query Parameters**:
  - `page`: integer, minimum 1 (default: 1).
  - `page_size`: integer, 1-100 (default: 25).
  - `document_id`: optional document ID (1-100 characters). Matches document events whose `resource_id` is the document ID, and grant events whose recorded `details.document_id` is the document ID.
  - `actor_id`: optional exact actor user ID (1-36 characters).
  - `action`: optional exact action name (1-100 characters), for example `document.download` or `permission.revoke`.
  - `outcome`: optional exact outcome, one of `SUCCESS`, `DENIED`, or `FAILURE`.
  - `timestamp_from` / `timestamp_to`: optional inclusive ISO-8601 bounds, normalized to UTC.
- **Response `200 OK`**: Same paginated envelope and safe event shape as `GET /api/v1/admin/audit`, limited to document activity.
- **Boundary**: This endpoint does not return document metadata values or bytes and does not grant any document access. Document title, filename, size, category, and MIME type values in `details` are redacted through the same default-deny allowlist as the audit endpoint. The administrator remains subject to the normal owner-or-active-grant rules on document endpoints.
- **Audit Coverage Note**: Reading audit, activity, or checkpoint data through these endpoints is itself recorded as `audit.read`, `audit.verify`, `audit.activity_read`, `audit.checkpoint_read`, and `audit.checkpoint_verify` events with `resource_type` `audit`, and the response is withheld with `503` if that event cannot be persisted. Checkpoint creation is recorded as `audit.checkpoint_created` after the anchor write. Known remaining read gaps (document listing/search, successful permission listing, administrative user-listing) are documented in `docs/ARCHITECTURE.md`.
