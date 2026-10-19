# TrustVault — Architecture & Security Specification

TrustVault is a secure document sharing platform designed with a primary focus on authorization correctness, private storage isolation, and a verifiable, tamper-evident audit trail.

---

## 1. System Overview & Core Principles

TrustVault is engineered around five mandatory security pillars:

1. **Default-Deny Authorization**: Every protected operation denies access unless an explicit ownership relation or active, unrevoked grant is confirmed in the current transaction.
2. **Server-Side Trust Boundary**: Frontend checks exist solely for user interface ergonomics. The backend is the sole authority; client-supplied role parameters or user IDs are rejected.
3. **Storage Decoupling**: Stored files are kept strictly outside the web server root. Physical file paths are generated via 256-bit unguessable random keys and are never exposed to clients.
4. **Immediate Revocation**: No cached authorization tokens or long-lived download URLs are used. When an access grant is revoked, the very next download or read attempt is blocked.
5. **Tamper-Evident Auditability**: Every instrumented authentication, state-changing, document access, access-denial, and administrative audit-read action produces a cryptographically hash-chained audit record. The exact recorded actions and the remaining gaps are listed in Section 5.

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
|  - Request ID & Security Headers Middleware (nosniff, DENY, CSP)        |
|  - Session Authentication Middleware (Argon2, Server-side sessions)    |
|  - Rate Limiter (Sliding window on login)                               |
+-------------------------------------------------------------------------+
       |                                          |
       v                                          v
+----------------------------------+   +----------------------------------+
| Central Authorization Service    |   | Private Persistent Storage       |
| (backend/app/services/           |   | (Outside Web Root)               |
|  authorization.py)               |   | - 256-bit unguessable keys       |
|  - Evaluates active session      |   | - Path traversal containment     |
|  - Evaluates document ownership  |   | - 10MB chunked stream validation |
|  - Evaluates active grant status |   +----------------------------------+
+----------------------------------+
       |
       v
+-------------------------------------------------------------------------+
|                  Database Layer (SQLAlchemy 2.0 + Alembic)              |
|                      Managed PostgreSQL / psycopg 3                     |
|  - users, sessions, documents, document_grants, audit_events            |
|  - Cryptographic Hash Chaining on audit_events                          |
+-------------------------------------------------------------------------+
```

---

## 4. Tamper-Evident Audit Chaining Design

Audit records form a cryptographic hash chain:

$$RecordHash_i = \text{SHA256}(Seq_i \parallel Timestamp_i \parallel Actor_i \parallel Action_i \parallel ResourceType_i \parallel ResourceId_i \parallel Outcome_i \parallel RequestId_i \parallel Details_i \parallel PreviousHash_i)$$

Where:
- $PreviousHash_1 = \text{"000...000"}_{64}$ (Genesis Hash)
- $PreviousHash_i = RecordHash_{i-1}$ for $i > 1$

### Verification Mechanism
`AuditService.verify_chain_integrity_bounded(db, ...)` verifies the chain from index 1 through a high-water mark captured at the start of the pass. Records are fetched in ascending keyset batches (bounded by `AUDIT_VERIFY_BATCH_SIZE`) using selected columns rather than materializing ORM entities or the full chain. For every record it:
1. Validates strictly ascending sequence numbers without gaps.
2. Validates that `event.previous_hash == previous_event.record_hash`.
3. Canonicalizes timestamps into UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
4. Recomputes the SHA-256 hash and asserts exact equality against `event.record_hash`.

The pass is bounded by `AUDIT_VERIFY_MAX_RECORDS` and `AUDIT_VERIFY_TIMEOUT_SECONDS`. The result distinguishes three outcomes:

- `VALID`: all records through the high-water mark were examined and passed.
- `INVALID`: an integrity failure was detected; the reported count stops before the failing record.
- `INCOMPLETE`: the record limit or time budget prevented complete verification. `is_valid` is `false`, and the result explicitly states that the pass was incomplete. A partial pass is never reported as full-chain success.

Administrators can invoke this verification through the read-only `GET /api/v1/admin/audit/verify` endpoint. The endpoint reports the status, the number of records verified, and a failure reason with full hash values redacted. It never rewrites a record, appends an event, truncates the chain, or returns stored hash-chain fields. Verification requests are limited per administrator by a process-local sliding-window limiter (`AUDIT_VERIFY_RATE_LIMIT_MAX_REQUESTS` per `AUDIT_VERIFY_RATE_LIMIT_WINDOW_SECONDS`, default 5 per 60 seconds); excess requests receive `429 Too Many Requests` with `Retry-After`.

### Verification Consistency and Limits
The high-water mark prevents verification from chasing audit writes that are appended during the pass: only records at or below the maximum sequence observed at the start are examined. This is not a single repeatable-read database snapshot. A record modified between batch reads can cause a mixed read, and a modification made after a record was already examined is not re-checked until the next run. For a stronger point-in-time result, run verification during a quiet window or against a database snapshot/read replica. The rate limiter is process-local and is not shared across workers or instances; deployment-level or Redis-backed enforcement is required to bound aggregate concurrency. If the chain exceeds the configured record limit or the time budget expires, the endpoint returns an explicit `INCOMPLETE` result rather than a partial success.

### Limitation & Production Anchoring
Hash chaining reliably detects unauthorized modification, insertion, or deletion of individual records within the observed chain. However, an attacker with full database superuser privileges could theoretically rewrite the entire chain from an arbitrary record forward. Truncating the current tail before a verification pass is also undetectable from database-internal state alone: the high-water mark is derived from the remaining rows, and the chain contains no self-authenticating record count. For high-assurance production environments, TrustVault supports streaming audit hashes to immutable external storage (e.g., AWS S3 Object Lock in Compliance Mode or RFC 3161 timestamping authorities) and recommends periodic external root-hash publication.

---

## 5. Administrative Audit API and Coverage

### API Surface
All three endpoints require the authenticated `admin` role and are registered under `/api/v1`:

- `GET /admin/audit`: filtered, paginated audit-event inspection across all actors and resources.
- `GET /admin/audit/verify`: bounded hash-chain verification with explicit `VALID`, `INVALID`, or `INCOMPLETE` outcomes and per-administrator rate limiting.
- `GET /admin/documents/activity`: filtered, paginated document and document-grant activity.

The audit and activity response schemas expose only `id`, `sequence_number`, `timestamp`, `actor_id`, `action`, `resource_type`, `resource_id`, `outcome`, `request_id`, `ip_address`, `user_agent`, and sanitized `details`. `previous_hash` and `record_hash` are deliberately excluded, as are any credential fields. `details` uses a default-deny allowlist that preserves correlation and account-management keys (`document_id`, `recipient_id`, `target_user_id`, `permission`, `reason`, `changed_fields`, `role`, `from_role`, `to_role`, `email`, `sessions_revoked`, and `verification_status`) and returns `[redacted]` for every other key, including document title, filename, size, category, MIME type, storage path/key, password, and token values. Raw audit rows are unchanged. Verification failure diagnostics redact full hash values. All three endpoints also return `Cache-Control: no-store` and `Pragma: no-cache`. String filters are trimmed, length-bounded, and exact-matched through bound SQLAlchemy expressions. `document_id` activity filtering matches direct document events by `resource_id` and grant events by the recorded `details.document_id`; LIKE metacharacters in the supplied ID are escaped.

These endpoints are read-only. They do not return document metadata values or bytes and do not create an alternative path to document access. An administrator querying audit data remains subject to the same owner-or-active-grant policy on document routes.

### Administrative Read Auditing
Each successful administrative read appends its own audit event with `resource_type` set to `audit` and no resource ID: `audit.read` for `GET /admin/audit`, `audit.verify` for `GET /admin/audit/verify` (with allowlisted `details.verification_status` recording `VALID`, `INVALID`, or `INCOMPLETE`), and `audit.activity_read` for `GET /admin/documents/activity`. The event is committed before the response is returned; if the event cannot be durably persisted, the endpoint returns `503 Audit trail unavailable` with `Cache-Control: no-store` instead of serving an unaudited response. Rate-limited (`429`) and non-administrator (`403`) requests do not create read events because no audit data is served. Verification still inspects only records at or below the high-water mark observed before its own read event is appended, so the read event never inflates `records_verified` for that pass.

### Recorded Audit Actions
The current build records the following events:

- Authentication and self-service: `user.register`, `user.login`, `user.login_failed`, `user.login_rate_limited`, `user.logout`, `user.update`.
- Administrative user management: `user.role_change`, `user.deactivate`, `user.reactivate`, `user.sessions_revoked`.
- Administrative audit inspection: `audit.read`, `audit.verify`, `audit.activity_read`.
- Documents: `document.upload`, `document.read`, `document.download`, `document.edit`, `document.delete`, including success and authorization-denial outcomes. Rejected uploads are recorded as `document.upload` with `DENIED` and an allowlisted `details.reason` (`insufficient_role`, `missing_filename`, `invalid_upload`, or `size_limit_exceeded`).
- Sharing: `permission.grant`, `permission.revoke`, and `permission.list_denied`.

### Known Coverage Gaps
The following operations are not currently recorded as audit events:

- Document list/search/read-metadata enumeration through `GET /documents`.
- Successful `GET /documents/{id}/permissions` reads (denied attempts are recorded as `permission.list_denied`).
- Administrative user-list/profile reads.
- Request-validation failures that occur before an audit call (for example, malformed multipart uploads or invalid pagination parameters); a syntactically valid but rejected upload is audited as described above.

These gaps mean the architecture does not claim that every read or every administrative query is audited. State-changing administrative actions and the document access paths listed above are audited; expanding read coverage would require a separate, explicit event-volume and privacy decision.
