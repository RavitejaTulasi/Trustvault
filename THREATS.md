# TrustVault Threat Model & Security Posture

This document defines the comprehensive threat model for **TrustVault**. It analyzes potential attack vectors, business and technical impact, architectural mitigations, automated test verification evidence, residual risks, and current status.

Status Classifications:
- **Mitigated**: Architectural control implemented, enforced server-side, and verified via automated tests.
- **Partially Mitigated**: Core defenses active; higher-tier controls scheduled in subsequent development milestones or external infrastructure.
- **Accepted Risk**: Documented inherent risk where remediation exceeds MVP scope or relies on hosting environment operational security.

---

## Threat Matrix Overview

| Threat ID | Threat Category | OWASP / Security Vector | Status | Primary Defense Layer |
|---|---|---|---|---|
| **TV-01** | Broken Object-Level Authorization (BOLA / IDOR) | OWASP API1:2023 | **Mitigated** | Centralized `AuthorizationService` evaluated on fresh DB state |
| **TV-02** | Broken Function-Level Authorization | OWASP API5:2023 | **Mitigated** | Server-side role enforcement (`require_admin`), client roles ignored |
| **TV-03** | Privilege Escalation (Vertical/Horizontal) | CWE-269 / CWE-250 | **Mitigated** | Role immutable via user endpoints, strict separation of privileges |
| **TV-04** | Insecure Direct File Access (Direct Download URL) | OWASP API1 / CWE-639 | **Mitigated** | Platform-mediated streaming; random 256-bit unguessable storage keys |
| **TV-05** | Revocation Races & Stale Authorization | CWE-672 / CWE-362 | **Mitigated** | Zero caching of authorization decisions; immediate query on request |
| **TV-06** | Session Theft & Cross-Site Request Forgery (CSRF) | OWASP A01:2021 / CWE-352 | **Mitigated** | HTTP-only, SameSite=Lax/Strict cookies, token hashing, CSRF headers |
| **TV-07** | Brute-Force Authentication & Credential Stuffing | OWASP A07:2021 / CWE-307 | **Mitigated** | Argon2 hashing, per-IP/account rate limits, failure auditing |
| **TV-08** | SQL Injection & Stored/Reflected XSS | OWASP A03:2021 | **Mitigated** | SQLAlchemy 2.0 parameterized queries, CSP headers, nosniff |
| **TV-09** | Path Traversal / Directory Traversal | CWE-22 / CWE-23 | **Mitigated** | Decoupled server keys, `is_relative_to` containment verification |
| **TV-10** | Malicious & Oversized File Uploads | CWE-434 / CWE-400 | **Mitigated** | Chunked stream size enforcement (10MB limit), magic byte validation |
| **TV-11** | Search & Metadata Leakage | CWE-200 / CWE-209 | **Mitigated** | DB-level authorization scope applied before search filters |
| **TV-12** | Audit Log Tampering or Omission | CWE-778 / CWE-353 | **Partially Mitigated** | SHA-256 cryptographic hash-chaining; external WORM anchoring noted |
| **TV-13** | Administrator Misuse & Overprivileged Admin | Principle of Least Privilege | **Mitigated** | No implicit document access; ownership/grant checks apply to admins |
| **TV-14** | Concurrent Modification & Race Conditions | CWE-362 | **Partially Mitigated** | Database transactions, unique constraints, atomic SQL updates |
| **TV-15** | Public Storage Misconfiguration | OWASP A05:2021 | **Mitigated** | Storage path strictly outside web root; no static routing to storage |
| **TV-16** | Secret Leakage through Git & Version Control | CWE-798 | **Mitigated** | `.gitignore` filters `.env`, `private_storage/`, `*.db`; `.env.example` template |
| **TV-17** | Insecure Caching of Sensitive Metadata & Bytes | CWE-525 / CWE-524 | **Mitigated** | `Cache-Control: no-store, no-cache`, security headers middleware |
| **TV-18** | Backup and Disaster Recovery Compromise | CWE-311 | **Accepted Risk** | Host-level encrypted volume snapshots; external storage backup policy |
| **TV-19** | Audit API Data Exposure and Verification Abuse | OWASP API1/API5 / CWE-200 | **Mitigated** | Admin-only RBAC, allowlisted read-only responses, bounded pagination |

---

## Detailed Threat Profiles

### TV-01: Broken Object-Level Authorization (BOLA / IDOR)
- **Attack Scenario**: Attacker modifies document UUID in `GET /documents/{id}`, `GET /documents/{id}/download`, or `PATCH /documents/{id}` to access or alter another user's private file.
- **Impact**: Critical confidentiality and integrity breach. Unauthorized access to proprietary documents.
- **Mitigation**: Centralized `AuthorizationService.authorize_document_access()` is executed unconditionally in every document route handler. Authorization checks verify active account, ownership, or valid non-revoked grant before returning any byte stream or metadata.
- **Test Evidence**: `test_cross_user_document_isolation`, `test_admin_cannot_access_document_contents`.
- **Residual Risk**: Zero at the application layer; rely on server-side authorization rather than frontend filtering or unguessable IDs.
- **Status**: **Mitigated**

### TV-02: Broken Function-Level Authorization
- **Attack Scenario**: A regular viewer or document owner attempts to invoke administrative user-management endpoints such as `GET /admin/users` or `PATCH /admin/users/{user_id}`, or the audit endpoints `GET /admin/audit`, `GET /admin/audit/verify`, and `GET /admin/documents/activity`.
- **Impact**: Unauthorized user administration, privilege changes, or audit-data disclosure.
- **Mitigation**: Route-level dependency `require_admin` verifies the authenticated session's server-stored user role on every administrative endpoint. Client-supplied role claims in cookies or bodies are never parsed or trusted.
- **Test Evidence**: `test_admin_list_users_requires_admin`, `test_admin_list_users_requires_admin_owner`, `test_unauthenticated_admin_endpoints_return_401`, `test_audit_endpoints_require_authentication`, `test_audit_endpoints_deny_non_admin_roles`.
- **Residual Risk**: Low. Server-side session validation only.
- **Status**: **Mitigated**

### TV-03: Privilege Escalation
- **Attack Scenario**: User submits `{"role": "admin"}` in `PATCH /auth/me` or user profile updates.
- **Impact**: Vertical privilege escalation resulting in full system administrative control.
- **Mitigation**: Strict Pydantic input schemas whitelist only user-editable profile fields (`full_name`, `password`); `UserUpdateRequest` has no role field. Role mutation is reserved for the admin-only user endpoint with explicit audit logging.
- **Test Evidence**: `test_register_sets_viewer_role`, `test_admin_update_user_role`, `test_admin_cannot_remove_own_admin_role`; schema field whitelist verified by inspection.
- **Residual Risk**: None. Roles are immutable via self-service APIs.
- **Status**: **Mitigated**

### TV-04: Insecure Direct File Access (Predictable Storage Paths)
- **Attack Scenario**: Attacker probes static web root paths (e.g., `https://example.com/uploads/document_1.pdf`) to bypass API authentication.
- **Impact**: Total confidentiality breach bypassing all authorization logic.
- **Mitigation**: Files are persisted outside the application web root in `STORAGE_DIR`. Files are named with 256-bit cryptographically random hex keys (`secrets.token_hex(32)`). Physical storage paths are never exposed to clients. All downloads must flow through `GET /documents/{id}/download` which verifies authorization immediately prior to streaming.
- **Test Evidence**: `test_owner_lifecycle_operations`, `test_cross_user_document_isolation`.
- **Residual Risk**: Low. Storage access relies on OS filesystem permissions for the backend service user.
- **Status**: **Mitigated**

### TV-05: Revocation Races and Stale Authorization
- **Attack Scenario**: Document owner revokes access for user B. User B attempts to download the file 1 second later using a cached session or active connection.
- **Impact**: Unauthorized retrieval of documents after access was formally revoked.
- **Mitigation**: No caching of authorization decisions is permitted. Every single request queries the live database transaction for the current state of `DocumentGrant.is_revoked`; there are no authorization tokens, signed URLs, or permission snapshots. Revoking a grant sets `is_revoked = True` in the same transaction that records the audit event, so the recipient's next metadata read, download, or edit is denied. Revoked grant rows are retained for audit history, and re-granting reactivates the row only after an explicit owner action.
- **Test Evidence**: `test_immediate_revocation_sequence` (grant → verified access → revoke → immediate 404 on metadata, download, and edit), `test_read_grant_permissions_enforced`, `test_edit_grant_permissions_enforced`, `test_regrant_after_revocation_restores_requested_permission`, `test_document_list_excludes_revoked_grant`.
- **Residual Risk**: Standard limitation: cannot erase a file that a recipient already physically downloaded to their local disk prior to revocation.
- **Status**: **Mitigated**

### TV-06: Session Theft and Cross-Site Request Forgery (CSRF)
- **Attack Scenario**: Cross-site script steals session tokens or malicious site submits state-changing requests using ambient credentials.
- **Impact**: Account takeover or unauthorized document deletion/sharing.
- **Mitigation**: Server-side session tokens stored in `HttpOnly`, `SameSite=Lax` (or `Strict` for mutations), `Secure` (in production) cookies. Session tokens stored in database are SHA-256 hashed so DB leakage does not reveal valid session tokens. CSRF double-submit token headers required for state-changing mutations (`POST`, `PATCH`, `DELETE`).
- **Test Evidence**: `test_csrf_missing_header_rejected`, `test_csrf_mismatched_token_rejected`, `test_csrf_valid_token_succeeds`.
- **Residual Risk**: Browser-level XSS could compromise client context; mitigated with strict CSP headers.
- **Status**: **Mitigated**

### TV-07: Brute-Force Authentication
- **Attack Scenario**: Automated dictionary attack against `POST /auth/login`.
- **Impact**: Compromise of user credentials.
- **Mitigation**: Argon2id password hashing with modern memory/time parameters. In-memory / Redis sliding-window rate limiting on login attempts (maximum 5 attempts per 5 minutes per IP/email). Failed attempts logged as audit events.
- **Test Evidence**: `test_login_rate_limiting_exceeded`, `test_login_rate_limit_reset_on_success`.
- **Residual Risk**: Distributed attacks across multiple IPs require edge/WAF rate limiting (Cloudflare/AWS WAF). In-memory rate limiter is process-local.
- **Status**: **Mitigated**

### TV-08: SQL Injection and Cross-Site Scripting (XSS)
- **Attack Scenario**: SQL injection payloads in document search/filter parameters (`GET /documents?q=' OR 1=1--`) or HTML/JS payloads in document titles.
- **Impact**: Database exfiltration or stored script execution in viewer browsers.
- **Mitigation**: SQLAlchemy 2.0 ORM with 100% parameterized statements; no raw string concatenation in queries. Search terms are passed as bound parameters, and SQL LIKE wildcards (`%`, `_`) are escaped so user input is matched literally. Security headers middleware injects `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Content-Security-Policy`. React frontend escapes rendered content by default.
- **Test Evidence**: `test_security_headers_present`, `test_search_treats_sql_injection_and_wildcards_as_literal`.
- **Residual Risk**: None identified within application codebase.
- **Status**: **Mitigated**

### TV-09: Path Traversal
- **Attack Scenario**: Attacker uploads a file with filename `../../../../etc/passwd` or attempts to download with manipulated storage key.
- **Impact**: Arbitrary file read or overwrite on the server host.
- **Mitigation**: Client-supplied filenames are purely stored as metadata in DB (`original_filename`) and sanitized for `Content-Disposition`. The physical filename on disk is generated on the server using `secrets.token_hex(32)`. `StorageService` verifies `target_path.is_relative_to(storage_dir)`.
- **Test Evidence**: `StorageService.get_file_path` rejects non-hex keys and traversal attempts; verified by code inspection. No dedicated path-traversal test is present.
- **Residual Risk**: Negligible.
- **Status**: **Mitigated**

### TV-10: Malicious and Oversized Uploads
- **Attack Scenario**: Attacker uploads a 10GB archive to exhaust server disk space (DoS) or uploads a `.exe`/malicious script disguised as `.pdf`.
- **Impact**: Server disk exhaustion, denial of service, or malware distribution.
- **Mitigation**: Chunked streaming writes with immediate size check aborting when accumulated bytes exceed `MAX_FILE_SIZE_BYTES` (10MB). Extension whitelist combined with magic byte inspection (first 512 bytes) for supported formats.
- **Test Evidence**: `test_invalid_file_type_and_magic_bytes_rejected`, `test_empty_upload_rejected`.
- **Residual Risk**: Zero-day exploit payloads inside valid PDF formats; production environments should integrate ClamAV or virus scanning pipelines.
- **Status**: **Mitigated**

### TV-11: Search and Metadata Leakage
- **Attack Scenario**: User searches or filters `GET /documents` with `q`, `category`, `owner_id`, or created-date ranges to discover titles, filenames, ownership, or existence of documents they are not authorized to view.
- **Impact**: Information disclosure / confidential metadata discovery.
- **Mitigation**: Search and filtering are implemented on the existing document-list endpoint rather than a separate bypass-prone route. The SQL query first applies the mandatory authorization criteria (User is owner OR User has an active, unrevoked grant), then ANDs the optional filters. Filters can only narrow visible results; they cannot widen access. Owner filters are evaluated inside this scope, so filtering by another user's ID does not reveal their documents. This applies equally to administrators; admin role alone does not widen metadata visibility. Search matches title/filename with bound parameters and escaped LIKE wildcards, and list responses expose only the caller's server-derived effective permission. Unauthorized single-document requests return deliberate 404 without metadata leakage.
- **Test Evidence**: `test_search_matches_title_and_filename_case_insensitively`, `test_owner_filter_never_expands_visibility`, `test_category_filter_and_empty_results`, `test_created_date_range_and_invalid_ranges`, `test_multiple_filters_combine`, `test_effective_permissions_for_owner_editor_and_reader`, `test_search_excludes_revoked_grants_and_deleted_documents`, `test_admin_search_scope_includes_only_owned_and_granted`, `test_owner_lifecycle_operations`, `test_cross_user_document_isolation`, `test_admin_cannot_list_unshared_document_metadata`, `test_document_list_excludes_revoked_grant`.
- **Residual Risk**: Low. Substring search uses a leading-wildcard `LIKE`, which may require a full scan as document volume grows; authorization filtering remains mandatory regardless of performance optimizations.
- **Status**: **Mitigated**

### TV-12: Audit Log Tampering or Omission
- **Attack Scenario**: Malicious actor or compromised account attempts to modify or delete audit log entries to conceal unauthorized actions.
- **Impact**: Loss of non-repudiation, forensics invalidation, compliance failure.
- **Mitigation**: Cryptographic hash-chaining using SHA-256 (`record_hash = SHA256(seq + timestamp + actor + action + outcome + details + previous_hash)`). `AuditService.verify_chain_integrity()` verifies continuity from genesis to latest record. Modifying or deleting any single record invalidates the entire subsequent chain. Administrators can invoke the same read-only verification through `GET /admin/audit/verify`; the endpoint reports validity, records verified, and a failure reason with full hash values redacted, without repairing or altering records.
- **Honest Limitation**: Hash chaining alone does not prevent an attacker with root database access from rewriting the entire database chain from an arbitrary sequence number forward. External anchoring (streaming to immutable WORM storage like AWS S3 Object Lock) is documented for production hardening.
- **Test Evidence**: `test_audit_service_initialization_and_verification`, `test_audit_service_detects_tampering`, `test_audit_verification_returns_valid_chain_metadata`, `test_audit_verification_detects_tampering_without_repairing_it`, `test_verification_detects_altered_record_hash`, `test_verification_detects_broken_previous_hash_link`, `test_verification_detects_sequence_gap`.
- **Status**: **Partially Mitigated** (Cryptographic chaining active; external anchoring recommended for production).

### TV-13: Administrator Misuse (Overprivileged Administrator)
- **Attack Scenario**: Rogue administrator uses admin role to browse and download confidential proprietary documents belonging to other users.
- **Impact**: Insider threat data breach.
- **Mitigation**: Administrators are NOT automatically granted metadata, content read, or download permissions. Listing, metadata retrieval, downloads, edits, deletion, and grant management all follow the same owner-or-active-grant policy for administrators as for every other user. Administrative capabilities are restricted to user account management, audit investigation, and platform health; document actions are available only under the same ownership/grant rules as other users. The audit and activity endpoints are read-only, admin-only, expose no document bytes, hash-chain internals, or document metadata values (audit `details` values are default-deny redacted), and cannot expand document access. State-changing administrative actions are recorded in the tamper-evident audit log with the admin's actor ID. Administrative user-list/profile reads and audit API reads are not currently audit-logged; this coverage gap is documented in `docs/ARCHITECTURE.md` Section 5.
- **Test Evidence**: `test_admin_cannot_access_document_contents`, `test_admin_cannot_list_unshared_document_metadata`, `test_admin_list_includes_owned_and_explicitly_granted_documents`, `test_admin_search_scope_includes_only_owned_and_granted`, `test_audit_chain_integrity`, `test_audit_endpoints_deny_non_admin_roles`, `test_audit_access_does_not_expand_document_visibility`, `test_audit_response_redacts_document_metadata_and_secret_values`.
- **Residual Risk**: Database superusers with direct OS/DB shell access can inspect physical storage; addressed by host encryption and access controls.
- **Status**: **Mitigated**

### TV-14: Concurrent Modification & Race Conditions
- **Attack Scenario**: Simultaneous grant and revoke requests or parallel edits leading to inconsistent grant state.
- **Impact**: Inconsistent permissions or corrupted document state.
- **Mitigation**: Database-level unique constraints (`uq_doc_user_grant`) prevent duplicate grant rows for the same document/recipient pair. Grant creation is an explicit atomic upsert: SQLite and PostgreSQL use `INSERT ... ON CONFLICT DO UPDATE`, which reactivates an existing row, updates the requested permission and grantor, and applies the latest write without leaving the transaction invalid. Unsupported dialects fall back to query-then-write while retaining the unique constraint. Every mutation executes inside a single transaction with the corresponding audit event.
- **Test Evidence**: `test_owner_can_grant_read_and_edit`, `test_immediate_revocation_sequence`, `test_regrant_after_revocation_restores_requested_permission`, `test_duplicate_grant_requests_keep_single_record`.
- **Residual Risk**: Concurrent duplicate writes are resolved last-writer-wins at the database. A dedicated simultaneous-request stress test is not implemented because the test suite shares one in-memory SQLite session; the uniqueness constraint and atomic upsert remain enforced. Extreme-load database deadlocks are not retried automatically by the application; they would surface as a server error and are left to deployment-level connection/transaction management.
- **Status**: **Partially Mitigated**

### TV-15: Public Storage Configuration
- **Attack Scenario**: Web server configuration error (e.g. Nginx alias or S3 public read bucket) exposes uploaded documents directly to the public Internet.
- **Impact**: Mass document exposure without authentication.
- **Mitigation**: Application config enforces `STORAGE_DIR` to reside outside the static web root. No static web server routing or public URL exposure exists for the storage path.
- **Test Evidence**: Architectural review and health check directory validation.
- **Residual Risk**: Hosting environment infrastructure misconfiguration.
- **Status**: **Mitigated**

### TV-16: Secret Leakage through Version Control
- **Attack Scenario**: Developer inadvertently commits database credentials or cryptographic secret keys to public GitHub repository.
- **Impact**: Complete infrastructure compromise.
- **Mitigation**: `.gitignore` strictly ignores `.env`, `*.db`, `*.sqlite`, `private_storage/`, `storage/`. A clean `.env.example` template with dummy placeholders is provided. No real credentials committed.
- **Test Evidence**: Automated git status and commit inspection.
- **Residual Risk**: None if developers follow established guidelines.
- **Status**: **Mitigated**

### TV-17: Insecure Caching of Sensitive Metadata and Bytes
- **Attack Scenario**: Shared proxy, browser cache, or CDN caches confidential document downloads or metadata, allowing subsequent users on the shared machine to view documents.
- **Impact**: Accidental data disclosure.
- **Mitigation**: Protected document downloads set `Cache-Control: no-store, no-cache, must-revalidate, private` and `Pragma: no-cache`. Administrative audit and document-activity endpoints set `Cache-Control: no-store` and `Pragma: no-cache`.
- **Test Evidence**: `test_admin_lists_audit_events_with_safe_fields_and_pagination`, `test_document_activity_correlates_document_and_grant_events`, and `test_audit_verification_returns_valid_chain_metadata` assert the audit/activity no-cache headers. Document download headers are verified by code inspection; no dedicated download-header test currently exists.
- **Residual Risk**: Negligible.
- **Status**: **Mitigated**

### TV-18: Backup and Recovery Compromise
- **Attack Scenario**: Unencrypted database dumps or file system backups stored in insecure locations.
- **Impact**: Exfiltration of entire document database and files.
- **Mitigation**: Managed PostgreSQL with transparent data encryption (TDE) at rest, encrypted EBS/volume storage, and strict IAM backup access policies.
- **Residual Risk**: Operational responsibility of hosting provider and cloud deployment administrator.
- **Status**: **Accepted Risk** (Infrastructure operational boundary).

### TV-19: Audit API Data Exposure and Verification Abuse
- **Attack Scenario**: A non-administrator attempts to enumerate audit events through the admin audit endpoints, or an administrator uses the read-only API to extract sensitive operational metadata or repeatedly triggers full-chain verification to consume server resources.
- **Impact**: Internal security-event disclosure (actor IDs, IP addresses, user agents, resource identifiers, request IDs) or resource exhaustion during chain verification on a large audit log.
- **Mitigation**: All three audit endpoints require `require_admin`, which revalidates the server-side session and stored role. Responses use an explicit field allowlist that excludes `previous_hash`, `record_hash`, credentials, document bytes, and storage keys, and `details` uses a default-deny key allowlist that returns `[redacted]` for document metadata, storage, credential, token, and unknown values. Responses disable caching. Verification diagnostics also redact full hash values. Pagination is capped at 100 events per request, string filters are length-bounded and parameterized, and activity text matching escapes LIKE metacharacters. Verification is read-only and cannot modify or repair the chain.
- **Test Evidence**: `test_audit_endpoints_require_authentication`, `test_audit_endpoints_deny_non_admin_roles`, `test_admin_lists_audit_events_with_safe_fields_and_pagination`, `test_audit_access_does_not_expand_document_visibility`, `test_audit_response_redacts_document_metadata_and_secret_values`, `test_verification_detects_altered_record_hash`, `test_verification_detects_broken_previous_hash_link`, `test_verification_detects_sequence_gap`.
- **Residual Risk**: Full-chain verification traverses every audit record and can become expensive as the log grows; the endpoint is administrator-only and does not mutate state. Audit API reads are not themselves audit-logged, so an administrator's investigation activity is not currently recorded. Deployment-level admin rate limiting and background verification are future hardening options.
- **Status**: **Mitigated**
