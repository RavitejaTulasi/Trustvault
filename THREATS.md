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
| **TV-12** | Audit Log Tampering or Omission | CWE-778 / CWE-353 | **Partially Mitigated** | Versioned SHA-256 hash-chaining; actor FK restriction; independently stored HMAC checkpoints (local dev + external S3 adapter; no live deployment verified) |
| **TV-13** | Administrator Misuse & Overprivileged Admin | Principle of Least Privilege | **Mitigated** | No implicit document access; ownership/grant checks apply to admins |
| **TV-14** | Concurrent Modification & Race Conditions | CWE-362 | **Partially Mitigated** | Database transactions, unique constraints, atomic SQL updates, serialized audit append allocation |
| **TV-15** | Public Storage Misconfiguration | OWASP A05:2021 | **Mitigated** | Storage path strictly outside web root; no static routing to storage |
| **TV-16** | Secret Leakage through Git & Version Control | CWE-798 | **Mitigated** | `.gitignore` filters `.env`, `private_storage/`, `*.db`; `.env.example` template |
| **TV-17** | Insecure Caching of Sensitive Metadata & Bytes | CWE-525 / CWE-524 | **Mitigated** | `Cache-Control: no-store, no-cache`, security headers middleware |
| **TV-18** | Backup and Disaster Recovery Compromise | CWE-311 | **Accepted Risk** | Host-level encrypted volume snapshots; external storage backup policy |
| **TV-19** | Audit API Data Exposure and Verification Abuse | OWASP API1/API5 / CWE-200 | **Mitigated** | Admin-only RBAC, allowlisted read-only responses, bounded pagination |
| **TV-20** | Upload/Delete Crash Windows and Orphaned Files | CWE-459 / CWE-362 | **Partially Mitigated** | Private staging, atomic rename, commit-before-unlink, startup reconciliation |
| **TV-21** | Storage Exhaustion and Unbounded Request Bodies | CWE-400 / CWE-770 | **Mitigated** | Body limits, streamed-byte counting, serialized per-user/global quotas |
| **TV-22** | Audit Denial Flooding | CWE-779 / CWE-400 | **Mitigated** | One aggregate denial event per IP window via atomic claim |
| **TV-23** | Online Audit Retention Conflict | CWE-459 / CWE-693 | **Partially Mitigated** | Online chain never deleted; destructive auto-delete rejected at startup |

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
- **Mitigation**: Argon2id password hashing with modern memory/time parameters. Shared database-backed fixed-window rate limiting on login attempts (maximum 5 attempts per 5 minutes per IP and per IP+email), reserved atomically before password verification. Successful logins clear the IP+email bucket but do not erase earlier IP-wide failures. Failed attempts logged as audit events. Client IPs are taken from the immediate peer unless it matches an explicit `TRUSTED_PROXY_IPS` allowlist; forwarded headers from other peers are ignored.
- **Test Evidence**: `test_login_rate_limiting_exceeded`, `test_login_success_does_not_reset_ip_wide_failures`, `test_spoofed_forwarded_for_does_not_bypass_rate_limit`, `test_trusted_proxy_address_is_used_for_audit_and_limits`, `test_login_fails_closed_when_shared_limiter_is_unavailable`.
- **Residual Risk**: Distributed attacks across multiple IPs require edge/WAF rate limiting (Cloudflare/AWS WAF). The shared limiter depends on database availability and intentionally fails closed with `503` when storage is unavailable or its bounded bucket table is full. Deployments behind a reverse proxy must configure the exact proxy CIDRs; otherwise rate limiting and audit attribution use the proxy's immediate address.
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
- **Attack Scenario**: Malicious actor or compromised account attempts to modify or delete audit log entries to conceal unauthorized actions, including truncating or rewriting the entire database chain.
- **Impact**: Loss of non-repudiation, forensics invalidation, compliance failure.
- **Mitigation**: Cryptographic hash-chaining uses versioned SHA-256 payloads. Version 2 binds the stable event ID, client IP, user agent, sequence, timestamp, actor, action, resource type/ID, outcome, request ID, details, and previous hash; version 1 preserves the original delimiter-separated payload so historical records and checkpoints remain verifiable. `AuditService.verify_chain_integrity()` verifies continuity from genesis to latest record. Modifying or deleting any single record invalidates the entire subsequent chain, and an unrecognized hash version is reported as invalid. The audit-hardening migration refuses to downgrade below `c3d4e5f6a7b8` while version 2 records exist, so a downgrade/re-upgrade cycle cannot silently relabel evidence as version 1; recovery is by restoring a pre-upgrade database snapshot, not by rewriting audit rows. `audit_events.actor_id` uses `ON DELETE RESTRICT`/`ON UPDATE RESTRICT`, so a referenced actor cannot be deleted or re-keyed out of the hash-covered identity; account deactivation preserves the reference. Administrators can invoke the same read-only verification through `GET /admin/audit/verify`; the endpoint reports validity, records verified, and a failure reason with full hash values redacted, without repairing or altering records. Independently stored checkpoints are implemented through a `CheckpointStore` adapter: `POST /admin/audit/checkpoints` verifies the committed chain and stores a checkpoint binding the audit stream ID, the highest verified sequence number, its record hash, the format version, a creation timestamp, and a link to the preceding checkpoint, with an HMAC integrity tag. Checkpoint writes are single-write compare-and-swap: they cannot move backwards, silently overwrite a conflicting checkpoint, or bless an invalid or incompletely verified chain. `GET /admin/audit/checkpoints/verify` re-verifies the bounded chain and compares it with the stored checkpoint: a changed hash, a missing checkpointed sequence, a rewritten history, or a corrupt checkpoint reports `INVALID`; a missing checkpoint or bounded verification limit reports `INCOMPLETE`; an unconfigured or unreachable/access-denied anchor reports `UNAVAILABLE`. A genesis-only checkpoint is always `INCOMPLETE` because it cannot distinguish an empty chain from truncation to zero, and none of these states is ever reported as `VALID`. When anchoring is enabled, a scheduler attempts checkpoint creation at startup and every `AUDIT_CHECKPOINT_INTERVAL_SECONDS`, taking a PostgreSQL advisory lock to serialize scheduled writers; its last attempt, success, failure, checkpoint age, and overdue state are exposed through `/health` so anchoring failures are observable and alertable.
- **Implemented Adapters**: Two adapters exist. `local_file` is a development-only local directory protected by `AUDIT_ANCHOR_HMAC_KEY`; it shares the application host and filesystem failure domain and is explicitly **not** production-grade independent anchoring (production startup rejects it). `s3` is an external adapter for Amazon S3 or S3-compatible object storage, using conditional writes (`If-None-Match: *`), the same HMAC-protected checkpoint document format, the AWS default credential chain (credentials are never read or stored by the application), and optional Object Lock retention and KMS encryption. **No bucket, credentials, endpoint, or live configuration exists in this repository, and the adapter has not been exercised against a real bucket**; external anchoring is therefore implemented in code but not deployed or verified. Production startup now rejects `disabled` and `local_file` and requires the `s3` adapter; it fails closed if the adapter cannot initialize. Outside production, the default `AUDIT_ANCHOR_MODE=disabled` makes checkpoint creation fail closed with `503` and checkpoint verification report `UNAVAILABLE`.
- **Attacker Capability Analysis**:
  1. *Primary database only*: rewriting or truncating the chain at or below a stored checkpoint produces a hash mismatch or a missing checkpointed sequence, which verification reports as `INVALID`. The attacker cannot forge or modify a checkpoint without the HMAC key, assuming the anchor destination and key are outside their control. History rewritten strictly after the latest checkpoint is caught by the ordinary full-chain verification, not by the checkpoint comparison alone.
  2. *Database and application process both compromised*: the attacker holds the HMAC key and the provider credentials available to the workload identity, so no in-process checkpoint adapter adds protection. This boundary is treated as fully compromised.
  3. *Anchor destination or signing key compromised*: destination-only compromise can delete or roll back checkpoint objects if the provider permits it; for the external adapter, resistance depends on bucket configuration (versioning, Object Lock in COMPLIANCE mode, delete/retention permissions withheld from the application identity). The adapter requests object-lock retention when configured but cannot enforce bucket policy, and it cannot detect deletion, overwrite, or rollback of its own objects when the provider permits them or when a provider returns stale/incomplete listings as success. It reads only the highest visible checkpoint, so verification may report `VALID` against an older checkpoint after such a rollback. Conditional writes also assume AWS-compatible `If-None-Match` and read-after-write behavior; S3-compatible services must be verified with a concurrent-write preflight. Key-only compromise allows forging checkpoints in either adapter. No provider-side configuration has been deployed or verified in this build, and the local adapter cannot prevent deletion of its own files.
  4. No checkpoint design can defend an attacker who controls every trust boundary simultaneously.
- **Test Evidence**: `test_hash_version_2_binds_event_identity_ip_and_user_agent`, `test_verification_detects_v2_identity_and_metadata_tampering`, `test_legacy_version_1_record_still_verifies_and_new_appends_use_version_2`, `test_referenced_actor_cannot_be_deleted`, `test_direct_actor_delete_is_rejected_by_database_constraint`, `test_actor_deactivation_preserves_identity_and_hash_chain`, `test_upgrade_preserves_legacy_hashes_checkpoints_and_actor_references`, `test_downgrade_is_refused_when_version_2_records_exist`, `test_v1_chain_downgrade_and_reupgrade_preserves_verification`, `test_audit_service_initialization_and_verification`, `test_audit_service_detects_tampering`, `test_audit_verification_returns_valid_chain_metadata`, `test_audit_verification_detects_tampering_without_repairing_it`, `test_verification_detects_altered_record_hash`, `test_verification_detects_broken_previous_hash_link`, `test_verification_detects_sequence_gap`, `test_verification_detects_out_of_range_low_sequence`, `test_create_checkpoint_from_verified_chain`, `test_create_checkpoint_refuses_invalid_chain`, `test_create_checkpoint_refuses_incomplete_chain`, `test_create_checkpoint_retry_is_idempotent`, `test_genesis_checkpoint_does_not_make_empty_or_extended_chain_valid`, `test_create_checkpoint_detects_anchor_ahead_of_chain`, `test_store_rejects_rollback_and_conflicting_checkpoints`, `test_verify_matching_checkpoint_and_chain_extension`, `test_verify_detects_rewritten_history_at_checkpoint`, `test_verify_detects_missing_checkpointed_sequence`, `test_verify_returns_unavailable_when_anchor_unavailable`, `test_local_store_detects_tampered_checkpoint`, `test_checkpoint_endpoints_require_admin`, `test_health_reports_unstarted_external_anchor_as_degraded`, `test_scheduler_creates_checkpoint_and_updates_observable_state`, `test_scheduler_failure_is_fail_closed_and_observable`, `test_health_reports_overdue_checkpoint`, `test_runtime_validation_rejects_disabled_production_anchor`, `test_checkpoint_creation_preserves_historical_records`, `test_s3_store_write_read_roundtrip`, `test_s3_store_idempotent_retry`, `test_s3_store_rejects_conflict_rollback_and_broken_link`, `test_s3_store_handles_lost_conditional_write_race`, `test_s3_store_maps_unavailable_errors`, `test_s3_store_maps_access_denied_for_read_and_write`, `test_api_factory_fails_closed_when_client_creation_raises`, `test_s3_info_reports_unavailable_when_configured_but_empty`, `test_s3_store_detects_tampered_checkpoint`, `test_s3_store_detects_malformed_oversized_and_incomplete_objects`, `test_s3_store_paginates_and_ignores_unrelated_objects`, `test_s3_store_rejects_object_key_payload_mismatch`, `test_s3_store_rejects_repeated_listing_token`, `test_s3_service_create_and_verify_valid_chain`, `test_s3_service_detects_rewrite_at_checkpoint`, `test_s3_service_access_denied_never_returns_valid`, `test_s3_service_unavailable_reports_unavailable`, `test_s3_api_access_denied_fails_closed_without_leaking_provider_details`, `test_s3_api_unavailable_returns_generic_503`.
- **Residual Risk**: The version-2 coverage, legacy migration, and serialized appends are verified on offline SQLite tests only. The eight-worker PostgreSQL append test is opt-in and was not run against a live database, so multi-worker PostgreSQL behavior and the PostgreSQL migration branch remain unverified. No automatic retry is performed after a PostgreSQL deadlock or serialization failure; the whole transaction aborts and the caller must retry the complete request. External anchoring remains unconfigured and untested against a live provider.
- **Status**: **Partially Mitigated** (Versioned hash coverage, actor immutability, append serialization, production startup enforcement, scheduled checkpoint creation, and observable anchor health implemented; PostgreSQL concurrency/migration and a live external provider remain unverified).

### TV-13: Administrator Misuse (Overprivileged Administrator)
- **Attack Scenario**: Rogue administrator uses admin role to browse and download confidential proprietary documents belonging to other users.
- **Impact**: Insider threat data breach.
- **Mitigation**: Administrators are NOT automatically granted metadata, content read, or download permissions. Listing, metadata retrieval, downloads, edits, deletion, and grant management all follow the same owner-or-active-grant policy for administrators as for every other user. Administrative capabilities are restricted to user account management, audit investigation, and platform health; document actions are available only under the same ownership/grant rules as other users. The audit and activity endpoints are read-only, admin-only, expose no document bytes, hash-chain internals, or document metadata values (audit `details` values are default-deny redacted), and cannot expand document access. State-changing administrative actions are recorded in the tamper-evident audit log with the admin's actor ID. Successful administrative reads of the audit and activity endpoints are themselves recorded (`audit.read`, `audit.verify`, `audit.activity_read`), and the endpoint refuses to serve data with `503` if that event cannot be persisted, so an investigation cannot proceed unaudited. Administrative user-list/profile reads remain not audit-logged; this coverage gap is documented in `docs/ARCHITECTURE.md` Section 5.
- **Test Evidence**: `test_admin_cannot_access_document_contents`, `test_admin_cannot_list_unshared_document_metadata`, `test_admin_list_includes_owned_and_explicitly_granted_documents`, `test_admin_search_scope_includes_only_owned_and_granted`, `test_audit_chain_integrity`, `test_audit_endpoints_deny_non_admin_roles`, `test_audit_access_does_not_expand_document_visibility`, `test_audit_response_redacts_document_metadata_and_secret_values`, `test_admin_audit_reads_are_audited_once`, `test_admin_read_event_details_expose_only_allowlisted_fields`, `test_admin_audit_reads_fail_closed_when_audit_write_fails`.
- **Residual Risk**: Database superusers with direct OS/DB shell access can inspect physical storage; addressed by host encryption and access controls.
- **Status**: **Mitigated**

### TV-14: Concurrent Modification & Race Conditions
- **Attack Scenario**: Simultaneous grant and revoke requests or parallel edits leading to inconsistent grant state.
- **Impact**: Inconsistent permissions or corrupted document state.
- **Mitigation**: Database-level unique constraints (`uq_doc_user_grant`) prevent duplicate grant rows for the same document/recipient pair. Grant creation is an explicit atomic upsert: SQLite and PostgreSQL use `INSERT ... ON CONFLICT DO UPDATE`, which reactivates an existing row, updates the requested permission and grantor, and applies the latest write without leaving the transaction invalid. Unsupported dialects fall back to query-then-write while retaining the unique constraint. Every mutation executes inside a single transaction with the corresponding audit event. Audit appends allocate sequence numbers through the singleton `audit_chain_state` row: the atomic increment takes the row write lock until commit/rollback, and the event insert plus chain-head hash update share that transaction, preventing duplicate sequence numbers or forked previous hashes. An actor referenced by audit history cannot be hard-deleted or re-keyed because `audit_events.actor_id` uses restrictive foreign keys.
- **Test Evidence**: `test_owner_can_grant_read_and_edit`, `test_immediate_revocation_sequence`, `test_regrant_after_revocation_restores_requested_permission`, `test_duplicate_grant_requests_keep_single_record`, `test_sqlite_file_sessions_serialize_sequence_allocation`, `test_concurrent_postgres_appends_allocate_unique_contiguous_sequences` (opt-in).
- **Residual Risk**: Concurrent duplicate document writes are resolved last-writer-wins at the database. The default suite verifies serialized audit allocation with independent file-backed SQLite sessions; the eight-worker PostgreSQL test is opt-in and was not run in this build. PostgreSQL deadlocks and serialization failures abort the complete transaction and are not retried automatically by the application; they surface to the caller for request-level retry and are left to deployment-level transaction management.
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
- **Mitigation**: Protected document downloads set `Cache-Control: no-store, no-cache, must-revalidate, private` and `Pragma: no-cache`. Administrative audit, document-activity, and checkpoint endpoints set `Cache-Control: no-store` and `Pragma: no-cache`.
- **Test Evidence**: `test_admin_lists_audit_events_with_safe_fields_and_pagination`, `test_document_activity_correlates_document_and_grant_events`, `test_audit_verification_returns_valid_chain_metadata`, `test_checkpoint_api_create_inspect_and_verify`, `test_checkpoint_api_refuses_invalid_chain`, `test_checkpoint_api_fails_closed_when_anchor_unavailable`, and `test_checkpoint_verify_is_rate_limited_and_separate` assert the audit/activity/checkpoint no-cache headers. Document download headers are verified by code inspection; no dedicated download-header test currently exists.
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
- **Mitigation**: All audit and checkpoint endpoints require `require_admin`, which revalidates the server-side session and stored role. Responses use an explicit field allowlist that excludes `previous_hash`, `record_hash`, checkpoint HMAC tags, credentials, document bytes, storage keys, and provider configuration (bucket names, object prefixes, endpoint URLs, and credentials); provider failures are mapped to fixed reasons (`anchor_unavailable`, `anchor_access_denied`) without returning or logging provider error payloads. `details` uses a default-deny key allowlist that returns `[redacted]` for document metadata, storage, credential, token, and unknown values. Responses disable caching. Verification diagnostics also redact full hash values. Pagination is capped at 100 events per request, string filters are length-bounded and parameterized, and activity text matching escapes LIKE metacharacters. Verification is read-only and cannot modify or repair the chain. Chain verification uses a high-water mark, indexed keyset batches, selected columns, a configurable maximum record count (`AUDIT_VERIFY_MAX_RECORDS`), and a wall-clock budget (`AUDIT_VERIFY_TIMEOUT_SECONDS`). If complete verification cannot finish, the endpoint returns an explicit `INCOMPLETE` result with `is_valid: false`; it never reports partial work as full success. A process-local sliding-window limiter permits `AUDIT_VERIFY_RATE_LIMIT_MAX_REQUESTS` per administrator per `AUDIT_VERIFY_RATE_LIMIT_WINDOW_SECONDS` (default 5 per 60 seconds) and returns `429` with `Retry-After` on excess requests. Checkpoint creation and checkpoint verification are additionally bounded by a separate per-administrator limiter (`AUDIT_CHECKPOINT_RATE_LIMIT_MAX_REQUESTS` per `AUDIT_CHECKPOINT_RATE_LIMIT_WINDOW_SECONDS`) and reuse the same bounded chain-verification limits. Each successful read is itself recorded as an audit event (`audit.read`, `audit.verify`, `audit.activity_read`, `audit.checkpoint_read`, `audit.checkpoint_verify`, `audit.checkpoint_created`) with `resource_type` `audit`, and the response is withheld with `503 Audit trail unavailable` if that event cannot be persisted. Denied (`403`) and rate-limited (`429`) requests serve no audit data and create no read events; the verification read event is appended only after the pass completes, so it never inflates `records_verified`.
- **Test Evidence**: `test_audit_endpoints_require_authentication`, `test_audit_endpoints_deny_non_admin_roles`, `test_admin_lists_audit_events_with_safe_fields_and_pagination`, `test_audit_access_does_not_expand_document_visibility`, `test_audit_response_redacts_document_metadata_and_secret_values`, `test_verification_detects_altered_record_hash`, `test_verification_detects_broken_previous_hash_link`, `test_verification_detects_sequence_gap`, `test_verification_accepts_empty_chain`, `test_verification_processes_large_chain_in_bounded_batches`, `test_verification_detects_out_of_range_low_sequence`, `test_verification_timeout_returns_incomplete_not_valid`, `test_audit_verification_reports_incomplete_without_full_success`, `test_audit_verification_is_rate_limited`, `test_admin_audit_reads_are_audited_once`, `test_admin_read_event_details_expose_only_allowlisted_fields`, `test_admin_audit_reads_fail_closed_when_audit_write_fails`, `test_failed_audit_write_rolls_back_partial_event_and_session_recovers`, `test_checkpoint_endpoints_require_admin`, `test_checkpoint_api_create_inspect_and_verify`, `test_checkpoint_verify_is_rate_limited_and_separate`, `test_checkpoint_creation_respects_verification_bounds`, `test_checkpoint_api_fails_closed_when_anchor_unavailable`, `test_checkpoint_creation_survives_audit_write_failure`, `test_checkpoint_api_duplicate_returns_already_present`, `test_api_factory_fails_closed_without_provider_client`, `test_s3_api_access_denied_fails_closed_without_leaking_provider_details`, `test_s3_api_unavailable_returns_generic_503`.
- **Residual Risk**: Verification still traverses every record through the high-water mark, so cost grows linearly with chain length even though memory and time are bounded. Both limiters are in-memory and process-local, so aggregate concurrency across workers or instances is not limited; a shared Redis-backed limiter is required for distributed enforcement. Batch reads are not a single repeatable-read snapshot; concurrent tampering between batches may require a re-run during a quiet window. Read auditing increases audit-log volume because inspection itself appends records; a busy administrator generates proportionally more events. Checkpoint creation and verification each append their own audit events after the pass, and a checkpoint never covers its own creation event. Background verification and a real external anchoring provider remain operational hardening options.
- **Status**: **Mitigated**

### TV-20: Upload/Delete Crash Windows and Orphaned Files

- **Attack Scenario**: A process crash or storage failure after a file is published but before the database commits, or after a soft-delete commit but before unlink, leaves unreferenced or deleted-document files on disk.
- **Impact**: Confidential bytes persist beyond their authorized lifecycle, or stale files accumulate.
- **Mitigation**: Uploads stream to private staging, fsync, and atomically rename before commit; failed transactions remove staged/final paths. Deletes commit the soft-delete and audit event before unlink. Startup reconciliation removes deleted-document files immediately and unreferenced/staging debris only after `STORAGE_ORPHAN_GRACE_SECONDS`; active files are protected and missing active files are reported, not silently replaced.
- **Test Evidence**: `test_upload_cleanup_when_finalize_fails`, `test_storage_reconciliation_preserves_active_and_recent_files`.
- **Residual Risk**: The filesystem and database are not one atomic transaction. A crash can expose a short-lived inconsistency until startup reconciliation runs, and an attacker with direct filesystem access is outside the application boundary.
- **Status**: **Partially Mitigated**

### TV-21: Storage Exhaustion and Unbounded Request Bodies

- **Attack Scenario**: An authenticated user uploads many or very large files, or sends an oversized/chunked request, to exhaust disk space or memory and deny service to others.
- **Impact**: Platform-wide storage exhaustion or resource-consumption denial of service.
- **Mitigation**: Multipart and JSON body limits are enforced before parsing, with streamed-byte counting when length is absent. Per-user active-document count (`409`), per-user bytes, and platform-wide bytes (`413`) are checked under the serialized `storage_quota_state` row in the same transaction as document creation. Files are streamed in chunks, not buffered whole.
- **Test Evidence**: `test_declared_json_body_over_limit_is_rejected_before_parsing`, `test_chunked_body_limit_counts_actual_bytes`, `test_upload_count_quota_rejects_and_cleans_staged_file`.
- **Residual Risk**: Quotas are per database and assume all workers share the same database. Reverse-proxy limits are deployment configuration and are not included. SQLite tests do not establish PostgreSQL multi-worker lock contention.
- **Status**: **Mitigated** (application boundary; deployment proxy layer remains operator responsibility)

### TV-22: Audit Denial Flooding

- **Attack Scenario**: A client repeatedly triggers failed logins from one IP, including rotating email addresses, to inflate the tamper-evident audit log and consume storage/write capacity.
- **Impact**: Audit-log growth and write amplification.
- **Mitigation**: The shared limiter records at most one `user.login_rate_limited` event per active IP bucket window. The `denial_audit_recorded` flag is reset when the window expires, and the claim is an atomic conditional update that shares the transaction with the event insert. Concurrent workers cannot duplicate the event; a failed event write rolls back the claim so a later denial can retry; failure still fails closed with `503`.
- **Test Evidence**: `test_denial_audit_is_claimed_once_per_ip_window`, `test_rate_limit_denials_emit_one_aggregated_audit_event`, `test_denial_audit_claim_rolls_back_when_event_write_fails`, `test_concurrent_denial_audit_claims_record_one_event`, `test_denial_audit_claim_and_event_commit_atomically`.
- **Residual Risk**: An attacker with many IP addresses can still generate one aggregate event per IP/window. Audit retention must be planned separately; online audit records are never auto-deleted.
- **Status**: **Mitigated**

### TV-23: Online Audit Retention Conflict

- **Attack Scenario**: An operator enables automatic deletion of audit records to meet a retention target, invalidating checkpoint verification and destroying non-repudiation evidence.
- **Impact**: Irrecoverable loss of audit integrity.
- **Mitigation**: The application never deletes online audit rows. `AUDIT_RETENTION_DAYS` applies only to independently managed archive copies, and `AUDIT_RETENTION_AUTO_DELETE=true` is rejected at startup. Archive/export operations remain outside the application.
- **Test Evidence**: `test_audit_retention_auto_delete_is_rejected`, `test_phase5_migration_upgrades_and_downgrades`.
- **Residual Risk**: No archive/export job ships in this repository; operators must implement and verify independent archive retention.
- **Status**: **Partially Mitigated**
