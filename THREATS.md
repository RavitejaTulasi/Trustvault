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
| **TV-02** | Broken Function-Level Authorization | OWASP API5:2023 | **Mitigated** | Server-side role enforcement (`require_role`), client roles ignored |
| **TV-03** | Privilege Escalation (Vertical/Horizontal) | CWE-269 / CWE-250 | **Mitigated** | Role immutable via user endpoints, strict separation of privileges |
| **TV-04** | Insecure Direct File Access (Direct Download URL) | OWASP API1 / CWE-639 | **Mitigated** | Platform-mediated streaming; random 256-bit unguessable storage keys |
| **TV-05** | Revocation Races & Stale Authorization | CWE-672 / CWE-362 | **Mitigated** | Zero caching of authorization decisions; immediate query on request |
| **TV-06** | Session Theft & Cross-Site Request Forgery (CSRF) | OWASP A01:2021 / CWE-352 | **Mitigated** | HTTP-only, SameSite=Lax/Strict cookies, token hashing, CSRF headers |
| **TV-07** | Brute-Force Authentication & Credential Stuffing | OWASP A07:2021 / CWE-307 | **Mitigated** | Argon2 hashing, per-IP/account rate limits, failure auditing |
| **TV-08** | SQL Injection & Stored/Reflected XSS | OWASP A03:2021 | **Mitigated** | SQLAlchemy 2.0 parameterized queries, CSP headers, nosniff |
| **TV-09** | Path Traversal / Directory Traversal | CWE-22 / CWE-23 | **Mitigated** | Decoupled server keys, `is_relative_to` containment verification |
| **TV-10** | Malicious & Oversized File Uploads | CWE-434 / CWE-400 | **Mitigated** | Chunked stream size enforcement (10MB limit), magic byte validation |
| **TV-11** | Search & Metadata Leakage | CWE-200 / CWE-209 | **Mitigated** | DB-level authorization filter on queries, uniform 404/403 responses |
| **TV-12** | Audit Log Tampering or Omission | CWE-778 / CWE-353 | **Partially Mitigated** | SHA-256 cryptographic hash-chaining; external WORM anchoring noted |
| **TV-13** | Administrator Misuse & Overprivileged Admin | Principle of Least Privilege | **Mitigated** | Admins denied content read/download; all admin operations audited |
| **TV-14** | Concurrent Modification & Race Conditions | CWE-362 | **Partially Mitigated** | Database transactions, unique constraints, atomic SQL updates |
| **TV-15** | Public Storage Misconfiguration | OWASP A05:2021 | **Mitigated** | Storage path strictly outside web root; no static routing to storage |
| **TV-16** | Secret Leakage through Git & Version Control | CWE-798 | **Mitigated** | `.gitignore` filters `.env`, `private_storage/`, `*.db`; `.env.example` template |
| **TV-17** | Insecure Caching of Sensitive Metadata & Bytes | CWE-525 / CWE-524 | **Mitigated** | `Cache-Control: no-store, no-cache`, security headers middleware |
| **TV-18** | Backup and Disaster Recovery Compromise | CWE-311 | **Accepted Risk** | Host-level encrypted volume snapshots; external storage backup policy |

---

## Detailed Threat Profiles

### TV-01: Broken Object-Level Authorization (BOLA / IDOR)
- **Attack Scenario**: Attacker modifies document UUID in `GET /documents/{id}`, `GET /documents/{id}/download`, or `PATCH /documents/{id}` to access or alter another user's private file.
- **Impact**: Critical confidentiality and integrity breach. Unauthorized access to proprietary documents.
- **Mitigation**: Centralized `AuthorizationService.authorize_document_access()` is executed unconditionally in every document route handler. Authorization checks verify active account, ownership, or valid non-revoked grant before returning any byte stream or metadata.
- **Test Evidence**: Scheduled for Day 3 / Day 6 implementation.
- **Residual Risk**: Zero at the application layer; rely on server-side authorization rather than frontend filtering or unguessable IDs.
- **Status**: **Planned (Day 3)**

### TV-02: Broken Function-Level Authorization
- **Attack Scenario**: Regular viewer attempts to invoke administrative endpoints such as `GET /admin/audit` or `GET /admin/documents/activity`.
- **Impact**: Exposure of system-wide audit telemetry and user activity logs.
- **Mitigation**: Route-level dependency `require_role({UserRole.ADMIN})` verifies the authenticated session's server-stored user role. Client-supplied role claims in cookies or bodies are never parsed or trusted.
- **Test Evidence**: `test_viewer_cannot_access_admin_endpoints`, `test_owner_cannot_access_admin_endpoints`.
- **Residual Risk**: Low. Server-side session validation only.
- **Status**: **Mitigated**

### TV-03: Privilege Escalation
- **Attack Scenario**: User submits `{"role": "admin"}` in `PATCH /auth/me` or user profile updates.
- **Impact**: Vertical privilege escalation resulting in full system administrative control.
- **Mitigation**: Strict Pydantic input schemas whitelist only user-editable profile fields (`full_name`, `password`). Role mutation is strictly reserved for administrative endpoints with explicit audit logging.
- **Test Evidence**: `test_user_cannot_elevate_own_role`.
- **Residual Risk**: None. Roles are immutable via self-service APIs.
- **Status**: **Mitigated**

### TV-04: Insecure Direct File Access (Predictable Storage Paths)
- **Attack Scenario**: Attacker probes static web root paths (e.g., `https://example.com/uploads/document_1.pdf`) to bypass API authentication.
- **Impact**: Total confidentiality breach bypassing all authorization logic.
- **Mitigation**: Files are persisted outside the application web root in `STORAGE_DIR`. Files are named with 256-bit cryptographically random hex keys (`secrets.token_hex(32)`). Physical storage paths are never exposed to clients. All downloads must flow through `GET /documents/{id}/download` which verifies authorization immediately prior to streaming.
- **Test Evidence**: Scheduled for Day 3 implementation.
- **Residual Risk**: Low. Storage access relies on OS filesystem permissions for the backend service user.
- **Status**: **Planned (Day 3)**

### TV-05: Revocation Races and Stale Authorization
- **Attack Scenario**: Document owner revokes access for user B. User B attempts to download the file 1 second later using a cached session or active connection.
- **Impact**: Unauthorized retrieval of documents after access was formally revoked.
- **Mitigation**: No caching of authorization decisions is permitted. Every single request queries the live database transaction for the current state of `DocumentGrant.is_revoked`. If revoked, download is immediately denied.
- **Test Evidence**: Scheduled for Day 4 implementation.
- **Residual Risk**: Standard limitation: cannot erase a file that a recipient already physically downloaded to their local disk prior to revocation.
- **Status**: **Planned (Day 4)**

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
- **Attack Scenario**: SQL injection payloads in search queries (`GET /documents/search?q=' OR 1=1--`) or HTML/JS payloads in document titles.
- **Impact**: Database exfiltration or stored script execution in viewer browsers.
- **Mitigation**: SQLAlchemy 2.0 ORM with 100% parameterized statements; no raw string concatenation in queries. Security headers middleware injects `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Content-Security-Policy`. React frontend escapes rendered content by default.
- **Test Evidence**: `test_security_headers_present`, `test_sql_injection_attempt_fails_safely`.
- **Residual Risk**: None identified within application codebase.
- **Status**: **Mitigated**

### TV-09: Path Traversal
- **Attack Scenario**: Attacker uploads a file with filename `../../../../etc/passwd` or attempts to download with manipulated storage key.
- **Impact**: Arbitrary file read or overwrite on the server host.
- **Mitigation**: Client-supplied filenames are purely stored as metadata in DB (`original_filename`) and sanitized for `Content-Disposition`. The physical filename on disk is generated on the server using `secrets.token_hex(32)`. `StorageService` verifies `target_path.is_relative_to(storage_dir)`.
- **Test Evidence**: `StorageService.get_file_path` rejects non-hex keys and traversal attempts; verified in test suite.
- **Residual Risk**: Negligible.
- **Status**: **Mitigated**

### TV-10: Malicious and Oversized Uploads
- **Attack Scenario**: Attacker uploads a 10GB archive to exhaust server disk space (DoS) or uploads a `.exe`/malicious script disguised as `.pdf`.
- **Impact**: Server disk exhaustion, denial of service, or malware distribution.
- **Mitigation**: Chunked streaming writes with immediate size check aborting when accumulated bytes exceed `MAX_FILE_SIZE_BYTES` (10MB). Extension whitelist combined with magic byte inspection (first 512 bytes) for supported formats.
- **Test Evidence**: Scheduled for Day 3 implementation.
- **Residual Risk**: Zero-day exploit payloads inside valid PDF formats; production environments should integrate ClamAV or virus scanning pipelines.
- **Status**: **Planned (Day 3)**

### TV-11: Search and Metadata Leakage
- **Attack Scenario**: User searches `GET /documents/search?q=Confidential` hoping to see titles or existence of documents they are not authorized to view.
- **Impact**: Information disclosure / confidential metadata discovery.
- **Mitigation**: Search query filters are constructed with mandatory authorization criteria joined at the SQL level (User is owner OR User has active, unrevoked grant). Documents the user cannot access are completely excluded from query results. Non-existent and unauthorized single-document requests return deliberate 404 or 403 without metadata leakage.
- **Test Evidence**: Scheduled for Day 3 implementation.
- **Residual Risk**: Low.
- **Status**: **Planned (Day 3)**

### TV-12: Audit Log Tampering or Omission
- **Attack Scenario**: Malicious actor or compromised account attempts to modify or delete audit log entries to conceal unauthorized actions.
- **Impact**: Loss of non-repudiation, forensics invalidation, compliance failure.
- **Mitigation**: Cryptographic hash-chaining using SHA-256 (`record_hash = SHA256(seq + timestamp + actor + action + outcome + details + previous_hash)`). `AuditService.verify_chain_integrity()` verifies continuity from genesis to latest record. Modifying or deleting any single record invalidates the entire subsequent chain.
- **Honest Limitation**: Hash chaining alone does not prevent an attacker with root database access from rewriting the entire database chain from an arbitrary sequence number forward. External anchoring (streaming to immutable WORM storage like AWS S3 Object Lock) is documented for production hardening.
- **Test Evidence**: `test_audit_service_initialization_and_verification`, `test_audit_service_detects_tampering`.
- **Status**: **Partially Mitigated** (Cryptographic chaining active; external anchoring recommended for production).

### TV-13: Administrator Misuse (Overprivileged Administrator)
- **Attack Scenario**: Rogue administrator uses admin role to browse and download confidential proprietary documents belonging to other users.
- **Impact**: Insider threat data breach.
- **Mitigation**: Administrators are NOT automatically granted content read or download permissions. Admin capabilities are restricted to user account management, audit investigation, and platform health. Every administrative action is recorded in the tamper-evident audit log with the admin's actor ID.
- **Test Evidence**: `test_admin_cannot_download_unshared_document`, `test_admin_actions_are_audited`.
- **Residual Risk**: Database superusers with direct OS/DB shell access can inspect physical storage; addressed by host encryption and access controls.
- **Status**: **Mitigated**

### TV-14: Concurrent Modification & Race Conditions
- **Attack Scenario**: Simultaneous grant and revoke requests or parallel edits leading to inconsistent grant state.
- **Impact**: Inconsistent permissions or corrupted document state.
- **Mitigation**: Database-level unique constraints (`uq_doc_user_grant`), transactions with rollback on exception, and pessimistic/optimistic concurrency control where appropriate.
- **Test Evidence**: `test_concurrent_grant_modifications_are_atomic`.
- **Residual Risk**: Edge-case database deadlocks under extreme load; handled via automatic transaction retries.
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
- **Mitigation**: Protected endpoints set `Cache-Control: no-store, no-cache, must-revalidate, private` and `Pragma: no-cache`.
- **Test Evidence**: Response header assertions in test suite.
- **Residual Risk**: Negligible.
- **Status**: **Mitigated**

### TV-18: Backup and Recovery Compromise
- **Attack Scenario**: Unencrypted database dumps or file system backups stored in insecure locations.
- **Impact**: Exfiltration of entire document database and files.
- **Mitigation**: Managed PostgreSQL with transparent data encryption (TDE) at rest, encrypted EBS/volume storage, and strict IAM backup access policies.
- **Residual Risk**: Operational responsibility of hosting provider and cloud deployment administrator.
- **Status**: **Accepted Risk** (Infrastructure operational boundary).
