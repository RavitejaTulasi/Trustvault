# TrustVault — Architecture & Security Specification

TrustVault is a secure document sharing platform designed with a primary focus on authorization correctness, private storage isolation, and a verifiable, tamper-evident audit trail.

---

## 1. System Overview & Core Principles

TrustVault is engineered around five mandatory security pillars:

1. **Default-Deny Authorization**: Every protected operation denies access unless an explicit ownership relation or active, unrevoked grant is confirmed in the current transaction.
2. **Server-Side Trust Boundary**: Frontend checks exist solely for user interface ergonomics. The backend is the sole authority; client-supplied role parameters or user IDs are rejected.
3. **Storage Decoupling**: Stored files are kept strictly outside the web server root. Physical file paths are generated via 256-bit unguessable random keys and are never exposed to clients.
4. **Immediate Revocation**: No cached authorization tokens or long-lived download URLs are used. When an access grant is revoked, the very next download or read attempt is blocked.
5. **Tamper-Evident Auditability**: Every sensitive action (authentication, document read, download, upload, edit, deletion, grant change, administrative query, and access denial) produces a cryptographically hash-chained audit record.

---

## 2. Role & Permission Matrix

TrustVault enforces three distinct roles, with fine-grained document-level permission overrides.

### Role Definitions

- **Administrator**: Responsible for platform governance, user lifecycle management, and security audit investigations.
  * *Critical Rule*: Administrators are **NOT** superusers with automatic bypass to read or download confidential document contents. Content inspection is restricted unless explicitly granted document ownership or access by an owner.
- **Document Owner**: Users who upload documents. Document owners have exclusive control over their documents (read, download, edit, delete, grant permissions, revoke permissions, and view document-specific audit history).
- **Viewer**: Read-only or read/edit participants who have been explicitly granted access to specific documents. Viewers cannot upload documents, delete documents, or grant permissions to others.

### Complete Permission Matrix

| Operation / Capability | Administrator | Document Owner (Own Docs) | Viewer (Granted 'edit') | Viewer (Granted 'read') | Unrelated User / Public |
|---|---|---|---|---|---|
| **System Health (`GET /health`)** | Yes | Yes | Yes | Yes | Yes (Public probe) |
| **User Authentication (`POST /auth/login`, `logout`)** | Yes | Yes | Yes | Yes | Yes (Public endpoint) |
| **Manage Users (`POST /admin/users`, toggle active)** | **Yes** | No (403 Forbidden) | No (403 Forbidden) | No (403 Forbidden) | No (401 Unauthorized) |
| **System-wide Audit Trail (`GET /admin/audit`)** | **Yes** | No (403 Forbidden) | No (403 Forbidden) | No (403 Forbidden) | No (401 Unauthorized) |
| **Upload New Document (`POST /documents`)** | No* | **Yes** | No (403 Forbidden) | No (403 Forbidden) | No (401 Unauthorized) |
| **Read Document Metadata (`GET /documents/{id}`)** | No* | **Yes** | **Yes** | **Yes** | No (403/404 Deliberate) |
| **Download Document Bytes (`GET /documents/{id}/download`)** | No* | **Yes** | **Yes** | **Yes** | No (403/404 Deliberate) |
| **Edit Document / Upload Version (`PATCH /documents/{id}`)** | No* | **Yes** | **Yes** | No (403 Forbidden) | No (403/404 Deliberate) |
| **Delete Document (`DELETE /documents/{id}`)** | No* | **Yes** (Owner only) | No (403 Forbidden) | No (403 Forbidden) | No (403/404 Deliberate) |
| **Grant Access to Named User (`POST /documents/{id}/permissions`)**| No* | **Yes** (Owner only) | No (403 Forbidden) | No (403 Forbidden) | No (403/404 Deliberate) |
| **Revoke Access (`DELETE /documents/{id}/permissions/{user_id}`)** | No* | **Yes** (Owner only) | No (403 Forbidden) | No (403 Forbidden) | No (403/404 Deliberate) |
| **View Document Permissions (`GET /documents/{id}/permissions`)** | No* | **Yes** (Owner only) | No (403 Forbidden) | No (403 Forbidden) | No (403/404 Deliberate) |
| **Search Documents (`GET /documents/search`)** | Metadata only | Own docs only | Granted docs only | Granted docs only | No (401 Unauthorized) |

*\* Note on Administrative Access*: If an administrator needs access to a document for legal discovery, an audited administrative delegation request must be executed or ownership reassigned through an explicitly logged administrative workflow. Administrators cannot silently eavesdrop on user documents.

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
`AuditService.verify_chain_integrity(db)` performs a complete traversal from index 1 to $N$:
1. Validates strictly ascending sequence numbers without gaps.
2. Validates that `event.previous_hash == previous_event.record_hash`.
3. Canonicalizes timestamps into UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
4. Recomputes the SHA-256 hash and asserts exact equality against `event.record_hash`.

### Limitation & Production Anchoring
Hash chaining reliably detects unauthorized modification, insertion, or deletion of individual records. However, an attacker with full database superuser privileges could theoretically rewrite the entire chain from an arbitrary record forward. For high-assurance production environments, TrustVault supports streaming audit hashes to immutable external storage (e.g., AWS S3 Object Lock in Compliance Mode or RFC 3161 timestamping authorities).
