# TrustVault — Secure Document Sharing with a Verifiable Audit Trail

TrustVault is a production-minded secure document sharing web application engineered from the ground up for strict authorization enforcement, private storage isolation, and a tamper-evident audit trail.

---

## Key Security Features

- **Centralized Authorization Engine**: Every protected route delegates to `AuthorizationService.authorize_document_access()`. Client roles, frontend states, and unguessable document IDs are never trusted.
- **Three-Tier Least Privilege Model**:
  - **Administrator**: Governance, user lifecycle, and audit investigations. *Administrators cannot read or download document contents without explicit owner grants.*
  - **Document Owner**: Exclusive lifecycle control over their own documents (upload, read, download, edit, delete, grant permissions, revoke permissions).
  - **Viewer**: Read-only or read/edit access strictly constrained by active, unrevoked grants.
- **Private Persistent Storage**: Document byte streams reside outside the web server root under 256-bit cryptographically random hex keys. Path traversal is strictly defended via filesystem containment checks.
- **Immediate Revocation**: Revoking a grant takes effect on the very next request. No authorization caches or long-lived presigned URLs are used.
- **Tamper-Evident Audit Trail**: All authentication, access, mutation, grant modifications, and access denials are recorded in an append-only cryptographic hash chain using SHA-256.

---

## Architecture Overview

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

## 7-Day Implementation Plan & Current Status

- [x] **Day 1: Project Foundation, Health Check & Threat Modeling**
  - Project scaffolding, Git setup, and clean environment configuration.
  - Core database schema (Users, Sessions, Documents, Grants, Audit Events, Versions) & Alembic migration.
  - FastAPI application with security middleware (Request ID, nosniff, DENY, CSP).
  - Liveness & readiness health check endpoint (`GET /health` & `GET /api/v1/health`).
  - Cryptographic audit trail service with SHA-256 hash chaining and tamper detection.
  - Automated integration tests (Pytest + HTTPX).
  - Comprehensive threat model (`THREATS.md`), AI prompt logs (`PROMPTS.md`), and architecture documentation (`docs/ARCHITECTURE.md`).
- [ ] **Day 2: Authentication, Sessions, Roles & Centralized Authorization Policy**
- [ ] **Day 3: Private Storage, File Uploads, Validation, Downloads & Versioning**
- [ ] **Day 4: Granular Permissions, Immediate Revocation & Audit Verification APIs**
- [ ] **Day 5: React + Vite Frontend, Search & Administrator Forensics Dashboard**
- [ ] **Day 6: Attack-Oriented Security Testing Suite & Defect Remediation**
- [ ] **Day 7: Live Cloud Deployment, Authorization-Removal Experiment & Demo Video**

---

## Quickstart & Local Setup

### 1. Prerequisites
- Python 3.12+ (Python 3.14 compatible)
- Git

### 2. Clone and Setup Environment
```bash
git clone <repo-url> trustvault
cd trustvault

# Copy environment template
cp .env.example .env

# Install backend dependencies
pip install -r backend/requirements.txt
```

### 3. Run Database Migrations
```bash
alembic upgrade head
```

### 4. Run the Development Server
```bash
uvicorn backend.app.main:app --reload --port 8000
```
Visit:
- Health check: `http://localhost:8000/health`
- Interactive API Docs: `http://localhost:8000/docs`

---

## Running Automated Tests

Run the full integration test suite with Pytest:
```bash
pytest backend/tests/ -v
```

All tests execute against an isolated in-memory database and evaluate live endpoints via HTTPX.

The default suite is fully offline. Real AWS S3 checkpoint integration tests are opt-in, skipped unless explicitly enabled, and require an independently approved test bucket; see [`docs/AWS_INTEGRATION_TESTING.md`](docs/AWS_INTEGRATION_TESTING.md). They have not been run against live AWS in this build.

---

## Demo Credentials (Seeded on Day 2)

| Role | Email | Password | Permissions Scope |
|---|---|---|---|
| **Administrator** | `admin@trustvault.local` | `AdminSecurePass123!` | User management, audit trail inspection |
| **Document Owner** | `owner@trustvault.local` | `OwnerSecurePass123!` | Upload, download, edit, delete own docs, grant/revoke sharing |
| **Viewer** | `viewer@trustvault.local` | `ViewerSecurePass123!` | Read & download explicitly granted documents |

---

## Environment Variables Reference

| Variable | Description | Default |
|---|---|---|
| `ENVIRONMENT` | Running mode (`development`, `production`, `testing`) | `development` |
| `DATABASE_URL` | PostgreSQL connection string or SQLite fallback | `sqlite:///./trustvault.db` |
| `SECRET_KEY` | Key for cryptographic signatures and session sealing | Random 32+ bytes |
| `STORAGE_DIR` | Private document storage directory (outside web root) | `./private_storage` |
| `SESSION_COOKIE_SECURE` | Set `true` in production to enforce HTTPS cookie flag | `false` |
| `MAX_FILE_SIZE_BYTES` | Maximum single file upload limit | `10485760` (10MB) |
| `CORS_ORIGINS` | Permitted cross-origin origins | `http://localhost:5173` |

---

## Known Limitations & Security Considerations

1. **Hash Chaining vs. Superuser DB Rewrite**:
   - Hash chaining guarantees detection of record modification, sequence deletion, or mid-chain alteration.
   - However, an attacker with full SQL superuser access who rewrites the entire chain from an arbitrary sequence number forward cannot be detected by database-internal hashing alone.
   - *Production Recommendation*: Stream audit records to write-once-read-many (WORM) storage (e.g. AWS S3 Object Lock) or publish periodic root hashes to an external timestamping authority.
2. **Post-Download Revocation**:
   - Immediate revocation terminates access for the very next platform request.
   - Revocation cannot wipe a file that a recipient already downloaded to their physical workstation prior to revocation.
