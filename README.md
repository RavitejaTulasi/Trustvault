# TrustVault — Secure Document Sharing with a Verifiable Audit Trail

TrustVault is a production-minded secure document sharing web application engineered from the ground up for strict authorization enforcement, private storage isolation, and a tamper-evident audit trail.

---

## Key Security Features

- **Centralized Authorization Engine**: Every protected route delegates to `AuthorizationService.authorize_document_access()`. Client roles, frontend states, and unguessable document IDs are never trusted.
- **Three-Tier Least Privilege Model**:
  - **Administrator**: Governance, user lifecycle, and audit investigations. *Administrators cannot read or download document contents without explicit owner grants.*
  - **Document Owner**: Exclusive lifecycle control over their own documents (upload, read, download, edit, delete, grant permissions, revoke permissions).
  - **Viewer**: Read-only or read/edit access strictly constrained by active, unrevoked grants.
- **Private Persistent Storage**: Document byte streams reside outside the web server root under 256-bit cryptographically random hex keys. Uploads are written to private staging, fsynced, and atomically published before the database commit; startup reconciliation cleans crash debris. Path traversal is strictly defended via filesystem containment checks.
- **Immediate Revocation**: Revoking a grant takes effect on the very next request. No authorization caches or long-lived presigned URLs are used.
- **Tamper-Evident Audit Trail**: All authentication, access, mutation, grant modifications, and access denials are recorded in an append-only cryptographic hash chain using SHA-256. Version 2 records bind the event ID, client IP, and user agent in addition to the chain fields, while version 1 records continue to verify unchanged.

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
|  - Rate Limiter (Shared database-backed fixed window on login)          |
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
|  - audit_chain_state (serialized append sequence and chain head)        |
|  - Versioned SHA-256 hash chain; actor identity locked by RESTRICT      |
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

All default tests are offline. Most use isolated in-memory SQLite; append-serialization tests use temporary file-backed SQLite so independent sessions contend for a real write lock. That is a portability check, not PostgreSQL verification.

PostgreSQL append-concurrency verification is opt-in and creates an isolated temporary schema with eight concurrent writers:

```powershell
$env:TRUSTVAULT_POSTGRES_INTEGRATION = "1"
$env:TRUSTVAULT_TEST_POSTGRES_URL = "postgresql+psycopg://user:password@host:5432/database"
python -m pytest backend/tests/test_audit_concurrency_postgres.py -v
```

The PostgreSQL test is skipped by default and has not been run against a live database in this build. It verifies unique, contiguous sequence allocation and a consistent chain head; it does not exercise provider-side checkpoint anchoring.

Real AWS S3 checkpoint integration tests are separately opt-in, skipped unless explicitly enabled, and require an independently approved test bucket; see [`docs/AWS_INTEGRATION_TESTING.md`](docs/AWS_INTEGRATION_TESTING.md). They have not been run against live AWS in this build.

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
   - *Implemented Mitigation*: The application writes HMAC-protected checkpoints to an external `s3` adapter and schedules them at `AUDIT_CHECKPOINT_INTERVAL_SECONDS`. Production startup requires that adapter, but no live bucket has been verified in this build; configure provider-side versioning/Object Lock and verify checkpoint creation before relying on it.
2. **Post-Download Revocation**:
   - Immediate revocation terminates access for the very next platform request.
   - Revocation cannot wipe a file that a recipient already downloaded to their physical workstation prior to revocation.
