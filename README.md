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
|  - login_rate_limit_buckets (shared, expiring login counters)           |
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

## Production Deployment (Docker Compose)

`docker-compose.yml` is fail-closed and requires explicit production configuration:

- PostgreSQL is not published on the host; only the backend container can reach it over the Compose network.
- `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `DATABASE_URL`, and `SECRET_KEY` must be set in `.env`. Compose refuses to start when any are missing.
- The backend runs with `ENVIRONMENT=production` and `SESSION_COOKIE_SECURE=true`.
- Startup rejects SQLite, missing database credentials, known default database passwords, insecure session cookies, and environment values that are not exactly `development`, `production`, or `testing`.
- Production also rejects `AUDIT_ANCHOR_MODE=disabled` and `local_file`; an external `s3` checkpoint anchor with `AUDIT_ANCHOR_S3_BUCKET`, `AUDIT_ANCHOR_S3_REGION`, and a strong `AUDIT_ANCHOR_HMAC_KEY` is required. The scheduled checkpoint worker starts with the application.
- Login rate limits are stored in the shared database and survive restarts and multiple workers. Run `alembic upgrade head` before starting a new deployment.
- `TRUSTED_PROXY_IPS` is empty by default because the Compose backend port is published directly. Set it only to the specific CIDR(s) of a reverse proxy you control. `X-Forwarded-For` is ignored from every other peer.

Create a local `.env` with strong, unique values (never commit it):

```dotenv
POSTGRES_USER=trustvault_app
POSTGRES_PASSWORD=<strong-unique-password>
POSTGRES_DB=trustvault
DATABASE_URL=postgresql+psycopg://trustvault_app:<url-encoded-strong-password>@db:5432/trustvault
SECRET_KEY=<at-least-32-random-bytes>
AUDIT_ANCHOR_MODE=s3
AUDIT_ANCHOR_S3_BUCKET=<independently-controlled-bucket>
AUDIT_ANCHOR_S3_REGION=<aws-region>
AUDIT_ANCHOR_HMAC_KEY=<at-least-32-random-bytes>
```

`POSTGRES_PASSWORD` is consumed by PostgreSQL directly. `DATABASE_URL` must contain the URL-encoded form of the same password. Generate values with `openssl rand -hex 32` and percent-encode URL-reserved characters in the URL. AWS credentials are supplied through the SDK's default credential chain, not this file. See `docs/ARCHITECTURE.md` for the provider setup and least-privilege policy.

`GET /health` exposes `components.audit_anchor` with the scheduler's last attempt/success/failure and an `overdue` flag. Top-level status becomes `degraded` when anchoring is unavailable or overdue; alert on any status other than `healthy`. The S3 adapter has not been exercised against a live bucket in this build, so production anchoring remains an operator-verified deployment step.

Validate the resolved Compose configuration, apply migrations, then start:

```bash
docker compose config
docker compose run --rm backend alembic -c /app/alembic.ini upgrade head
docker compose up --build -d
```

The local SQLite configuration in `.env.example` is for development only and is rejected when `ENVIRONMENT=production`.

For Render, `render.yaml` leaves `TRUSTED_PROXY_IPS` as a dashboard-supplied value (`sync: false`). Verify the actual deployment's proxy addresses with the provider or your network tooling, then configure `TRUSTED_PROXY_IPS` with the exact CIDR(s) for your service before relying on forwarded client IPs for rate limiting or audit attribution. Until it is configured, the application safely ignores `X-Forwarded-For` and uses the immediate peer address; if that peer is a shared proxy, clients may share the same login limit.

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

## Demo Credentials (Not Seeded)

No seed script ships in this repository, so these accounts are not created automatically. The values below are configuration defaults only. Do not use them in production.

| Role | Email | Password | Permissions Scope |
|---|---|---|---|
| **Administrator** | `admin@trustvault.local` | `AdminSecurePass123!` | User management, audit trail inspection |
| **Document Owner** | `owner@trustvault.local` | `OwnerSecurePass123!` | Upload, download, edit, delete own docs, grant/revoke sharing |
| **Viewer** | `viewer@trustvault.local` | `ViewerSecurePass123!` | Read & download explicitly granted documents |

---

## Environment Variables Reference

| Variable | Description | Default |
|---|---|---|
| `ENVIRONMENT` | Exact running mode: `development`, `production`, or `testing`. Invalid capitalization and typos are rejected at startup. | `development` |
| `DATABASE_URL` | Development/testing SQLite URL, or a production PostgreSQL URL with non-empty credentials. Production rejects SQLite, missing credentials, and known default passwords. | `sqlite:///./trustvault.db` |
| `SECRET_KEY` | Key for cryptographic signatures and session sealing. Docker Compose requires an explicit value; set at least 32 random bytes in production. | Insecure development default |
| `STORAGE_DIR` | Private document storage directory (outside web root) | `./private_storage` |
| `SESSION_COOKIE_SECURE` | Must be `true` when `ENVIRONMENT=production`; startup fails otherwise. | `false` |
| `LOGIN_RATE_LIMIT_MAX_ATTEMPTS` | Failed login attempts allowed per IP and per IP+email in a window. | `5` |
| `LOGIN_RATE_LIMIT_WINDOW_SECONDS` | Fixed window duration for shared login rate limiting. | `300` |
| `LOGIN_RATE_LIMIT_MAX_BUCKETS` | Maximum retained shared limiter buckets; new attempts fail closed when full. | `50000` |
| `TRUSTED_PROXY_IPS` | Comma-separated proxy CIDRs allowed to supply `X-Forwarded-For`. Empty disables forwarding-header trust. Wildcards are rejected. | Empty |
| `AUDIT_ANCHOR_MODE` | Checkpoint adapter: `disabled`, development-only `local_file`, or external `s3`. Production requires `s3` and fails startup otherwise. | `disabled` |
| `AUDIT_ANCHOR_HMAC_KEY` | HMAC key (at least 32 characters) protecting checkpoint documents; required for `local_file` and `s3`. | Empty |
| `AUDIT_ANCHOR_S3_BUCKET` / `AUDIT_ANCHOR_S3_REGION` | Externally controlled bucket and region; required for `s3`. Credentials come from the AWS default credential chain. | Empty |
| `AUDIT_ANCHOR_S3_PREFIX` | Object key prefix for checkpoint documents. | `trustvault-audit-checkpoints` |
| `AUDIT_ANCHOR_S3_ENDPOINT_URL` | Optional custom S3-compatible endpoint; must use HTTPS in production. | Empty |
| `AUDIT_ANCHOR_S3_KMS_KEY_ID` | Optional KMS key for server-side checkpoint encryption. | Empty |
| `AUDIT_ANCHOR_S3_OBJECT_LOCK_MODE` / `AUDIT_ANCHOR_S3_OBJECT_LOCK_DAYS` | Optional provider-side retention request (`GOVERNANCE` or `COMPLIANCE`). | Empty / `30` |
| `AUDIT_CHECKPOINT_INTERVAL_SECONDS` | Interval between scheduled checkpoint attempts when anchoring is enabled. | `3600` |
| `AUDIT_CHECKPOINT_MAX_AGE_SECONDS` | Age after which health marks the anchor overdue; must be at least the interval. | `7200` |
| `AUDIT_CHECKPOINT_RATE_LIMIT_MAX_REQUESTS` / `AUDIT_CHECKPOINT_RATE_LIMIT_WINDOW_SECONDS` | Per-administrator checkpoint API limiter. | `5` / `60` |
| `MAX_FILE_SIZE_BYTES` | Maximum single file upload limit | `10485760` (10 MiB) |
| `MAX_MULTIPART_OVERHEAD_BYTES` | Multipart request allowance above the per-file limit | `1048576` (1 MiB) |
| `MAX_JSON_BODY_BYTES` | Maximum non-multipart request body | `65536` (64 KiB) |
| `STORAGE_ORPHAN_GRACE_SECONDS` | Minimum age before startup reconciliation removes unreferenced or stale staging files | `3600` |
| `MAX_USER_STORAGE_BYTES` | Active stored bytes allowed per user | `104857600` (100 MiB) |
| `MAX_GLOBAL_STORAGE_BYTES` | Active stored bytes allowed across all users | `1073741824` (1 GiB) |
| `MAX_UPLOADS_PER_USER` | Active document count allowed per user | `1000` |
| `AUDIT_RETENTION_DAYS` | Retention objective for independently held audit archives; the online chain is retained indefinitely | `2555` |
| `AUDIT_RETENTION_AUTO_DELETE` | Destructive automatic deletion of online audit records; setting `true` fails startup | `false` |
| `CORS_ORIGINS` | Permitted cross-origin origins | `http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000` |

---

## Known Limitations & Security Considerations

1. **Hash Chaining vs. Superuser DB Rewrite**:
   - Hash chaining guarantees detection of record modification, sequence deletion, or mid-chain alteration.
   - However, an attacker with full SQL superuser access who rewrites the entire chain from an arbitrary sequence number forward cannot be detected by database-internal hashing alone.
   - *Implemented Mitigation*: The application writes HMAC-protected checkpoints to an external `s3` adapter and schedules them at `AUDIT_CHECKPOINT_INTERVAL_SECONDS`. Production startup requires that adapter, but no live bucket has been verified in this build; configure provider-side versioning/Object Lock and verify checkpoint creation before relying on it.
2. **Post-Download Revocation**:
   - Immediate revocation terminates access for the very next platform request.
   - Revocation cannot wipe a file that a recipient already downloaded to their physical workstation prior to revocation.
3. **Proxy-Aware Client IPs**:
   - Forwarded headers are accepted only from explicitly configured `TRUSTED_PROXY_IPS`.
   - If a deployment proxy is not configured, rate limiting and audit events use the immediate peer address. A Render deployment must set the exact proxy CIDR(s) for the service; no wildcard trust is permitted.
4. **Audit Append Retries and Deadlocks**:
   - Concurrent audit appends serialize on the singleton `audit_chain_state` row; the sequence allocation, event insert, and chain-head update commit or roll back together.
   - A PostgreSQL deadlock or serialization failure aborts the whole transaction, including the associated business mutation. The application does not automatically retry inside an aborted transaction; callers must retry the complete request.
   - The SQLite append test does not establish PostgreSQL behavior. The opt-in PostgreSQL concurrency test and migration path remain unverified in this build.
5. **Storage Crash Recovery**:
   - Uploads and deletes favor a recoverable ordering: files are atomically published before commit, and soft-deletes commit before unlink. A crash can leave an unreferenced file or a file for a soft-deleted document.
   - Startup reconciliation removes deleted-document files immediately and removes other unreferenced files only after `STORAGE_ORPHAN_GRACE_SECONDS`. Missing active files are reported, not recreated. The filesystem and database are not a single atomic transaction.
6. **Storage Quotas**:
   - Admission serializes on the `storage_quota_state` row and checks active documents for the user and platform. Count and byte limits are per database, not per worker.
   - The SQLite test suite verifies admission logic and cleanup, not multi-worker PostgreSQL lock contention.
7. **Request-Size Enforcement**:
   - The application rejects declared over-limit bodies and counts streamed bytes for bodies without a trusted length. Production reverse proxies should also enforce equivalent limits before forwarding; no proxy is included in this repository, so that layer remains deployment configuration.
8. **Audit Retention**:
   - The online hash chain is retained indefinitely so checkpoints and verification remain possible. `AUDIT_RETENTION_DAYS` describes the retention objective for independently managed archive copies only.
   - Automatic online audit deletion is deliberately rejected. No archive/export job ships in this repository.
9. **Schema Downgrades**:
   - Forward migrations are supported. Downgrading below `c3d4e5f6a7b8` is refused once any version 2 audit record exists, because the legacy schema cannot represent the per-record hash version; a downgrade/re-upgrade cycle would relabel V2 evidence as V1 and verification would report tampering.
   - Back up the database before any migration. Recover from a failed release by restoring a snapshot taken before V2 records were written, or by remaining on the current schema; never delete or rewrite audit rows to force a downgrade. V1-only chains downgrade and re-upgrade normally.
