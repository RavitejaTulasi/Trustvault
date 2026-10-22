# TrustVault — Secure Document Sharing with a Verifiable Audit Trail

TrustVault is a production-minded secure document sharing web application engineered from the ground up for strict authorization enforcement, private storage isolation, and a tamper-evident audit trail.

---

## Key Security Features

- **Centralized Authorization Engine**: Every protected route delegates to `AuthorizationService.authorize_document_access()`. Client roles, frontend states, and unguessable document IDs are never trusted.
- **Three-Tier Least Privilege Model**:
  - **Administrator**: Governance, user lifecycle, and audit investigations. *Administrators cannot read or download document contents without explicit owner grants.*
  - **Document Owner**: Exclusive lifecycle control over their own documents (upload, read, download, edit, delete, grant permissions, revoke permissions).
  - **Viewer**: Read-only or read/edit access strictly constrained by active, unrevoked grants.
- **Private Persistent Storage**: Document byte streams reside outside the web root under 256-bit cryptographically random hex keys.
- **Immediate Revocation**: Revoking a grant takes effect on the next request.
- **Tamper-Evident Audit Trail**: Versioned SHA-256 hash chaining with actor identity binding and HMAC-protected, externally anchorable checkpoints.
- **Premium Interaction Layer**: Website-wide pointer-responsive spotlight, speed-sensitive 3D cinematic vault, and consistent, high-visibility card hover interactions (lift, border, glow).

---

## Architecture Overview

(See `docs/ARCHITECTURE.md` for details)

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
- Production rejects `AUDIT_ANCHOR_MODE=disabled`. The deployment templates use HMAC-protected `local_file` checkpoints on persistent storage; these are not independent of the application host and do not protect against host compromise. External checkpoint adapters are not included in this build. The scheduled checkpoint worker starts with the application.
- Login rate limits are stored in the shared database and survive restarts and multiple workers. Run `alembic upgrade head` before starting a new deployment.
- `TRUSTED_PROXY_IPS` is empty by default because the Compose backend port is published directly. Set it only to the specific CIDR(s) of a reverse proxy you control. `X-Forwarded-For` is ignored from every other peer.

Create a local `.env` with strong, unique values (never commit it):

```dotenv
POSTGRES_USER=trustvault_app
POSTGRES_PASSWORD=<strong-unique-password>
POSTGRES_DB=trustvault
DATABASE_URL=postgresql+psycopg://trustvault_app:<url-encoded-strong-password>@db:5432/trustvault
SECRET_KEY=<at-least-32-random-bytes>
AUDIT_ANCHOR_MODE=local_file
AUDIT_ANCHOR_HMAC_KEY=<at-least-32-random-bytes>
```

`POSTGRES_PASSWORD` is consumed by PostgreSQL directly. `DATABASE_URL` must contain the URL-encoded form of the same password. Generate values with `openssl rand -hex 32` and percent-encode URL-reserved characters in the URL.

`GET /health` exposes `components.audit_anchor` with the scheduler's last attempt/success/failure and an `overdue` flag. Local-file anchoring is reported as `local_only` unless the checkpoint is overdue, and keeps overall health degraded in production because it is not independent of the app host. Top-level status also becomes `degraded` when anchoring is unavailable or overdue; alert on any status other than `healthy`. External checkpoint adapters are not included in this build.

Validate the resolved Compose configuration, apply migrations, then start:

```bash
docker compose config
docker compose run --rm backend alembic -c /app/alembic.ini upgrade head
docker compose up --build -d
```

The local SQLite configuration in `.env.example` is for development only and is rejected when `ENVIRONMENT=production`.

The Render blueprint deploys the API, PostgreSQL, and frontend together in one Docker web service. The API serves the built frontend at `/` and serves API routes on the same origin, preserving the existing `SameSite=Lax` session and CSRF cookie behavior. This avoids split-origin authentication problems with Render's shared `onrender.com` domains. If you rename the web service or attach a custom domain, update `CORS_ORIGINS` to that exact origin.

`TRUSTED_PROXY_IPS` is empty by default. Until you configure exact trusted proxy CIDRs, the app safely ignores `X-Forwarded-For` and uses the immediate peer address; if that peer is a shared proxy, clients may share the same login limit.

---

## Running Automated Tests

Run the full integration test suite with Pytest:
```bash
pytest backend/tests/ -v
```

All default tests are offline. Most use isolated in-memory SQLite; append-serialization tests use temporary file-backed SQLite so independent sessions contend for a real write lock. Those SQLite checks are portability checks, not PostgreSQL verification.

PostgreSQL multi-worker verification is opt-in. Each module creates an isolated temporary schema and covers audit-chain append serialization, grant revocation races, shared login rate-limit admission, storage-quota admission, and checkpoint writer serialization:

```powershell
$env:TRUSTVAULT_POSTGRES_INTEGRATION = "1"
$env:TRUSTVAULT_TEST_POSTGRES_URL = "postgresql+psycopg://user:password@host:5432/database"
python -m pytest backend/tests/test_audit_concurrency_postgres.py backend/tests/test_postgres_audit_transactions.py backend/tests/test_postgres_grant_concurrency.py backend/tests/test_postgres_login_rate_limit.py backend/tests/test_postgres_storage_quota.py backend/tests/test_postgres_checkpoint_concurrency.py -v
```

The suite is skipped by default. In this build it was executed against a local PostgreSQL 16 instance: 287 tests passed with the PostgreSQL modules enabled. That run verifies database-level serialization, the revoke-wins grant path, and the Alembic upgrade/downgrade path for the new grant column. It is not a production-scale load test.

---

## Demo Credentials (Not Seeded)

No seed script ships in this repository, so these accounts are not created automatically. The values below are configuration defaults only. Do not use them in production.

| Role | Email | Password | Permissions Scope |
|---|---|---|---|
| **Administrator** |`you@example.com` | `Youexample@1`  | User management, audit trail inspection |
| **Document Owner** | `local-owner@example.com` | `Localowner@123` | Upload, download, edit, delete own docs, grant/revoke sharing |
| **Viewer** | `local-reader@example.com` | `Localviewer@123` | Read & download explicitly granted documents |

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
| `AUDIT_ANCHOR_MODE` | Checkpoint storage: `disabled` or same-host `local_file`. Production rejects `disabled`; `local_file` keeps health degraded because it is not independent. | `disabled` |
| `AUDIT_ANCHOR_HMAC_KEY` | HMAC key (at least 32 characters) protecting checkpoint documents; required for `local_file`. | Empty |
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
   - *Implemented Mitigation*: The application writes HMAC-protected checkpoints and schedules them at `AUDIT_CHECKPOINT_INTERVAL_SECONDS`. Deployment templates currently use `local_file` on persistent storage; it shares the application host and is not independent protection. External checkpoint adapters are not included in this build, so this risk remains partially mitigated.
2. **Post-Download Revocation**:
   - Immediate revocation terminates access for the very next platform request.
   - Revocation cannot wipe a file that a recipient already downloaded to their physical workstation prior to revocation.
3. **Proxy-Aware Client IPs**:
   - Forwarded headers are accepted only from explicitly configured `TRUSTED_PROXY_IPS`.
   - If a deployment proxy is not configured, rate limiting and audit events use the immediate peer address. A Render deployment must set the exact proxy CIDR(s) for the service; no wildcard trust is permitted.
4. **Audit Append Retries and Deadlocks**:
   - Concurrent audit appends serialize on the singleton `audit_chain_state` row; the sequence allocation, event insert, and chain-head update commit or roll back together.
   - A PostgreSQL deadlock or serialization failure aborts the whole transaction, including the associated business mutation. The application does not automatically retry inside an aborted transaction; callers must retry the complete request.
   - The opt-in PostgreSQL suite exercises eight concurrent first appends, rollback/commit sequence reuse, a concurrent append during bounded verification, and checkpoint writer serialization against PostgreSQL 16. It does not establish behavior under production-scale load or automate deadlock retries.
5. **Storage Crash Recovery**:
   - Uploads and deletes favor a recoverable ordering: files are atomically published before commit, and soft-deletes commit before unlink. A crash can leave an unreferenced file or a file for a soft-deleted document.
   - Startup reconciliation removes deleted-document files immediately and removes other unreferenced files only after `STORAGE_ORPHAN_GRACE_SECONDS`. Missing active files are reported, not recreated. The filesystem and database are not a single atomic transaction.
6. **Storage Quotas**:
   - Admission serializes on the `storage_quota_state` row and checks active documents for the user and platform. Count and byte limits are per database, not per worker.
   - Both SQLite unit tests and the opt-in PostgreSQL concurrency suite verify admission serialization; the latter also covers cross-owner global byte limits.
7. **Grant Revocation Races**:
   - Grant writes capture the grant's monotonic `revocation_version` and apply only if it is unchanged. A revocation that wins the race makes the stale grant request return `409 Conflict` instead of silently reactivating access, even if a later re-grant has changed the row again.
   - Concurrent grant requests without an intervening revocation remain last-writer-wins. The behavior is verified against PostgreSQL 16; retries are caller-visible and are not automatic.
8. **Request-Size Enforcement**:
   - The application rejects declared over-limit bodies and counts streamed bytes for bodies without a trusted length. Production reverse proxies should also enforce equivalent limits before forwarding; no proxy is included in this repository, so that layer remains deployment configuration.
9. **Audit Retention**:
   - The online hash chain is retained indefinitely so checkpoints and verification remain possible. `AUDIT_RETENTION_DAYS` describes the retention objective for independently managed archive copies only.
   - Automatic online audit deletion is deliberately rejected. No archive/export job ships in this repository.
10. **Schema Downgrades**:
   - Forward migrations are supported. Downgrading below `c3d4e5f6a7b8` is refused once any version 2 audit record exists, because the legacy schema cannot represent the per-record hash version; a downgrade/re-upgrade cycle would relabel V2 evidence as V1 and verification would report tampering.
   - Back up the database before any migration. Recover from a failed release by restoring a snapshot taken before V2 records were written, or by remaining on the current schema; never delete or rewrite audit rows to force a downgrade. V1-only chains downgrade and re-upgrade normally.
   - Revision `e5f6a7b8c9d0` adds the internal grant `revocation_version`; its upgrade/downgrade/re-upgrade path was exercised on PostgreSQL 16. The V2 audit downgrade refusal remains intentionally unexercised against a populated production database.
