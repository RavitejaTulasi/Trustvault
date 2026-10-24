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
- The backend runs with `ENVIRONMENT=production`, `SESSION_COOKIE_SECURE=true`, `SESSION_COOKIE_HTTPONLY=true`, and a supported `SESSION_COOKIE_SAMESITE` value (`lax`, `strict`, or `none`).
- Startup rejects SQLite, missing database credentials, known default database passwords, insecure session cookies, and environment values that are not exactly `development`, `staging`, `production`, or `testing`.
- Production and staging require HMAC-protected checkpoints in a separately administered PostgreSQL service (`AUDIT_ANCHOR_MODE=postgresql`). Provision its schema with `backend/scripts/provision_audit_anchor.sql` and grant the application role only `SELECT` and `INSERT`. The service must be in a separate database-server and administration failure domain; a distinct hostname alone is not proof. The scheduled checkpoint worker starts with the application and fails startup if the anchor endpoint/schema cannot be reached.
- Login rate limits are stored in the shared database and survive restarts and multiple workers. The container entrypoint applies `alembic upgrade head` before Uvicorn starts when `TRUSTVAULT_MIGRATE_ON_START=true` (the default). Set it to `false` only when migrations are managed by an external deploy step. Take and verify a database backup before a release that runs migrations, and do not run multiple migration-enabled instances concurrently.
- `TRUSTED_PROXY_IPS` is empty by default because the Compose backend port is published directly. Set it only to the specific CIDR(s) of a reverse proxy you control. `X-Forwarded-For` is ignored from every other peer.

Create a local `.env` with strong, unique values (never commit it):

```dotenv
POSTGRES_USER=trustvault_app
POSTGRES_PASSWORD=<strong-unique-password>
POSTGRES_DB=trustvault
DATABASE_URL=postgresql+psycopg://trustvault_app:<url-encoded-strong-password>@db:5432/trustvault
SECRET_KEY=<at-least-32-random-bytes>
AUDIT_ANCHOR_MODE=postgresql
AUDIT_ANCHOR_HMAC_KEY=<at-least-32-random-bytes>
AUDIT_ANCHOR_DATABASE_URL=postgresql+psycopg://trustvault_anchor:<url-encoded-secret>@<independent-anchor-host>:5432/trustvault_anchor
```

`POSTGRES_PASSWORD` is consumed by PostgreSQL directly. `DATABASE_URL` must contain the URL-encoded form of the same password. The audit anchor database is a separately provisioned service and must not share the application PostgreSQL host or its administration credentials. Generate secrets with `openssl rand -hex 32` and percent-encode URL-reserved characters in URLs. Provision the anchor owner and restricted app role before enabling PostgreSQL anchoring; `local_file` is development-only.

`GET /health` exposes `components.audit_anchor` with the scheduler's last attempt/success/failure and an `overdue` flag. PostgreSQL anchoring reports `ok` after a successful checkpoint. `independence_verified` remains false because provider-level administrative and failure-domain separation must be verified by the operator. Local-file anchoring is reported as `local_only` and is not accepted for production. Alert on any top-level status other than `healthy`.

For Render, configure the Supabase application database URL, the independent anchor database URL, and Supabase Storage values in the dashboard. The blueprint generates `SECRET_KEY` and `AUDIT_ANCHOR_HMAC_KEY`, and the Docker image includes the Supabase root CA at `/app/certs/prod-ca-2021.crt` for `sslmode=verify-full`. Take a recoverable database backup before a release that runs migrations. The blueprint also declares `preDeployCommand`; the container startup migration is a fallback for services whose dashboard has no pre-deploy command. Running both is idempotent because `alembic upgrade head` is a no-op at head. A failed migration stops startup and does not automatically restore a database backup. Verify the migration logs and health endpoint after release.

For Compose, provision the application database and independent anchor database separately, then:

```bash
docker compose config
docker compose up --build -d
```

Startup applies pending migrations by default. Back up PostgreSQL first and inspect the migration/release before starting or updating the backend. To keep migrations as an explicit operator action instead, set `TRUSTVAULT_MIGRATE_ON_START=false` and run `docker compose run --rm backend alembic -c /app/alembic.ini upgrade head` once before `docker compose up`. Neither deployment path automatically backs up data.

### Isolated SQLite Backup and Restore

`backend/scripts/backup_restore.py` backs up only SQLite databases and local private-storage directories. It creates a consistent SQLite snapshot, includes SHA-256 hashes in the archive manifest, verifies every archive entry before restoring, rejects path traversal and existing output paths, and checks SQLite integrity after restore. It never overwrites the source or an existing destination:

```powershell
python backend\scripts\backup_restore.py backup `
  --database D:\Trustvault\trustvault_dev_isolated.db `
  --storage D:\Trustvault\private_storage_dev `
  --destination D:\Trustvault\backups\isolated-before.zip

python backend\scripts\backup_restore.py restore `
  --archive D:\Trustvault\backups\isolated-before.zip `
  --destination D:\Trustvault\restore-validation
```

Use a new destination path. The SQLite database snapshot is consistent, but the database and private-storage files are not captured atomically with each other. Quiesce uploads, deletions, and recovery work for a coordinated local capture. The manifest hashes detect accidental archive damage; they are not a signature against an attacker able to rewrite both archive contents and manifest. This utility is not a PostgreSQL backup tool. Production recovery still requires a provider-native PostgreSQL backup, coordinated private-storage and audit-anchor snapshots, and an isolated restore drill.

The local SQLite configuration in `.env.example` is for development only and is rejected when `ENVIRONMENT=production`.

The Render blueprint deploys the API and built frontend in one Docker web service, with PostgreSQL and document storage in Supabase. The API serves the frontend at `/` and serves API routes on the same origin, preserving the existing `SameSite=Lax` session and CSRF cookie behavior. This avoids split-origin authentication problems with Render's shared `onrender.com` domains. If you rename the web service or attach a custom domain, update `CORS_ORIGINS` to that exact origin. Deploy `main`; the current `render.yaml` and container startup migration are on that branch.

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

## Staging Demo Accounts

No seed script ships in this repository, so demo accounts are not created automatically. A staging deployment can enable a server-side credential discovery endpoint:

1. Set `ENVIRONMENT=staging` (never `production`; staging applies the same security guards as production).
2. Set `DEMO_LOGIN_ENABLED=true` and provide `DEMO_ADMIN_*`, `DEMO_OWNER_*`, and `DEMO_VIEWER_*` email/password pairs in the service's secret environment.
3. Ensure each email belongs to an active user with the matching `admin`, `owner`, or `viewer` role.

When enabled, the login page fetches `GET /api/v1/auth/demo-accounts` and offers role buttons that fill the normal sign-in form. The endpoint returns a credential only after verifying the user, role, active state, and Argon2id password hash. It returns `404` in production or when the flag is off, sets `Cache-Control: no-store`, and keeps credentials out of the frontend bundle and repository. The passwords are never displayed in the UI.

Demo passwords must be distinct, at least 12 characters, and stored only in the staging service's secret configuration. Production configuration rejects `DEMO_LOGIN_ENABLED=true` at startup, and the production Render blueprint sets it to `false`.

---

## Environment Variables Reference

| Variable | Description | Default |
|---|---|---|
| `ENVIRONMENT` | Exact running mode: `development`, `staging`, `production`, or `testing`. Staging applies the same security guards as production. Invalid capitalization and typos are rejected at startup. | `development` |
| `DATABASE_URL` | Development/testing SQLite URL, or a PostgreSQL URL with non-empty credentials. Production and staging reject SQLite, missing credentials, and known default passwords. | `sqlite:///./trustvault.db` |
| `SECRET_KEY` | Accepted by configuration and required by deployment templates, but not currently used by application runtime code. Do not rely on it for session signing or revocation. | Insecure development default |
| `STORAGE_DIR` | Private document storage directory (outside web root) | `./private_storage` |
| `SESSION_COOKIE_SECURE` | Must be `true` when `ENVIRONMENT` is `production` or `staging`; startup fails otherwise. | `false` |
| `SESSION_COOKIE_HTTPONLY` | Must be `true` when `ENVIRONMENT` is `production` or `staging`; prevents JavaScript from reading the session cookie. | `true` |
| `SESSION_COOKIE_SAMESITE` | Must be `lax`, `strict`, or `none` in production/staging. `none` requires the secure cookie setting. | `lax` |
| `LOGIN_RATE_LIMIT_MAX_ATTEMPTS` | Failed login attempts allowed per IP and per IP+email in a window. | `5` |
| `LOGIN_RATE_LIMIT_WINDOW_SECONDS` | Fixed window duration for shared login rate limiting. | `300` |
| `LOGIN_RATE_LIMIT_MAX_BUCKETS` | Maximum retained shared limiter buckets; new attempts fail closed when full. | `50000` |
| `TRUSTED_PROXY_IPS` | Comma-separated proxy CIDRs allowed to supply `X-Forwarded-For`. Empty disables forwarding-header trust. Wildcards are rejected. | Empty |
| `AUDIT_ANCHOR_MODE` | `disabled`, same-host `local_file` (development only), or separately administered `postgresql`. Production and staging require `postgresql`. | `disabled` |
| `AUDIT_ANCHOR_DATABASE_URL` | Connection URL for independent PostgreSQL checkpoint storage. The application role should have only `SELECT` and `INSERT` on its provisioned table. | Empty |
| `AUDIT_ANCHOR_HMAC_KEY` | HMAC key (at least 32 characters) protecting checkpoint documents; required when anchoring is enabled. | Empty |
| `AUDIT_CHECKPOINT_INTERVAL_SECONDS` | Interval between scheduled checkpoint attempts when anchoring is enabled. | `3600` |
| `AUDIT_CHECKPOINT_MAX_AGE_SECONDS` | Age after which health marks the anchor overdue; must be at least the interval. | `7200` |
| `AUDIT_CHECKPOINT_RATE_LIMIT_MAX_REQUESTS` / `AUDIT_CHECKPOINT_RATE_LIMIT_WINDOW_SECONDS` | Per-administrator checkpoint API limiter. | `5` / `60` |
| `MAX_FILE_SIZE_BYTES` | Maximum single file upload limit | `10485760` (10 MiB) |
| `MAX_MULTIPART_OVERHEAD_BYTES` | Multipart request allowance above the per-file limit | `1048576` (1 MiB) |
| `MAX_JSON_BODY_BYTES` | Maximum non-multipart request body | `65536` (64 KiB) |
| `STORAGE_ORPHAN_GRACE_SECONDS` | Reserved for a future orphan-cleanup policy; currently unused because file age alone cannot prove that an upload has stopped | `3600` |
| `MAX_USER_STORAGE_BYTES` | Active stored bytes allowed per user | `104857600` (100 MiB) |
| `MAX_GLOBAL_STORAGE_BYTES` | Active stored bytes allowed across all users | `1073741824` (1 GiB) |
| `MAX_UPLOADS_PER_USER` | Active document count allowed per user | `1000` |
| `AUDIT_RETENTION_DAYS` | Retention objective for independently held audit archives; the online chain is retained indefinitely | `2555` |
| `AUDIT_RETENTION_AUTO_DELETE` | Destructive automatic deletion of online audit records; setting `true` fails startup | `false` |
| `CORS_ORIGINS` | Permitted cross-origin origins | `http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000` |
| `DEMO_LOGIN_ENABLED` | Enables the staging-only demo credential discovery endpoint. Startup rejects it when `ENVIRONMENT=production`. | `false` |
| `DEMO_ADMIN_EMAIL` / `DEMO_ADMIN_PASSWORD` | Credentials for the admin demo button. Password must be at least 12 characters. | Empty |
| `DEMO_OWNER_EMAIL` / `DEMO_OWNER_PASSWORD` | Credentials for the document-owner demo button. Password must be at least 12 characters. | Empty |
| `DEMO_VIEWER_EMAIL` / `DEMO_VIEWER_PASSWORD` | Credentials for the viewer demo button. Password must be at least 12 characters. | Empty |

---

## Known Limitations & Security Considerations

1. **Hash Chaining vs. Superuser DB Rewrite**:
   - Hash chaining guarantees detection of record modification, sequence deletion, or mid-chain alteration.
   - However, an attacker with full SQL superuser access who rewrites the entire chain from an arbitrary sequence number forward cannot be detected by database-internal hashing alone.
   - *Implemented Mitigation*: The application can write HMAC-protected checkpoints to a separately administered PostgreSQL anchor service. The application role is restricted to `SELECT` and `INSERT`; the schema/table owner should be a separate non-login role. This protects against an application-database-only rewrite if the anchor service and its administrators remain independent. It does not protect against compromise of the application runtime or its HMAC key, nor an anchor-database administrator who can rewrite the checkpoint table. Verify provider administration, backups, and retention separation before production.
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
   - Startup reconciliation removes files referenced by soft-deleted documents. It reports missing active files but does not recreate them, and it currently does not sweep unreferenced or staging files; `STORAGE_ORPHAN_GRACE_SECONDS` is reserved and unused. Back up the database and document storage together and verify them with a restore drill because the filesystem and database are not one atomic transaction.
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
