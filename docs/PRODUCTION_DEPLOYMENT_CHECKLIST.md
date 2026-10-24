# TrustVault Production Deployment Checklist

## Readiness status

**Not ready for production.** The application configuration now requires a
separately administered PostgreSQL audit anchor, but no operator-verified
anchor failure domain or production PostgreSQL/private-storage restore drill
has been recorded. Do not treat the isolated SQLite backup drill as proof of
production recovery.

## Blockers before the first production release

- [ ] Identify the actual production provider and provision the application
  PostgreSQL database and audit-anchor PostgreSQL service under separate
  administration and failure domains. Verify this from provider/account
  ownership and infrastructure records; different URLs or hostnames alone do
  not establish independence. With Supabase, use a second project in a
  **different region** (or another provider): same-region projects can share a
  shared-pooler hostname, which the startup host-distinct check rejects.
- [ ] For the selected Supabase PostgreSQL + private Supabase Storage
  architecture, configure the Render service with the Supabase database URL,
  `STORAGE_BACKEND=supabase`, the project URL, server-side service-role key,
  and the verified private bucket name. The current Blueprint uses dashboard-
  supplied values for these settings; do not place credentials in this file.
- [ ] Keep `STORAGE_DIR` on the Render persistent disk for upload staging and
  health checks. Configure Render's HTTP health-check path as `/health`.
- [ ] Configure both PostgreSQL URLs for `sslmode=verify-full` and the verified
  provider CA certificate. The repository includes the public Supabase root CA
  at `certs/prod-ca-2021.crt`; the Docker image copies it to
  `/app/certs/prod-ca-2021.crt`, so the one-shot pre-deploy migration process
  and the running web service read the same regular file. (Replace this file
  and path if a different provider CA is required.) Production startup rejects
  either URL unless both TLS query parameters are present and each
  `sslrootcert` points to a readable regular file. This fail-fast check does
  not validate certificate contents or prove a successful TLS handshake; verify
  the actual handshake in staging. In particular, Supabase shared poolers have
  had intermediate-CA conformance issues with strict verification; test the
  exact pooler endpoint and runtime image before release.
- [ ] Provision the anchor owner and application roles using the provider's
  secure role-management process, then apply
  `backend/scripts/provision_audit_anchor.sql`. The owner must not be available
  to the application. The runtime role must not own the database, schema, or
  table; must not be superuser, have `CREATEDB`/`CREATEROLE`, or inherit
  privileged role memberships; and must have only `USAGE` on the anchor schema
  plus `SELECT`/`INSERT` on `checkpoints`.
- [ ] Verify anchor network restrictions and TLS. Require certificate and host
  verification (for PostgreSQL, `sslmode=verify-full`) where supported by the
  selected provider; document any provider-specific connection mechanism before
  deployment. Store credentials and the HMAC key in a secret manager, rotate
  them under a documented process, and never place them in logs or repo files.
- [ ] Configure production environment variables from the names below. Keep
  secrets in the hosting provider's secret manager; do not commit them.
- [ ] Confirm the actual provider's PostgreSQL, private-storage, and anchor
  backup mechanisms and retention from provider documentation/account
  settings. They are not configured or proven by this repository. Take a
  coordinated backup and restore it only into an isolated environment.
- [ ] Review the Alembic migration and its release compatibility. Take and
  verify a recoverable database backup before running the Render
  `preDeployCommand`. A failed deployment leaves the previous web release
  running, but does **not** roll back database changes.
- [ ] Confirm the first deployment's health response reports a successful
  checkpoint and alert on an unhealthy, overdue, or unavailable anchor.
  `independence_verified` intentionally remains `false` until an operator
  records the external administration/failure-domain verification.

## Audit-anchor operator verification

Record evidence for every check in the deployment/change record. Application
configuration can confirm only that PostgreSQL is selected and that its host
differs from the application database host; the application deliberately
reports `independence_verified: false` because it cannot verify provider
ownership, infrastructure, or administrator separation.

- [ ] **Service and administrative ownership:** record provider account,
  project/service identifiers, database owner role, application role, and
  which operators can administer each service. Confirm the application
  runtime's operators cannot administer or rewrite the anchor.
- [ ] **Infrastructure/failure domain:** confirm region, cluster, provider
  project/account, control plane, and failure-domain separation. A second
  database, URL, or DNS name on the same managed cluster/account is not enough.
- [ ] **Network/access controls:** restrict ingress to the application egress
  path and authorized operator access; disable public access if possible;
  verify no application role memberships or role switching can elevate
  privileges.
- [ ] **TLS and credentials:** verify a valid CA chain and hostname using
  `sslmode=verify-full` or the provider's equivalent. Verify secret-manager
  storage, least-privileged access, rotation ownership, and that logs redact
  connection credentials.
- [ ] **Schema provisioning:** apply the SQL script with an administrative
  provisioning identity. Confirm the schema/table owner is the non-runtime
  owner role and the app role is not an owner.
- [ ] **Runtime permissions:** run the following read-only checks while
  connected as an anchor administrator, substituting role/schema identifiers
  (not credentials). Expected: all role attributes shown as `false`, no role
  memberships, database `CONNECT` is `true` and `CREATE`/`TEMP` are `false`,
  `USAGE` on the anchor schema is `true` and `CREATE` is `false`, table
  `SELECT` and `INSERT` are `true`, and `UPDATE`, `DELETE`, `TRUNCATE`,
  `REFERENCES`, and `TRIGGER` are `false`.

  ```sql
  SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolinherit
  FROM pg_roles
  WHERE rolname = 'trustvault_anchor_app';

  SELECT
    pg_get_userbyid(namespace.nspowner) AS schema_owner,
    pg_get_userbyid(relation.relowner) AS table_owner
  FROM pg_namespace AS namespace
  JOIN pg_class AS relation
    ON relation.relnamespace = namespace.oid
  WHERE namespace.nspname = 'trustvault_audit_anchor'
    AND relation.relname = 'checkpoints';

  SELECT parent.rolname AS inherited_role
  FROM pg_auth_members AS membership
  JOIN pg_roles AS parent ON parent.oid = membership.roleid
  JOIN pg_roles AS app ON app.oid = membership.member
  WHERE app.rolname = 'trustvault_anchor_app';

  SELECT
    has_database_privilege('trustvault_anchor_app',
                           current_database(), 'CREATE') AS can_create_schema,
    has_database_privilege('trustvault_anchor_app',
                           current_database(), 'CONNECT') AS can_connect,
    has_database_privilege('trustvault_anchor_app',
                           current_database(), 'TEMP') AS can_create_temp,
    has_schema_privilege('trustvault_anchor_app',
                         'trustvault_audit_anchor', 'USAGE') AS can_use_schema,
    has_schema_privilege('trustvault_anchor_app',
                         'trustvault_audit_anchor', 'CREATE') AS can_create_in_schema,
    has_table_privilege('trustvault_anchor_app',
      'trustvault_audit_anchor.checkpoints', 'SELECT') AS can_select,
    has_table_privilege('trustvault_anchor_app',
      'trustvault_audit_anchor.checkpoints', 'INSERT') AS can_insert,
    has_table_privilege('trustvault_anchor_app',
      'trustvault_audit_anchor.checkpoints', 'UPDATE') AS can_update,
    has_table_privilege('trustvault_anchor_app',
      'trustvault_audit_anchor.checkpoints', 'DELETE') AS can_delete,
    has_table_privilege('trustvault_anchor_app',
      'trustvault_audit_anchor.checkpoints', 'TRUNCATE') AS can_truncate,
    has_table_privilege('trustvault_anchor_app',
      'trustvault_audit_anchor.checkpoints', 'REFERENCES') AS can_reference,
    has_table_privilege('trustvault_anchor_app',
      'trustvault_audit_anchor.checkpoints', 'TRIGGER') AS can_create_trigger;
  ```

- [ ] **Checkpoint operation:** after deploying to a non-production
  environment, create a checkpoint through the authenticated administrative
  endpoint; verify the returned sequence/HMAC status without exposing the
  HMAC key, then run audit verification and retain sanitized responses.
- [ ] **Outage/recovery:** in staging only, block anchor connectivity using the
  provider's supported control. Confirm checkpoint creation/verification fail
  closed, health reports an unavailable/degraded anchor component, alerts fire,
  and application data is not silently treated as independently anchored.
  Restore connectivity and verify a subsequent checkpoint plus chain
  verification. Record recovery time and any missed checkpoint interval.
- [ ] **Health and evidence:** alert on `components.audit_anchor.status !=
  "ok"`, `overdue == true`, an unsuccessful checkpoint, or overall status
  other than `healthy`. The endpoint may return HTTP 200 with overall
  `degraded` when only the anchor is unhealthy; an HTTP-status-only monitor is
  insufficient. Retain the sanitized health, verification, permission,
  ownership, and provider-separation evidence.

## Production environment variable names

Required/configured for the Supabase + Render production blueprint:

- `ENVIRONMENT`
- `DATABASE_URL` — dashboard-supplied Supabase PostgreSQL URL; use the
  verified Session Pooler endpoint if required by Render's network path, and
  include verified TLS settings.
- `SECRET_KEY` — required by the blueprint, but current application runtime
  does not consume it for session signing; do not assume it provides session
  protection.
- `STORAGE_BACKEND` — set to `supabase`.
- `STORAGE_DIR`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY` — server-side secret; never expose to the
  frontend or commit it.
- `SUPABASE_STORAGE_BUCKET` — name of the verified private bucket.
- `SESSION_COOKIE_SECURE`
- `SESSION_COOKIE_HTTPONLY`
- `SESSION_COOKIE_SAMESITE`
- `CORS_ORIGINS`
- `AUDIT_ANCHOR_MODE`
- `AUDIT_ANCHOR_DATABASE_URL`
- `AUDIT_ANCHOR_HMAC_KEY`
- `TRUSTED_PROXY_IPS`

`DATABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, and `AUDIT_ANCHOR_DATABASE_URL`
are secrets. The blueprint generates `SECRET_KEY` and `AUDIT_ANCHOR_HMAC_KEY`.
The database URLs must point to the intended PostgreSQL services and use
verified TLS. Never expose variable values in logs, screenshots, or support
requests.

## Supabase + Render quick path

1. **App project:** create a Supabase project and a private storage bucket.
   From the project's Connect dialog, copy the **Session Pooler** connection
   string (IPv4), change its scheme from `postgresql://` to
   `postgresql+psycopg://`, set the username to `postgres.<APP_REF>`, and make
   the query string `?sslmode=verify-full&sslrootcert=/app/certs/prod-ca-2021.crt`
   (replacing any existing `sslmode` parameter).
2. **Anchor project:** create a dedicated second Supabase project in a
   **different region**, then in its SQL editor create the roles and provision
   the schema:

   ```sql
   CREATE ROLE trustvault_anchor_owner NOLOGIN;
   CREATE ROLE trustvault_anchor_app LOGIN PASSWORD '<strong-random-password>';
   ```

   Run `backend/scripts/provision_audit_anchor.sql` as a role that can
   administer `trustvault_anchor_owner` (grant the owner role to the
   provisioning role first if required). Build the anchor URL with the
   `postgresql+psycopg://` scheme, username
   `trustvault_anchor_app.<ANCHOR_REF>`, and the same TLS query parameters.
3. **Render:** New > Blueprint, select this repository and the branch
   `feat/trustvault-release-clean` (the current `render.yaml` and deployment
   changes are not on `main`). Supply `DATABASE_URL`, `SUPABASE_URL`,
   `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_STORAGE_BUCKET`, and
   `AUDIT_ANCHOR_DATABASE_URL` when prompted. `SECRET_KEY` and
   `AUDIT_ANCHOR_HMAC_KEY` are generated by the blueprint.
4. **Verify:** the pre-deploy command runs Alembic, then `/health` must report
   a successful anchor checkpoint. Verify login, upload, download, and audit
   verification before promoting the deployment.

The retained `trustvault-postgres` Render database is unused when
`DATABASE_URL` points to Supabase; delete it from the dashboard after
verification. Never point the anchor at the application Supabase project, even
through a different hostname.

## Deployment procedure

1. Confirm the Render service uses the intended production PostgreSQL database
   and a persistent private-storage disk mounted at `STORAGE_DIR`.
2. Verify cookie settings are secure and the CORS allowlist contains only the
   actual frontend origin. Keep trusted proxy configuration empty unless exact
   proxy CIDRs have been verified.
3. Complete the audit-anchor operator checklist and attach evidence. Do not
   infer independence from environment configuration or a successful database
   connection.
4. Before a release, verify a current PostgreSQL backup is restorable and
   storage/anchor backup points are coordinated. Review migration changes for
   compatibility and rehearse the exact revision against an isolated
   PostgreSQL copy. The repository migration integration suite is a migration
   test, not a backup/restore drill.
5. Run exactly one controlled migration step for the release. Render's
   [documented pre-deploy command](https://render.com/docs/deploys#pre-deploy-command)
   runs the Alembic upgrade as a one-shot `preDeployCommand`; Uvicorn startup
   does not run migrations. The configured migration command is
   `alembic -c /app/alembic.ini upgrade head`. If managing migration invocation
   outside the Blueprint, disable the automatic step first and run one
   reviewed command, not both paths.
6. Verify the migrated schema revision and application health before
   directing traffic to the release. A failed Render deployment leaves the
   previous web release running but does **not** undo database changes.
7. After release, check `/health`, authentication, upload/download, sharing,
   revocation, and audit verification. Confirm a scheduled checkpoint succeeds
   and the health component is not overdue.
8. If application behavior regresses, roll back application code only when it
   remains compatible with the migrated schema. For irreversible/data-changing
   migrations, use a tested forward-fix or restore the coordinated database,
   private-storage, and audit-anchor recovery point in isolation first. An
   application rollback does not reverse a migration.

## Backup and recovery

- `backend/scripts/backup_restore.py` supports **SQLite plus local storage
  only**. Its isolated development test is not a production backup method.
  Its SHA-256 manifest detects accidental changes, but is not signed and does
  not authenticate an archive against a malicious party who can rewrite both
  content and manifest. Protect archives with the provider's encryption,
  access-control, and integrity/authentication mechanisms.
- **Provider mechanism is not configured/verified:** this repository names a
  Render application PostgreSQL database and persistent disk in `render.yaml`,
  but does not establish the active production provider, backup/PITR plan,
  storage snapshot mechanism, or audit-anchor backup mechanism. Obtain and
  record those details from the actual provider before scheduling a production
  drill. Do not substitute the SQLite utility.
- **Supabase backup status:** the operator reports that no database backup or
  PITR is currently listed in the Supabase project. Treat managed recovery as
  unavailable until the Dashboard confirms otherwise. Supabase documents
  logical exports with its CLI; a logical database export is not a backup of
  the bytes in the `trustvault-bucket` object store. The following runbook is
  prepared but has not been executed.
- **Supabase application-database export:** after the maintenance/quiescence
  gate below and explicit operator authorization, use the
  [Supabase CLI backup/restore procedure](https://supabase.com/docs/guides/platform/migrating-within-supabase/backup-restore)
  to export roles, schema, and data. Use a protected credential flow; do not
  put a real connection string or password in shell history, logs, or a
  command-line argument. Keep the three export files encrypted and outside
  the Supabase project/account failure domain. Record the project identifier,
  exact `alembic_version`, UTC capture interval, CLI/tool versions, checksums,
  encryption-key identifier (never key material), and change-record reference.
- **Supabase Storage object export:** independently enumerate and download all
  objects from the private `trustvault-bucket` using an authorized Storage API
  or provider-supported object export. Preserve each opaque object key and
  record its byte size, computed SHA-256, content type, and relevant object
  metadata in a manifest. Store the encrypted object archive and manifest
  outside the Supabase project/account failure domain. Do not treat a database
  dump or Storage metadata rows as object-byte recovery.
- **Isolated Supabase restore drill:** restore the database exports to a
  dedicated, non-production Supabase/PostgreSQL target with compatible
  PostgreSQL extensions and roles, and restore the object archive into a new
  private bucket. Do not reuse the production bucket. Verify the schema and
  Alembic revision, relational integrity, document/version-to-storage-key
  references, complete object-key coverage and SHA-256 checksums, and private
  access behavior. Verify the audit hash chain and compare the restored
  application audit head with a checkpoint from the matching audit-anchor
  recovery point. Record the exact recovery point, mismatches, RPO/RTO, and
  sanitized evidence. Do not call this complete until an actual isolated
  restore passes.
- Before backup, put the app into a maintenance/read-only state that blocks
  uploads, deletions, storage recovery/reconciliation, and other database or
  storage mutations. Drain in-flight requests/workers and verify no upload or
  deletion operation remains active. Keep the application quiesced until all
  three snapshots are complete. If the provider offers atomic point-in-time
  snapshots across PostgreSQL and storage, verify that guarantee explicitly;
  do not assume it.
- While writes are quiesced, ensure a fresh audit checkpoint has completed,
  then capture the application PostgreSQL backup and private-storage snapshot.
  Capture the anchor PostgreSQL backup after that checkpoint is durable and
  before resuming writes. If a quiesced snapshot cannot be provided, use
  provider-documented point-in-time recovery/versioned object storage and
  establish the exact shared recovery timestamp. Never pair a database point
  with storage from an unrelated time.
- Record opaque backup/snapshot identifiers, source service identifiers,
  database schema/Alembic revision, start/end timestamps in UTC, provider
  checksums or independently calculated file manifests, encryption/key
  identifiers (not key values), and operator/change-record reference. Keep
  metadata and backups protected outside the production failure domain.
- Store backups outside the application account and production failure domain;
  encrypt them, restrict access, monitor backup completion, and define retention.
- Restore all three systems into isolated, access-restricted resources with
  outbound production access disabled. Use the matching application version
  first; validate schema revision before considering any migration. Do not
  overwrite production or the source snapshots.
- Verify PostgreSQL recovery (`pg_amcheck` or provider-supported equivalent,
  expected Alembic revision, foreign-key/integrity checks, expected table
  counts), private-storage object checksums and document/version-to-object
  references, grants/ownership, and staging/recovery operation state.
- Verify the audit hash chain and the restored external checkpoint against the
  restored application's audit head. A checkpoint newer than the restored
  application database indicates a mismatched recovery point; do not waive
  that mismatch.
- Run read-only application smoke tests, document download checksum checks,
  grant/revocation checks, and health monitoring. Record RPO, RTO, restore
  operator, exact recovery point, checksums, sanitized results, and defects.
  The actual-provider drill is **BLOCKED** until the provider and mechanisms
  are identified and used.

## Storage reconciliation and recovery behavior

The current reconciliation path deletes files associated with soft-deleted
documents/versions, reports missing files for active records, and does not
sweep unreferenced files or staging files based only on age. Recovery behavior
must continue to enforce document ownership, upload identity/idempotency, and
recovery fencing. Before enabling any future orphan cleanup, require a
quiescence/ownership proof and a separate retention review; file age alone is
not sufficient evidence that an upload is abandoned.

## Validation evidence and remaining tests

- **Completed in this readiness pass:** 422 backend tests passed and 24
  PostgreSQL integration cases were skipped by the default opt-in guard. The
  opt-in PostgreSQL concurrency, migration, checkpoint adapter, and audit
  transaction tests passed separately (71 passed) against a newly created
  disposable PostgreSQL target. No protected or production database was used.
- **Completed in this readiness pass:** frontend tests (158), typecheck, lint,
  and production build passed. The build still reports the 736.81 kB minified
  `three-core` chunk.
- **Completed in this readiness pass:** reconciliation and storage-recovery
  regression tests passed. They verify active-file preservation, reporting of
  missing active files, and non-removal of unrelated orphan/staging files.
- **Completed in this readiness pass:** an isolated SQLite/private-storage
  backup was restored to a new temporary destination; SQLite integrity and
  row counts for 13 tables matched, and all 215 storage files matched by
  SHA-256. This proves only the SQLite utility path.
- **Still required before production:** perform the production-like PostgreSQL
  and private-storage backup/restore drill described above. This remains a
  release blocker.
- The full backend run emitted one Starlette/httpx deprecation warning. Resolve
  it during dependency maintenance; it did not fail tests.
- The frontend build has previously reported a large minified `three-core`
  chunk. Consider lazy-loading the 3D experience and reviewing vendor chunk
  boundaries; this is a performance improvement, not a security control.

## Hosting notes for a low-cost student deployment

The existing Render blueprint combines the API and built frontend in one web
service, uses a managed PostgreSQL database, and mounts private storage on a
persistent disk. This minimizes service count, but a persistent disk and a
separately administered PostgreSQL audit anchor add cost and operational work.
Compare current provider pricing and backup/PITR guarantees before selecting
plans. Do not collapse the audit anchor into the application's database merely
to reduce cost while claiming independent anchoring. If that control is
unaffordable, explicitly revise the security objective and production
configuration before deployment rather than bypassing the production guard.
