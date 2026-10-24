# PostgreSQL integration testing

The PostgreSQL concurrency harness is destructive within its explicitly
configured disposable database: each test invocation creates a uniquely named
schema and drops only that schema with `CASCADE`. Never configure the harness
with the application, shared development, staging, or production database.

## Provisioning a local disposable target

The harness does not start services. Provision the database manually and verify
it before opting in. Docker Desktop is one option; the project's normal
`docker-compose.yml` is not a test-only stack because it also configures and
starts the application backend.

For a local Docker target:

1. Start Docker Desktop manually and inspect existing containers before choosing
   a unique test-container name and an unused port.
2. Create a PostgreSQL container bound only to loopback (for example,
   `127.0.0.1:55432`), with ephemeral storage such as a container `tmpfs`.
   Configure a unique PostgreSQL `cluster_name` at server startup. Use a
   generated, test-only bootstrap password; Docker environment settings may be
   visible to local Docker administrators. Never reuse application or
   production credentials.
3. Connect interactively as the bootstrap administrator. Create a dedicated
   login role with `NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT`, set its
   password interactively, and create the dedicated test database owned by
   the bootstrap administrator (not the test role). Grant the test role only
   `CONNECT` and `CREATE` on that database. Do not grant it database ownership,
   superuser, database-creation, or role-management privileges.
4. Record the expected client host/port, database, role, server `cluster_name`,
   and server port. Verify these values against the running server using a
   read-only identity query before enabling tests.
5. Configure the environment variables below in the current PowerShell process
   using a local secret manager or a private prompt. Do not print the URL or
   save it in the repository. URL-encode any reserved characters in the
   password. The disposable confirmation is an explicit operator assertion;
   it is not proof by itself that a database is disposable.

Required process environment:

| Variable | Required value |
| --- | --- |
| `TRUSTVAULT_POSTGRES_INTEGRATION` | `1` |
| `TRUSTVAULT_TEST_POSTGRES_URL` | PostgreSQL URL for the dedicated test role/database |
| `TRUSTVAULT_TEST_POSTGRES_DATABASE` | Exact disposable database name |
| `TRUSTVAULT_TEST_POSTGRES_ROLE` | Exact non-superuser test role |
| `TRUSTVAULT_TEST_POSTGRES_HOST` | Exact client-side host in the URL |
| `TRUSTVAULT_TEST_POSTGRES_PORT` | Exact client-side port in the URL |
| `TRUSTVAULT_TEST_POSTGRES_SERVER_ID` | Exact PostgreSQL `cluster_name` |
| `TRUSTVAULT_TEST_POSTGRES_SERVER_PORT` | PostgreSQL server's listening port |
| `TRUSTVAULT_TEST_POSTGRES_DISPOSABLE_CONFIRM` | `I_CONFIRM_SCHEMA_CASCADE` |

These checks are safety interlocks, not proof that a database is disposable.
The `cluster_name` marker is an operator-configured PostgreSQL setting, and
the disposable confirmation is an operator assertion; either can be copied or
misconfigured. Verify the Docker container ID/image, loopback port binding,
ephemeral storage, and PostgreSQL identity independently before setting the
test variables. Do not use the confirmation phrase as a substitute for this
review.

The harness also rejects a target using the same PostgreSQL database name as
the application's original configured database URL, captured before pytest
overrides the application connection with SQLite. It validates URL fields
before opening a connection, then checks `current_database()`, `current_user`,
`cluster_name`, server port, superuser/database-creation/role-creation
privileges, template status, database ownership, role memberships, and
database `CREATE` privilege before creating a schema. The test role must not
belong to any other role, which prevents membership-based `SET ROLE` privilege
elevation. Each connection used by the test engine is checked again before its
search path is set. A mismatch aborts without schema creation. Cleanup rechecks
identity and schema ownership, then drops only the UUID-named schema created
by that fixture invocation. It never drops a database. If setup is interrupted
after schema creation but before the harness can confirm ownership, it leaves
the schema untouched for manual inspection.

The test role requires database `CREATE` so it can create its own test schema.
The bootstrap administrator remains the database owner; the test role must not
own the database. Use only the dedicated disposable database: the test role's
schema-creation privilege and `CASCADE` cleanup are not safe for a shared
database.

After verifying the target, run from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests -m postgres_integration -q
```

When finished, remove the disposable target only through an explicitly
authorized, manually reviewed local cleanup. Do not automate container removal
or database deletion as part of the test harness.

## Alembic migration verification

The concurrency fixture uses `Base.metadata.create_all()` and is not migration
coverage. The migration harness uses the same explicit target settings and
identity/privilege checks, but a separate opt-in:

```powershell
$env:TRUSTVAULT_POSTGRES_MIGRATION_INTEGRATION = "1"
.\.venv\Scripts\python.exe -m pytest backend\tests\test_postgres_migrations.py -m postgres_migration_integration -q
```

Keep the migration flag unset or `0` except while intentionally running this
test. It rejects host port `55432`. Before running it, independently verify the
disposable container ID/image, loopback-only port binding, ephemeral storage,
and PostgreSQL identity. The database identity query verifies the configured
database, role, `cluster_name`, server port, non-privileged role attributes,
database ownership, role memberships, and database `CREATE` privilege; URL
validation verifies the configured client host and port. These checks cannot
prove container identity by themselves.

The Alembic environment accepts migration-test mode only when both the
migration opt-in and an explicit SQLAlchemy PostgreSQL connection plus a
generated schema are supplied. It refuses offline operation and will not fall
back to the application URL. The harness creates a UUID-named schema owned by
the test role, disposes the setup engine, and creates a fresh engine with the
generated schema in PostgreSQL's connection-startup `search_path` options.
This makes SQLAlchemy initialize its PostgreSQL dialect with the generated
schema as its default schema, rather than changing `search_path` after dialect
initialization. The harness verifies current schema, target identity, and
schema ownership before applying migrations and explicitly sets Alembic's
version-table schema. The migrations currently use unqualified table and
function names; the startup search path scopes those names and the generated
PL/pgSQL functions/triggers to the isolated schema. No migration inspected
uses `CREATE EXTENSION` or references another application schema explicitly.

The integration test upgrades the complete chain to head and checks the
revision, expected tables, and PostgreSQL trigger/function objects in the
generated schema. A separate scenario upgrades through
`c7d8e9f0a1b2`, inserts legacy documents and versions, then upgrades to head
to verify storage-registry backfill and owner assignment. Both scenarios are
opt-in and remain unverified until they run against the independently verified
disposable target. Cleanup uses a new connection with the same schema-bound
startup options, rechecks database identity, SQLAlchemy's default schema, and
schema ownership, then drops only the generated schema with `CASCADE`; it
never drops or resets a database. If identity or ownership cannot be
reverified, cleanup fails closed and leaves the schema for manual inspection.

Malformed legacy-key and orphan-reference rejection, plus trigger behavior,
still need separate PostgreSQL scenarios before full migration readiness can
be claimed. Never use a production downgrade as rollback.

Only a verified run against the disposable PostgreSQL target is evidence of
PostgreSQL concurrency or migration behavior.
