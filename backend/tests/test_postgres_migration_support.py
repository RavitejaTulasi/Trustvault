import os
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend.tests import postgres_concurrency_support as postgres_support
from backend.tests import postgres_migration_support as migration_support


def _migration_target_environment() -> dict[str, str]:
    return {
        migration_support.MIGRATION_RUN_ENV_VAR: "1",
        postgres_support.URL_ENV_VAR: (
            "postgresql+psycopg://test_role:synthetic-password"
            "@127.0.0.1:55433/trustvault_test"
        ),
        postgres_support.DATABASE_ENV_VAR: "trustvault_test",
        postgres_support.ROLE_ENV_VAR: "test_role",
        postgres_support.HOST_ENV_VAR: "127.0.0.1",
        postgres_support.PORT_ENV_VAR: "55433",
        postgres_support.SERVER_ID_ENV_VAR: "unique-disposable-server",
        postgres_support.SERVER_PORT_ENV_VAR: "5432",
        postgres_support.DISPOSABLE_CONFIRM_ENV_VAR: (
            postgres_support.DISPOSABLE_CONFIRMATION
        ),
    }


def test_migration_target_requires_its_separate_opt_in():
    environment = _migration_target_environment()
    environment[migration_support.MIGRATION_RUN_ENV_VAR] = "0"

    with pytest.raises(ValueError, match="is required"):
        migration_support.validate_postgres_migration_target(
            environment,
            application_url="sqlite:///application.db",
        )


@pytest.mark.parametrize("flag", ["true", "yes", "2"])
def test_migration_target_rejects_ambiguous_opt_in(flag: str):
    environment = _migration_target_environment()
    environment[migration_support.MIGRATION_RUN_ENV_VAR] = flag

    with pytest.raises(ValueError, match="must be set to 0 or 1"):
        migration_support.validate_postgres_migration_target(
            environment,
            application_url="sqlite:///application.db",
        )


def test_migration_target_reuses_explicit_disposable_target_validation():
    target = migration_support.validate_postgres_migration_target(
        _migration_target_environment(),
        application_url="sqlite:///application.db",
    )

    assert target.database == "trustvault_test"
    assert target.role == "test_role"
    assert target.host == "127.0.0.1"
    assert target.port == 55433
    assert target.server_id == "unique-disposable-server"
    assert target.server_port == 5432
    assert "synthetic-password" not in repr(target)


def test_migration_target_rejects_application_database_reuse():
    environment = _migration_target_environment()
    application_url = environment[postgres_support.URL_ENV_VAR].replace(
        "test_role:synthetic-password",
        "application_role:application-password",
    )

    with pytest.raises(ValueError, match="matches the application's"):
        migration_support.validate_postgres_migration_target(
            environment,
            application_url=application_url,
        )


def test_migration_target_rejects_protected_persistent_port():
    environment = _migration_target_environment()
    environment[postgres_support.PORT_ENV_VAR] = "55432"
    environment[postgres_support.URL_ENV_VAR] = environment[
        postgres_support.URL_ENV_VAR
    ].replace(":55433/", ":55432/")

    with pytest.raises(ValueError, match="protected persistent database port"):
        migration_support.validate_postgres_migration_target(
            environment,
            application_url="sqlite:///application.db",
        )


def test_alembic_migration_opt_in_fails_without_injected_connection():
    environment = os.environ.copy()
    environment[migration_support.MIGRATION_RUN_ENV_VAR] = "1"
    command = (
        "from alembic import command; "
        "from alembic.config import Config; "
        "command.upgrade(Config('alembic.ini'), 'head')"
    )
    repository_root = Path(__file__).resolve().parents[2]

    result = subprocess.run(
        [sys.executable, "-c", command],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "requires both explicit opt-in and migration-test connection" in (
        result.stderr
    )
    assert "password" not in result.stderr.lower()


@pytest.mark.parametrize(
    ("connection_expression", "schema", "message"),
    [
        ("None", "trustvault_migration_test_" + "a" * 32, "connection"),
        (
            "type('C', (), {'dialect': type('D', (), "
            "{'name': 'postgresql'})()})()",
            "invalid-schema",
            "schema",
        ),
        (
            "create_engine('sqlite://').connect()",
            "trustvault_migration_test_" + "a" * 32,
            "requires PostgreSQL",
        ),
    ],
)
def test_alembic_migration_mode_rejects_invalid_injected_configuration(
    connection_expression: str,
    schema: str,
    message: str,
):
    environment = os.environ.copy()
    environment[migration_support.MIGRATION_RUN_ENV_VAR] = "1"
    command = (
        "from alembic import command; "
        "from alembic.config import Config; "
        "from sqlalchemy import create_engine; "
        "config = Config('alembic.ini'); "
        f"config.attributes['connection'] = {connection_expression}; "
        f"config.attributes['version_table_schema'] = {schema!r}; "
        "config.attributes['trustvault_postgres_migration_test'] = True; "
        "command.upgrade(config, 'head')"
    )
    repository_root = Path(__file__).resolve().parents[2]

    result = subprocess.run(
        [sys.executable, "-c", command],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert message in result.stderr
    assert "application database" not in result.stderr.lower()


class _FakeConnection:
    def __init__(self, default_schema_name: str):
        self.dialect = SimpleNamespace(
            name="postgresql",
            default_schema_name=default_schema_name,
        )
        self.statements: list[str] = []

    def execute(self, statement, parameters=None):
        sql = str(statement)
        self.statements.append(sql)
        if "SELECT count(*)" in sql:
            return SimpleNamespace(scalar_one=lambda: 0)
        if "SELECT" in sql:
            return SimpleNamespace(
                scalar_one_or_none=lambda: True,
                scalars=lambda: [],
            )
        return SimpleNamespace()

    def commit(self):
        pass


class _FakeEngine:
    def __init__(self, connection: _FakeConnection, on_dispose=None):
        self.connection = connection
        self.disposed = False
        self.on_dispose = on_dispose

    @contextmanager
    def connect(self):
        yield self.connection

    def dispose(self):
        self.disposed = True
        if self.on_dispose is not None:
            self.on_dispose()


@pytest.mark.parametrize(
    ("target_revision", "expected_revision"),
    [
        ("head", "migration-head"),
        ("c7d8e9f0a1b2", "c7d8e9f0a1b2"),
    ],
)
def test_migration_execution_uses_fresh_engine_bound_before_dialect_init(
    monkeypatch: pytest.MonkeyPatch,
    target_revision: str,
    expected_revision: str,
):
    target = migration_support.validate_postgres_migration_target(
        _migration_target_environment(),
        application_url="sqlite:///application.db",
    )
    schema = "trustvault_migration_test_" + "b" * 32
    setup_connection = _FakeConnection("public")
    schema_connection = _FakeConnection(schema)
    setup_engine = _FakeEngine(setup_connection)
    schema_engine = _FakeEngine(schema_connection)
    cleanup_engine = _FakeEngine(_FakeConnection(schema))
    engine_calls: list[tuple[object, dict[str, object]]] = []
    created_engines = [setup_engine, schema_engine, cleanup_engine]
    bound_engine_created_after_dispose: list[bool] = []
    upgrades: list[str] = []
    object_checks: list[str] = []

    def fake_create_engine(url, **kwargs):
        engine_calls.append((url, kwargs))
        if len(engine_calls) == 1:
            return created_engines.pop(0)
        previous_engine_disposed = (
            setup_engine.disposed
            if len(engine_calls) == 2
            else schema_engine.disposed
        )
        bound_engine_created_after_dispose.append(previous_engine_disposed)
        return created_engines.pop(0)

    monkeypatch.setattr(migration_support, "create_engine", fake_create_engine)
    monkeypatch.setattr(
        migration_support,
        "validate_postgres_migration_target",
        lambda: target,
    )
    monkeypatch.setattr(migration_support.uuid, "uuid4", lambda: SimpleNamespace(
        hex=schema.removeprefix(migration_support._MIGRATION_SCHEMA_PREFIX)
    ))
    monkeypatch.setattr(
        migration_support,
        "_verify_connected_target",
        lambda connection, _target: None,
    )
    monkeypatch.setattr(
        migration_support,
        "_schema_is_owned_and_current",
        lambda connection, current_schema, expected_role: (
            connection.dialect.default_schema_name == current_schema
            and expected_role == target.role
        ),
    )
    monkeypatch.setattr(
        migration_support,
        "_verify_migration_objects",
        lambda _connection, current_schema: object_checks.append(
            current_schema
        ),
    )
    monkeypatch.setattr(
        migration_support,
        "_create_alembic_config",
        lambda connection, current_schema: SimpleNamespace(),
    )
    monkeypatch.setattr(
        migration_support.command,
        "upgrade",
        lambda _config, revision: upgrades.append(revision),
    )
    monkeypatch.setattr(
        migration_support.MigrationContext,
        "configure",
        lambda *_args, **_kwargs: SimpleNamespace(
            get_current_revision=lambda: expected_revision
        ),
    )
    monkeypatch.setattr(
        migration_support.ScriptDirectory,
        "from_config",
        lambda _config: SimpleNamespace(
            get_current_head=lambda: "migration-head",
            get_revision=lambda revision: SimpleNamespace(revision=revision),
        ),
    )

    with migration_support.migrated_postgres_schema(
        target_revision=target_revision
    ) as migrated:
        assert migrated.schema == schema
        assert migrated.revision == expected_revision

    assert setup_engine.disposed
    assert upgrades == [target_revision]
    assert bound_engine_created_after_dispose == [True, True]
    assert engine_calls[1][1]["connect_args"] == {
        "options": f"-csearch_path={schema}"
    }
    assert engine_calls[2][1]["connect_args"] == {
        "options": f"-csearch_path={schema}"
    }
    assert any(
        "CREATE SCHEMA" in statement for statement in setup_connection.statements
    )
    assert any(
        "DROP SCHEMA" in statement
        for statement in cleanup_engine.connection.statements
    )
    assert object_checks == (
        [schema] if target_revision == "head" else []
    )


@pytest.mark.parametrize("failure", ["identity", "ownership"])
def test_cleanup_refuses_drop_after_identity_or_ownership_change(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
):
    target = migration_support.validate_postgres_migration_target(
        _migration_target_environment(),
        application_url="sqlite:///application.db",
    )
    schema = "trustvault_migration_test_" + "c" * 32
    connection = _FakeConnection(schema)
    engine = _FakeEngine(connection)

    monkeypatch.setattr(
        migration_support,
        "_create_schema_bound_engine",
        lambda _target, _schema: engine,
    )
    if failure == "identity":
        monkeypatch.setattr(
            migration_support,
            "_verify_connected_target",
            lambda *_: (_ for _ in ()).throw(
                RuntimeError("connected identity changed")
            ),
        )
    else:
        monkeypatch.setattr(
            migration_support,
            "_verify_connected_target",
            lambda *_: None,
        )
        monkeypatch.setattr(
            migration_support,
            "_schema_is_owned_and_current",
            lambda *_: False,
        )

    with pytest.raises(RuntimeError):
        migration_support._cleanup_migration_schema(target, schema)

    assert not any("DROP SCHEMA" in sql for sql in connection.statements)
    assert engine.disposed


@pytest.mark.parametrize("schema", ["public", "trustvault_migration_test_not-hex"])
def test_schema_bound_engine_rejects_invalid_schema(
    monkeypatch: pytest.MonkeyPatch,
    schema: str,
):
    target = migration_support.validate_postgres_migration_target(
        _migration_target_environment(),
        application_url="sqlite:///application.db",
    )
    engine_factory_called = False

    def fail_if_engine_created(*args, **kwargs):
        nonlocal engine_factory_called
        engine_factory_called = True
        raise AssertionError("Engine must not be created for invalid schema.")

    monkeypatch.setattr(migration_support, "create_engine", fail_if_engine_created)

    with pytest.raises(ValueError, match="invalid migration schema"):
        migration_support._create_schema_bound_engine(target, schema)

    assert not engine_factory_called


def test_unknown_target_revision_fails_and_still_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
):
    target = migration_support.validate_postgres_migration_target(
        _migration_target_environment(),
        application_url="sqlite:///application.db",
    )
    schema = "trustvault_migration_test_" + "d" * 32
    setup_connection = _FakeConnection("public")
    schema_connection = _FakeConnection(schema)
    cleanup_connection = _FakeConnection(schema)
    setup_engine = _FakeEngine(setup_connection)
    schema_engine = _FakeEngine(schema_connection)
    cleanup_engine = _FakeEngine(cleanup_connection)
    engines = [setup_engine, schema_engine, cleanup_engine]

    monkeypatch.setattr(
        migration_support,
        "validate_postgres_migration_target",
        lambda: target,
    )
    monkeypatch.setattr(
        migration_support.uuid,
        "uuid4",
        lambda: SimpleNamespace(
            hex=schema.removeprefix(migration_support._MIGRATION_SCHEMA_PREFIX)
        ),
    )
    monkeypatch.setattr(
        migration_support,
        "create_engine",
        lambda *_args, **_kwargs: engines.pop(0),
    )
    monkeypatch.setattr(
        migration_support,
        "_verify_connected_target",
        lambda *_: None,
    )
    monkeypatch.setattr(
        migration_support,
        "_schema_is_owned_and_current",
        lambda *_: True,
    )
    monkeypatch.setattr(
        migration_support,
        "_create_alembic_config",
        lambda *_: SimpleNamespace(),
    )
    monkeypatch.setattr(migration_support.command, "upgrade", lambda *_: None)
    monkeypatch.setattr(
        migration_support.ScriptDirectory,
        "from_config",
        lambda _config: SimpleNamespace(
            get_revision=lambda _revision: None,
        ),
    )

    with pytest.raises(RuntimeError, match="Unknown Alembic target revision"):
        with migration_support.migrated_postgres_schema(
            target_revision="not-a-revision"
        ):
            pytest.fail("Unknown target revision must not yield a schema.")

    assert any("DROP SCHEMA" in sql for sql in cleanup_connection.statements)
