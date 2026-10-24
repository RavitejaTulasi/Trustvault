from contextlib import contextmanager
import os
import re
import subprocess
import sys

import pytest

import backend.tests.postgres_concurrency_support as postgres_support


def _target_environment() -> dict[str, str]:
    return {
        postgres_support.RUN_ENV_VAR: "1",
        postgres_support.URL_ENV_VAR: (
            "postgresql+psycopg://test_role:synthetic-password"
            "@127.0.0.1:55432/trustvault_test"
        ),
        postgres_support.DATABASE_ENV_VAR: "trustvault_test",
        postgres_support.ROLE_ENV_VAR: "test_role",
        postgres_support.HOST_ENV_VAR: "127.0.0.1",
        postgres_support.PORT_ENV_VAR: "55432",
        postgres_support.SERVER_ID_ENV_VAR: "trustvault-postgres-test-unique",
        postgres_support.SERVER_PORT_ENV_VAR: "5432",
        postgres_support.DISPOSABLE_CONFIRM_ENV_VAR: (
            postgres_support.DISPOSABLE_CONFIRMATION
        ),
    }


def _expected_identity(**overrides: object) -> dict[str, object]:
    identity: dict[str, object] = {
        "database_name": "trustvault_test",
        "role_name": "test_role",
        "server_id": "trustvault-postgres-test-unique",
        "server_port": 5432,
        "is_superuser": False,
        "can_create_database": False,
        "can_create_roles": False,
        "is_template": False,
        "owns_database": False,
        "has_role_memberships": False,
        "can_create_schema": True,
    }
    identity.update(overrides)
    return identity


@pytest.mark.parametrize(
    ("environment_update", "message"),
    [
        ({"TRUSTVAULT_TEST_POSTGRES_URL": ""}, "URL"),
        (
            {"TRUSTVAULT_TEST_POSTGRES_URL": "sqlite:///unrelated.db"},
            "PostgreSQL",
        ),
        (
            {
                "TRUSTVAULT_TEST_POSTGRES_URL": (
                    "postgresql+psycopg://test_role:pw@127.0.0.1:55432"
                    "/another_database"
                )
            },
            "database",
        ),
        (
            {
                "TRUSTVAULT_TEST_POSTGRES_URL": (
                    "postgresql+psycopg://another_role:pw@127.0.0.1:55432"
                    "/trustvault_test"
                )
            },
            "role",
        ),
    ],
)
def test_target_configuration_rejects_missing_or_mismatched_values(
    environment_update: dict[str, str],
    message: str,
):
    environment = _target_environment()
    environment.update(environment_update)

    with pytest.raises(ValueError, match=message) as error:
        postgres_support.validate_postgres_test_target(
            environment,
            application_url="sqlite:///application.db",
        )

    assert "synthetic-password" not in str(error.value)
    assert "pw@" not in str(error.value)


def test_target_configuration_requires_opt_in_flag():
    environment = _target_environment()
    environment[postgres_support.RUN_ENV_VAR] = "0"

    with pytest.raises(ValueError, match="is required"):
        postgres_support.validate_postgres_test_target(
            environment,
            application_url="sqlite:///application.db",
        )


def test_target_configuration_rejects_application_database_reuse():
    environment = _target_environment()
    application_url = environment[postgres_support.URL_ENV_VAR].replace(
        "test_role:synthetic-password",
        "application_role:application-password",
    )

    with pytest.raises(ValueError, match="matches the application's"):
        postgres_support.validate_postgres_test_target(
            environment,
            application_url=application_url,
        )


def test_test_overridden_sqlite_does_not_hide_original_application_database(
    monkeypatch,
):
    environment = _target_environment()
    original_application_url = environment[postgres_support.URL_ENV_VAR].replace(
        "test_role:synthetic-password",
        "application_role:application-password",
    )
    monkeypatch.setattr(
        postgres_support,
        "_APPLICATION_DATABASE_URL_AT_LOAD",
        original_application_url,
    )

    with pytest.raises(ValueError, match="matches the application's"):
        postgres_support.validate_postgres_test_target(environment)


def test_original_application_database_url_must_be_present(monkeypatch):
    monkeypatch.setattr(postgres_support, "_APPLICATION_DATABASE_URL_AT_LOAD", "")

    with pytest.raises(ValueError, match="original database URL is not configured"):
        postgres_support.validate_postgres_test_target(_target_environment())


def test_malformed_original_application_database_url_fails_closed():
    with pytest.raises(ValueError, match="cannot be validated"):
        postgres_support.validate_postgres_test_target(
            _target_environment(),
            application_url="://not-a-url",
        )


def test_ambiguous_original_postgres_database_url_fails_closed():
    with pytest.raises(ValueError, match="does not identify a database"):
        postgres_support.validate_postgres_test_target(
            _target_environment(),
            application_url="postgresql://application-role@127.0.0.1",
        )


def test_unsupported_original_application_database_backend_fails_closed():
    with pytest.raises(ValueError, match="unsupported backend"):
        postgres_support.validate_postgres_test_target(
            _target_environment(),
            application_url="mysql://application-role@127.0.0.1/application",
        )


def test_conftest_captures_original_database_url_before_sqlite_override():
    original_database_url = (
        "postgresql+psycopg://synthetic-role@127.0.0.1:55432/"
        "synthetic-application"
    )
    code = (
        "import backend.tests.conftest\n"
        "from backend.app import config, database\n"
        f"assert config._APPLICATION_DATABASE_URL_AT_LOAD == {original_database_url!r}\n"
        "assert config.settings.DATABASE_URL == 'sqlite:///:memory:'\n"
        "assert database.db_url == 'sqlite:///:memory:'\n"
        "print('configuration-order-verified')\n"
    )
    environment = os.environ.copy()
    environment["ENVIRONMENT"] = "testing"
    environment["DATABASE_URL"] = original_database_url
    environment.pop(postgres_support.RUN_ENV_VAR, None)

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=os.getcwd(),
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, (
        "Fresh-process configuration import check failed without exposing "
        "database configuration."
    )
    assert result.stdout.strip() == "configuration-order-verified"


def test_target_configuration_requires_explicit_disposable_confirmation():
    environment = _target_environment()
    environment[postgres_support.DISPOSABLE_CONFIRM_ENV_VAR] = ""

    with pytest.raises(ValueError, match="explicitly confirm"):
        postgres_support.validate_postgres_test_target(
            environment,
            application_url="sqlite:///application.db",
        )


def test_target_configuration_accepts_explicit_disposable_test_target():
    target = postgres_support.validate_postgres_test_target(
        _target_environment(),
        application_url="sqlite:///application.db",
    )

    assert target.database == "trustvault_test"
    assert target.role == "test_role"
    assert target.host == "127.0.0.1"
    assert target.port == 55432
    assert target.server_id == "trustvault-postgres-test-unique"
    assert target.server_port == 5432
    assert "synthetic-password" not in repr(target)


def test_target_configuration_accepts_different_postgres_application_database():
    target = postgres_support.validate_postgres_test_target(
        _target_environment(),
        application_url=(
            "postgresql+psycopg://application_role:application-password"
            "@127.0.0.1:55432/trustvault_application"
        ),
    )

    assert target.database == "trustvault_test"
    assert target.role == "test_role"


@pytest.mark.parametrize(
    "identity_update",
    [
        {"database_name": "application"},
        {"role_name": "application_role"},
        {"server_id": "unexpected-server"},
        {"server_port": 55433},
        {"is_superuser": True},
        {"can_create_database": True},
        {"can_create_roles": True},
        {"is_template": True},
        {"owns_database": True},
        {"has_role_memberships": True},
        {"can_create_schema": False},
    ],
)
def test_connection_identity_rejects_unexpected_or_unsafe_target(
    identity_update: dict[str, object],
):
    target = postgres_support.validate_postgres_test_target(
        _target_environment(),
        application_url="sqlite:///application.db",
    )

    class Result:
        def mappings(self):
            return self

        def one(self):
            return _expected_identity(**identity_update)

    class Connection:
        def execute(self, statement):
            assert str(statement).lstrip().startswith("SELECT current_database()")
            return Result()

    with pytest.raises(RuntimeError, match="identity or isolation checks failed"):
        postgres_support._verify_connected_target(Connection(), target)


class _FakeResult:
    def mappings(self):
        return self

    def one(self):
        return _expected_identity()


class _FakeScalarResult:
    def scalar_one_or_none(self):
        return True


class _FakeConnection:
    def __init__(self, statements: list[str]):
        self.statements = statements

    def execute(self, statement, _parameters=None):
        assert _parameters is None or set(_parameters) == {"schema"}
        rendered = str(statement)
        self.statements.append(rendered)
        if rendered.lstrip().startswith("SELECT current_database()"):
            return _FakeResult()
        if rendered.lstrip().startswith("SELECT nspowner"):
            return _FakeScalarResult()
        return None


class _FakeAdminEngine:
    def __init__(self):
        self.statements: list[str] = []
        self.disposed = False

    @contextmanager
    def connect(self):
        yield _FakeConnection(self.statements)

    def dispose(self):
        self.disposed = True


def test_schema_setup_failure_cleans_only_its_created_schema(monkeypatch):
    environment = _target_environment()
    monkeypatch.setattr(postgres_support.os, "environ", environment)
    admin_engine = _FakeAdminEngine()
    engine_calls = 0

    def fake_create_engine(url, **options):
        nonlocal engine_calls
        engine_calls += 1
        assert url.get_backend_name() == "postgresql"
        if engine_calls == 1:
            assert options == {"isolation_level": "AUTOCOMMIT"}
            return admin_engine
        assert set(options) == {"connect_args"}
        raise RuntimeError("simulated test-engine setup failure")

    monkeypatch.setattr(postgres_support, "create_engine", fake_create_engine)

    with pytest.raises(RuntimeError, match="simulated test-engine setup failure"):
        with postgres_support.isolated_postgres_schema():
            pytest.fail("The schema fixture must not yield after setup failure.")

    creates = [
        statement
        for statement in admin_engine.statements
        if statement.startswith("CREATE SCHEMA")
    ]
    drops = [
        statement
        for statement in admin_engine.statements
        if statement.startswith("DROP SCHEMA")
    ]
    assert len(creates) == 1
    assert len(drops) == 1
    created_schema = re.search(r'"(trustvault_concurrency_test_[0-9a-f]+)"', creates[0])
    dropped_schema = re.search(r'"(trustvault_concurrency_test_[0-9a-f]+)"', drops[0])
    assert created_schema is not None
    assert dropped_schema is not None
    assert created_schema.group(1) == dropped_schema.group(1)
    assert "CASCADE" in drops[0]
    assert admin_engine.disposed is True


def test_cleanup_refuses_schema_not_owned_by_test_role():
    class UnownedSchemaResult:
        def scalar_one_or_none(self):
            return False

    class Connection:
        def __init__(self):
            self.statements: list[str] = []

        def execute(self, statement, parameters=None):
            assert parameters == {"schema": "trustvault_test_schema"}
            self.statements.append(str(statement))
            return UnownedSchemaResult()

    connection = Connection()

    with pytest.raises(RuntimeError, match="not owned by this test role"):
        postgres_support._drop_owned_schema(connection, "trustvault_test_schema")

    assert len(connection.statements) == 1
    assert "DROP SCHEMA" not in connection.statements[0]


def test_identity_failure_does_not_create_or_drop_a_schema(monkeypatch):
    environment = _target_environment()
    monkeypatch.setattr(postgres_support.os, "environ", environment)
    admin_engine = _FakeAdminEngine()
    engine_calls = 0

    def fake_create_engine(url, **options):
        nonlocal engine_calls
        engine_calls += 1
        assert url.get_backend_name() == "postgresql"
        assert options == {"isolation_level": "AUTOCOMMIT"}
        return admin_engine

    original_execute = _FakeConnection.execute

    def mismatched_execute(connection, statement, parameters=None):
        if str(statement).lstrip().startswith("SELECT current_database()"):
            assert parameters is None
            connection.statements.append(str(statement))

            class MismatchedResult(_FakeResult):
                def one(self):
                    return _expected_identity(database_name="wrong_database")

            return MismatchedResult()
        return original_execute(connection, statement, parameters)

    monkeypatch.setattr(_FakeConnection, "execute", mismatched_execute)
    monkeypatch.setattr(postgres_support, "create_engine", fake_create_engine)

    with pytest.raises(RuntimeError, match="identity or isolation checks failed"):
        with postgres_support.isolated_postgres_schema():
            pytest.fail("The schema fixture must fail its identity preflight.")

    assert engine_calls == 1
    assert not any(
        statement.startswith(("CREATE SCHEMA", "DROP SCHEMA"))
        for statement in admin_engine.statements
    )
    assert admin_engine.disposed is True
