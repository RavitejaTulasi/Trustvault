"""Migration coverage for historical audit hashes, checkpoints, and actor FKs."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import MetaData, Table, create_engine, event, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from backend.app import database as database_module
from backend.app.models.audit import (
    AUDIT_HASH_VERSION_CURRENT,
    AUDIT_HASH_VERSION_LEGACY,
    AuditChainState,
    AuditEvent,
    AuditOutcome,
)
from backend.app.models.base import generate_uuid
from backend.app.services.audit_service import GENESIS_HASH, AuditService
from backend.app.services.checkpoint_service import CheckpointService
from backend.app.services.checkpoint_store import (
    AUDIT_STREAM_ID,
    CHECKPOINT_FORMAT_VERSION,
    AuditCheckpoint,
    LocalFileCheckpointStore,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
LEGACY_HEAD = "b6f1c8e9a2d4"


def _enable_sqlite_foreign_keys(engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def _alembic_config(monkeypatch: pytest.MonkeyPatch, db_path: Path) -> Config:
    db_url = f"sqlite:///{db_path.as_posix()}"
    monkeypatch.setattr(database_module, "db_url", db_url, raising=True)
    config = Config()
    config.set_main_option(
        "script_location",
        str(REPO_ROOT / "backend" / "migrations"),
    )
    config.set_main_option("sqlalchemy.url", db_url)
    return config


def test_upgrade_preserves_legacy_hashes_checkpoints_and_actor_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    db_path = tmp_path / "legacy-audit.sqlite"
    config = _alembic_config(monkeypatch, db_path)
    command.upgrade(config, LEGACY_HEAD)

    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    _enable_sqlite_foreign_keys(engine)
    metadata = MetaData()
    users = Table("users", metadata, autoload_with=engine)
    audit_events = Table("audit_events", metadata, autoload_with=engine)

    actor_id = generate_uuid()
    base_time = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)
    with engine.begin() as connection:
        connection.execute(
            users.insert().values(
                id=actor_id,
                email="legacy-actor@example.com",
                hashed_password="legacy-hash",
                full_name="Legacy Actor",
                role="admin",
                is_active=True,
                created_at=base_time,
                updated_at=base_time,
            )
        )

    event_hashes: list[str] = []
    previous_hash = GENESIS_HASH
    for sequence_number in (1, 2):
        event_time = base_time + timedelta(seconds=sequence_number)
        event_id = generate_uuid()
        details = '{"reason":"legacy"}'
        record_hash = AuditService.calculate_hash(
            sequence_number=sequence_number,
            timestamp=event_time,
            actor_id=actor_id,
            action=f"test.legacy.{sequence_number}",
            resource_type="legacy",
            resource_id=f"legacy-{sequence_number}",
            outcome=AuditOutcome.SUCCESS,
            request_id=None,
            details_str=details,
            previous_hash=previous_hash,
            hash_version=AUDIT_HASH_VERSION_LEGACY,
        )
        with engine.begin() as connection:
            connection.execute(
                audit_events.insert().values(
                    id=event_id,
                    sequence_number=sequence_number,
                    timestamp=event_time,
                    actor_id=actor_id,
                    action=f"test.legacy.{sequence_number}",
                    resource_type="legacy",
                    resource_id=f"legacy-{sequence_number}",
                    outcome=AuditOutcome.SUCCESS,
                    request_id=None,
                    ip_address="203.0.113.10",
                    user_agent="Legacy-Client/1.0",
                    details=details,
                    previous_hash=previous_hash,
                    record_hash=record_hash,
                )
            )
        event_hashes.append(record_hash)
        previous_hash = record_hash

    checkpoint_store = LocalFileCheckpointStore(tmp_path / "anchors", b"k" * 32)
    _, checkpoint_created = checkpoint_store.write_checkpoint(
        AuditCheckpoint(
            format_version=CHECKPOINT_FORMAT_VERSION,
            stream_id=AUDIT_STREAM_ID,
            sequence_number=2,
            record_hash=event_hashes[-1],
            created_at=datetime.now(UTC),
        )
    )
    assert checkpoint_created is True
    engine.dispose()

    command.upgrade(config, "head")

    upgraded_engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    _enable_sqlite_foreign_keys(upgraded_engine)
    session_factory = sessionmaker(bind=upgraded_engine)
    with session_factory() as db:
        chain = AuditService.verify_chain_integrity_bounded(
            db,
            max_records=100,
            batch_size=10,
            timeout_seconds=10,
        )
        assert chain.status == "VALID", chain.failure_reason
        assert chain.records_verified == 2

        stored_events = (
            db.query(AuditEvent).order_by(AuditEvent.sequence_number.asc()).all()
        )
        assert [event.hash_version for event in stored_events] == [
            AUDIT_HASH_VERSION_LEGACY,
            AUDIT_HASH_VERSION_LEGACY,
        ]

        state = db.get(AuditChainState, 1)
        assert state is not None
        assert state.last_sequence == 2
        assert state.last_hash == event_hashes[-1]

        historical_checkpoint = CheckpointService.verify_checkpoint(
            db,
            checkpoint_store,
            max_records=100,
            batch_size=10,
            timeout_seconds=10,
        )
        assert historical_checkpoint.status == "VALID"
        assert historical_checkpoint.checkpoint_sequence == 2

        new_event = AuditService.log_event(
            db,
            action="test.legacy.after_upgrade",
            outcome=AuditOutcome.SUCCESS,
            actor_id=actor_id,
            ip_address="203.0.113.25",
            user_agent="TrustVault-Migration/1.0",
        )
        db.commit()

        assert new_event.sequence_number == 3
        assert new_event.hash_version == AUDIT_HASH_VERSION_CURRENT
        assert new_event.previous_hash == event_hashes[-1]

        extended_chain = AuditService.verify_chain_integrity_bounded(
            db,
            max_records=100,
            batch_size=10,
            timeout_seconds=10,
        )
        assert extended_chain.status == "VALID", extended_chain.failure_reason

        extended_checkpoint = CheckpointService.verify_checkpoint(
            db,
            checkpoint_store,
            max_records=100,
            batch_size=10,
            timeout_seconds=10,
        )
        assert extended_checkpoint.status == "VALID"
        assert extended_checkpoint.chain_head_sequence == 3

    with upgraded_engine.connect() as connection:
        actor_foreign_keys = [
            foreign_key
            for foreign_key in inspect(connection).get_foreign_keys("audit_events")
            if foreign_key["constrained_columns"] == ["actor_id"]
        ]
        assert len(actor_foreign_keys) == 1
        assert actor_foreign_keys[0].get("options", {}).get("ondelete") == "RESTRICT"

    with pytest.raises(IntegrityError), upgraded_engine.begin() as connection:
        connection.execute(
            text("DELETE FROM users WHERE id = :actor_id"),
            {"actor_id": actor_id},
        )

    upgraded_engine.dispose()


def test_downgrade_is_refused_when_version_2_records_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    db_path = tmp_path / "v2-downgrade.sqlite"
    config = _alembic_config(monkeypatch, db_path)
    command.upgrade(config, "head")

    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    session_factory = sessionmaker(bind=engine)
    with session_factory() as db:
        event = AuditService.log_event(
            db,
            action="test.v2.before_downgrade",
            outcome=AuditOutcome.SUCCESS,
        )
        db.commit()
        assert event.hash_version == AUDIT_HASH_VERSION_CURRENT
        event_id = event.id

    with pytest.raises(RuntimeError, match="hash version 2"):
        command.downgrade(config, LEGACY_HEAD)

    inspector = inspect(engine)
    assert "hash_version" in {
        column["name"] for column in inspector.get_columns("audit_events")
    }
    assert "audit_chain_state" in inspector.get_table_names()
    with engine.connect() as connection:
        version = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one()
        stored_version = connection.execute(
            text("SELECT hash_version FROM audit_events WHERE id = :event_id"),
            {"event_id": event_id},
        ).scalar_one()
    assert version in {"c3d4e5f6a7b8", "d4e5f6a7b8c9"}
    assert stored_version == AUDIT_HASH_VERSION_CURRENT

    with session_factory() as db:
        result = AuditService.verify_chain_integrity_bounded(
            db,
            max_records=100,
            batch_size=10,
            timeout_seconds=10,
        )
        assert result.status == "VALID", result.failure_reason
    engine.dispose()


def test_v1_chain_downgrade_and_reupgrade_preserves_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    db_path = tmp_path / "v1-downgrade.sqlite"
    config = _alembic_config(monkeypatch, db_path)
    command.upgrade(config, LEGACY_HEAD)

    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    metadata = MetaData()
    audit_events = Table("audit_events", metadata, autoload_with=engine)
    event_time = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)
    event_id = generate_uuid()
    record_hash = AuditService.calculate_hash(
        sequence_number=1,
        timestamp=event_time,
        actor_id=None,
        action="test.legacy.downgrade",
        resource_type=None,
        resource_id=None,
        outcome=AuditOutcome.SUCCESS,
        request_id=None,
        details_str=None,
        previous_hash=GENESIS_HASH,
        hash_version=AUDIT_HASH_VERSION_LEGACY,
    )
    with engine.begin() as connection:
        connection.execute(
            audit_events.insert().values(
                id=event_id,
                sequence_number=1,
                timestamp=event_time,
                actor_id=None,
                action="test.legacy.downgrade",
                resource_type=None,
                resource_id=None,
                outcome=AuditOutcome.SUCCESS,
                request_id=None,
                ip_address=None,
                user_agent=None,
                details=None,
                previous_hash=GENESIS_HASH,
                record_hash=record_hash,
            )
        )

    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT hash_version FROM audit_events")
            ).scalar_one()
            == AUDIT_HASH_VERSION_LEGACY
        )

    command.downgrade(config, LEGACY_HEAD)
    downgraded = inspect(engine)
    assert "hash_version" not in {
        column["name"] for column in downgraded.get_columns("audit_events")
    }
    assert "audit_chain_state" not in downgraded.get_table_names()

    command.upgrade(config, "head")
    upgraded = inspect(engine)
    assert "hash_version" in {
        column["name"] for column in upgraded.get_columns("audit_events")
    }

    session_factory = sessionmaker(bind=engine)
    with session_factory() as db:
        stored = db.query(AuditEvent).one()
        assert stored.hash_version == AUDIT_HASH_VERSION_LEGACY
        result = AuditService.verify_chain_integrity_bounded(
            db,
            max_records=100,
            batch_size=10,
            timeout_seconds=10,
        )
        assert result.status == "VALID", result.failure_reason

        appended = AuditService.log_event(
            db,
            action="test.v2.after_reupgrade",
            outcome=AuditOutcome.SUCCESS,
        )
        db.commit()
        assert appended.hash_version == AUDIT_HASH_VERSION_CURRENT
        extended = AuditService.verify_chain_integrity_bounded(
            db,
            max_records=100,
            batch_size=10,
            timeout_seconds=10,
        )
        assert extended.status == "VALID", extended.failure_reason
    engine.dispose()



def test_upgrade_refuses_corrupted_legacy_audit_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    db_path = tmp_path / "corrupted-legacy-audit.sqlite"
    config = _alembic_config(monkeypatch, db_path)

    # Create the database at the schema immediately before the target migration.
    command.upgrade(config, LEGACY_HEAD)

    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    metadata = MetaData()
    audit_events = Table("audit_events", metadata, autoload_with=engine)

    event_time = datetime(2026, 10, 20, 12, 0, 1, tzinfo=UTC)
    event_id = generate_uuid()
    details = '{"reason":"legacy"}'

    valid_hash = AuditService.calculate_hash(
        sequence_number=1,
        timestamp=event_time,
        actor_id=None,
        action="test.legacy.corruption",
        resource_type="legacy",
        resource_id="legacy-corrupted",
        outcome=AuditOutcome.SUCCESS,
        request_id=None,
        details_str=details,
        previous_hash=GENESIS_HASH,
        hash_version=AUDIT_HASH_VERSION_LEGACY,
    )

    with engine.begin() as connection:
        connection.execute(
            audit_events.insert().values(
                id=event_id,
                sequence_number=1,
                timestamp=event_time,
                actor_id=None,
                action="test.legacy.corruption",
                resource_type="legacy",
                resource_id="legacy-corrupted",
                outcome=AuditOutcome.SUCCESS,
                request_id=None,
                ip_address=None,
                user_agent=None,
                details=details,
                previous_hash=GENESIS_HASH,
                record_hash=valid_hash,
            )
        )

        # Simulate historical audit-record tampering.
        connection.execute(
            text(
                "UPDATE audit_events "
                "SET record_hash = :bad_hash "
                "WHERE sequence_number = 1"
            ),
            {"bad_hash": "f" * 64},
        )

    engine.dispose()

    with pytest.raises(RuntimeError, match="record hash mismatch"):
        command.upgrade(config, "head")

    # Confirm validation failed before the target migration changed the schema.
    check_engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    try:
        inspector = inspect(check_engine)
        column_names = {
            column["name"]
            for column in inspector.get_columns("audit_events")
        }

        assert "hash_version" not in column_names
        assert "audit_chain_state" not in inspector.get_table_names()
    finally:
        check_engine.dispose()



@pytest.mark.parametrize(
    ("sequence_number", "stored_previous_hash", "expected_error"),
    [
        # Sequence must start at 1 and remain contiguous.
        (2, GENESIS_HASH, "sequence gap or invalid sequence"),
        # The first event must link to the genesis hash.
        (1, "a" * 64, "previous-hash link mismatch"),
    ],
    ids=["sequence-gap", "broken-previous-hash"],
)
def test_upgrade_refuses_invalid_legacy_chain_structure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sequence_number: int,
    stored_previous_hash: str,
    expected_error: str,
):
    db_path = tmp_path / f"invalid-chain-{sequence_number}.sqlite"
    config = _alembic_config(monkeypatch, db_path)

    # Create only the schema preceding the migration under test.
    command.upgrade(config, LEGACY_HEAD)

    engine = create_engine(f"sqlite:///{db_path.as_posix()}")
    try:
        audit_events = Table(
            "audit_events",
            MetaData(),
            autoload_with=engine,
        )

        event_time = datetime(2026, 10, 20, 12, 0, 1, tzinfo=UTC)
        event_id = generate_uuid()
        action = "test.legacy.invalid_chain"

        # Calculate a matching hash for the stored fields. This ensures
        # the broken-link case fails because of the link, not the record hash.
        record_hash = AuditService.calculate_hash(
            sequence_number=sequence_number,
            timestamp=event_time,
            actor_id=None,
            action=action,
            resource_type="legacy",
            resource_id="invalid-chain",
            outcome=AuditOutcome.SUCCESS,
            request_id=None,
            details_str=None,
            previous_hash=stored_previous_hash,
            hash_version=AUDIT_HASH_VERSION_LEGACY,
        )

        with engine.begin() as connection:
            connection.execute(
                audit_events.insert().values(
                    id=event_id,
                    sequence_number=sequence_number,
                    timestamp=event_time,
                    actor_id=None,
                    action=action,
                    resource_type="legacy",
                    resource_id="invalid-chain",
                    outcome=AuditOutcome.SUCCESS,
                    request_id=None,
                    ip_address=None,
                    user_agent=None,
                    details=None,
                    previous_hash=stored_previous_hash,
                    record_hash=record_hash,
                )
            )

        engine.dispose()

        with pytest.raises(RuntimeError, match=expected_error):
            command.upgrade(config, "head")

        # Validation must reject the chain before altering the schema.
        check_engine = create_engine(f"sqlite:///{db_path.as_posix()}")
        try:
            inspector = inspect(check_engine)
            column_names = {
                column["name"]
                for column in inspector.get_columns("audit_events")
            }

            assert "hash_version" not in column_names
            assert "audit_chain_state" not in inspector.get_table_names()
        finally:
            check_engine.dispose()

    finally:
        engine.dispose()
