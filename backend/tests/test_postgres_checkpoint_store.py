from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from backend.app.services.checkpoint_store import (
    AuditCheckpoint,
    CheckpointConflictError,
    CheckpointIntegrityError,
    PostgresCheckpointStore,
)
from backend.tests.postgres_concurrency_support import (
    POSTGRES_INTEGRATION_MARKERS,
    isolated_postgres_schema,
)

pytestmark = POSTGRES_INTEGRATION_MARKERS


def test_postgres_checkpoint_store_is_append_only_and_detects_tampering():
    with isolated_postgres_schema() as isolated:
        with isolated.engine.begin() as connection:
            connection.execute(
                text(
                    f'''CREATE TABLE "{isolated.schema}".checkpoints (
                        stream_id text NOT NULL,
                        sequence_number bigint NOT NULL,
                        record_hash text NOT NULL,
                        checkpoint_document text NOT NULL,
                        PRIMARY KEY (stream_id, sequence_number)
                    )'''
                )
            )

        store = PostgresCheckpointStore(
            isolated.engine.url,
            b"k" * 64,
            schema=isolated.schema,
        )
        now = datetime.now(UTC)
        genesis = AuditCheckpoint(
            format_version=1,
            stream_id="trustvault.audit",
            sequence_number=0,
            record_hash="0" * 64,
            created_at=now,
        )
        first, created = store.write_checkpoint(genesis)
        assert created is True
        assert first.integrity_tag is not None
        assert store.read_latest() == first

        retry, created = store.write_checkpoint(genesis)
        assert created is False
        assert retry == first

        with pytest.raises(CheckpointConflictError):
            store.write_checkpoint(
                AuditCheckpoint(
                    format_version=1,
                    stream_id="trustvault.audit",
                    sequence_number=0,
                    record_hash="1" * 64,
                    created_at=now,
                )
            )

        second, created = store.write_checkpoint(
            AuditCheckpoint(
                format_version=1,
                stream_id="trustvault.audit",
                sequence_number=1,
                record_hash="2" * 64,
                created_at=now,
                previous_checkpoint_hmac=first.integrity_tag,
            )
        )
        assert created is True
        assert second.sequence_number == 1
        assert store.read_latest() == second

        try:
            with isolated.engine.begin() as connection:
                connection.execute(
                    text(
                        f'''UPDATE "{isolated.schema}".checkpoints
                            SET checkpoint_document = 'tampered'
                            WHERE sequence_number = 1'''
                    )
                )
            with pytest.raises(CheckpointIntegrityError):
                store.read_latest()
        finally:
            store.close()
