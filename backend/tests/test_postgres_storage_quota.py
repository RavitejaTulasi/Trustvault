"""Opt-in PostgreSQL concurrency tests for storage quota admission."""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import func, select

from backend.app.config import settings
from backend.app.models.document import Document
from backend.app.models.user import UserRole
from backend.app.services.storage_quota import (
    StorageQuotaExceeded,
    StorageQuotaService,
)
from backend.tests.postgres_concurrency_support import (
    POSTGRES_INTEGRATION_MARKERS,
    PostgresTestSchema,
    isolated_postgres_schema,
)
from backend.tests.test_auth import VALID_PASSWORD, make_user

pytestmark = POSTGRES_INTEGRATION_MARKERS


@pytest.fixture
def pg_schema():
    with isolated_postgres_schema() as schema:
        yield schema


def _document(owner_id: str, marker: str, size_bytes: int) -> Document:
    return Document(
        title=f"Quota {marker}",
        original_filename=f"quota-{marker}.pdf",
        storage_key=f"quota-{marker}-{uuid.uuid4().hex}",
        file_size_bytes=size_bytes,
        mime_type="application/pdf",
        category="General",
        owner_id=owner_id,
        is_deleted=False,
    )


def test_concurrent_upload_count_admission_allows_exactly_one_document(
    pg_schema: PostgresTestSchema,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "MAX_UPLOADS_PER_USER", 1)
    monkeypatch.setattr(settings, "MAX_USER_STORAGE_BYTES", 1_000_000)
    monkeypatch.setattr(settings, "MAX_GLOBAL_STORAGE_BYTES", 1_000_000)

    with pg_schema.session_factory() as session:
        owner = make_user(
            session,
            email="quota-count@example.com",
            password=VALID_PASSWORD,
            role=UserRole.OWNER,
        )
        session.commit()
        owner_id = owner.id

    workers = 4
    barrier = threading.Barrier(workers)

    def upload(index: int) -> str:
        with pg_schema.session_factory() as session:
            barrier.wait(timeout=30)
            try:
                StorageQuotaService.acquire_upload_slot(session, owner_id, 10)
                session.add(_document(owner_id, str(index), 10))
                session.commit()
            except StorageQuotaExceeded:
                session.rollback()
                return "denied"
            return "uploaded"

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(upload, range(workers)))

    assert results.count("uploaded") == 1
    assert results.count("denied") == workers - 1

    with pg_schema.session_factory() as session:
        assert session.scalar(select(func.count(Document.id))) == 1


def test_concurrent_global_byte_admission_serializes_across_owners(
    pg_schema: PostgresTestSchema,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "MAX_UPLOADS_PER_USER", 100)
    monkeypatch.setattr(settings, "MAX_USER_STORAGE_BYTES", 1_000_000)
    monkeypatch.setattr(settings, "MAX_GLOBAL_STORAGE_BYTES", 50)

    with pg_schema.session_factory() as session:
        first_owner = make_user(
            session,
            email="quota-global-a@example.com",
            password=VALID_PASSWORD,
            role=UserRole.OWNER,
        )
        second_owner = make_user(
            session,
            email="quota-global-b@example.com",
            password=VALID_PASSWORD,
            role=UserRole.OWNER,
        )
        session.commit()
        owner_ids = [first_owner.id, second_owner.id]

    workers = 4
    barrier = threading.Barrier(workers)

    def upload(index: int) -> str:
        owner_id = owner_ids[index % len(owner_ids)]
        with pg_schema.session_factory() as session:
            barrier.wait(timeout=30)
            try:
                StorageQuotaService.acquire_upload_slot(session, owner_id, 40)
                session.add(_document(owner_id, f"global-{index}", 40))
                session.commit()
            except StorageQuotaExceeded:
                session.rollback()
                return "denied"
            return "uploaded"

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(upload, range(workers)))

    assert results.count("uploaded") == 1
    assert results.count("denied") == workers - 1

    with pg_schema.session_factory() as session:
        assert session.scalar(select(func.count(Document.id))) == 1
        assert (
            session.scalar(select(func.sum(Document.file_size_bytes)))
            == 40
        )
