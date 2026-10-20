"""Opt-in PostgreSQL concurrency test for document grant upserts."""

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import func, select

from backend.app.api.documents import (
    _get_active_grant,
    _get_grant,
    _upsert_grant,
    revoke_document_permission,
)
from backend.app.models.document import Document
from backend.app.models.grant import DocumentGrant
from backend.app.models.user import UserRole
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


def _seed_active_grant(pg_schema: PostgresTestSchema) -> tuple[str, str, str]:
    with pg_schema.session_factory() as session:
        owner = make_user(
            session,
            email="revoke-owner@example.com",
            password=VALID_PASSWORD,
            role=UserRole.OWNER,
        )
        recipient = make_user(
            session,
            email="revoke-recipient@example.com",
            password=VALID_PASSWORD,
            role=UserRole.VIEWER,
        )
        document = Document(
            title="Revoke Race",
            original_filename="revoke-race.pdf",
            storage_key=uuid.uuid4().hex,
            file_size_bytes=16,
            mime_type="application/pdf",
            category="General",
            owner_id=owner.id,
            is_deleted=False,
        )
        session.add(document)
        session.flush()
        _upsert_grant(
            session,
            document.id,
            recipient.id,
            "edit",
            owner.id,
            expected_revocation_version=None,
        )
        session.commit()
        return owner.id, recipient.id, document.id


def test_concurrent_grant_upserts_keep_one_row(
    pg_schema: PostgresTestSchema,
):
    with pg_schema.session_factory() as session:
        owner = make_user(
            session,
            email="grant-owner@example.com",
            password=VALID_PASSWORD,
            role=UserRole.OWNER,
        )
        recipient = make_user(
            session,
            email="grant-recipient@example.com",
            password=VALID_PASSWORD,
            role=UserRole.VIEWER,
        )
        document = Document(
            title="Concurrent Grant",
            original_filename="concurrent-grant.pdf",
            storage_key=uuid.uuid4().hex,
            file_size_bytes=16,
            mime_type="application/pdf",
            category="General",
            owner_id=owner.id,
            is_deleted=False,
        )
        session.add(document)
        session.commit()
        owner_id = owner.id
        recipient_id = recipient.id
        document_id = document.id

    barrier = threading.Barrier(2)

    def upsert(permission: str) -> str:
        with pg_schema.session_factory() as session:
            barrier.wait(timeout=30)
            _upsert_grant(
                session,
                document_id,
                recipient_id,
                permission,
                owner_id,
                expected_revocation_version=None,
            )
            session.commit()
            return permission

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(upsert, ["read", "edit"]))

    assert sorted(results) == ["edit", "read"]

    with pg_schema.session_factory() as session:
        assert (
            session.scalar(
                select(func.count(DocumentGrant.id)).where(
                    DocumentGrant.document_id == document_id,
                    DocumentGrant.user_id == recipient_id,
                )
            )
            == 1
        )
        grant = session.scalar(
            select(DocumentGrant).where(
                DocumentGrant.document_id == document_id,
                DocumentGrant.user_id == recipient_id,
            )
        )
        assert grant is not None
        assert grant.permission in {"read", "edit"}
        assert grant.is_revoked is False


def test_revoke_wins_when_grant_commits_after_concurrent_revoke(
    pg_schema: PostgresTestSchema,
):
    owner_id, recipient_id, document_id = _seed_active_grant(pg_schema)
    revoke_locked = threading.Event()
    grant_started = threading.Event()
    release_revoke = threading.Event()

    def revoke() -> None:
        with pg_schema.session_factory() as session:
            grant = session.scalar(
                select(DocumentGrant).where(
                    DocumentGrant.document_id == document_id,
                    DocumentGrant.user_id == recipient_id,
                    DocumentGrant.is_revoked.is_(False),
                )
            )
            assert grant is not None
            grant.is_revoked = True
            grant.revocation_version += 1
            session.flush()
            revoke_locked.set()
            assert grant_started.wait(timeout=10)
            assert release_revoke.wait(timeout=10)
            session.commit()

    def grant():
        with pg_schema.session_factory() as session:
            assert revoke_locked.wait(timeout=10)
            grant_started.set()
            outcome = _upsert_grant(
                session,
                document_id,
                recipient_id,
                "read",
                owner_id,
                expected_revocation_version=0,
            )
            result = (outcome.applied, outcome.grant.is_revoked)
            session.commit()
            return result

    with ThreadPoolExecutor(max_workers=2) as executor:
        revoke_future = executor.submit(revoke)
        grant_future = executor.submit(grant)
        assert grant_started.wait(timeout=10)
        release_revoke.set()
        revoke_future.result(timeout=30)
        applied, is_revoked = grant_future.result(timeout=30)

    assert applied is False
    assert is_revoked is True

    with pg_schema.session_factory() as session:
        grant = session.scalar(
            select(DocumentGrant).where(
                DocumentGrant.document_id == document_id,
                DocumentGrant.user_id == recipient_id,
            )
        )
        assert grant is not None
        assert grant.is_revoked is True
        assert grant.revocation_version == 1
        assert _get_active_grant(session, document_id, recipient_id) is None


def test_pre_revoke_grant_cannot_override_later_regrant(
    pg_schema: PostgresTestSchema,
):
    owner_id, recipient_id, document_id = _seed_active_grant(pg_schema)

    with pg_schema.session_factory() as session:
        grant = _get_grant(session, document_id, recipient_id)
        assert grant is not None
        grant.is_revoked = True
        grant.revocation_version += 1
        session.commit()

    with pg_schema.session_factory() as session:
        regrant = _upsert_grant(
            session,
            document_id,
            recipient_id,
            "read",
            owner_id,
            expected_revocation_version=1,
        )
        session.commit()
        assert regrant.applied is True
        assert regrant.grant.is_revoked is False

    with pg_schema.session_factory() as session:
        delayed = _upsert_grant(
            session,
            document_id,
            recipient_id,
            "edit",
            owner_id,
            expected_revocation_version=0,
        )
        session.commit()
        assert delayed.applied is False

    with pg_schema.session_factory() as session:
        active = _get_active_grant(session, document_id, recipient_id)
        assert active is not None
        assert active.permission == "read"
        assert active.is_revoked is False
        assert active.revocation_version == 1


def test_concurrent_revokes_advance_generation_for_each_revoke(
    pg_schema: PostgresTestSchema,
):
    owner_id, recipient_id, document_id = _seed_active_grant(pg_schema)
    barrier = threading.Barrier(2)
    request = SimpleNamespace(
        state=SimpleNamespace(
            client_ip="203.0.113.71",
            user_agent="pytest",
            request_id="req-concurrent-revoke",
        )
    )
    current_user = SimpleNamespace(
        id=owner_id,
        role=UserRole.OWNER,
        is_active=True,
    )
    original_get_active_grant = _get_active_grant

    def synced_get_active_grant(db, document_id, user_id):
        grant = original_get_active_grant(db, document_id, user_id)
        if user_id == recipient_id and grant is not None:
            barrier.wait(timeout=10)
        return grant

    def revoke():
        with pg_schema.session_factory() as session:
            return revoke_document_permission(
                document_id,
                recipient_id,
                request,
                current_user=current_user,
                db=session,
            )

    with (
        patch(
            "backend.app.api.documents._get_active_grant",
            new=synced_get_active_grant,
        ),
        ThreadPoolExecutor(max_workers=2) as executor,
    ):
        results = list(executor.map(lambda _: revoke(), range(2)))

    assert len(results) == 2

    with pg_schema.session_factory() as session:
        grant = _get_grant(session, document_id, recipient_id)
        assert grant is not None
        assert grant.is_revoked is True
        assert grant.revocation_version == 2
        assert _get_active_grant(session, document_id, recipient_id) is None
