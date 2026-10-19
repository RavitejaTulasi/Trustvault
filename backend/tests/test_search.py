"""
Day 5 Integration Tests for Secure Document Search, Filtering & Effective Permissions

Verifies authorized-scope search across title/filename, category/owner/date filters,
combined filters, validation failures, revocation exclusion, admin isolation, and
server-derived effective permissions.
"""

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.app.models.document import Document
from backend.app.models.user import UserRole
from backend.tests.test_auth import VALID_PASSWORD, make_user


async def _login(client: AsyncClient, email: str) -> None:
    await client.post("/api/v1/auth/logout")
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": VALID_PASSWORD},
    )
    assert resp.status_code == 200


async def _upload(
    client: AsyncClient,
    title: str,
    filename: str,
    category: str = "General",
) -> str:
    resp = await client.post(
        "/api/v1/documents",
        files={"file": (filename, b"%PDF-1.4 Test document bytes", "application/pdf")},
        data={"title": title, "category": category},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _list_documents(client: AsyncClient, **params) -> dict:
    resp = await client.get("/api/v1/documents", params=params)
    assert resp.status_code == 200, resp.text
    return resp.json()


def _set_created_at(db: Session, document_id: str, value: datetime) -> None:
    document = db.get(Document, document_id)
    assert document is not None
    document.created_at = value
    document.updated_at = value
    db.commit()


@pytest.mark.asyncio
async def test_search_matches_title_and_filename_case_insensitively(
    async_client: AsyncClient, db_session: Session
):
    """Search matches both title and original filename as a literal substring."""
    owner = make_user(
        db_session,
        email="owner_search_text@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    tax_id = await _upload(
        async_client,
        title="Quarterly Tax Report",
        filename="q3_tax.pdf",
        category="Financial",
    )
    trip_id = await _upload(
        async_client,
        title="Vacation Plans",
        filename="summer_trip.pdf",
        category="Personal",
    )

    by_title = await _list_documents(async_client, q="TAX")
    assert by_title["total"] == 1
    assert [doc["id"] for doc in by_title["documents"]] == [tax_id]

    by_filename = await _list_documents(async_client, q="SUMMER_TRIP")
    assert by_filename["total"] == 1
    assert [doc["id"] for doc in by_filename["documents"]] == [trip_id]

    literal_wildcard = await _list_documents(async_client, q="%")
    assert literal_wildcard["total"] == 0
    assert literal_wildcard["documents"] == []


@pytest.mark.asyncio
async def test_search_treats_sql_injection_and_wildcards_as_literal(
    async_client: AsyncClient, db_session: Session
):
    """SQL metacharacters are parameterized and LIKE wildcards are escaped."""
    owner = make_user(
        db_session,
        email="owner_search_injection@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    doc_id = await _upload(
        async_client,
        title="Confidential Strategy",
        filename="strategy.pdf",
        category="Executive",
    )

    injection = await _list_documents(async_client, q="' OR 1=1--")
    assert injection["total"] == 0
    assert injection["documents"] == []

    underscore = await _list_documents(async_client, q="_")
    assert underscore["total"] == 0

    normal = await _list_documents(async_client, q="Confidential")
    assert normal["total"] == 1
    assert normal["documents"][0]["id"] == doc_id


@pytest.mark.asyncio
async def test_category_filter_and_empty_results(async_client: AsyncClient, db_session: Session):
    """Category filtering is exact, and misses return an empty success response."""
    owner = make_user(
        db_session,
        email="owner_search_category@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    financial_id = await _upload(
        async_client, "Budget", "budget.pdf", category="Financial"
    )
    await _upload(async_client, "Contract", "contract.pdf", category="Legal")

    financial = await _list_documents(async_client, category="Financial")
    assert financial["total"] == 1
    assert [doc["id"] for doc in financial["documents"]] == [financial_id]

    missing = await _list_documents(async_client, category="Does Not Exist")
    assert missing["total"] == 0
    assert missing["documents"] == []

    beyond_last_page = await _list_documents(
        async_client, category="Financial", page=5, page_size=10
    )
    assert beyond_last_page["total"] == 1
    assert beyond_last_page["documents"] == []


@pytest.mark.asyncio
async def test_owner_filter_never_expands_visibility(async_client: AsyncClient, db_session: Session):
    """Filtering by another owner's ID cannot reveal that owner's documents."""
    owner_a = make_user(
        db_session,
        email="owner_filter_a@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    owner_b = make_user(
        db_session,
        email="owner_filter_b@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()

    await _login(async_client, owner_b.email)
    owner_b_doc_id = await _upload(
        async_client, "Owner B Private", "owner_b_private.pdf", category="Private"
    )

    await _login(async_client, owner_a.email)
    owner_a_doc_id = await _upload(
        async_client, "Owner A Private", "owner_a_private.pdf", category="Private"
    )

    other_owner = await _list_documents(async_client, owner_id=owner_b.id)
    assert other_owner["total"] == 0
    assert other_owner["documents"] == []

    other_owner_with_query = await _list_documents(
        async_client, owner_id=owner_b.id, q="Owner B"
    )
    assert other_owner_with_query["total"] == 0
    assert owner_b_doc_id not in {
        doc["id"] for doc in other_owner_with_query["documents"]
    }

    own_docs = await _list_documents(async_client, owner_id=owner_a.id)
    assert own_docs["total"] == 1
    assert [doc["id"] for doc in own_docs["documents"]] == [owner_a_doc_id]


@pytest.mark.asyncio
async def test_created_date_range_and_invalid_ranges(async_client: AsyncClient, db_session: Session):
    """Created-at ranges are inclusive and invalid or malformed ranges are rejected."""
    owner = make_user(
        db_session,
        email="owner_search_dates@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    early_id = await _upload(async_client, "January Doc", "january.pdf")
    late_id = await _upload(async_client, "February Doc", "february.pdf")
    _set_created_at(db_session, early_id, datetime(2026, 1, 10, 12, 0, tzinfo=UTC))
    _set_created_at(db_session, late_id, datetime(2026, 2, 10, 12, 0, tzinfo=UTC))

    first_page = await _list_documents(async_client, page=1, page_size=1)
    assert first_page["total"] == 2
    assert [doc["id"] for doc in first_page["documents"]] == [late_id]

    second_page = await _list_documents(async_client, page=2, page_size=1)
    assert second_page["total"] == 2
    assert [doc["id"] for doc in second_page["documents"]] == [early_id]

    february = await _list_documents(
        async_client,
        created_from="2026-02-01T00:00:00Z",
        created_to="2026-02-28T23:59:59Z",
    )
    assert february["total"] == 1
    assert [doc["id"] for doc in february["documents"]] == [late_id]

    january = await _list_documents(
        async_client,
        created_from="2026-01-01",
        created_to="2026-01-31",
    )
    assert january["total"] == 1
    assert [doc["id"] for doc in january["documents"]] == [early_id]

    invalid_range = await async_client.get(
        "/api/v1/documents",
        params={
            "created_from": "2026-03-01T00:00:00Z",
            "created_to": "2026-02-01T00:00:00Z",
        },
    )
    assert invalid_range.status_code == 422

    malformed_date = await async_client.get(
        "/api/v1/documents", params={"created_from": "not-a-date"}
    )
    assert malformed_date.status_code == 422


@pytest.mark.asyncio
async def test_multiple_filters_combine(async_client: AsyncClient, db_session: Session):
    """Search, category, owner, and date filters are combined with AND semantics."""
    owner = make_user(
        db_session,
        email="owner_search_combined@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    target_id = await _upload(
        async_client, "Q3 Tax Report", "q3_tax_report.pdf", category="Financial"
    )
    february_id = await _upload(
        async_client, "Q3 Tax Draft", "q3_tax_draft.pdf", category="Financial"
    )
    legal_id = await _upload(
        async_client, "Q3 Legal Report", "q3_legal_report.pdf", category="Legal"
    )
    _set_created_at(db_session, target_id, datetime(2026, 1, 15, 12, 0, tzinfo=UTC))
    _set_created_at(db_session, february_id, datetime(2026, 2, 15, 12, 0, tzinfo=UTC))
    _set_created_at(db_session, legal_id, datetime(2026, 1, 15, 12, 0, tzinfo=UTC))

    combined = await _list_documents(
        async_client,
        q="tax",
        category="Financial",
        owner_id=owner.id,
        created_from="2026-01-01T00:00:00Z",
        created_to="2026-01-31T23:59:59Z",
    )
    assert combined["total"] == 1
    assert [doc["id"] for doc in combined["documents"]] == [target_id]
    assert combined["documents"][0]["effective_permission"] == "owner"


@pytest.mark.asyncio
async def test_effective_permissions_for_owner_editor_and_reader(
    async_client: AsyncClient, db_session: Session
):
    """Effective permission is server-derived as owner, edit, or read for visible docs."""
    owner = make_user(
        db_session,
        email="owner_search_effective@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    editor = make_user(
        db_session,
        email="editor_search_effective@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
    )
    reader = make_user(
        db_session,
        email="reader_search_effective@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
    )
    admin = make_user(
        db_session,
        email="admin_search_effective@example.com",
        password=VALID_PASSWORD,
        role=UserRole.ADMIN,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    doc_id = await _upload(
        async_client, "Shared Visibility", "shared_visibility.pdf", category="Shared"
    )
    assert (
        await async_client.post(
            f"/api/v1/documents/{doc_id}/permissions",
            json={"user_id": reader.id, "permission": "read"},
        )
    ).status_code == 201
    assert (
        await async_client.post(
            f"/api/v1/documents/{doc_id}/permissions",
            json={"user_id": editor.id, "permission": "edit"},
        )
    ).status_code == 201

    expected = {
        owner.email: "owner",
        editor.email: "edit",
        reader.email: "read",
    }
    for email, permission in expected.items():
        await _login(async_client, email)
        results = await _list_documents(async_client, q="Shared Visibility")
        assert results["total"] == 1
        assert results["documents"][0]["id"] == doc_id
        assert results["documents"][0]["effective_permission"] == permission

    await _login(async_client, reader.email)
    spoofed = await _list_documents(
        async_client, q="Shared Visibility", effective_permission="owner"
    )
    assert spoofed["documents"][0]["effective_permission"] == "read"

    await _login(async_client, admin.email)
    admin_results = await _list_documents(async_client, q="Shared Visibility")
    assert admin_results["total"] == 0
    assert admin_results["documents"] == []


@pytest.mark.asyncio
async def test_search_excludes_revoked_grants_and_deleted_documents(
    async_client: AsyncClient, db_session: Session
):
    """Revoked grants immediately remove documents from search; deleted docs are excluded."""
    owner = make_user(
        db_session,
        email="owner_search_revoked@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    reader = make_user(
        db_session,
        email="reader_search_revoked@example.com",
        password=VALID_PASSWORD,
        role=UserRole.VIEWER,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    doc_id = await _upload(
        async_client, "Revocation Search", "revocation_search.pdf"
    )
    assert (
        await async_client.post(
            f"/api/v1/documents/{doc_id}/permissions",
            json={"user_id": reader.id, "permission": "read"},
        )
    ).status_code == 201

    await _login(async_client, reader.email)
    before = await _list_documents(async_client, q="Revocation Search")
    assert before["total"] == 1
    assert before["documents"][0]["effective_permission"] == "read"

    await _login(async_client, owner.email)
    assert (
        await async_client.delete(
            f"/api/v1/documents/{doc_id}/permissions/{reader.id}"
        )
    ).status_code == 200

    await _login(async_client, reader.email)
    after_revoke = await _list_documents(async_client, q="Revocation Search")
    assert after_revoke["total"] == 0
    assert after_revoke["documents"] == []
    assert (await async_client.get(f"/api/v1/documents/{doc_id}")).status_code == 404

    await _login(async_client, owner.email)
    assert (await async_client.delete(f"/api/v1/documents/{doc_id}")).status_code == 204
    after_delete = await _list_documents(async_client, q="Revocation Search")
    assert after_delete["total"] == 0
    assert after_delete["documents"] == []


@pytest.mark.asyncio
async def test_admin_search_scope_includes_only_owned_and_granted(
    async_client: AsyncClient, db_session: Session
):
    """Admin search/filtering never widens visibility beyond ownership or active grants."""
    owner = make_user(
        db_session,
        email="owner_search_admin@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    admin = make_user(
        db_session,
        email="admin_search_admin@example.com",
        password=VALID_PASSWORD,
        role=UserRole.ADMIN,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    hidden_id = await _upload(
        async_client, "Admin Hidden", "admin_hidden.pdf", category="Private"
    )
    shared_id = await _upload(
        async_client, "Admin Shared", "admin_shared.pdf", category="Shared"
    )
    assert (
        await async_client.post(
            f"/api/v1/documents/{shared_id}/permissions",
            json={"user_id": admin.id, "permission": "read"},
        )
    ).status_code == 201

    await _login(async_client, admin.email)
    admin_owned_id = await _upload(
        async_client, "Admin Owned", "admin_owned.pdf", category="Private"
    )

    results = await _list_documents(async_client, q="Admin")
    assert results["total"] == 2
    by_id = {doc["id"]: doc for doc in results["documents"]}
    assert set(by_id) == {admin_owned_id, shared_id}
    assert hidden_id not in by_id
    assert by_id[admin_owned_id]["effective_permission"] == "owner"
    assert by_id[shared_id]["effective_permission"] == "read"

    hidden_filter = await _list_documents(
        async_client, owner_id=owner.id, q="Admin Hidden"
    )
    assert hidden_filter["total"] == 0
    assert hidden_filter["documents"] == []


@pytest.mark.asyncio
async def test_invalid_query_parameters_and_empty_search(
    async_client: AsyncClient, db_session: Session
):
    """Malformed filters return 422 and non-matching searches return an empty page."""
    owner = make_user(
        db_session,
        email="owner_search_validation@example.com",
        password=VALID_PASSWORD,
        role=UserRole.OWNER,
    )
    db_session.commit()

    await _login(async_client, owner.email)
    await _upload(async_client, "Validation Doc", "validation.pdf", category="General")

    malformed_requests = [
        {"page": 0},
        {"page_size": 0},
        {"page_size": 101},
        {"page": "not-an-integer"},
        {"q": ""},
        {"q": "   "},
        {"q": "a" * 256},
        {"owner_id": ""},
        {"category": ""},
        {"category": "a" * 101},
    ]
    for params in malformed_requests:
        resp = await async_client.get("/api/v1/documents", params=params)
        assert resp.status_code == 422, params

    empty = await _list_documents(async_client, q="no-such-document")
    assert empty["total"] == 0
    assert empty["documents"] == []
    assert empty["page"] == 1
    assert empty["page_size"] == 25
