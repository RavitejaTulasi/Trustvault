# TrustVault — REST API Specification

This document details the complete API contract for TrustVault, including authentication requirements, role restrictions, authorization policies, validation rules, and error codes.

---

## Standard Response Standards & Error Conventions

### Status Codes
- `200 OK`: Request succeeded.
- `201 Created`: Resource successfully created.
- `204 No Content`: Resource successfully deleted or updated without body response.
- `400 Bad Request`: Validation failure, invalid payload, or malformed parameter.
- `401 Unauthorized`: Authentication required or invalid/expired session cookie.
- `403 Forbidden`: Authenticated identity lacks the required platform role (for example, an admin-only endpoint).
- `404 Not Found`: Deliberate 404 returned for inaccessible or non-existent documents to prevent existence discovery, or a non-existent endpoint/resource.
- `413 Payload Too Large`: Upload exceeds maximum allowed file size (10MB).
- `422 Unprocessable Entity`: Malformed query parameter, invalid filter value, or invalid date range.
- `429 Too Many Requests`: Rate limit exceeded (e.g. login brute-force throttle).
- `503 Service Unavailable`: Database or storage health failure.

### Security Headers on Every Response
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-Request-ID: <uuid>`

---

## 1. Authentication Endpoints

### `POST /api/v1/auth/login`
- **Authentication**: None (Public)
- **Rate Limit**: 5 attempts per 5 minutes per IP/email.
- **Request Body**:
  ```json
  {
    "email": "user@trustvault.local",
    "password": "SecurePassword123!"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "id": "u_984f1b...",
    "email": "user@trustvault.local",
    "full_name": "Alice Smith",
    "role": "owner",
    "is_active": true,
    "created_at": "2026-10-19T10:00:00.000000Z",
    "updated_at": "2026-10-19T10:00:00.000000Z"
  }
  ```
- **Cookies Set**:
  - `trustvault_session`: HttpOnly, SameSite=Lax, Secure (in production).
  - `trustvault_csrf`: SameSite=Lax (readable by frontend for inclusion in `X-CSRF-Token` headers).
- **Audit Events**: `user.login`, `user.login_failed`, or `user.login_rate_limited`

### `POST /api/v1/auth/logout`
- **Authentication**: Required (`SessionCookie`)
- **Action**: Revokes session in database, clears session cookies.
- **Response `204 No Content`**: Empty body.
- **Audit Event**: `user.logout`

### `GET /api/v1/auth/me`
- **Authentication**: Required
- **Response `200 OK`**: Current user profile and assigned role.

---

## 2. Document Endpoints

### `POST /api/v1/documents`
- **Authentication**: Required
- **Role Requirement**: Document Owner or Admin (Viewers receive `403 Forbidden`)
- **Content-Type**: `multipart/form-data`
- **Parameters**:
  - `file`: UploadFile (binary, max 10MB, validated extension & magic bytes)
  - `title`: string (1-255 chars)
  - `category`: string (optional, default: "General")
- **Response `201 Created`**:
  ```json
  {
    "id": "doc_a1b2c3...",
    "title": "Quarterly Financial Audit",
    "original_filename": "q3_audit.pdf",
    "file_size_bytes": 1048576,
    "mime_type": "application/pdf",
    "category": "Financial",
    "owner_id": "u_984f1b...",
    "is_deleted": false,
    "created_at": "2026-10-19T10:00:00.000000Z",
    "updated_at": "2026-10-19T10:00:00.000000Z"
  }
  ```
- **Audit Event**: `document.upload`

### `GET /api/v1/documents`
- **Authentication**: Required
- **Authorization Rule**: Returns only documents owned by the caller OR documents where the caller has an active, non-revoked grant. This scope is applied before any search or filter and applies equally to administrators; admin role alone does not expose other users' document metadata.
- **Query Parameters**:
  - `page`: integer, minimum 1 (default: 1).
  - `page_size`: integer, 1-100 (default: 25).
  - `q`: optional string, 1-255 characters. Case-insensitive literal substring match against `title` and `original_filename`. SQL LIKE wildcards (`%`, `_`) are escaped and matched literally.
  - `category`: optional string, 1-100 characters. Exact category match.
  - `owner_id`: optional string, 1-64 characters. Exact owner ID match, evaluated inside the caller's authorized scope. Filtering by another user's ID returns only the caller's visible matches (normally an empty result); it cannot expand access.
  - `created_from`: optional ISO-8601 datetime. Inclusive lower bound on `created_at`. Naive datetimes are interpreted as UTC; timezone offsets are normalized to UTC.
  - `created_to`: optional ISO-8601 datetime. Inclusive upper bound on `created_at`. Naive datetimes are interpreted as UTC; timezone offsets are normalized to UTC.
- **Validation**: Invalid pagination, blank/oversized string filters, malformed datetimes, or `created_from > created_to` return `422 Unprocessable Entity`.
- **Sorting**: `created_at` descending. Pagination and sorting match the previous list behavior.
- **Response `200 OK`**:
  ```json
  {
    "documents": [
      {
        "id": "doc_a1b2c3...",
        "title": "Quarterly Financial Audit",
        "original_filename": "q3_audit.pdf",
        "file_size_bytes": 1048576,
        "mime_type": "application/pdf",
        "category": "Financial",
        "owner_id": "u_984f1b...",
        "is_deleted": false,
        "created_at": "2026-10-19T10:00:00.000000Z",
        "updated_at": "2026-10-19T10:00:00.000000Z",
        "effective_permission": "owner"
      }
    ],
    "total": 1,
    "page": 1,
    "page_size": 25
  }
  ```
- **Effective Permission**: Calculated server-side from the current database state for each visible document: `owner` (caller owns it), `edit` (active edit grant), or `read` (active read grant). It is never accepted from the client. Revoked grants are excluded.
- **Notes**: Search and filtering are provided by this endpoint; there is no separate `/documents/search` route.

### `GET /api/v1/documents/{id}`
- **Authentication**: Required
- **Authorization Rule**: Must be owner or have an active grant. All other callers receive `404 Not Found`.
- **Response `200 OK`**: Document metadata (no version-history field is exposed by the current schema).
- **Audit Event**: `document.read` (Outcome: SUCCESS or DENIED)

### `GET /api/v1/documents/{id}/download`
- **Authentication**: Required
- **Authorization Rule**: Must be owner or have active grant with `read` or `edit`.
- **Response `200 OK`**: Binary byte stream with `Content-Disposition: attachment; filename="..."`.
- **Audit Event**: `document.download` (Outcome: SUCCESS or DENIED)

### `PATCH /api/v1/documents/{id}`
- **Authentication**: Required
- **Authorization Rule**: Owner or active grant with `edit`. Other callers receive `404 Not Found`.
- **Request Body**: Editable metadata only (`title`, `category`). Replacement-file upload is **not implemented** on this endpoint.
- **Response `200 OK`**: Updated document metadata.
- **Audit Event**: `document.edit` (SUCCESS when fields change; DENIED on unauthorized attempts)

### `DELETE /api/v1/documents/{id}`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY. Viewers, editors, and administrators cannot delete another user's document.
- **Response `204 No Content`**: Empty body; the document is soft-deleted and the physical file is removed.
- **Audit Event**: `document.delete` (Outcome: SUCCESS or DENIED)

---

## 3. Permission & Sharing Endpoints

### `GET /api/v1/documents/{id}/permissions`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY. Non-owners (including active grantees) receive `404 Not Found` to avoid disclosing sharing relationships.
- **Response `200 OK`**:
  ```json
  {
    "grants": [
      {
        "id": "gr_5c9d...",
        "document_id": "doc_a1b2c3...",
        "user_id": "u_recipient_123",
        "permission": "read",
        "granted_by_id": "u_owner_456",
        "is_revoked": false,
        "created_at": "2026-10-19T10:00:00.000000Z",
        "updated_at": "2026-10-19T10:00:00.000000Z"
      }
    ]
  }
  ```
- **Notes**: Includes revoked grants so owners can see historical sharing state.
- **Audit Event**: `permission.list_denied` on unauthorized attempts.

### `POST /api/v1/documents/{id}/permissions`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY. Non-owners receive `404 Not Found`.
- **Request Body**:
  ```json
  {
    "user_id": "u_recipient_123",
    "permission": "read"
  }
  ```
- **Validation**: `permission` must be `read` or `edit`; recipient must exist and be active; granting to the owner is rejected with `400 Bad Request`.
- **Upsert Semantics**: Re-granting to a previously revoked user reactivates the existing grant row, updates `granted_by_id`/`permission`, and clears `is_revoked`. The write uses the database `(document_id, user_id)` unique constraint with `ON CONFLICT DO UPDATE` on SQLite and PostgreSQL, so duplicate/concurrent requests leave exactly one grant row and apply the latest requested permission.
- **Response `201 Created`**: Grant representation (same shape as list items).
- **Audit Event**: `permission.grant` (Outcome: SUCCESS or DENIED)

### `DELETE /api/v1/documents/{id}/permissions/{user_id}`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY. Non-owners receive `404 Not Found`.
- **Action**: Immediately sets `is_revoked = True` in the current database transaction. There are no cached tokens or pre-signed URLs, so the very next request from the recipient is denied.
- **Response `200 OK`**: `{"detail": "Permission successfully revoked"}`
- **Error**: `404 Not Found` when no active grant exists for that recipient.
- **Audit Event**: `permission.revoke` (Outcome: SUCCESS or DENIED)

---

## 4. Administration Endpoints

All endpoints in this section require the Administrator role (`UserRole.ADMIN`).

### `GET /api/v1/admin/users`
- **Authentication**: Required
- **Query Parameters**: `page`, `page_size`
- **Response `200 OK`**: Paginated user list (`users`, `total`, `page`, `page_size`).

### `GET /api/v1/admin/users/{user_id}`
- **Authentication**: Required
- **Response `200 OK`**: User profile.
- **Error**: `404 Not Found` for an unknown user.

### `PATCH /api/v1/admin/users/{user_id}`
- **Authentication**: Required
- **Request Body**: `role` (`admin`, `owner`, or `viewer`) and/or `is_active`.
- **Response `200 OK`**: Updated user profile.
- **Errors**: `400 Bad Request` when an administrator attempts to remove their own admin role; `404 Not Found` for an unknown user.
- **Audit Events**: `user.role_change`, `user.deactivate`, or `user.reactivate`

### `POST /api/v1/admin/users/{user_id}/revoke-sessions`
- **Authentication**: Required
- **Action**: Immediately invalidates all active sessions for the target user.
- **Response `200 OK`**: `{"user_id": "...", "sessions_revoked": N}`
- **Audit Event**: `user.sessions_revoked`

### `GET /api/v1/admin/audit` — Planned (not implemented)
- **Status**: Planned for a later milestone. System-wide audit records continue to be written to the tamper-evident audit store; a read-only admin query API is not registered in the current build.

### `GET /api/v1/admin/documents/activity` — Planned (not implemented)
- **Status**: Planned for a later milestone. Document lifecycle events remain available in the audit store without exposing file contents; no HTTP activity endpoint is registered in the current build.
