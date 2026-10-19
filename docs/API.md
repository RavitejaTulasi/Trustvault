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
- `403 Forbidden`: Authenticated identity lacks necessary role or document permission.
- `404 Not Found`: Deliberate 404 returned for unshared documents to prevent existence discovery, or non-existent endpoint.
- `413 Payload Too Large`: Upload exceeds maximum allowed file size (10MB).
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
    "role": "owner"
  }
  ```
- **Cookies Set**:
  - `trustvault_session`: HttpOnly, SameSite=Lax, Secure (in production).
  - `trustvault_csrf`: SameSite=Lax (readable by frontend for inclusion in `X-CSRF-Token` headers).
- **Audit Event**: `auth.login.success` or `auth.login.failure`

### `POST /api/v1/auth/logout`
- **Authentication**: Required (`SessionCookie`)
- **Action**: Revokes session in database, clears session cookies.
- **Response `200 OK`**: `{"detail": "Logged out successfully"}`
- **Audit Event**: `auth.logout`

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
    "created_at": "2026-10-19T10:00:00.000000Z"
  }
  ```
- **Audit Event**: `document.upload`

### `GET /api/v1/documents`
- **Authentication**: Required
- **Authorization Rule**: Returns only documents owned by user OR documents where user has an active, non-revoked grant.
- **Response `200 OK`**: List of document summaries with user's effective permission (`owner`, `edit`, or `read`).

### `GET /api/v1/documents/search`
- **Authentication**: Required
- **Query Parameters**: `q` (name/title search), `owner`, `category`, `date_from`, `date_to`.
- **Authorization Rule**: Database query joins on ownership and active grant table. Zero inaccessible documents or metadata returned.

### `GET /api/v1/documents/{id}`
- **Authentication**: Required
- **Authorization Rule**: Must be owner or have active grant. Unauthorized callers receive `404 Not Found` (or `403 Forbidden`).
- **Response `200 OK`**: Full document metadata and version history.
- **Audit Event**: `document.read` or `document.access.denied`

### `GET /api/v1/documents/{id}/download`
- **Authentication**: Required
- **Authorization Rule**: Must be owner or have active grant with `read` or `edit`.
- **Response `200 OK`**: Binary byte stream with `Content-Disposition: attachment; filename="..."`.
- **Audit Event**: `document.download` (Outcome: SUCCESS or DENIED)

### `PATCH /api/v1/documents/{id}`
- **Authentication**: Required
- **Authorization Rule**: Owner or active grant with `edit`.
- **Request Body**: Editable metadata (title, category) or replacement file stream.
- **Audit Event**: `document.edit`

### `DELETE /api/v1/documents/{id}`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY. Viewers and editors cannot delete documents.
- **Response `200 OK`**: `{"detail": "Document successfully deleted"}`
- **Audit Event**: `document.delete`

---

## 3. Permission & Sharing Endpoints

### `GET /api/v1/documents/{id}/permissions`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY.
- **Response `200 OK`**: List of named users and active/revoked grant status.

### `POST /api/v1/documents/{id}/permissions`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY.
- **Request Body**:
  ```json
  {
    "user_id": "u_recipient_123",
    "permission": "read"
  }
  ```
- **Audit Event**: `permission.grant`

### `DELETE /api/v1/documents/{id}/permissions/{user_id}`
- **Authentication**: Required
- **Authorization Rule**: Document Owner ONLY.
- **Action**: Immediately sets `is_revoked = True` in current database transaction.
- **Response `200 OK`**: `{"detail": "Permission successfully revoked"}`
- **Audit Event**: `permission.revoke`

---

## 4. Administration Endpoints

### `GET /api/v1/admin/audit`
- **Authentication**: Required
- **Role Requirement**: Administrator ONLY (`UserRole.ADMIN`).
- **Query Parameters**: `limit`, `offset`, `actor_id`, `action`, `outcome`, `start_date`, `end_date`.
- **Response `200 OK`**: Chronological audit trail with hash-chain verification status.
- **Audit Event**: `admin.audit.query`

### `GET /api/v1/admin/documents/activity`
- **Authentication**: Required
- **Role Requirement**: Administrator ONLY (`UserRole.ADMIN`).
- **Response `200 OK`**: Document lifecycle events (uploads, deletions, sharing volume) across system without exposing file contents.
