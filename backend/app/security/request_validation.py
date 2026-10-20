"""Validation for client-controlled values persisted in database columns."""

import ipaddress
import re

from fastapi import status

from backend.app.limits import (
    MAX_IP_ADDRESS_LENGTH,
    MAX_MIME_TYPE_LENGTH,
    MAX_ORIGINAL_FILENAME_LENGTH,
    MAX_REQUEST_ID_LENGTH,
    MAX_USER_AGENT_LENGTH,
)

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_MIME_TYPE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/"
    r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$"
)


class RequestMetadataValidationError(ValueError):
    """A client-controlled value cannot be persisted without ambiguity."""

    def __init__(self, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def _contains_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def validate_request_id(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    if len(value) > MAX_REQUEST_ID_LENGTH:
        raise RequestMetadataValidationError(
            f"X-Request-ID must be at most {MAX_REQUEST_ID_LENGTH} characters"
        )
    if not _REQUEST_ID_PATTERN.fullmatch(value):
        raise RequestMetadataValidationError(
            "X-Request-ID contains unsupported characters",
        )
    return value


def validate_user_agent(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    if len(value) > MAX_USER_AGENT_LENGTH:
        raise RequestMetadataValidationError(
            f"User-Agent must be at most {MAX_USER_AGENT_LENGTH} characters",
            status_code=status.HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE,
        )
    if _contains_control_characters(value):
        raise RequestMetadataValidationError(
            "User-Agent contains control characters",
            status_code=status.HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE,
        )
    return value


def validate_ip_address(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    candidate = value.strip()
    if len(candidate) > MAX_IP_ADDRESS_LENGTH:
        raise RequestMetadataValidationError("Client IP address is too long")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise RequestMetadataValidationError("Client IP address is invalid") from exc


def validate_original_filename(value: str | None) -> str:
    if not value:
        raise RequestMetadataValidationError("No filename provided")
    if len(value) > MAX_ORIGINAL_FILENAME_LENGTH:
        raise RequestMetadataValidationError(
            f"Filename must be at most {MAX_ORIGINAL_FILENAME_LENGTH} characters"
        )
    if _contains_control_characters(value):
        raise RequestMetadataValidationError(
            "Filename contains control characters"
        )
    if "/" in value or "\\" in value:
        raise RequestMetadataValidationError(
            "Filename must not contain path separators"
        )
    if value in {".", ".."} or value != value.strip():
        raise RequestMetadataValidationError("Filename is invalid")
    return value


def validate_mime_type(value: str | None) -> str:
    candidate = (value or "application/octet-stream").strip()
    if len(candidate) > MAX_MIME_TYPE_LENGTH:
        raise RequestMetadataValidationError(
            f"Content-Type must be at most {MAX_MIME_TYPE_LENGTH} characters"
        )
    if not _MIME_TYPE_PATTERN.fullmatch(candidate):
        raise RequestMetadataValidationError("Content-Type is invalid")
    return candidate
