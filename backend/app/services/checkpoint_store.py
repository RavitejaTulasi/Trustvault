"""HMAC-protected local storage for audit-chain checkpoints."""

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, Engine, make_url
from sqlalchemy.exc import SQLAlchemyError

CHECKPOINT_FORMAT_VERSION = 1
AUDIT_STREAM_ID = "trustvault.audit"
GENESIS_CHECKPOINT_SEQUENCE = 0
_HEX_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CHECKPOINT_FILENAME_PATTERN = re.compile(r"^checkpoint-(\d{20})\.json$")
_MIN_HMAC_KEY_BYTES = 32
_MAX_CHECKPOINT_DOCUMENT_BYTES = 64 * 1024
_ANCHOR_CONNECT_TIMEOUT_SECONDS = 5
_ANCHOR_POOL_TIMEOUT_SECONDS = 5
_ANCHOR_STATEMENT_TIMEOUT_MILLISECONDS = 10_000


class CheckpointError(Exception):
    """Base class for audit checkpoint errors."""


class CheckpointStoreUnavailableError(CheckpointError):
    """The checkpoint store is not configured or cannot be reached."""


class CheckpointIntegrityError(CheckpointError):
    """A stored checkpoint failed validation or its integrity tag."""


class CheckpointConflictError(CheckpointError):
    """A checkpoint conflicts with the stored checkpoint history."""


class CheckpointRollbackError(CheckpointError):
    """A checkpoint would move the stored checkpoint sequence backwards."""


@dataclass(frozen=True)
class AuditCheckpoint:
    """One immutable checkpoint over a verified audit-chain prefix."""

    format_version: int
    stream_id: str
    sequence_number: int
    record_hash: str
    created_at: datetime
    previous_checkpoint_hmac: str | None = None
    integrity_tag: str | None = None


class CheckpointStore(Protocol):
    """Interface implemented by the configured checkpoint store."""

    def close(self) -> None:
        """Release resources held by the adapter."""

    def read_latest(self) -> AuditCheckpoint | None:
        """Return the highest-sequence checkpoint, or None when none exists."""

    def write_checkpoint(self, checkpoint: AuditCheckpoint) -> tuple[AuditCheckpoint, bool]:
        """
        Persist a checkpoint using compare-and-swap semantics.

        Returns (stored_checkpoint, created). Idempotent retries of an existing
        sequence/hash pair return the stored checkpoint with created=False.
        Conflicting or backwards writes raise CheckpointConflictError or
        CheckpointRollbackError.
        """


class UnavailableCheckpointStore:
    """
    Fail-closed placeholder used when no checkpoint adapter is configured.

    It is not an anchor: every operation raises so callers cannot accidentally
    treat disabled anchoring as a verified checkpoint.
    """

    def close(self) -> None:
        """The unavailable adapter has no resources to release."""

    def read_latest(self) -> AuditCheckpoint | None:
        raise CheckpointStoreUnavailableError("Audit checkpoint anchoring is not configured")

    def write_checkpoint(self, checkpoint: AuditCheckpoint) -> tuple[AuditCheckpoint, bool]:
        raise CheckpointStoreUnavailableError("Audit checkpoint anchoring is not configured")


def format_checkpoint_timestamp(value: datetime) -> str:
    """Canonical UTC timestamp representation used inside the HMAC payload."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    else:
        value = value.astimezone(UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_checkpoint_payload(payload: dict) -> bytes:
    """Serialize a checkpoint payload deterministically for HMAC computation."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_checkpoint_payload(checkpoint: AuditCheckpoint) -> dict:
    """Build the canonical HMAC payload for a checkpoint."""
    return {
        "format_version": checkpoint.format_version,
        "stream_id": checkpoint.stream_id,
        "sequence_number": checkpoint.sequence_number,
        "record_hash": checkpoint.record_hash,
        "created_at": format_checkpoint_timestamp(checkpoint.created_at),
        "previous_checkpoint_hmac": checkpoint.previous_checkpoint_hmac,
    }


def compute_checkpoint_tag(hmac_key: bytes, payload: dict) -> str:
    """Compute the HMAC-SHA256 integrity tag over a canonical checkpoint payload."""
    return hmac.new(hmac_key, canonical_checkpoint_payload(payload), hashlib.sha256).hexdigest()


def serialize_checkpoint(hmac_key: bytes, checkpoint: AuditCheckpoint) -> str:
    """Serialize a checkpoint into the stored JSON document format."""
    payload = build_checkpoint_payload(checkpoint)
    document = {"payload": payload, "hmac": compute_checkpoint_tag(hmac_key, payload)}
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def validate_checkpoint_payload(payload: dict) -> AuditCheckpoint:
    """Validate a payload that has already passed HMAC verification."""
    try:
        format_version = payload["format_version"]
        stream_id = payload["stream_id"]
        sequence_number = payload["sequence_number"]
        record_hash = payload["record_hash"]
        created_at_raw = payload["created_at"]
        previous_checkpoint_hmac = payload.get("previous_checkpoint_hmac")
    except KeyError as exc:
        raise CheckpointIntegrityError("Stored checkpoint is missing required fields") from exc

    if not isinstance(format_version, int) or isinstance(format_version, bool):
        raise CheckpointIntegrityError("Stored checkpoint has an invalid format version")
    if not isinstance(stream_id, str) or not stream_id:
        raise CheckpointIntegrityError("Stored checkpoint has an invalid stream identifier")
    if (
        not isinstance(sequence_number, int)
        or isinstance(sequence_number, bool)
        or sequence_number < GENESIS_CHECKPOINT_SEQUENCE
    ):
        raise CheckpointIntegrityError("Stored checkpoint has an invalid sequence number")
    if not isinstance(record_hash, str) or _HEX_HASH_PATTERN.fullmatch(record_hash) is None:
        raise CheckpointIntegrityError("Stored checkpoint has an invalid record hash")
    if (
        previous_checkpoint_hmac is not None
        and (
            not isinstance(previous_checkpoint_hmac, str)
            or _HEX_HASH_PATTERN.fullmatch(previous_checkpoint_hmac) is None
        )
    ):
        raise CheckpointIntegrityError("Stored checkpoint has an invalid preceding link")
    if not isinstance(created_at_raw, str):
        raise CheckpointIntegrityError("Stored checkpoint has an invalid creation timestamp")
    try:
        created_at = datetime.fromisoformat(created_at_raw)
    except ValueError as exc:
        raise CheckpointIntegrityError(
            "Stored checkpoint has an invalid creation timestamp"
        ) from exc
    if created_at.tzinfo is None:
        raise CheckpointIntegrityError("Stored checkpoint timestamp must include a timezone")

    return AuditCheckpoint(
        format_version=format_version,
        stream_id=stream_id,
        sequence_number=sequence_number,
        record_hash=record_hash,
        created_at=created_at.astimezone(UTC),
        previous_checkpoint_hmac=previous_checkpoint_hmac,
    )


def parse_checkpoint_document(hmac_key: bytes, raw: bytes | str) -> AuditCheckpoint:
    """Parse and integrity-verify a stored checkpoint document."""
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > _MAX_CHECKPOINT_DOCUMENT_BYTES:
            raise CheckpointIntegrityError("Stored checkpoint exceeds the size limit")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CheckpointIntegrityError("Stored checkpoint could not be decoded") from exc
    elif len(raw) > _MAX_CHECKPOINT_DOCUMENT_BYTES:
        raise CheckpointIntegrityError("Stored checkpoint exceeds the size limit")

    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise CheckpointIntegrityError("Stored checkpoint could not be read") from exc

    if not isinstance(document, dict):
        raise CheckpointIntegrityError("Stored checkpoint has an invalid document shape")
    payload = document.get("payload")
    stored_tag = document.get("hmac")
    if not isinstance(payload, dict) or not isinstance(stored_tag, str):
        raise CheckpointIntegrityError("Stored checkpoint has an invalid document shape")

    expected_tag = compute_checkpoint_tag(hmac_key, payload)
    if not hmac.compare_digest(expected_tag, stored_tag):
        raise CheckpointIntegrityError("Stored checkpoint failed its integrity check")

    checkpoint = validate_checkpoint_payload(payload)
    return AuditCheckpoint(
        format_version=checkpoint.format_version,
        stream_id=checkpoint.stream_id,
        sequence_number=checkpoint.sequence_number,
        record_hash=checkpoint.record_hash,
        created_at=checkpoint.created_at,
        previous_checkpoint_hmac=checkpoint.previous_checkpoint_hmac,
        integrity_tag=stored_tag,
    )


def validate_new_checkpoint(checkpoint: AuditCheckpoint, *, stream_id: str) -> None:
    """Validate a checkpoint that is about to be written to a store."""
    if checkpoint.format_version != CHECKPOINT_FORMAT_VERSION:
        raise CheckpointConflictError("Unsupported checkpoint format version")
    if checkpoint.stream_id != stream_id:
        raise CheckpointConflictError("Checkpoint stream identifier does not match")
    if (
        not isinstance(checkpoint.sequence_number, int)
        or isinstance(checkpoint.sequence_number, bool)
        or checkpoint.sequence_number < GENESIS_CHECKPOINT_SEQUENCE
    ):
        raise CheckpointConflictError("Checkpoint sequence number is invalid")
    if (
        not isinstance(checkpoint.record_hash, str)
        or _HEX_HASH_PATTERN.fullmatch(checkpoint.record_hash) is None
    ):
        raise CheckpointConflictError("Checkpoint record hash is invalid")
    if checkpoint.created_at.tzinfo is None:
        raise CheckpointConflictError("Checkpoint creation timestamp must include a timezone")
    if (
        checkpoint.previous_checkpoint_hmac is not None
        and (
            not isinstance(checkpoint.previous_checkpoint_hmac, str)
            or _HEX_HASH_PATTERN.fullmatch(checkpoint.previous_checkpoint_hmac) is None
        )
    ):
        raise CheckpointConflictError("Checkpoint link to the preceding checkpoint is invalid")


def enforce_store_progression(
    latest: AuditCheckpoint | None,
    checkpoint: AuditCheckpoint,
) -> tuple[AuditCheckpoint, bool] | None:
    """
    Apply monotonic compare-and-swap rules against the latest stored checkpoint.

    Returns (latest, False) when the write is an idempotent retry, or None when
    the caller must proceed with the write. Raises CheckpointRollbackError or
    CheckpointConflictError when the write must be refused.
    """
    if latest is not None:
        if latest.sequence_number > checkpoint.sequence_number:
            raise CheckpointRollbackError("Checkpoint sequence would move backwards")
        if latest.sequence_number == checkpoint.sequence_number:
            if hmac.compare_digest(latest.record_hash, checkpoint.record_hash):
                return latest, False
            raise CheckpointConflictError(
                "A different checkpoint already exists at this sequence"
            )
        if latest.integrity_tag != checkpoint.previous_checkpoint_hmac:
            raise CheckpointConflictError(
                "Checkpoint does not extend the most recently stored checkpoint"
            )
    elif checkpoint.previous_checkpoint_hmac is not None:
        raise CheckpointConflictError(
            "Checkpoint references a preceding checkpoint that is not stored"
        )
    return None


class LocalFileCheckpointStore:
    """
    Checkpoint adapter backed by a local directory.

    Each checkpoint is one JSON file named by its zero-padded sequence number.
    Files are written with exclusive creation so an existing sequence cannot be
    silently overwritten, and every record carries an HMAC over its payload.
    This adapter shares the application host and is not independent anchoring.
    """

    def __init__(
        self,
        directory: Path,
        hmac_key: bytes,
        *,
        stream_id: str = AUDIT_STREAM_ID,
    ) -> None:
        if len(hmac_key) < _MIN_HMAC_KEY_BYTES:
            raise ValueError(
                "Audit checkpoint HMAC key must be at least 32 bytes; "
                "configure AUDIT_ANCHOR_HMAC_KEY."
            )
        self._directory = Path(directory)
        self._hmac_key = hmac_key
        self._stream_id = stream_id

    def close(self) -> None:
        """The local file adapter does not hold persistent resources."""

    def _checkpoint_path(self, sequence_number: int) -> Path:
        return self._directory / f"checkpoint-{sequence_number:020d}.json"

    def _list_checkpoint_paths(self) -> list[tuple[int, Path]]:
        if not self._directory.exists():
            return []
        paths: list[tuple[int, Path]] = []
        for path in self._directory.iterdir():
            match = _CHECKPOINT_FILENAME_PATTERN.match(path.name)
            if match is not None and path.is_file():
                paths.append((int(match.group(1)), path))
        return sorted(paths, key=lambda item: item[0])

    def _load_file(self, path: Path) -> AuditCheckpoint:
        try:
            with path.open("r", encoding="utf-8") as handle:
                raw = handle.read(_MAX_CHECKPOINT_DOCUMENT_BYTES + 1)
        except OSError as exc:
            raise CheckpointIntegrityError("Stored checkpoint could not be read") from exc
        return parse_checkpoint_document(self._hmac_key, raw)

    def read_latest(self) -> AuditCheckpoint | None:
        try:
            paths = self._list_checkpoint_paths()
        except OSError as exc:
            raise CheckpointStoreUnavailableError("Checkpoint store is unavailable") from exc
        if not paths:
            return None
        return self._load_file(paths[-1][1])

    def write_checkpoint(self, checkpoint: AuditCheckpoint) -> tuple[AuditCheckpoint, bool]:
        validate_new_checkpoint(checkpoint, stream_id=self._stream_id)
        latest = self.read_latest()
        idempotent = enforce_store_progression(latest, checkpoint)
        if idempotent is not None:
            return idempotent

        try:
            self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = self._checkpoint_path(checkpoint.sequence_number)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            existing = self._load_file(self._checkpoint_path(checkpoint.sequence_number))
            if hmac.compare_digest(existing.record_hash, checkpoint.record_hash):
                return existing, False
            raise CheckpointConflictError(
                "A different checkpoint already exists at this sequence"
            ) from None
        except OSError as exc:
            raise CheckpointStoreUnavailableError("Checkpoint store is unavailable") from exc

        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(serialize_checkpoint(self._hmac_key, checkpoint))
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise CheckpointStoreUnavailableError("Checkpoint store is unavailable") from exc

        stored = AuditCheckpoint(
            format_version=checkpoint.format_version,
            stream_id=checkpoint.stream_id,
            sequence_number=checkpoint.sequence_number,
            record_hash=checkpoint.record_hash,
            created_at=checkpoint.created_at,
            previous_checkpoint_hmac=checkpoint.previous_checkpoint_hmac,
            integrity_tag=compute_checkpoint_tag(
                self._hmac_key, build_checkpoint_payload(checkpoint)
            ),
        )
        return stored, True


class PostgresCheckpointStore:
    """
    Checkpoint adapter backed by a separately administered PostgreSQL service.

    The application role must have SELECT and INSERT only on the pre-provisioned
    table. The table owner and database administrators must be outside the
    application's control plane for this store to provide independent evidence.
    """

    def __init__(
        self,
        database_url: str | URL,
        hmac_key: bytes,
        *,
        schema: str = "trustvault_audit_anchor",
        stream_id: str = AUDIT_STREAM_ID,
    ) -> None:
        if len(hmac_key) < _MIN_HMAC_KEY_BYTES:
            raise ValueError(
                "Audit checkpoint HMAC key must be at least 32 bytes; "
                "configure AUDIT_ANCHOR_HMAC_KEY."
            )
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", schema):
            raise ValueError("Audit checkpoint schema name is invalid")

        parsed_url = make_url(database_url)
        if parsed_url.get_backend_name() != "postgresql":
            raise ValueError("Independent audit anchoring requires PostgreSQL")

        self._engine: Engine = create_engine(
            parsed_url,
            pool_pre_ping=True,
            pool_size=1,
            max_overflow=0,
            pool_timeout=_ANCHOR_POOL_TIMEOUT_SECONDS,
            connect_args={
                "connect_timeout": _ANCHOR_CONNECT_TIMEOUT_SECONDS,
                "options": (
                    "-c statement_timeout="
                    f"{_ANCHOR_STATEMENT_TIMEOUT_MILLISECONDS}"
                ),
            },
        )
        self._hmac_key = hmac_key
        self._schema = schema
        self._stream_id = stream_id
        self._table = f'"{schema}"."checkpoints"'

    def close(self) -> None:
        self._engine.dispose()

    def read_latest(self) -> AuditCheckpoint | None:
        statement = text(
            f"SELECT checkpoint_document FROM {self._table} "
            "WHERE stream_id = :stream_id "
            "ORDER BY sequence_number DESC LIMIT 1"
        )
        try:
            with self._engine.connect() as connection:
                raw = connection.execute(
                    statement, {"stream_id": self._stream_id}
                ).scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise CheckpointStoreUnavailableError(
                "Independent audit checkpoint store is unavailable"
            ) from exc
        if raw is None:
            return None
        checkpoint = parse_checkpoint_document(self._hmac_key, raw)
        if checkpoint.stream_id != self._stream_id:
            raise CheckpointIntegrityError(
                "Stored checkpoint has an unexpected stream identifier"
            )
        return checkpoint

    def write_checkpoint(
        self, checkpoint: AuditCheckpoint
    ) -> tuple[AuditCheckpoint, bool]:
        validate_new_checkpoint(checkpoint, stream_id=self._stream_id)
        select_latest = text(
            f"SELECT checkpoint_document FROM {self._table} "
            "WHERE stream_id = :stream_id "
            "ORDER BY sequence_number DESC LIMIT 1"
        )
        insert_checkpoint = text(
            f"INSERT INTO {self._table} "
            "(stream_id, sequence_number, record_hash, checkpoint_document) "
            "VALUES (:stream_id, :sequence_number, :record_hash, "
            ":checkpoint_document)"
        )
        try:
            with self._engine.begin() as connection:
                connection.execute(
                    text(
                        "SELECT pg_advisory_xact_lock("
                        "hashtextextended(:stream_id, 0))"
                    ),
                    {"stream_id": self._stream_id},
                )
                raw_latest = connection.execute(
                    select_latest, {"stream_id": self._stream_id}
                ).scalar_one_or_none()
                latest = (
                    parse_checkpoint_document(self._hmac_key, raw_latest)
                    if raw_latest is not None
                    else None
                )
                if latest is not None and latest.stream_id != self._stream_id:
                    raise CheckpointIntegrityError(
                        "Stored checkpoint has an unexpected stream identifier"
                    )

                idempotent = enforce_store_progression(latest, checkpoint)
                if idempotent is not None:
                    return idempotent

                document = serialize_checkpoint(self._hmac_key, checkpoint)
                connection.execute(
                    insert_checkpoint,
                    {
                        "stream_id": self._stream_id,
                        "sequence_number": checkpoint.sequence_number,
                        "record_hash": checkpoint.record_hash,
                        "checkpoint_document": document,
                    },
                )
        except CheckpointError:
            raise
        except SQLAlchemyError as exc:
            raise CheckpointStoreUnavailableError(
                "Independent audit checkpoint store is unavailable"
            ) from exc

        stored = parse_checkpoint_document(self._hmac_key, document)
        return stored, True
