"""
Independently Stored Audit-Chain Checkpoints

A checkpoint binds an audit stream identifier, the highest verified sequence
number, the corresponding record hash, a format version, a creation timestamp,
and a link to the preceding checkpoint. Checkpoints are stored outside the
primary audit database through an adapter so that the persistence mechanism and
its permissions can differ between development and production.

Threat model (honest boundaries):
- A database-only attacker cannot rewrite the audit chain undetected once a
  checkpoint exists and the anchor store/key are outside their control, because
  the stored checkpoint is HMAC-protected and the chain is compared against it.
- An attacker who also controls the application process has access to the HMAC
  key and can forge local checkpoints. The provided local adapter therefore
  cannot defend against that boundary.
- An attacker who controls the anchor destination can delete or roll back
  local checkpoint files. Append-only/WORM provider semantics and provider-side
  key management are required to resist that boundary.

The local file adapter is a development and test mechanism. It shares the
application host and filesystem failure domain and is NOT production-grade
independent anchoring. No external production provider is configured in this
build.
"""

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

CHECKPOINT_FORMAT_VERSION = 1
AUDIT_STREAM_ID = "trustvault.audit"
GENESIS_CHECKPOINT_SEQUENCE = 0

_HEX_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CHECKPOINT_FILENAME_PATTERN = re.compile(r"^checkpoint-(\d{20})\.json$")
_MIN_HMAC_KEY_BYTES = 32


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
    """Adapter boundary for independently stored checkpoints."""

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
    treat disabled anchoring as a verified external checkpoint.
    """

    def read_latest(self) -> AuditCheckpoint | None:
        raise CheckpointStoreUnavailableError("Audit checkpoint anchoring is not configured")

    def write_checkpoint(self, checkpoint: AuditCheckpoint) -> tuple[AuditCheckpoint, bool]:
        raise CheckpointStoreUnavailableError("Audit checkpoint anchoring is not configured")


def _format_timestamp(value: datetime) -> str:
    """Canonical UTC timestamp representation used inside the HMAC payload."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    else:
        value = value.astimezone(UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical_payload(payload: dict) -> bytes:
    """Serialize a checkpoint payload deterministically for HMAC computation."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class LocalFileCheckpointStore:
    """
    Development-only checkpoint adapter backed by a local directory.

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

    def _compute_tag(self, payload: dict) -> str:
        return hmac.new(
            self._hmac_key, _canonical_payload(payload), hashlib.sha256
        ).hexdigest()

    def _payload_for(self, checkpoint: AuditCheckpoint) -> dict:
        return {
            "format_version": checkpoint.format_version,
            "stream_id": checkpoint.stream_id,
            "sequence_number": checkpoint.sequence_number,
            "record_hash": checkpoint.record_hash,
            "created_at": _format_timestamp(checkpoint.created_at),
            "previous_checkpoint_hmac": checkpoint.previous_checkpoint_hmac,
        }

    def _serialize(self, checkpoint: AuditCheckpoint) -> str:
        payload = self._payload_for(checkpoint)
        document = {"payload": payload, "hmac": self._compute_tag(payload)}
        return json.dumps(document, sort_keys=True, separators=(",", ":"))

    def _validate_payload(self, payload: dict) -> AuditCheckpoint:
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

    def _load_file(self, path: Path) -> AuditCheckpoint:
        try:
            with path.open("r", encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, ValueError) as exc:
            raise CheckpointIntegrityError("Stored checkpoint could not be read") from exc

        if not isinstance(document, dict):
            raise CheckpointIntegrityError("Stored checkpoint has an invalid document shape")
        payload = document.get("payload")
        stored_tag = document.get("hmac")
        if not isinstance(payload, dict) or not isinstance(stored_tag, str):
            raise CheckpointIntegrityError("Stored checkpoint has an invalid document shape")

        expected_tag = self._compute_tag(payload)
        if not hmac.compare_digest(expected_tag, stored_tag):
            raise CheckpointIntegrityError("Stored checkpoint failed its integrity check")

        checkpoint = self._validate_payload(payload)
        return AuditCheckpoint(
            format_version=checkpoint.format_version,
            stream_id=checkpoint.stream_id,
            sequence_number=checkpoint.sequence_number,
            record_hash=checkpoint.record_hash,
            created_at=checkpoint.created_at,
            previous_checkpoint_hmac=checkpoint.previous_checkpoint_hmac,
            integrity_tag=stored_tag,
        )

    def read_latest(self) -> AuditCheckpoint | None:
        try:
            paths = self._list_checkpoint_paths()
        except OSError as exc:
            raise CheckpointStoreUnavailableError("Checkpoint store is unavailable") from exc
        if not paths:
            return None
        return self._load_file(paths[-1][1])

    def _validate_new_checkpoint(self, checkpoint: AuditCheckpoint) -> None:
        if checkpoint.format_version != CHECKPOINT_FORMAT_VERSION:
            raise CheckpointConflictError("Unsupported checkpoint format version")
        if checkpoint.stream_id != self._stream_id:
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

    def write_checkpoint(self, checkpoint: AuditCheckpoint) -> tuple[AuditCheckpoint, bool]:
        self._validate_new_checkpoint(checkpoint)
        latest = self.read_latest()

        if latest is not None:
            if latest.sequence_number > checkpoint.sequence_number:
                raise CheckpointRollbackError(
                    "Checkpoint sequence would move backwards"
                )
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
                handle.write(self._serialize(checkpoint))
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
            integrity_tag=self._compute_tag(self._payload_for(checkpoint)),
        )
        return stored, True
