"""
Independently Stored Audit-Chain Checkpoints

A checkpoint binds an audit stream identifier, the highest verified sequence
number, the corresponding record hash, a format version, a creation timestamp,
and a link to the preceding checkpoint. Checkpoints are stored outside the
primary audit database through an adapter so that the persistence mechanism and
its permissions can differ between development and production.

Implemented adapters:
- ``LocalFileCheckpointStore``: development-only local directory (same host and
  filesystem failure domain; never production-grade independent anchoring).
- ``S3CheckpointStore``: external object storage (Amazon S3 or an S3-compatible
  service) using the AWS default credential chain. No bucket, credentials, or
  endpoint are configured in this repository; until an independently controlled
  destination is configured and verified, production checkpoint operations fail
  closed. Bucket versioning and Object Lock (WORM) are required for the strong
  threat-model guarantees described in THREATS.md.

Threat model (honest boundaries):
- A database-only attacker cannot rewrite the audit chain undetected once a
  checkpoint exists and the anchor store/key are outside their control, because
  the stored checkpoint is HMAC-protected and the chain is compared against it.
- An attacker who also controls the application process has access to the HMAC
  key and can forge checkpoints. No adapter can defend that boundary.
- An attacker who controls the anchor destination can delete or roll back
  checkpoints unless the provider enforces immutability (for example S3 Object
  Lock in COMPLIANCE mode) or versioning with restricted delete permissions.
- The S3 adapter is code-complete but is not verified against a live bucket in
  this build, and no production anchoring is claimed until an operator
  configures and tests an actual destination.
"""

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

CHECKPOINT_FORMAT_VERSION = 1
AUDIT_STREAM_ID = "trustvault.audit"
GENESIS_CHECKPOINT_SEQUENCE = 0
DEFAULT_S3_CHECKPOINT_PREFIX = "trustvault-audit-checkpoints"

_HEX_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CHECKPOINT_FILENAME_PATTERN = re.compile(r"^checkpoint-(\d{20})\.json$")
_MIN_HMAC_KEY_BYTES = 32
_MAX_CHECKPOINT_DOCUMENT_BYTES = 64 * 1024
_S3_LIST_PAGE_SIZE = 1000
_S3_MAX_LIST_PAGES = 1000

_S3_DENIED_CODES = frozenset(
    {
        "403",
        "AccessDenied",
        "AllAccessDisabled",
        "ExpiredToken",
        "InvalidAccessKeyId",
        "InvalidToken",
        "SignatureDoesNotMatch",
        "TokenRefreshRequired",
    }
)
_S3_UNAVAILABLE_EXCEPTION_NAMES = frozenset(
    {
        "ConnectTimeoutError",
        "ConnectionClosedError",
        "ConnectionError",
        "CredentialRetrievalError",
        "EndpointConnectionError",
        "HTTPClientError",
        "MaxRetryError",
        "NewConnectionError",
        "NoCredentialsError",
        "PartialCredentialsError",
        "ProxyConnectionError",
        "ReadTimeoutError",
        "SSLError",
    }
)


class CheckpointError(Exception):
    """Base class for audit checkpoint errors."""


class CheckpointStoreUnavailableError(CheckpointError):
    """The checkpoint store is not configured or cannot be reached."""


class CheckpointStoreAccessDeniedError(CheckpointStoreUnavailableError):
    """The checkpoint store rejected the request because of missing permissions."""


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


def _s3_error_code(exc: Exception) -> str | None:
    """Extract an AWS error code from a ClientError-like exception."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            code = error.get("Code")
            if isinstance(code, str):
                return code
    return None


def _is_botocore_error(exc: Exception) -> bool:
    """Detect botocore errors without importing the optional dependency."""
    return any(cls.__name__ == "BotoCoreError" for cls in type(exc).__mro__)


def classify_s3_error(exc: Exception) -> CheckpointError | None:
    """
    Map a provider exception to a checkpoint error without leaking provider details.

    Returns None for exceptions that do not look like provider/transport errors
    so unexpected programming errors still propagate.
    """
    code = _s3_error_code(exc)
    if code is not None:
        if code in _S3_DENIED_CODES:
            return CheckpointStoreAccessDeniedError(
                "Checkpoint store access was denied"
            )
        if code == "NoSuchKey":
            return CheckpointIntegrityError(
                "Stored checkpoint disappeared between listing and retrieval"
            )
        if code == "PreconditionFailed":
            return CheckpointConflictError("Checkpoint store rejected the conditional write")
        return CheckpointStoreUnavailableError("Checkpoint store request failed")

    if (
        type(exc).__name__ in _S3_UNAVAILABLE_EXCEPTION_NAMES
        or _is_botocore_error(exc)
    ):
        return CheckpointStoreUnavailableError(
            "Checkpoint store could not be reached or authenticated"
        )
    return None


def create_s3_client(
    *,
    region: str,
    endpoint_url: str | None = None,
    connect_timeout_seconds: float = 5.0,
    read_timeout_seconds: float = 10.0,
    max_attempts: int = 3,
):
    """
    Create a boto3 S3 client using the AWS default credential chain.

    No credentials, bucket, or endpoint are embedded here. Returns None when
    boto3 is not installed so callers can fail closed without importing an
    optional dependency at module load time.
    """
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        return None

    config = Config(
        connect_timeout=connect_timeout_seconds,
        read_timeout=read_timeout_seconds,
        retries={"max_attempts": max_attempts, "mode": "standard"},
        signature_version="s3v4",
    )
    kwargs: dict = {"region_name": region, "config": config}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    return boto3.client("s3", **kwargs)


class S3CheckpointStore:
    """
    External checkpoint adapter backed by Amazon S3 or an S3-compatible service.

    The adapter stores the same JSON checkpoint document format as the local
    adapter (one object per sequence number) and uses conditional writes
    (If-None-Match) for compare-and-swap semantics. Bucket versioning and Object
    Lock are strongly recommended; configure object-lock mode to have the
    adapter request retention on every write. The bucket must live outside the
    database/application trust boundary for anchoring to be meaningful.
    """

    def __init__(
        self,
        bucket: str,
        *,
        hmac_key: bytes,
        client,
        prefix: str = DEFAULT_S3_CHECKPOINT_PREFIX,
        stream_id: str = AUDIT_STREAM_ID,
        object_lock_mode: str | None = None,
        object_lock_retain_days: int = 30,
        kms_key_id: str | None = None,
    ) -> None:
        if not bucket or not bucket.strip():
            raise ValueError("Audit checkpoint S3 bucket must not be empty")
        if len(hmac_key) < _MIN_HMAC_KEY_BYTES:
            raise ValueError(
                "Audit checkpoint HMAC key must be at least 32 bytes; "
                "configure AUDIT_ANCHOR_HMAC_KEY."
            )
        if object_lock_mode not in (None, "", "GOVERNANCE", "COMPLIANCE"):
            raise ValueError("Unsupported S3 object lock mode")
        if object_lock_retain_days < 1:
            raise ValueError("S3 object lock retention must be at least one day")
        self._bucket = bucket.strip()
        self._client = client
        self._hmac_key = hmac_key
        self._stream_id = stream_id
        self._prefix = (prefix or "").strip().strip("/")
        self._object_lock_mode = object_lock_mode or None
        self._object_lock_retain_days = object_lock_retain_days
        self._kms_key_id = kms_key_id or None

    def _object_key(self, sequence_number: int) -> str:
        name = f"checkpoint-{sequence_number:020d}.json"
        return f"{self._prefix}/{name}" if self._prefix else name

    def _sequence_from_key(self, key: str) -> int | None:
        if not isinstance(key, str):
            return None
        name = key.rsplit("/", 1)[-1]
        match = _CHECKPOINT_FILENAME_PATTERN.match(name)
        if match is None:
            return None
        return int(match.group(1))

    def _list_checkpoint_objects(self) -> list[tuple[int, str]]:
        objects: list[tuple[int, str]] = []
        continuation_token: str | None = None
        seen_tokens: set[str] = set()
        page_count = 0
        list_prefix = f"{self._prefix}/" if self._prefix else ""
        while True:
            page_count += 1
            if page_count > _S3_MAX_LIST_PAGES:
                raise CheckpointStoreUnavailableError(
                    "Checkpoint store listing exceeded the page limit"
                )
            request: dict = {
                "Bucket": self._bucket,
                "Prefix": list_prefix,
                "MaxKeys": _S3_LIST_PAGE_SIZE,
            }
            if continuation_token:
                request["ContinuationToken"] = continuation_token
            response = self._client.list_objects_v2(**request)
            if not isinstance(response, dict):
                raise CheckpointStoreUnavailableError(
                    "Checkpoint store returned an invalid response"
                )
            contents = response.get("Contents", [])
            if contents is None:
                contents = []
            if not isinstance(contents, list):
                raise CheckpointStoreUnavailableError(
                    "Checkpoint store returned an invalid response"
                )
            for item in contents:
                if not isinstance(item, dict):
                    raise CheckpointStoreUnavailableError(
                        "Checkpoint store returned an invalid response"
                    )
                sequence_number = self._sequence_from_key(item.get("Key"))
                if (
                    sequence_number is not None
                    and item["Key"] == self._object_key(sequence_number)
                ):
                    objects.append((sequence_number, item["Key"]))
            if not response.get("IsTruncated"):
                break
            continuation_token = response.get("NextContinuationToken")
            if not isinstance(continuation_token, str) or not continuation_token:
                raise CheckpointStoreUnavailableError(
                    "Checkpoint store returned an incomplete listing"
                )
            if continuation_token in seen_tokens:
                raise CheckpointStoreUnavailableError(
                    "Checkpoint store returned an incomplete listing"
                )
            seen_tokens.add(continuation_token)
        return objects

    def _read_checkpoint_object(self, key: str) -> AuditCheckpoint:
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
        except Exception as exc:
            mapped = classify_s3_error(exc)
            if mapped is not None:
                raise mapped from None
            raise
        if not isinstance(response, dict):
            raise CheckpointStoreUnavailableError(
                "Checkpoint store returned an invalid response"
            )
        body = response.get("Body")
        if body is None or not hasattr(body, "read"):
            raise CheckpointStoreUnavailableError(
                "Checkpoint store returned an invalid response"
            )
        try:
            raw = body.read(_MAX_CHECKPOINT_DOCUMENT_BYTES + 1)
        except Exception as exc:
            mapped = classify_s3_error(exc)
            if mapped is not None:
                raise mapped from None
            raise CheckpointStoreUnavailableError(
                "Checkpoint store response could not be read"
            ) from exc
        if not isinstance(raw, (bytes, bytearray)):
            raise CheckpointIntegrityError("Stored checkpoint has an invalid body")
        checkpoint = parse_checkpoint_document(self._hmac_key, bytes(raw))
        expected_sequence = self._sequence_from_key(key)
        if (
            expected_sequence is None
            or checkpoint.sequence_number != expected_sequence
        ):
            raise CheckpointIntegrityError(
                "Stored checkpoint does not match its object key"
            )
        return checkpoint

    def read_latest(self) -> AuditCheckpoint | None:
        try:
            objects = self._list_checkpoint_objects()
        except CheckpointError:
            raise
        except Exception as exc:
            mapped = classify_s3_error(exc)
            if mapped is not None:
                raise mapped from None
            raise
        if not objects:
            return None
        _, key = max(objects, key=lambda item: item[0])
        return self._read_checkpoint_object(key)

    def write_checkpoint(self, checkpoint: AuditCheckpoint) -> tuple[AuditCheckpoint, bool]:
        validate_new_checkpoint(checkpoint, stream_id=self._stream_id)
        latest = self.read_latest()
        idempotent = enforce_store_progression(latest, checkpoint)
        if idempotent is not None:
            return idempotent

        request: dict = {
            "Bucket": self._bucket,
            "Key": self._object_key(checkpoint.sequence_number),
            "Body": serialize_checkpoint(self._hmac_key, checkpoint).encode("utf-8"),
            "ContentType": "application/json",
            "IfNoneMatch": "*",
        }
        if self._kms_key_id:
            request["ServerSideEncryption"] = "aws:kms"
            request["SSEKMSKeyId"] = self._kms_key_id
        if self._object_lock_mode:
            request["ObjectLockMode"] = self._object_lock_mode
            request["ObjectLockRetainUntilDate"] = datetime.now(UTC) + timedelta(
                days=self._object_lock_retain_days
            )

        try:
            response = self._client.put_object(**request)
        except Exception as exc:
            if _s3_error_code(exc) == "PreconditionFailed":
                return self._resolve_lost_conditional_write(checkpoint)
            mapped = classify_s3_error(exc)
            if mapped is not None:
                raise mapped from None
            raise

        if not isinstance(response, dict):
            raise CheckpointStoreUnavailableError(
                "Checkpoint store returned an invalid response"
            )
        metadata = response.get("ResponseMetadata")
        if isinstance(metadata, dict):
            status_code = metadata.get("HTTPStatusCode")
            if status_code is not None and status_code != 200:
                raise CheckpointStoreUnavailableError(
                    "Checkpoint store rejected the write"
                )

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

    def _resolve_lost_conditional_write(
        self, checkpoint: AuditCheckpoint
    ) -> tuple[AuditCheckpoint, bool]:
        """Handle a lost conditional-write race against another writer."""
        key = self._object_key(checkpoint.sequence_number)
        try:
            existing = self._read_checkpoint_object(key)
        except (
            CheckpointStoreAccessDeniedError,
            CheckpointStoreUnavailableError,
        ):
            raise
        except CheckpointError:
            raise CheckpointConflictError(
                "A conflicting checkpoint may exist at this sequence"
            ) from None
        if hmac.compare_digest(existing.record_hash, checkpoint.record_hash):
            return existing, False
        raise CheckpointConflictError(
            "A different checkpoint already exists at this sequence"
        )
