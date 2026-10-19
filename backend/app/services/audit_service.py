"""
TrustVault Audit Trail Service with Cryptographic Hash Chaining
Implements an append-only, tamper-evident audit log for compliance and forensics.

Integrity Mechanism:
Each record includes `previous_hash` (pointing to the prior record's `record_hash`)
and `record_hash` (computed across sequence, timestamp, actor, action, resource,
outcome, request_id, details, and previous_hash).

Honest Security Limitation Notice:
Hash chaining ensures that any mid-chain alteration or omission is immediately detectable.
However, hash chaining alone cannot protect against an attacker with full database overwrite
privileges who rewrites the entire chain from a given point forward. For production deployment,
we recommend external anchoring (e.g., streaming logs to write-once-read-many / WORM cloud storage,
AWS S3 Object Lock, or publishing periodic root hashes to an external timestamping service).
"""

import hashlib
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.audit import AuditEvent

GENESIS_HASH = "0" * 64

VerificationStatus = Literal["VALID", "INVALID", "INCOMPLETE"]


@dataclass(frozen=True)
class AuditVerificationResult:
    """Outcome of a bounded audit-chain verification pass."""

    status: VerificationStatus
    records_verified: int
    failure_reason: str | None = None
    tail_hash: str | None = None


class AuditService:
    @staticmethod
    def format_timestamp(dt: datetime) -> str:
        """
        Canonical UTC timestamp representation: YYYY-MM-DDTHH:MM:SS.ffffffZ
        Guarantees exact byte-for-byte reproducibility regardless of whether the
        underlying database driver returns timezone-aware or naive UTC objects.
        """
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        else:
            dt = dt.astimezone(UTC)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    @classmethod
    def calculate_hash(
        cls,
        sequence_number: int,
        timestamp: datetime,
        actor_id: str | None,
        action: str,
        resource_type: str | None,
        resource_id: str | None,
        outcome: str,
        request_id: str | None,
        details_str: str | None,
        previous_hash: str,
    ) -> str:
        """
        Computes deterministic SHA-256 hash for an audit record.
        Fields are canonically ordered to ensure reproducibility.
        """
        timestamp_str = cls.format_timestamp(timestamp)
        payload = (
            f"seq:{sequence_number}|"
            f"ts:{timestamp_str}|"
            f"actor:{actor_id or ''}|"
            f"action:{action}|"
            f"res_type:{resource_type or ''}|"
            f"res_id:{resource_id or ''}|"
            f"outcome:{outcome}|"
            f"req_id:{request_id or ''}|"
            f"details:{details_str or ''}|"
            f"prev:{previous_hash}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def log_event(
        cls,
        db: Session,
        action: str,
        outcome: str,
        actor_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        request_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """
        Appends an immutable audit event to the tamper-evident chain within the current transaction.
        """
        # Fetch the most recent event to determine sequence and previous hash
        stmt = select(AuditEvent).order_by(AuditEvent.sequence_number.desc()).limit(1)
        last_event = db.execute(stmt).scalars().first()

        if last_event is None:
            sequence_number = 1
            previous_hash = GENESIS_HASH
        else:
            sequence_number = last_event.sequence_number + 1
            previous_hash = last_event.record_hash

        event_time = datetime.now(UTC)
        details_str = json.dumps(details, sort_keys=True) if details else None

        record_hash = cls.calculate_hash(
            sequence_number=sequence_number,
            timestamp=event_time,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            request_id=request_id,
            details_str=details_str,
            previous_hash=previous_hash,
        )

        event = AuditEvent(
            sequence_number=sequence_number,
            timestamp=event_time,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            request_id=request_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details_str,
            previous_hash=previous_hash,
            record_hash=record_hash,
        )
        db.add(event)
        db.flush()
        return event

    @classmethod
    def _load_verification_batch(
        cls,
        db: Session,
        after_sequence: int,
        high_water_mark: int,
        batch_size: int,
    ) -> list[Mapping[str, Any]]:
        """
        Fetch one ordered batch of audit columns using an indexed keyset range.

        Column selection avoids populating the ORM identity map, and the high-water
        mark bounds the traversal to records committed at the start of verification.
        """
        stmt = (
            select(
                AuditEvent.sequence_number,
                AuditEvent.timestamp,
                AuditEvent.actor_id,
                AuditEvent.action,
                AuditEvent.resource_type,
                AuditEvent.resource_id,
                AuditEvent.outcome,
                AuditEvent.request_id,
                AuditEvent.details,
                AuditEvent.previous_hash,
                AuditEvent.record_hash,
            )
            .where(
                AuditEvent.sequence_number > after_sequence,
                AuditEvent.sequence_number <= high_water_mark,
            )
            .order_by(AuditEvent.sequence_number.asc())
            .limit(batch_size)
        )
        return list(db.execute(stmt).mappings().all())

    @classmethod
    def verify_chain_integrity_bounded(
        cls,
        db: Session,
        *,
        max_records: int,
        batch_size: int,
        timeout_seconds: float,
        clock: Callable[[], float] | None = None,
    ) -> AuditVerificationResult:
        """
        Verify the chain in bounded batches within a record and time budget.

        A high-water mark captured at the start defines the verification boundary.
        The result is VALID only after every record at or below that mark has been
        examined. If the chain exceeds the record limit or the deadline expires,
        the result is INCOMPLETE and never reports full-chain success.
        """
        clock = clock or time.monotonic
        deadline = clock() + timeout_seconds

        low_sequence, high_water_mark = db.execute(
            select(
                func.min(AuditEvent.sequence_number),
                func.max(AuditEvent.sequence_number),
            )
        ).one()
        if high_water_mark is None:
            return AuditVerificationResult("VALID", 0, tail_hash=GENESIS_HASH)
        if low_sequence is None or low_sequence < 1:
            return AuditVerificationResult(
                "INVALID",
                0,
                (
                    "Sequence gap detected at index 1: expected 1, found "
                    f"{low_sequence if low_sequence is not None else 'no valid sequence'}"
                ),
            )
        if high_water_mark > max_records:
            return AuditVerificationResult(
                "INCOMPLETE",
                0,
                (
                    "Verification incomplete: audit chain contains "
                    f"{high_water_mark} records, exceeding the configured limit of "
                    f"{max_records}"
                ),
            )

        expected_sequence = 1
        expected_prev_hash = GENESIS_HASH
        last_sequence = 0

        while True:
            if clock() >= deadline:
                return AuditVerificationResult(
                    "INCOMPLETE",
                    expected_sequence - 1,
                    (
                        "Verification incomplete: the configured time limit was "
                        f"exceeded after verifying {expected_sequence - 1} of "
                        f"{high_water_mark} records"
                    ),
                )

            rows = cls._load_verification_batch(
                db,
                after_sequence=last_sequence,
                high_water_mark=high_water_mark,
                batch_size=batch_size,
            )
            if not rows:
                break

            for row in rows:
                sequence_number = row["sequence_number"]
                if sequence_number != expected_sequence:
                    return AuditVerificationResult(
                        "INVALID",
                        expected_sequence - 1,
                        (
                            f"Sequence gap detected at index {expected_sequence}: "
                            f"expected {expected_sequence}, found {sequence_number}"
                        ),
                    )

                previous_hash = row["previous_hash"]
                if previous_hash != expected_prev_hash:
                    return AuditVerificationResult(
                        "INVALID",
                        expected_sequence - 1,
                        (
                            f"Hash link broken at sequence {sequence_number}: "
                            f"previous_hash '{previous_hash}' does not match "
                            f"expected '{expected_prev_hash}'"
                        ),
                    )

                computed_hash = cls.calculate_hash(
                    sequence_number=sequence_number,
                    timestamp=row["timestamp"],
                    actor_id=row["actor_id"],
                    action=row["action"],
                    resource_type=row["resource_type"],
                    resource_id=row["resource_id"],
                    outcome=row["outcome"],
                    request_id=row["request_id"],
                    details_str=row["details"],
                    previous_hash=previous_hash,
                )

                if row["record_hash"] != computed_hash:
                    return AuditVerificationResult(
                        "INVALID",
                        expected_sequence - 1,
                        (
                            f"Record tampering detected at sequence {sequence_number}: "
                            f"stored hash '{row['record_hash']}' does not match "
                            f"computed '{computed_hash}'"
                        ),
                    )

                expected_prev_hash = row["record_hash"]
                last_sequence = sequence_number
                expected_sequence += 1

            if last_sequence >= high_water_mark:
                return AuditVerificationResult(
                    "VALID", last_sequence, tail_hash=expected_prev_hash
                )

        if expected_sequence <= high_water_mark:
            return AuditVerificationResult(
                "INVALID",
                expected_sequence - 1,
                (
                    f"Sequence gap detected at index {expected_sequence}: "
                    f"expected {expected_sequence}, found end of chain at sequence "
                    f"{last_sequence}"
                ),
            )

        return AuditVerificationResult(
            "VALID", expected_sequence - 1, tail_hash=expected_prev_hash
        )

    @classmethod
    def verify_chain_integrity(cls, db: Session) -> tuple[bool, str | None, int]:
        """
        Verifies the cryptographic integrity of the entire audit log chain.
        Returns: (is_valid, failure_reason_if_any, total_records_verified)

        Uses the configured resource limits. An incomplete pass returns
        is_valid=False with an explanatory failure reason.
        """
        result = cls.verify_chain_integrity_bounded(
            db,
            max_records=settings.AUDIT_VERIFY_MAX_RECORDS,
            batch_size=settings.AUDIT_VERIFY_BATCH_SIZE,
            timeout_seconds=settings.AUDIT_VERIFY_TIMEOUT_SECONDS,
        )
        return result.status == "VALID", result.failure_reason, result.records_verified
