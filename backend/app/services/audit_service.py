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
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.audit import AuditEvent

GENESIS_HASH = "0" * 64


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
    def verify_chain_integrity(cls, db: Session) -> tuple[bool, str | None, int]:
        """
        Verifies the cryptographic integrity of the entire audit log chain.
        Returns: (is_valid, failure_reason_if_any, total_records_verified)
        """
        stmt = select(AuditEvent).order_by(AuditEvent.sequence_number.asc())
        events = list(db.execute(stmt).scalars().all())

        if not events:
            return True, None, 0

        expected_prev_hash = GENESIS_HASH
        for idx, event in enumerate(events, start=1):
            # Check sequence continuity
            if event.sequence_number != idx:
                return False, f"Sequence gap detected at index {idx}: expected {idx}, found {event.sequence_number}", idx - 1

            # Check previous hash link
            if event.previous_hash != expected_prev_hash:
                return (
                    False,
                    f"Hash link broken at sequence {event.sequence_number}: previous_hash '{event.previous_hash}' does not match expected '{expected_prev_hash}'",
                    idx - 1,
                )

            # Recompute record hash
            computed_hash = cls.calculate_hash(
                sequence_number=event.sequence_number,
                timestamp=event.timestamp,
                actor_id=event.actor_id,
                action=event.action,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                outcome=event.outcome,
                request_id=event.request_id,
                details_str=event.details,
                previous_hash=event.previous_hash,
            )

            if event.record_hash != computed_hash:
                return (
                    False,
                    f"Record tampering detected at sequence {event.sequence_number}: stored hash '{event.record_hash}' does not match computed '{computed_hash}'",
                    idx - 1,
                )

            expected_prev_hash = event.record_hash

        return True, None, len(events)
