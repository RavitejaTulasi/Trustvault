"""
Audit-Chain Checkpoint Creation and Verification

Creation only checkpoints a verified, committed prefix. Verification compares
the live audit chain against the stored checkpoint and fails closed: an
unavailable store never produces a VALID result.
"""

import hmac
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.audit import AuditEvent
from backend.app.services.audit_service import (
    GENESIS_HASH,
    AuditService,
    VerificationStatus,
)
from backend.app.services.checkpoint_store import (
    AUDIT_STREAM_ID,
    CHECKPOINT_FORMAT_VERSION,
    AuditCheckpoint,
    CheckpointConflictError,
    CheckpointIntegrityError,
    CheckpointRollbackError,
    CheckpointStore,
    CheckpointStoreUnavailableError,
)


class CheckpointCreationError(Exception):
    """Raised when a safe checkpoint cannot be created."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class CheckpointCreationResult:
    """Result of a checkpoint creation attempt."""

    checkpoint: AuditCheckpoint
    already_present: bool


@dataclass(frozen=True)
class CheckpointVerificationResult:
    """Outcome of comparing the live audit chain with a stored checkpoint."""

    status: VerificationStatus
    records_verified: int
    checkpoint_sequence: int | None
    chain_head_sequence: int | None
    failure_reason: str | None = None


class CheckpointService:
    @staticmethod
    def _hash_at_sequence(db: Session, sequence_number: int) -> str | None:
        if sequence_number == 0:
            return GENESIS_HASH
        stored_hash = db.execute(
            select(AuditEvent.record_hash).where(
                AuditEvent.sequence_number == sequence_number
            )
        ).scalar_one_or_none()
        return stored_hash

    @classmethod
    def create_checkpoint(
        cls,
        db: Session,
        store: CheckpointStore,
        *,
        max_records: int,
        batch_size: int,
        timeout_seconds: float,
        now: Callable[[], datetime] | None = None,
    ) -> CheckpointCreationResult:
        """
        Create a checkpoint over the highest verified, committed prefix.

        The audit chain is verified first. If a checkpoint already exists, the
        live chain is compared at the checkpointed sequence before any new
        checkpoint is written, so a truncated or rewritten history is refused
        instead of silently re-anchored.
        """
        verification = AuditService.verify_chain_integrity_bounded(
            db,
            max_records=max_records,
            batch_size=batch_size,
            timeout_seconds=timeout_seconds,
        )
        if verification.status == "INVALID":
            raise CheckpointCreationError("chain_invalid")
        if verification.status == "INCOMPLETE":
            raise CheckpointCreationError("chain_incomplete")
        if verification.tail_hash is None:
            raise CheckpointCreationError("chain_incomplete")

        head_sequence = verification.records_verified
        head_hash = verification.tail_hash

        try:
            existing = store.read_latest()
        except CheckpointStoreUnavailableError:
            raise CheckpointCreationError("anchor_unavailable") from None
        except CheckpointIntegrityError:
            raise CheckpointCreationError("anchor_integrity_failure") from None

        previous_hmac: str | None = None
        if existing is not None:
            if existing.format_version != CHECKPOINT_FORMAT_VERSION:
                raise CheckpointCreationError("anchor_format_unsupported")
            if existing.stream_id != AUDIT_STREAM_ID:
                raise CheckpointCreationError("anchor_stream_mismatch")
            if existing.integrity_tag is None:
                raise CheckpointCreationError("anchor_integrity_failure")
            if existing.sequence_number > head_sequence:
                raise CheckpointCreationError("anchor_ahead_of_chain")

            live_hash = cls._hash_at_sequence(db, existing.sequence_number)
            if live_hash is None or not hmac.compare_digest(
                live_hash, existing.record_hash
            ):
                raise CheckpointCreationError("anchor_chain_mismatch")
            if existing.sequence_number == head_sequence:
                return CheckpointCreationResult(existing, True)
            previous_hmac = existing.integrity_tag

        clock = now or (lambda: datetime.now(UTC))
        checkpoint = AuditCheckpoint(
            format_version=CHECKPOINT_FORMAT_VERSION,
            stream_id=AUDIT_STREAM_ID,
            sequence_number=head_sequence,
            record_hash=head_hash,
            created_at=clock(),
            previous_checkpoint_hmac=previous_hmac,
        )

        try:
            stored, created = store.write_checkpoint(checkpoint)
        except CheckpointRollbackError:
            raise CheckpointCreationError("anchor_rollback_detected") from None
        except CheckpointConflictError:
            raise CheckpointCreationError("anchor_conflict") from None
        except CheckpointIntegrityError:
            raise CheckpointCreationError("anchor_integrity_failure") from None
        except CheckpointStoreUnavailableError:
            raise CheckpointCreationError("anchor_unavailable") from None

        return CheckpointCreationResult(stored, not created)

    @classmethod
    def verify_checkpoint(
        cls,
        db: Session,
        store: CheckpointStore,
        *,
        max_records: int,
        batch_size: int,
        timeout_seconds: float,
    ) -> CheckpointVerificationResult:
        """
        Verify the live chain against the stored checkpoint.

        Store outages are reported as UNAVAILABLE. A missing checkpoint,
        bounded verification, or unsupported format is
        reported as INCOMPLETE. A confirmed chain or checkpoint mismatch is
        reported as INVALID. A genesis-only checkpoint is INCOMPLETE because it
        cannot distinguish a legitimately empty chain from truncation to zero.
        VALID is returned only when a non-genesis checkpoint and the chain match.
        """
        chain = AuditService.verify_chain_integrity_bounded(
            db,
            max_records=max_records,
            batch_size=batch_size,
            timeout_seconds=timeout_seconds,
        )
        if chain.status == "INVALID":
            return CheckpointVerificationResult(
                "INVALID",
                chain.records_verified,
                None,
                None,
                chain.failure_reason or "Audit chain verification failed",
            )

        try:
            checkpoint = store.read_latest()
        except CheckpointStoreUnavailableError:
            return CheckpointVerificationResult(
                "UNAVAILABLE",
                chain.records_verified,
                None,
                None,
                "Checkpoint anchoring is unavailable or not configured",
            )
        except CheckpointIntegrityError:
            return CheckpointVerificationResult(
                "INVALID",
                chain.records_verified,
                None,
                None,
                "Stored checkpoint failed its integrity check",
            )

        if checkpoint is None:
            return CheckpointVerificationResult(
                "INCOMPLETE",
                chain.records_verified,
                None,
                None,
                "No checkpoint is available for comparison",
            )
        if checkpoint.format_version != CHECKPOINT_FORMAT_VERSION:
            return CheckpointVerificationResult(
                "INCOMPLETE",
                chain.records_verified,
                checkpoint.sequence_number,
                None,
                "Unsupported checkpoint format version",
            )
        if checkpoint.stream_id != AUDIT_STREAM_ID:
            return CheckpointVerificationResult(
                "INCOMPLETE",
                chain.records_verified,
                checkpoint.sequence_number,
                None,
                "Checkpoint stream identifier does not match the audit chain",
            )

        if chain.status == "INCOMPLETE":
            return CheckpointVerificationResult(
                "INCOMPLETE",
                chain.records_verified,
                checkpoint.sequence_number,
                None,
                chain.failure_reason or "Audit chain verification was incomplete",
            )

        if checkpoint.sequence_number == 0:
            return CheckpointVerificationResult(
                "INCOMPLETE",
                chain.records_verified,
                checkpoint.sequence_number,
                chain.records_verified,
                (
                    "Only a genesis checkpoint is available; an empty or truncated "
                    "audit history cannot be reported as fully anchored"
                ),
            )

        chain_head = chain.records_verified
        if checkpoint.sequence_number > chain_head:
            return CheckpointVerificationResult(
                "INVALID",
                chain.records_verified,
                checkpoint.sequence_number,
                chain_head,
                "Checkpointed sequence no longer exists in the audit chain",
            )

        live_hash = cls._hash_at_sequence(db, checkpoint.sequence_number)
        if live_hash is None:
            return CheckpointVerificationResult(
                "INVALID",
                chain.records_verified,
                checkpoint.sequence_number,
                chain_head,
                "Checkpointed sequence no longer exists in the audit chain",
            )
        if not hmac.compare_digest(live_hash, checkpoint.record_hash):
            return CheckpointVerificationResult(
                "INVALID",
                chain.records_verified,
                checkpoint.sequence_number,
                chain_head,
                "Audit chain hash at the checkpointed sequence does not match the checkpoint",
            )

        return CheckpointVerificationResult(
            "VALID",
            chain.records_verified,
            checkpoint.sequence_number,
            chain_head,
            None,
        )
