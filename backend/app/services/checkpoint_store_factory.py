"""
Construct the configured audit checkpoint store.

The factory is shared by the administrative API and the scheduled checkpoint
worker so both paths use exactly the same fail-closed adapter selection. It never
falls back to a local store when an external provider is misconfigured.
"""

import logging
from collections.abc import Callable
from typing import Any

from backend.app.config import Settings
from backend.app.services.checkpoint_store import (
    CheckpointStore,
    LocalFileCheckpointStore,
    S3CheckpointStore,
    UnavailableCheckpointStore,
    create_s3_client,
)

logger = logging.getLogger(__name__)


def create_checkpoint_store(
    config: Settings,
    *,
    s3_client_factory: Callable[..., Any] = create_s3_client,
) -> CheckpointStore:
    """Instantiate the adapter selected by ``AUDIT_ANCHOR_MODE``."""
    if config.AUDIT_ANCHOR_MODE == "local_file":
        try:
            return LocalFileCheckpointStore(
                config.resolved_audit_anchor_path,
                config.AUDIT_ANCHOR_HMAC_KEY.encode("utf-8"),
            )
        except (OSError, ValueError):
            logger.error("Audit checkpoint store initialization failed")
    elif config.AUDIT_ANCHOR_MODE == "s3":
        try:
            client = s3_client_factory(
                region=config.AUDIT_ANCHOR_S3_REGION,
                endpoint_url=config.AUDIT_ANCHOR_S3_ENDPOINT_URL or None,
                connect_timeout_seconds=config.AUDIT_ANCHOR_S3_CONNECT_TIMEOUT_SECONDS,
                read_timeout_seconds=config.AUDIT_ANCHOR_S3_READ_TIMEOUT_SECONDS,
                max_attempts=config.AUDIT_ANCHOR_S3_MAX_ATTEMPTS,
            )
            if client is None:
                logger.error(
                    "Audit checkpoint S3 adapter is unavailable because boto3 "
                    "is not installed"
                )
                return UnavailableCheckpointStore()
            return S3CheckpointStore(
                config.AUDIT_ANCHOR_S3_BUCKET,
                hmac_key=config.AUDIT_ANCHOR_HMAC_KEY.encode("utf-8"),
                client=client,
                prefix=config.AUDIT_ANCHOR_S3_PREFIX,
                object_lock_mode=config.AUDIT_ANCHOR_S3_OBJECT_LOCK_MODE or None,
                object_lock_retain_days=config.AUDIT_ANCHOR_S3_OBJECT_LOCK_DAYS,
                kms_key_id=config.AUDIT_ANCHOR_S3_KMS_KEY_ID or None,
            )
        except Exception:  # noqa: BLE001 - fail closed on client/config errors
            logger.error("Audit checkpoint store initialization failed")
    return UnavailableCheckpointStore()
