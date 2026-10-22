"""Construct the configured local audit checkpoint store."""

import logging

from backend.app.config import Settings
from backend.app.services.checkpoint_store import (
    CheckpointStore,
    LocalFileCheckpointStore,
    UnavailableCheckpointStore,
)

logger = logging.getLogger(__name__)


def create_checkpoint_store(config: Settings) -> CheckpointStore:
    """Instantiate the adapter selected by ``AUDIT_ANCHOR_MODE``."""
    if config.AUDIT_ANCHOR_MODE == "local_file":
        try:
            return LocalFileCheckpointStore(
                config.resolved_audit_anchor_path,
                config.AUDIT_ANCHOR_HMAC_KEY.encode("utf-8"),
            )
        except (OSError, ValueError):
            logger.error("Audit checkpoint store initialization failed")
    return UnavailableCheckpointStore()
