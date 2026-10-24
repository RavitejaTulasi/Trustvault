"""Transactional state changes for globally owned storage keys."""

from sqlalchemy import update
from sqlalchemy.orm import Session

from backend.app.models.storage_object import StorageObject


def transition_storage_object(
    db: Session,
    storage_key: str,
    expected_state: str | tuple[str, ...],
    new_state: str,
) -> None:
    expected_states = (
        (expected_state,) if isinstance(expected_state, str) else expected_state
    )
    result = db.execute(
        update(StorageObject)
        .where(
            StorageObject.storage_key == storage_key,
            StorageObject.state.in_(expected_states),
        )
        .values(state=new_state)
        .execution_options(synchronize_session="fetch")
    )
    if result.rowcount != 1:
        raise RuntimeError("Storage object state transition was not owned")
