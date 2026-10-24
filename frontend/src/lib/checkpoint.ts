import type { HealthResponse } from '../types';

/**
 * Checkpoint controls are only truthful when the backend can prove all of the
 * following: the scheduler is healthy, the adapter is external, the
 * destination is independent of this deployment, and independence has been
 * verified.
 */
export function isCheckpointAnchoringOperational(
  health: HealthResponse | null | undefined,
): boolean {
  const anchor = health?.components?.audit_anchor;
  if (!anchor) {
    return false;
  }
  return (
    anchor.status === 'ok' &&
    anchor.available === true &&
    anchor.external_adapter === true &&
    anchor.independent === true &&
    anchor.independence_verified === true
  );
}
