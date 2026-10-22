import type { EffectivePermission } from '../types';

export type BadgeTone = 'success' | 'warning' | 'danger' | 'info' | 'neutral';

export function PermissionBadge({ permission }: { permission: EffectivePermission }) {
  return <span className={`badge badge-${permission}`}>{permission}</span>;
}

export function OutcomeBadge({ outcome }: { outcome: string }) {
  const normalized = outcome.toUpperCase();
  const tone =
    normalized === 'SUCCESS' ? 'success' : normalized === 'DENIED' ? 'warning' : 'danger';
  return <span className={`badge badge-outcome-${tone}`}>{normalized}</span>;
}

export function StatusBadge({
  label,
  tone = 'neutral',
}: {
  label: string;
  tone?: BadgeTone;
}) {
  return (
    <span className={`badge badge-${tone}`}>
      <span className="badge-dot" aria-hidden="true" />
      {label}
    </span>
  );
}
