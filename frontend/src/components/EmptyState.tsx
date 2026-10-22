import type { ReactNode } from 'react';
import { InboxIcon } from './Icons';

interface EmptyStateProps {
  title: string;
  description: string;
  action?: ReactNode;
}

export default function EmptyState({ title, description, action }: EmptyStateProps) {
  return (
    <div className="empty-state">
      <span className="empty-state-icon" aria-hidden="true">
        <InboxIcon width={26} height={26} />
      </span>
      <h2 className="empty-state-title">{title}</h2>
      <p className="empty-state-copy">{description}</p>
      {action && <div className="empty-state-action">{action}</div>}
    </div>
  );
}
