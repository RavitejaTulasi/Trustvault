import type { ReactNode } from 'react';
import BackButton from './BackButton';

interface PageHeaderProps {
  eyebrow?: string;
  title: string;
  description?: string;
  actions?: ReactNode;
  backTo?: string;
  backLabel?: string;
}

export default function PageHeader({
  eyebrow,
  title,
  description,
  actions,
  backTo,
  backLabel,
}: PageHeaderProps) {
  return (
    <div className="page-header">
      <div className="page-header-copy">
        {backTo && <BackButton fallback={backTo} label={backLabel} />}
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h1 className="page-title">{title}</h1>
        {description && <p className="page-description">{description}</p>}
      </div>
      {actions && <div className="page-header-actions">{actions}</div>}
    </div>
  );
}
