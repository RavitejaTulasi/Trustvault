import { useId } from 'react';
import type { DemoAccount, Role } from '../types';

const ROLE_LABELS: Record<Role, string> = {
  admin: 'Administrator',
  owner: 'Document owner',
  viewer: 'Viewer',
};

interface DemoAccountsProps {
  accounts: DemoAccount[];
  onSelect: (account: DemoAccount) => void;
  className?: string;
  disabled?: boolean;
}

export default function DemoAccounts({
  accounts,
  onSelect,
  className = '',
  disabled = false,
}: DemoAccountsProps) {
  const titleId = useId();

  if (accounts.length === 0) {
    return null;
  }

  return (
    <section
      className={`demo-accounts${className ? ` ${className}` : ''}`}
      aria-labelledby={titleId}
    >
      <p className="demo-accounts-kicker">Staging only</p>
      <h2 className="demo-accounts-title" id={titleId}>
        Explore TrustVault
      </h2>
      <p className="demo-accounts-copy">
        Choose a role to fill the sign-in form. You still sign in normally.
      </p>
      <div className="demo-account-list">
        {accounts.map((account) => {
          const roleLabel = ROLE_LABELS[account.role] ?? account.role;
          return (
            <button
              key={account.role}
              type="button"
              className="demo-account"
              onClick={() => onSelect(account)}
              disabled={disabled}
              aria-label={`Use ${roleLabel} demo account, ${account.email}`}
            >
              <span className="demo-account-role">{roleLabel}</span>
              <span className="demo-account-email">{account.email}</span>
            </button>
          );
        })}
      </div>
      <p className="demo-accounts-note">
        Credentials are supplied by the staging server at runtime.
      </p>
    </section>
  );
}
