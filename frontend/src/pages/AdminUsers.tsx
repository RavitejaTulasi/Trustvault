import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import AppShell from '../components/AppShell';
import Dialog from '../components/Dialog';
import EmptyState from '../components/EmptyState';
import PageHeader from '../components/PageHeader';
import { StatusBadge } from '../components/Badges';
import { useToast } from '../components/useToast';
import {
  BadgeCheckIcon,
  EyeIcon,
  EyeOffIcon,
  KeyIcon,
  PlusIcon,
  RefreshIcon,
  ShieldAlertIcon,
  UsersIcon,
} from '../components/Icons';
import { useSession } from '../hooks/useSession';
import {
  createUser,
  listUsers,
  resetUserPassword,
  revokeUserSessions,
  updateUser,
} from '../api';
import { ApiError } from '../api';
import { describeError, formatDate, getInitials, roleLabel } from '../lib/format';
import type { Role, UserResponse } from '../types';

const PAGE_SIZE = 25;
const ROLES: Role[] = ['viewer', 'owner', 'admin'];
const PASSWORD_RULES = [
  { label: '12+ characters', test: (value: string) => value.length >= 12 },
  { label: 'Uppercase', test: (value: string) => /[A-Z]/.test(value) },
  { label: 'Lowercase', test: (value: string) => /[a-z]/.test(value) },
  { label: 'Number', test: (value: string) => /\d/.test(value) },
  {
    label: 'Symbol',
    test: (value: string) =>
      value.split('').some((char) => "!@#$%^&*()_+-=[]{}|;':\",./<>?".includes(char)),
  },
];

interface CreateAccountForm {
  fullName: string;
  email: string;
  password: string;
  confirmPassword: string;
  role: Role;
}

const EMPTY_ACCOUNT: CreateAccountForm = {
  fullName: '',
  email: '',
  password: '',
  confirmPassword: '',
  role: 'viewer',
};

type PendingAction = { userId: string; kind: 'deactivate' | 'revoke' };

export default function AdminUsers() {
  const navigate = useNavigate();
  const { user, loading: sessionLoading, error: sessionError, reload } = useSession();
  const { pushToast } = useToast();

  const [users, setUsers] = useState<UserResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState<CreateAccountForm>(EMPTY_ACCOUNT);
  const [createError, setCreateError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [showCreatePassword, setShowCreatePassword] = useState(false);
  const [adminConfirmed, setAdminConfirmed] = useState(false);
  const [resetTarget, setResetTarget] = useState<UserResponse | null>(null);
  const [resetValue, setResetValue] = useState('');
  const [resetConfirm, setResetConfirm] = useState('');
  const [showResetPassword, setShowResetPassword] = useState(false);
  const [resetError, setResetError] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);
  const requestRef = useRef(0);
  const createNameRef = useRef<HTMLInputElement>(null);
  const resetPasswordRef = useRef<HTMLInputElement>(null);

  const isAdmin = user?.role === 'admin';

  const loadUsers = useCallback(
    async (targetPage: number) => {
      const request = requestRef.current + 1;
      requestRef.current = request;
      setLoading(true);
      setLoadError(null);
      setPending(null);
      try {
        const result = await listUsers({ page: targetPage, page_size: PAGE_SIZE });
        if (request !== requestRef.current) {
          return;
        }
        setUsers(result.users);
        setTotal(result.total);
        setPage(result.page);
      } catch (err) {
        if (request !== requestRef.current) {
          return;
        }
        if (err instanceof ApiError && err.status === 401) {
          navigate('/login', { replace: true });
          return;
        }
        setLoadError(describeError(err, 'Could not load accounts'));
      } finally {
        if (request === requestRef.current) {
          setLoading(false);
        }
      }
    },
    [navigate],
  );

  useEffect(() => {
    if (isAdmin) {
      // eslint-disable-next-line react/set-state-in-effect -- page fetch reflects server state after session load
      void loadUsers(1);
    }
  }, [isAdmin, loadUsers]);

  const replaceUser = (updated: UserResponse) => {
    setUsers((current) =>
      current.map((item) => (item.id === updated.id ? updated : item)),
    );
  };

  const handleRoleChange = async (target: UserResponse, role: Role) => {
    if (role === target.role) {
      return;
    }
    setActionError(null);
    setBusy(target.id);
    try {
      const updated = await updateUser(target.id, { role });
      replaceUser(updated);
      pushToast({
        title: 'Role updated',
        description: `${updated.full_name} is now ${roleLabel(updated.role)}.`,
        tone: 'success',
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        navigate('/login', { replace: true });
        return;
      }
      setActionError(describeError(err, 'Could not update this account'));
    } finally {
      setBusy(null);
    }
  };

  const handleActiveChange = async (target: UserResponse, isActive: boolean) => {
    setActionError(null);
    setPending(null);
    setBusy(target.id);
    try {
      const updated = await updateUser(target.id, { is_active: isActive });
      replaceUser(updated);
      pushToast({
        title: isActive ? 'Account activated' : 'Account deactivated',
        description: isActive
          ? `${updated.full_name} can sign in again.`
          : `${updated.full_name} is signed out and cannot sign in until reactivated.`,
        tone: isActive ? 'success' : 'info',
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        navigate('/login', { replace: true });
        return;
      }
      setActionError(describeError(err, 'Could not update this account'));
    } finally {
      setBusy(null);
    }
  };

  const handleRevokeSessions = async (target: UserResponse) => {
    setActionError(null);
    setPending(null);
    setBusy(target.id);
    try {
      const result = await revokeUserSessions(target.id);
      pushToast({
        title: 'Sessions revoked',
        description:
          result.sessions_revoked === 1
            ? `1 active session of ${target.full_name} was invalidated.`
            : `${result.sessions_revoked} active sessions of ${target.full_name} were invalidated.`,
        tone: 'success',
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        navigate('/login', { replace: true });
        return;
      }
      setActionError(describeError(err, 'Could not revoke sessions'));
    } finally {
      setBusy(null);
    }
  };

  const updateCreateField = <Key extends keyof CreateAccountForm>(
    key: Key,
    value: CreateAccountForm[Key],
  ) => {
    setCreateForm((current) => ({ ...current, [key]: value }));
  };

  const openCreateDialog = () => {
    setCreateForm(EMPTY_ACCOUNT);
    setCreateError(null);
    setShowCreatePassword(false);
    setAdminConfirmed(false);
    setCreateOpen(true);
  };

  const closeCreateDialog = () => {
    if (!creating) {
      setCreateOpen(false);
    }
  };

  const createRulesMet = PASSWORD_RULES.map((rule) => rule.test(createForm.password));
  const createPasswordValid = createRulesMet.every(Boolean);

  const handleCreateAccount = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setCreateError(null);

    if (createForm.fullName.trim().length < 2) {
      setCreateError('Enter a full name (at least 2 characters).');
      return;
    }
    if (!createPasswordValid) {
      setCreateError('Choose an initial password that meets every requirement.');
      return;
    }
    if (createForm.password !== createForm.confirmPassword) {
      setCreateError('The passwords do not match.');
      return;
    }
    if (createForm.role === 'admin' && !adminConfirmed) {
      setCreateError('Confirm the administrator access before creating this account.');
      return;
    }

    setCreating(true);
    try {
      const created = await createUser({
        full_name: createForm.fullName.trim(),
        email: createForm.email.trim(),
        password: createForm.password,
        role: createForm.role,
        is_active: true,
      });
      setCreateOpen(false);
      setCreateForm(EMPTY_ACCOUNT);
      setShowCreatePassword(false);
      setAdminConfirmed(false);
      pushToast({
        title: 'Account created',
        description: `${created.full_name} can sign in as ${roleLabel(created.role)}.`,
        tone: 'success',
      });
      void loadUsers(1);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        navigate('/login', { replace: true });
        return;
      }
      setCreateError(describeError(err, 'Could not create this account'));
    } finally {
      setCreating(false);
    }
  };

  const resetRulesMet = PASSWORD_RULES.map((rule) => rule.test(resetValue));
  const resetPasswordValid = resetRulesMet.every(Boolean);

  const openResetDialog = (target: UserResponse) => {
    setResetTarget(target);
    setResetValue('');
    setResetConfirm('');
    setResetError(null);
    setShowResetPassword(false);
  };

  const closeResetDialog = () => {
    if (!resetting) {
      setResetTarget(null);
    }
  };

  const handleResetPassword = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setResetError(null);
    if (!resetTarget) {
      return;
    }
    if (!resetPasswordValid) {
      setResetError('Choose a new password that meets every requirement.');
      return;
    }
    if (resetValue !== resetConfirm) {
      setResetError('The passwords do not match.');
      return;
    }

    setResetting(true);
    try {
      const result = await resetUserPassword(resetTarget.id, resetValue);
      const sessionCount = result.sessions_revoked;
      setResetTarget(null);
      setResetValue('');
      setResetConfirm('');
      setShowResetPassword(false);
      pushToast({
        title: 'Password reset',
        description:
          sessionCount === 1
            ? `${resetTarget.full_name}'s password was replaced and 1 active session was signed out. Share the new password securely.`
            : `${resetTarget.full_name}'s password was replaced and ${sessionCount} active sessions were signed out. Share the new password securely.`,
        tone: 'success',
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        navigate('/login', { replace: true });
        return;
      }
      setResetError(describeError(err, 'Could not reset this account password'));
    } finally {
      setResetting(false);
    }
  };

  if (sessionLoading) {
    return (
      <div className="booting" aria-busy="true">
        <span className="brand-mark">
          <UsersIcon width={24} height={24} />
        </span>
        <p>Loading account administration�?�</p>
      </div>
    );
  }

  if (sessionError || !user) {
    return (
      <main className="page-content">
        <div className="panel">
          <div className="panel-body">
            <div role="alert" className="alert alert-error">
              {sessionError ?? 'Could not load your session'}
            </div>
            <button type="button" className="btn btn-primary" onClick={() => void reload()}>
              <RefreshIcon width={17} height={17} />
              Retry
            </button>
          </div>
        </div>
      </main>
    );
  }

  if (!isAdmin) {
    return (
      <AppShell user={user}>
        <PageHeader
          eyebrow="Administration"
          title="User management"
          description="Account administration is restricted to administrators."
          backTo="/"
          backLabel="Overview"
        />
        <div className="panel">
          <EmptyState
            title="Administrator access required"
            description="Your account does not have permission to manage users. No account data was requested."
            action={
              <Link to="/" className="btn btn-secondary btn-sm">
                Back to overview
              </Link>
            }
          />
        </div>
      </AppShell>
    );
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const hasPrev = page > 1 && !loading;
  const hasNext = page < totalPages && !loading;

  return (
    <AppShell user={user}>
      <PageHeader
        eyebrow="Administration"
        title="User management"
        description="Create accounts, assign roles, control activation, reset passwords, and revoke sessions. Every change is recorded in the audit trail."
        backTo="/"
        backLabel="Overview"
        actions={
          <button type="button" className="btn btn-primary" onClick={openCreateDialog}>
            <PlusIcon width={16} height={16} />
            Create user
          </button>
        }
      />

      {actionError && (
        <div role="alert" className="alert alert-error">
          {actionError}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => void loadUsers(page)}
          >
            Reload accounts
          </button>
        </div>
      )}

      {loadError && (
        <div role="alert" className="alert alert-error">
          {loadError}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => void loadUsers(page)}
          >
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div className="panel" aria-busy="true">
          <div className="skeleton-table">
            {[0, 1, 2, 3, 4].map((row) => (
              <div key={row} className="skeleton skeleton-line" />
            ))}
          </div>
        </div>
      ) : users.length === 0 ? (
        <div className="panel">
          <EmptyState
            title="No accounts"
            description="No registered accounts were returned for this page."
          />
        </div>
      ) : (
        <>
          <div className="table-wrap">
            <table>
              <caption>{total} registered accounts</caption>
              <thead>
                <tr>
                  <th scope="col">Account</th>
                  <th scope="col">Role</th>
                  <th scope="col">Status</th>
                  <th scope="col" className="hide-sm">
                    Registered
                  </th>
                  <th scope="col">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {users.map((account) => {
                  const isSelf = account.id === user.id;
                  const isBusy = busy === account.id;
                  const isArmed =
                    pending?.userId === account.id && pending.kind === 'deactivate';
                  const revokeArmed =
                    pending?.userId === account.id && pending.kind === 'revoke';

                  return (
                    <tr key={account.id}>
                      <td>
                        <div className="user-cell">
                          <span className="avatar avatar-sm" aria-hidden="true">
                            {getInitials(account.full_name)}
                          </span>
                          <div className="cell-title">
                            <span>
                              {account.full_name}
                              {isSelf && <span className="cell-sub"> · you</span>}
                            </span>
                            <span className="cell-sub">{account.email}</span>
                          </div>
                        </div>
                      </td>
                      <td>
                        <label className="sr-only" htmlFor={`role-${account.id}`}>
                          Role for {account.full_name}
                        </label>
                        <select
                          id={`role-${account.id}`}
                          className="select select-sm"
                          value={account.role}
                          disabled={isSelf || isBusy}
                          title={
                            isSelf
                              ? 'Administrators cannot remove their own admin role'
                              : undefined
                          }
                          onChange={(event) =>
                            void handleRoleChange(account, event.target.value as Role)
                          }
                        >
                          {ROLES.map((role) => (
                            <option key={role} value={role}>
                              {roleLabel(role)}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <StatusBadge
                          label={account.is_active ? 'Active' : 'Inactive'}
                          tone={account.is_active ? 'success' : 'danger'}
                        />
                      </td>
                      <td className="hide-sm">{formatDate(account.created_at)}</td>
                      <td>
                        <div className="cell-actions">
                          {!isSelf && (
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              disabled={isBusy}
                              onClick={() => openResetDialog(account)}
                            >
                              <KeyIcon width={14} height={14} />
                              Reset password
                            </button>
                          )}
                          {account.is_active ? (
                            isArmed ? (
                              <>
                                <button
                                  type="button"
                                  className="btn btn-danger btn-sm"
                                  disabled={isBusy}
                                  onClick={() => void handleActiveChange(account, false)}
                                >
                                  {isBusy ? 'Deactivating…' : 'Confirm deactivate'}
                                </button>
                                <button
                                  type="button"
                                  className="btn btn-ghost btn-sm"
                                  disabled={isBusy}
                                  onClick={() => setPending(null)}
                                >
                                  Cancel
                                </button>
                              </>
                            ) : (
                              <button
                                type="button"
                                className="btn btn-secondary btn-sm"
                                disabled={isBusy}
                                onClick={() =>
                                  setPending({ userId: account.id, kind: 'deactivate' })
                                }
                              >
                                Deactivate
                              </button>
                            )
                          ) : (
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              disabled={isBusy}
                              onClick={() => void handleActiveChange(account, true)}
                            >
                              {isBusy ? 'Activating…' : 'Activate'}
                            </button>
                          )}
                          {revokeArmed ? (
                            <>
                              <button
                                type="button"
                                className="btn btn-danger btn-sm"
                                disabled={isBusy}
                                onClick={() => void handleRevokeSessions(account)}
                              >
                                {isBusy ? 'Revoking…' : 'Confirm revoke'}
                              </button>
                              <button
                                type="button"
                                className="btn btn-ghost btn-sm"
                                disabled={isBusy}
                                onClick={() => setPending(null)}
                              >
                                Cancel
                              </button>
                            </>
                          ) : (
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              disabled={isBusy}
                              onClick={() => setPending({ userId: account.id, kind: 'revoke' })}
                            >
                              <ShieldAlertIcon width={14} height={14} />
                              Revoke sessions
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="table-meta">
            <span>
              <BadgeCheckIcon width={13} height={13} /> Deactivation and session revocation take
              effect immediately
            </span>
            <nav className="pagination" aria-label="User pagination">
              <span className="pagination-info">
                Page {page} of {totalPages}
              </span>
              <div className="pagination-controls">
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  disabled={!hasPrev}
                  onClick={() => void loadUsers(page - 1)}
                >
                  Previous
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  disabled={!hasNext}
                  onClick={() => void loadUsers(page + 1)}
                >
                  Next
                </button>
              </div>
            </nav>
          </div>
        </>
      )}

      {createOpen && (
        <Dialog
          label="Create user"
          description="The account can sign in immediately with the initial password you set."
          onClose={closeCreateDialog}
          initialFocusRef={createNameRef}
        >
          <form className="auth-form" onSubmit={handleCreateAccount}>
            {createError && (
              <div role="alert" className="alert alert-error">
                {createError}
              </div>
            )}

            <div className="field">
              <label htmlFor="create-user-name">Full name</label>
              <input
                ref={createNameRef}
                id="create-user-name"
                className="input"
                type="text"
                value={createForm.fullName}
                onChange={(event) => updateCreateField('fullName', event.target.value)}
                autoComplete="name"
                maxLength={255}
                required
              />
            </div>

            <div className="field">
              <label htmlFor="create-user-email">Email</label>
              <input
                id="create-user-email"
                className="input"
                type="email"
                value={createForm.email}
                onChange={(event) => updateCreateField('email', event.target.value)}
                autoComplete="off"
                placeholder="person@example.com"
                required
              />
            </div>

            <div className="field">
              <label htmlFor="create-user-role">Initial role</label>
              <select
                id="create-user-role"
                className="select"
                value={createForm.role}
                onChange={(event) => {
                  updateCreateField('role', event.target.value as Role);
                  setAdminConfirmed(false);
                }}
              >
                {ROLES.map((role) => (
                  <option key={role} value={role}>
                    {roleLabel(role)}
                  </option>
                ))}
              </select>
            </div>

            {createForm.role === 'admin' && (
              <label className="check-row" htmlFor="create-user-admin-confirm">
                <input
                  id="create-user-admin-confirm"
                  type="checkbox"
                  checked={adminConfirmed}
                  onChange={(event) => setAdminConfirmed(event.target.checked)}
                />
                <span>I confirm this account should have full administrator access.</span>
              </label>
            )}

            <div className="field">
              <label htmlFor="create-user-password">Initial password</label>
              <div className="input-wrap">
                <input
                  id="create-user-password"
                  className="input"
                  type={showCreatePassword ? 'text' : 'password'}
                  value={createForm.password}
                  onChange={(event) => updateCreateField('password', event.target.value)}
                  autoComplete="new-password"
                  minLength={12}
                  maxLength={128}
                  required
                />
                <button
                  type="button"
                  className="input-action"
                  aria-label={showCreatePassword ? 'Hide password' : 'Show password'}
                  aria-pressed={showCreatePassword}
                  onClick={() => setShowCreatePassword((visible) => !visible)}
                >
                  {showCreatePassword ? (
                    <EyeOffIcon width={18} height={18} />
                  ) : (
                    <EyeIcon width={18} height={18} />
                  )}
                </button>
              </div>
              <div className="password-strength" aria-label="Password requirements">
                {PASSWORD_RULES.map((rule, index) => (
                  <span
                    key={rule.label}
                    className={`strength-pill${createRulesMet[index] ? ' is-met' : ''}`}
                  >
                    {createRulesMet[index] ? '✓ ' : ''}
                    {rule.label}
                  </span>
                ))}
              </div>
            </div>

            <div className="field">
              <label htmlFor="create-user-confirm">Confirm password</label>
              <input
                id="create-user-confirm"
                className="input"
                type={showCreatePassword ? 'text' : 'password'}
                value={createForm.confirmPassword}
                onChange={(event) =>
                  updateCreateField('confirmPassword', event.target.value)
                }
                autoComplete="new-password"
                required
              />
            </div>

            <p className="field-hint">
              Share the initial password through a secure channel. It is not shown again.
            </p>

            <div className="form-actions">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={closeCreateDialog}
                disabled={creating}
              >
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={creating}>
                {creating ? 'Creating…' : 'Create account'}
              </button>
            </div>
          </form>
        </Dialog>
      )}

      {resetTarget && (
        <Dialog
          label="Reset password"
          description={`Set a replacement password for ${resetTarget.full_name} (${resetTarget.email}).`}
          onClose={closeResetDialog}
          initialFocusRef={resetPasswordRef}
        >
          <form className="auth-form" onSubmit={handleResetPassword}>
            {resetError && (
              <div role="alert" className="alert alert-error">
                {resetError}
              </div>
            )}

            <div className="field">
              <label htmlFor="reset-user-password">New password</label>
              <div className="input-wrap">
                <input
                  ref={resetPasswordRef}
                  id="reset-user-password"
                  className="input"
                  type={showResetPassword ? 'text' : 'password'}
                  value={resetValue}
                  onChange={(event) => setResetValue(event.target.value)}
                  autoComplete="new-password"
                  minLength={12}
                  maxLength={128}
                  required
                />
                <button
                  type="button"
                  className="input-action"
                  aria-label={showResetPassword ? 'Hide password' : 'Show password'}
                  aria-pressed={showResetPassword}
                  onClick={() => setShowResetPassword((visible) => !visible)}
                >
                  {showResetPassword ? (
                    <EyeOffIcon width={18} height={18} />
                  ) : (
                    <EyeIcon width={18} height={18} />
                  )}
                </button>
              </div>
              <div className="password-strength" aria-label="Password requirements">
                {PASSWORD_RULES.map((rule, index) => (
                  <span
                    key={rule.label}
                    className={`strength-pill${resetRulesMet[index] ? ' is-met' : ''}`}
                  >
                    {resetRulesMet[index] ? '✓ ' : ''}
                    {rule.label}
                  </span>
                ))}
              </div>
            </div>

            <div className="field">
              <label htmlFor="reset-user-confirm">Confirm new password</label>
              <input
                id="reset-user-confirm"
                className="input"
                type={showResetPassword ? 'text' : 'password'}
                value={resetConfirm}
                onChange={(event) => setResetConfirm(event.target.value)}
                autoComplete="new-password"
                required
              />
            </div>

            <p className="field-hint">
              The current password cannot be viewed. This replaces it immediately and signs
              out every active session for {resetTarget.full_name}. Share the new password
              through a secure channel.
            </p>

            <div className="form-actions">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={closeResetDialog}
                disabled={resetting}
              >
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={resetting}>
                {resetting ? 'Resetting…' : 'Reset password'}
              </button>
            </div>
          </form>
        </Dialog>
      )}
    </AppShell>
  );
}
