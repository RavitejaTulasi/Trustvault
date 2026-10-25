import { useState } from 'react';
import type { FormEvent } from 'react';
import { Link } from 'react-router-dom';
import AppShell from '../components/AppShell';
import PageHeader from '../components/PageHeader';
import {
  BadgeCheckIcon,
  EyeIcon,
  EyeOffIcon,
  LockIcon,
  RefreshIcon,
  ShieldIcon,
} from '../components/Icons';
import { useSession } from '../hooks/useSession';
import { changePassword, updateMe } from '../auth';
import { describeError, formatDateTime, getInitials, roleLabel } from '../lib/format';

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

export default function Settings() {
  const { user, loading, error, setUser, reload } = useSession();

  const [fullName, setFullName] = useState('');
  const [nameReady, setNameReady] = useState(false);
  const [savingName, setSavingName] = useState(false);
  const [nameError, setNameError] = useState<string | null>(null);
  const [nameNotice, setNameNotice] = useState<string | null>(null);

  const [currentPassword, setCurrentPassword] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [passwordChanged, setPasswordChanged] = useState(false);

  if (user && !nameReady) {
    setFullName(user.full_name);
    setNameReady(true);
  }

  const rulesMet = PASSWORD_RULES.map((rule) => rule.test(password));
  const passwordValid = rulesMet.every(Boolean);

  const handleProfile = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setNameError(null);
    setNameNotice(null);
    if (fullName.trim().length < 2) {
      setNameError('Enter your full name (at least 2 characters).');
      return;
    }
    if (!user || fullName.trim() === user.full_name) {
      setNameNotice('No changes to save.');
      return;
    }
    setSavingName(true);
    try {
      const updated = await updateMe({ full_name: fullName.trim() });
      setUser(updated);
      setFullName(updated.full_name);
      setNameNotice('Profile updated.');
    } catch (err) {
      setNameError(describeError(err, 'Could not update your profile'));
    } finally {
      setSavingName(false);
    }
  };

  const handlePassword = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPasswordError(null);
    if (!currentPassword) {
      setPasswordError('Enter your current password.');
      return;
    }
    if (!passwordValid) {
      setPasswordError('Choose a password that meets every requirement.');
      return;
    }
    if (password !== confirmPassword) {
      setPasswordError('The passwords do not match.');
      return;
    }
    if (password === currentPassword) {
      setPasswordError('Choose a password different from your current password.');
      return;
    }
    setSavingPassword(true);
    try {
      await changePassword(currentPassword, password);
      // The backend keeps this session active and signs out every other one.
      setCurrentPassword('');
      setPassword('');
      setConfirmPassword('');
      setPasswordChanged(true);
    } catch (err) {
      setPasswordError(describeError(err, 'Could not change your password'));
    } finally {
      setSavingPassword(false);
    }
  };

  if (loading) {
    return (
      <div className="booting" aria-busy="true">
        <span className="brand-mark">
          <LockIcon width={24} height={24} />
        </span>
        <p>Loading account settings…</p>
      </div>
    );
  }

  if (error || !user) {
    return (
      <main className="page-content">
        <div className="panel">
          <div className="panel-body">
            <div role="alert" className="alert alert-error">
              {error ?? 'Could not load your session'}
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

  return (
    <AppShell user={user}>
      <PageHeader
        eyebrow="Account"
        title="Settings"
        description="Manage your profile and credentials, and review the account controls supported by this deployment."
        backTo="/"
        backLabel="Overview"
      />

      <div className="settings-page">
        <section className="panel" aria-labelledby="profile-title">
          <div className="panel-header">
            <div>
              <h2 id="profile-title" className="panel-title">
                Profile
              </h2>
              <p className="panel-description">
                Your display name appears in the workspace navigation.
              </p>
            </div>
          </div>
          <div className="panel-body">
            {nameError && (
              <div role="alert" className="alert alert-error">
                {nameError}
              </div>
            )}
            {nameNotice && (
              <div role="status" className="notice notice-success">
                {nameNotice}
              </div>
            )}
            <form onSubmit={handleProfile}>
              <div className="field">
                <label htmlFor="settings-name">Full name</label>
                <input
                  id="settings-name"
                  className="input"
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  autoComplete="name"
                  minLength={2}
                  maxLength={255}
                  required
                />
              </div>
              <div className="form-actions">
                <button type="submit" className="btn btn-primary" disabled={savingName}>
                  {savingName ? 'Saving…' : 'Save profile'}
                </button>
              </div>
            </form>
          </div>
        </section>

        <section className="panel" aria-labelledby="account-title">
          <div className="panel-header">
            <div>
              <h2 id="account-title" className="panel-title">
                Account
              </h2>
              <p className="panel-description">
                Read-only identity details stored on your account.
              </p>
            </div>
          </div>
          <div className="panel-body">
            <div className="user-card" style={{ marginBottom: 18 }}>
              <span className="avatar" aria-hidden="true">
                {getInitials(user.full_name)}
              </span>
              <span className="user-card-copy">
                <span className="user-card-name">{user.full_name}</span>
                <span className="user-card-role">{user.email}</span>
              </span>
            </div>
            <div className="account-list">
              <div className="account-row">
                <span className="account-key">Email</span>
                <span className="account-value">{user.email}</span>
              </div>
              <div className="account-row">
                <span className="account-key">Role</span>
                <span className="account-value">{roleLabel(user.role)}</span>
              </div>
              <div className="account-row">
                <span className="account-key">Member since</span>
                <span className="account-value">{formatDateTime(user.created_at)}</span>
              </div>
              <div className="account-row">
                <span className="account-key">Status</span>
                <span className="account-value">{user.is_active ? 'Active' : 'Inactive'}</span>
              </div>
            </div>
            <p className="field-hint" style={{ marginTop: 14 }}>
              Email address changes and role assignments are not self-service. Contact an
              administrator if either needs to change.
            </p>
          </div>
        </section>

        <section className="panel" aria-labelledby="security-title">
          <div className="panel-header">
            <div>
              <h2 id="security-title" className="panel-title">
                Security
              </h2>
              <p className="panel-description">
                Changing your password requires your current password. Review the
                controls enforced by the server.
              </p>
            </div>
          </div>
          <div className="panel-body">
            {passwordChanged ? (
              <div className="auth-feature">
                <span className="auth-feature-icon">
                  <BadgeCheckIcon width={18} height={18} />
                </span>
                <div>
                  <h3 className="section-title">Password updated</h3>
                  <p className="section-copy">
                    Your other sessions have been signed out. This session stays active
                    with the new password.
                  </p>
                </div>
              </div>
            ) : (
              <form onSubmit={handlePassword}>
                {passwordError && (
                  <div role="alert" className="alert alert-error">
                    {passwordError}
                  </div>
                )}
                <div className="field">
                  <label htmlFor="settings-current-password">Current password</label>
                  <input
                    id="settings-current-password"
                    className="input"
                    type={showPassword ? 'text' : 'password'}
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    autoComplete="current-password"
                    maxLength={128}
                    required
                  />
                </div>
                <div className="field">
                  <label htmlFor="settings-password">New password</label>
                  <div className="input-wrap">
                    <input
                      id="settings-password"
                      className="input"
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="new-password"
                      minLength={12}
                      maxLength={128}
                      required
                    />
                    <button
                      type="button"
                      className="input-action"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      aria-pressed={showPassword}
                      onClick={() => setShowPassword((visible) => !visible)}
                    >
                      {showPassword ? (
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
                        className={`strength-pill${rulesMet[index] ? ' is-met' : ''}`}
                      >
                        {rulesMet[index] ? '✓ ' : ''}
                        {rule.label}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="field">
                  <label htmlFor="settings-confirm">Confirm new password</label>
                  <input
                    id="settings-confirm"
                    className="input"
                    type={showPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    autoComplete="new-password"
                    required
                  />
                </div>
                <div className="form-actions">
                  <button type="submit" className="btn btn-primary" disabled={savingPassword}>
                    {savingPassword ? 'Updating…' : 'Change password'}
                  </button>
                </div>
              </form>
            )}

            {passwordChanged && (
              <div className="form-actions">
                <Link to="/" className="btn btn-primary">
                  Back to overview
                </Link>
              </div>
            )}

            <div className="settings-scope">
              <h3 className="section-title">Server-enforced controls</h3>
              <div className="snapshot-list">
                <div className="snapshot-row">
                  <span className="snapshot-label">
                    <LockIcon width={14} height={14} /> Session cookie
                  </span>
                  <span className="snapshot-value">HttpOnly</span>
                </div>
                <div className="snapshot-row">
                  <span className="snapshot-label">
                    <ShieldIcon width={14} height={14} /> CSRF protection
                  </span>
                  <span className="snapshot-value">Enabled</span>
                </div>
                <div className="snapshot-row">
                  <span className="snapshot-label">
                    <RefreshIcon width={14} height={14} /> Session revocation
                  </span>
                  <span className="snapshot-value">On password change</span>
                </div>
              </div>
              <p className="field-hint" style={{ marginTop: 14 }}>
                Workspace-wide configuration — database, storage, cookies, and audit anchoring —
                is managed by the deployment environment. It is not editable from this page.
              </p>
            </div>
          </div>
        </section>
      </div>
    </AppShell>
  );
}
