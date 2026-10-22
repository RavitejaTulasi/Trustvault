import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { changePassword, getMe, logout } from '../auth';
import RouteFallback from '../components/RouteFallback';
import {
  ChevronLeftIcon,
  EyeIcon,
  EyeOffIcon,
  LockIcon,
  ShieldIcon,
} from '../components/Icons';
import InteractiveSurface from '../components/motion/InteractiveSurface';
import MagneticButton from '../components/motion/MagneticButton';
import { describeError } from '../lib/format';
import type { UserResponse } from '../types';

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

export default function ChangePasswordPage() {
  const navigate = useNavigate();
  const [user, setUser] = useState<UserResponse | null>(null);
  const [checking, setChecking] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((session) => {
        if (cancelled) {
          return;
        }
        if (session === null) {
          navigate('/login', { replace: true });
          return;
        }
        if (!session.must_change_password) {
          navigate('/', { replace: true });
          return;
        }
        setUser(session);
        setChecking(false);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setLoadError(describeError(err, 'Could not verify your session'));
          setChecking(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [navigate]);

  const rulesMet = PASSWORD_RULES.map((rule) => rule.test(newPassword));
  const passwordValid = rulesMet.every(Boolean);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    if (!passwordValid) {
      setError('Choose a password that meets every requirement.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('The new passwords do not match.');
      return;
    }
    if (newPassword === currentPassword) {
      setError('Choose a password different from your temporary password.');
      return;
    }
    setSubmitting(true);
    try {
      await changePassword(currentPassword, newPassword);
      navigate('/', { replace: true });
    } catch (err) {
      setError(describeError(err, 'Could not change your password'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleSignOut = async () => {
    try {
      await logout();
    } finally {
      navigate('/login', { replace: true });
    }
  };

  if (checking) {
    return <RouteFallback />;
  }

  if (loadError || !user) {
    return (
      <main className="standalone-state">
        <div role="alert" className="alert alert-error">
          {loadError ?? 'Your session could not be loaded.'}
        </div>
        <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
          Retry
        </button>
      </main>
    );
  }

  return (
    <div className="auth-layout">
      <section className="auth-brand" aria-label="About TrustVault">
        <div className="auth-brand-inner">
          <Link to="/" className="brand" aria-label="TrustVault home">
            <span className="brand-mark">
              <ShieldIcon width={22} height={22} />
            </span>
            <span className="brand-copy">
              <span className="brand-name">TrustVault</span>
              <span className="brand-tagline">Secure documents</span>
            </span>
          </Link>
          <span className="auth-kicker">Required before entry</span>
          <h1 className="auth-headline">Replace the temporary key.</h1>
          <p className="auth-subhead">
            Your administrator issued a temporary password. Choose a private password
            before opening any document or workspace data.
          </p>
          <div className="auth-feature-list">
            <div className="auth-feature">
              <span className="auth-feature-icon">
                <LockIcon width={17} height={17} />
              </span>
              <div>
                <p className="auth-feature-title">Workspace access stays locked</p>
                <p className="auth-feature-copy">
                  Only account recovery endpoints are available until this change is complete.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <main className="auth-panel">
        <InteractiveSurface className="auth-card">
          <button type="button" className="auth-back" onClick={() => void handleSignOut()}>
            <ChevronLeftIcon width={13} height={13} />
            Sign out
          </button>

          <div className="auth-card-brand">
            <span className="brand">
              <span className="brand-mark">
                <ShieldIcon width={22} height={22} />
              </span>
              <span className="brand-copy">
                <span className="brand-name">TrustVault</span>
                <span className="brand-tagline">Secure documents</span>
              </span>
            </span>
          </div>

          <header className="auth-card-header">
            <p className="eyebrow">Account security</p>
            <h1 className="auth-title">Choose your own password.</h1>
            <p className="auth-subtitle">
              Signed in as <strong>{user.email}</strong>. Enter the temporary password
              once, then set a new one.
            </p>
          </header>

          {error && (
            <div role="alert" className="alert alert-error">
              {error}
            </div>
          )}

          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="field">
              <label htmlFor="temporary-password">Temporary password</label>
              <input
                id="temporary-password"
                className="input"
                type="password"
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
                required
                autoComplete="current-password"
              />
            </div>
            <div className="field">
              <label htmlFor="new-password">New password</label>
              <div className="input-wrap">
                <input
                  id="new-password"
                  className="input"
                  type={showPasswords ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  required
                  minLength={12}
                  maxLength={128}
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className="input-action"
                  aria-label={showPasswords ? 'Hide passwords' : 'Show passwords'}
                  aria-pressed={showPasswords}
                  onClick={() => setShowPasswords((visible) => !visible)}
                >
                  {showPasswords ? (
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
                    {rulesMet[index] ? 'Met: ' : ''}
                    {rule.label}
                  </span>
                ))}
              </div>
            </div>
            <div className="field">
              <label htmlFor="confirm-new-password">Confirm new password</label>
              <input
                id="confirm-new-password"
                className="input"
                type={showPasswords ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                required
                autoComplete="new-password"
              />
            </div>
            <MagneticButton
              type="submit"
              className="btn btn-primary btn-block"
              disabled={submitting}
            >
              {submitting ? 'Updating.' : 'Update password and continue'}
            </MagneticButton>
          </form>

          <p className="auth-concept-note">
            Existing sessions are revoked and a fresh session is issued after the change.
          </p>
        </InteractiveSurface>
      </main>
    </div>
  );
}
