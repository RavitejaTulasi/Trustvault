import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { login, getMe } from '../auth';
import { ApiError, NetworkError } from '../api';
import { ChevronLeftIcon, ShieldIcon } from '../components/Icons';
import InteractiveSurface from '../components/motion/InteractiveSurface';
import MagneticButton from '../components/motion/MagneticButton';

/**
 * Build the session-restoration banner text. HTTP 401 never reaches this:
 * getMe() resolves null for it (an ordinary logged-out session, no banner).
 * Anything rejected here is a genuine server (5xx) or network failure, so the
 * exact cause is surfaced instead of hidden; the form stays usable because the
 * backend may have recovered by the time the user submits.
 */
function describeRestoreError(err: unknown): string {
  if (err instanceof ApiError) {
    return err.detail;
  }
  if (err instanceof NetworkError) {
    return err.message;
  }
  return 'Could not check your session. You can still try signing in.';
}

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [restoreError, setRestoreError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  // Restore session: an already-authenticated visitor skips the login form.
  // HTTP 401 (resolved as null above) is the normal logged-out case and shows
  // no banner; other failures must be visible, so they are surfaced below
  // without preventing sign-in attempts.
  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((user) => {
        if (user && !cancelled) {
          navigate(user.must_change_password ? '/change-password' : '/', {
            replace: true,
          });
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setRestoreError(describeRestoreError(err));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [navigate]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const user = await login(email, password);
      navigate(user.must_change_password ? '/change-password' : '/', {
        replace: true,
      });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail);
      } else if (err instanceof NetworkError) {
        setError(err.message);
      } else {
        setError('Login failed. Please try again.');
      }
    } finally {
      setSubmitting(false);
    }
  };

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
          <span className="auth-kicker">Private by default</span>
          <h1 className="auth-headline">A private room for consequential work.</h1>
          <p className="auth-subhead">
            Sign in to a workspace where every document request is checked against your
            current permissions, not a cached idea of them.
          </p>
          <div className="auth-feature-list">
            <div className="auth-feature">
              <span className="auth-feature-icon">
                <ShieldIcon width={17} height={17} />
              </span>
              <div>
                <p className="auth-feature-title">Server-enforced access</p>
                <p className="auth-feature-copy">
                  Visibility, editing, and sharing are re-validated with every request.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <main className="auth-panel">
        <InteractiveSurface className="auth-card">
          <Link to="/" className="auth-back">
            <ChevronLeftIcon width={13} height={13} />
            Back to home
          </Link>

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
            <p className="eyebrow">Workspace access</p>
            <h1 className="auth-title">Open your vault.</h1>
            <p className="auth-subtitle">
              Use the email and password associated with your workspace account.
            </p>
          </header>

          {restoreError && (
            <div role="status" className="alert alert-warning">
              <p>{restoreError}</p>
              <p>You can still try signing in.</p>
            </div>
          )}

          {error && (
            <div role="alert" className="alert alert-error">
              {error}
            </div>
          )}

          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="field">
              <label htmlFor="login-email">Email</label>
              <input
                id="login-email"
                className="input"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                placeholder="you@example.com"
              />
            </div>
            <div className="field">
              <label htmlFor="login-password">Password</label>
              <input
                id="login-password"
                className="input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
                placeholder="Your password"
              />
            </div>
            <MagneticButton
              type="submit"
              className="btn btn-primary btn-block"
              disabled={submitting}
            >
              {submitting ? 'Signing in.' : 'Sign in'}
            </MagneticButton>
          </form>

          <p className="auth-alt">
            New to TrustVault? <Link to="/register">Create an account</Link>
          </p>

          <p className="auth-concept-note">
            Session cookies are HttpOnly and state-changing requests require a CSRF
            token. Access decisions remain on the server.
          </p>
        </InteractiveSurface>
      </main>
    </div>
  );
}
