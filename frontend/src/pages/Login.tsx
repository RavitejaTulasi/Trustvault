import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { login, getMe } from '../auth';
import { ApiError, NetworkError } from '../api';

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
        if (user && !cancelled) navigate('/dashboard', { replace: true });
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
      await login(email, password);
      navigate('/dashboard', { replace: true });
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
    <main className="login-page">
      <h2>Sign in</h2>
      {restoreError && (
        <div role="status" className="restore-notice">
          <p>{restoreError}</p>
          <p>You can still try signing in.</p>
        </div>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="login-email">Email</label>
          <input
            id="login-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="email"
            placeholder="you@example.com"
          />
        </div>
        <div>
          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
            placeholder="Password"
          />
        </div>
        <button type="submit" disabled={submitting}>
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}
