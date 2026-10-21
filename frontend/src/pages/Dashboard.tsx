import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { getMe, logout } from '../auth';
import { ApiError, NetworkError } from '../api';
import type { UserResponse } from '../types';

export default function Dashboard() {
  const [user, setUser] = useState<UserResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const navigate = useNavigate();

  const loadSession = () => {
    setLoading(true);
    setLoadError(null);
    getMe()
      .then((session) => {
        if (session) {
          setUser(session);
          setLoading(false);
        } else {
          navigate('/login', { replace: true });
        }
      })
      .catch((err: unknown) => {
        // 5xx / network failures stay on the dashboard with a retry option;
        // they must NOT be treated as an unauthenticated session.
        setLoading(false);
        if (err instanceof ApiError) {
          setLoadError(err.detail);
        } else if (err instanceof NetworkError) {
          setLoadError(err.message);
        } else {
          setLoadError('Could not load your session');
        }
      });
  };

  useEffect(() => {
    loadSession();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navigate]);

  const handleLogout = async () => {
    setLoggingOut(true);
    setLogoutError(null);
    try {
      await logout();
      navigate('/login', { replace: true });
    } catch (err) {
      // The session cookie is still set, so the user is NOT logged out.
      setLoggingOut(false);
      if (err instanceof ApiError) {
        setLogoutError(err.detail);
      } else if (err instanceof NetworkError) {
        setLogoutError(err.message);
      } else {
        setLogoutError('Logout failed. Please try again.');
      }
    }
  };

  if (loading) {
    return (
      <main className="dashboard" aria-busy="true">
        <p>Loading…</p>
      </main>
    );
  }

  if (loadError) {
    return (
      <main className="dashboard">
        <p role="alert" className="error">
          {loadError}
        </p>
        <button type="button" onClick={loadSession}>
          Retry
        </button>
      </main>
    );
  }

  return (
    <main className="dashboard">
      <h2>Welcome, {user?.full_name}</h2>
      <p>
        Email: {user?.email} · Role: {user?.role}
      </p>
      <p>
        <Link to="/documents">View documents</Link>
      </p>
      {logoutError && (
        <p role="alert" className="error">
          {logoutError}
        </p>
      )}
      <button type="button" onClick={handleLogout} disabled={loggingOut}>
        {loggingOut ? 'Signing out…' : 'Logout'}
      </button>
    </main>
  );
}
