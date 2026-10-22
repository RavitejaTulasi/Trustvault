import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getMe } from '../auth';
import { describeError } from '../lib/format';
import type { UserResponse } from '../types';

interface SessionState {
  user: UserResponse | null;
  loading: boolean;
  error: string | null;
  setUser: (user: UserResponse) => void;
  reload: () => Promise<void>;
}

/**
 * Resolve the current server-side session once per page mount.
 * HTTP 401 resolves to null and redirects to /login; server or network errors
 * stay on the page with a retry path so they are never mistaken for logout.
 */
export function useSession(): SessionState {
  const navigate = useNavigate();
  const [user, setUser] = useState<UserResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const session = await getMe();
      if (session === null) {
        navigate('/login', { replace: true });
        return;
      }
      if (session.must_change_password) {
        navigate('/change-password', { replace: true });
        return;
      }
      setUser(session);
      setLoading(false);
    } catch (err: unknown) {
      setLoading(false);
      setError(describeError(err, 'Could not load your session'));
    }
  }, [navigate]);

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect -- initial session hydration must run on mount
    void reload();
  }, [reload]);

  return { user, loading, error, setUser, reload };
}
