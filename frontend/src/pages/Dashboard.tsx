import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, useReducedMotion } from 'motion/react';
import { getMe } from '../auth';
import { ApiError, NetworkError } from '../api';
import type { UserResponse } from '../types';
import AppShell from '../components/AppShell';
import PageHeader from '../components/PageHeader';
import OverviewVault from '../components/motion/OverviewVault';
import PointerSpotlight from '../components/motion/PointerSpotlight';
import { StatusBadge } from '../components/Badges';
import {
  ActivityIcon,
  ArrowRightIcon,
  FileIcon,
  KeyIcon,
  SettingsIcon,
  ShareIcon,
  ShieldIcon,
  UsersIcon,
} from '../components/Icons';
import { canManageDocuments } from '../lib/navigation';
import { formatDate, getInitials, roleLabel } from '../lib/format';

export default function Dashboard({ initialUser }: { initialUser?: UserResponse | null } = {}) {
  const [user, setUser] = useState<UserResponse | null>(initialUser ?? null);
  const [loading, setLoading] = useState(initialUser === undefined);
  const [loadError, setLoadError] = useState<string | null>(null);
  const navigate = useNavigate();
  const reduceMotion = useReducedMotion();

  const loadSession = () => {
    setLoading(true);
    setLoadError(null);
    getMe()
      .then((session) => {
        if (session) {
          if (session.must_change_password) {
            navigate('/change-password', { replace: true });
            return;
          }
          setUser(session);
          setLoading(false);
        } else {
          navigate('/login', { replace: true });
        }
      })
      .catch((err: unknown) => {
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
    if (initialUser === undefined) {
      loadSession();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialUser, navigate]);

  if (loading) {
    return (
      <div className="booting" aria-busy="true">
        <span className="brand-mark">
          <ShieldIcon width={24} height={24} />
        </span>
        <p>Loading your workspaceâ€¦</p>
      </div>
    );
  }

  if (loadError) {
    return (
      <main className="standalone-state">
        <p role="alert" className="alert alert-error">
          {loadError}
        </p>
        <button type="button" className="btn btn-primary" onClick={loadSession}>
          Retry
        </button>
      </main>
    );
  }

  if (!user) {
    return (
      <main className="standalone-state" aria-busy="true">
        <p className="section-copy">Loading your sessionâ€¦</p>
      </main>
    );
  }

  const canManage = canManageDocuments(user.role);

  return (
    <AppShell user={user}>
      <div className="dashboard">
        <PageHeader
          eyebrow="Overview"
          title="Workspace overview"
          description="Your session, access, and the shortcuts that matter. Every visibility decision is enforced by the server."
        />

        <motion.section
          className="overview-hero motion-surface"
          aria-labelledby="overview-hero-title"
          data-pointer-surface
          initial={reduceMotion ? false : { opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.65, ease: [0.16, 1, 0.3, 1] }}
        >
          <div className="overview-hero-copy">
            <div className="overview-status">
              <StatusBadge label="Session verified" tone="success" />
              <StatusBadge label={`${roleLabel(user.role)} account`} tone="neutral" />
            </div>
            <p className="overview-welcome">Welcome, {user.full_name}</p>
            <h2 id="overview-hero-title" className="overview-title">
              Sensitive work, visible only where it belongs.
            </h2>
            <p className="overview-lede">
              Open your library, review what has been shared with you, and keep access
              explicit. Your role and available actions come directly from the signed-in
              session.
            </p>
            <div className="overview-actions">
              <Link to="/documents" className="btn btn-primary">
                Open documents
                <ArrowRightIcon width={16} height={16} />
              </Link>
              <Link
                to={canManage ? '/access' : '/shared'}
                className="btn btn-secondary"
              >
                {canManage ? 'Review sharing' : 'View shared files'}
              </Link>
            </div>
          </div>

          <div className="overview-hero-art">
            <OverviewVault />
          </div>
          <PointerSpotlight />
        </motion.section>

        <div className="overview-grid">
          <section className="panel" aria-labelledby="account-overview-title">
            <div className="panel-header">
              <div>
                <h2 id="account-overview-title" className="panel-title">
                  Account
                </h2>
                <p className="panel-description">Identity returned by the server session.</p>
              </div>
              <span className="avatar" aria-hidden="true">
                {getInitials(user.full_name)}
              </span>
            </div>
            <div className="panel-body">
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
                  <span className="account-value">{formatDate(user.created_at)}</span>
                </div>
                <div className="account-row">
                  <span className="account-key">Status</span>
                  <StatusBadge
                    label={user.is_active ? 'Active' : 'Inactive'}
                    tone={user.is_active ? 'success' : 'warning'}
                  />
                </div>
              </div>
            </div>
          </section>

          <section className="panel" aria-labelledby="quick-actions-title">
            <div className="panel-header">
              <div>
                <h2 id="quick-actions-title" className="panel-title">
                  Quick actions
                </h2>
                <p className="panel-description">Pages available to your role.</p>
              </div>
            </div>
            <div className="panel-body">
              <div className="quick-actions">
                <Link to="/documents" className="quick-action">
                  <span className="quick-action-icon">
                    <FileIcon />
                  </span>
                  <span className="quick-action-copy">
                    <span className="quick-action-title">My documents</span>
                    <span className="quick-action-description">Search and open files</span>
                  </span>
                  <ArrowRightIcon />
                </Link>
                <Link to="/shared" className="quick-action">
                  <span className="quick-action-icon">
                    <ShareIcon />
                  </span>
                  <span className="quick-action-copy">
                    <span className="quick-action-title">Shared with me</span>
                    <span className="quick-action-description">Files granted to you</span>
                  </span>
                  <ArrowRightIcon />
                </Link>
                {canManage && (
                  <Link to="/access" className="quick-action">
                    <span className="quick-action-icon">
                      <KeyIcon />
                    </span>
                    <span className="quick-action-copy">
                      <span className="quick-action-title">Access & sharing</span>
                      <span className="quick-action-description">Inspect active grants</span>
                    </span>
                    <ArrowRightIcon />
                  </Link>
                )}
                {user.role === 'admin' && (
                  <Link to="/admin/users" className="quick-action">
                    <span className="quick-action-icon">
                      <UsersIcon />
                    </span>
                    <span className="quick-action-copy">
                      <span className="quick-action-title">Users</span>
                      <span className="quick-action-description">Roles and sessions</span>
                    </span>
                    <ArrowRightIcon />
                  </Link>
                )}
                {user.role === 'admin' && (
                  <Link to="/admin/audit" className="quick-action">
                    <span className="quick-action-icon">
                      <ActivityIcon />
                    </span>
                    <span className="quick-action-copy">
                      <span className="quick-action-title">Audit</span>
                      <span className="quick-action-description">Events, document activity, verification</span>
                    </span>
                    <ArrowRightIcon />
                  </Link>
                )}
                <Link to="/settings" className="quick-action">
                  <span className="quick-action-icon">
                    <SettingsIcon />
                  </span>
                  <span className="quick-action-copy">
                    <span className="quick-action-title">Settings</span>
                    <span className="quick-action-description">Profile and password</span>
                  </span>
                  <ArrowRightIcon />
                </Link>
              </div>
            </div>
          </section>

          <section
            className="panel panel-wide card-tilt"
            aria-labelledby="security-overview-title"
          >
            <div className="panel-header">
              <div>
                <h2 id="security-overview-title" className="panel-title">
                  Security posture
                </h2>
                <p className="panel-description">
                  Controls that apply to this workspace as built.
                </p>
              </div>
              <StatusBadge label="Server enforced" tone="info" />
            </div>
            <div className="panel-body">
              <div className="snapshot-list">
                <div className="snapshot-row">
                  <span className="snapshot-label">
                    <ShieldIcon /> Session cookie
                  </span>
                  <span className="snapshot-value">HttpOnly</span>
                </div>
                <div className="snapshot-row">
                  <span className="snapshot-label">
                    <KeyIcon /> CSRF protection
                  </span>
                  <span className="snapshot-value">Required for state changes</span>
                </div>
                <div className="snapshot-row">
                  <span className="snapshot-label">
                    <UsersIcon /> Access checks
                  </span>
                  <span className="snapshot-value">Re-evaluated per request</span>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </AppShell>
  );
}
