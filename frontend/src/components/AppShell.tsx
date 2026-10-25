import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import type { ReactNode } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { motion } from 'motion/react';
import type { UserResponse } from '../types';
import { logout } from '../auth';
import { describeError, getInitials, roleLabel } from '../lib/format';
import { navigationGroupsForRole, pageTitleFor } from '../lib/navigation';
import CommandPalette from './CommandPalette';
import IconButton from './IconButton';
import Menu from './Menu';
import NotificationBell from './NotificationBell';
import PageTransition from './motion/PageTransition';
import {
  CloseIcon,
  FileIcon,
  LogOutIcon,
  MenuIcon,
  SearchIcon,
  SettingsIcon,
  ShieldIcon,
} from './Icons';

interface AppShellProps {
  user: UserResponse;
  children: ReactNode;
}

const MOBILE_QUERY = '(max-width: 960px)';
const SIDEBAR_PREFERENCE_KEY = 'trustvault.sidebar.collapsed';
const DRAWER_FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function readSidebarPreference(): boolean {
  if (typeof window === 'undefined') {
    return true;
  }
  try {
    const stored = window.localStorage.getItem(SIDEBAR_PREFERENCE_KEY);
    return stored === null ? true : stored === 'true';
  } catch {
    return true;
  }
}

function storeSidebarPreference(collapsed: boolean): void {
  try {
    window.localStorage.setItem(SIDEBAR_PREFERENCE_KEY, String(collapsed));
  } catch {
    // Storage can be unavailable in hardened browser contexts.
  }
}

function subscribeToMediaQuery(onChange: () => void): () => void {
  if (typeof window.matchMedia !== 'function') {
    return () => undefined;
  }
  const query = window.matchMedia(MOBILE_QUERY);
  query.addEventListener('change', onChange);
  return () => query.removeEventListener('change', onChange);
}

function getMobileSnapshot(): boolean {
  if (typeof window.matchMedia !== 'function') {
    return false;
  }
  return window.matchMedia(MOBILE_QUERY).matches;
}

function getMobileServerSnapshot(): boolean {
  return false;
}

function useIsMobile(): boolean {
  return useSyncExternalStore(
    subscribeToMediaQuery,
    getMobileSnapshot,
    getMobileServerSnapshot,
  );
}

export default function AppShell({ user, children }: AppShellProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const isMobile = useIsMobile();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerPath, setDrawerPath] = useState(location.pathname);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const [sidebarPreference, setSidebarPreference] = useState(readSidebarPreference);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  const drawerVisible = isMobile && drawerOpen && drawerPath === location.pathname;
  const sidebarCollapsed = !isMobile && sidebarPreference;
  const pageTitle = pageTitleFor(location.pathname);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen((open) => !open);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  useEffect(() => {
    if (!drawerVisible) {
      return;
    }
    let focusAttempts = 0;
    let focusTimer = 0;
    const focusCloseButton = () => {
      const closeButton = closeButtonRef.current;
      if (!closeButton) {
        return;
      }
      if (window.getComputedStyle(closeButton).visibility === 'visible' || focusAttempts >= 20) {
        closeButton.focus();
        return;
      }
      focusAttempts += 1;
      focusTimer = window.setTimeout(focusCloseButton, 16);
    };
    focusTimer = window.setTimeout(focusCloseButton, 0);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const sidebar = document.getElementById('app-sidebar');
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setDrawerOpen(false);
        menuButtonRef.current?.focus();
        return;
      }
      if (event.key !== 'Tab' || !sidebar) {
        return;
      }
      const focusable = Array.from(
        sidebar.querySelectorAll<HTMLElement>(DRAWER_FOCUSABLE),
      );
      if (focusable.length === 0) {
        event.preventDefault();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      window.clearTimeout(focusTimer);
      document.body.style.overflow = previousOverflow;
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [drawerVisible]);

  const openDrawer = () => {
    setDrawerPath(location.pathname);
    setDrawerOpen(true);
  };

  const closeDrawer = () => {
    setDrawerOpen(false);
    menuButtonRef.current?.focus();
  };

  const toggleNavigation = () => {
    if (isMobile) {
      openDrawer();
      return;
    }
    setSidebarPreference((collapsed) => {
      storeSidebarPreference(!collapsed);
      return !collapsed;
    });
  };

  const handleLogout = async () => {
    setLogoutError(null);
    setLoggingOut(true);
    try {
      await logout();
      navigate('/login', { replace: true });
    } catch (err: unknown) {
      setLoggingOut(false);
      setLogoutError(describeError(err, 'Logout failed. Please try again.'));
    }
  };

  const signOut = () => {
    setDrawerOpen(false);
    void handleLogout();
  };

  const drawerHidden = !drawerVisible && isMobile;
  const groups = navigationGroupsForRole(user.role);

  return (
    <div className={`app-shell${sidebarCollapsed ? ' is-sidebar-collapsed' : ''}`}>
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>

      <aside
        id="app-sidebar"
        className={`sidebar${drawerVisible ? ' is-open' : ''}${sidebarCollapsed ? ' is-collapsed' : ''}`}
        data-collapsed={sidebarCollapsed || undefined}
        aria-hidden={drawerHidden || undefined}
        inert={drawerHidden || undefined}
      >
        <div className="sidebar-head">
          {!isMobile && (
            <IconButton
              ref={menuButtonRef}
              label={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'}
              className="sidebar-menu-toggle"
              aria-expanded={!sidebarCollapsed}
              aria-controls="app-sidebar"
              onClick={toggleNavigation}
            >
              <MenuIcon />
            </IconButton>
          )}
          <IconButton
            ref={closeButtonRef}
            label="Close navigation"
            className="sidebar-close"
            onClick={closeDrawer}
          >
            <CloseIcon />
          </IconButton>
        </div>

        <nav className="sidebar-nav" aria-label="Primary">
          {groups.map((group) => (
            <div className="nav-group" key={group.label}>
              <p className="nav-section-label">{group.label}</p>
              {group.items.map((item) => {
                const Icon = item.icon;
                const index = groups
                  .flatMap((entry) => entry.items)
                  .findIndex((entry) => entry.to === item.to);
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.end}
                    className={({ isActive }) => `nav-link${isActive ? ' is-active' : ''}`}
                    aria-label={item.label}
                    title={sidebarCollapsed ? item.label : undefined}
                    onClick={() => setDrawerOpen(false)}
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && (
                          <motion.span
                            layoutId="nav-active"
                            className="nav-active-pill"
                            transition={{ type: 'spring', stiffness: 460, damping: 40 }}
                            aria-hidden="true"
                          />
                        )}
                        <Icon className="nav-icon" />
                        <span>{item.label}</span>
                        <span className="nav-index" aria-hidden="true">
                          {String(index + 1).padStart(2, '0')}
                        </span>
                      </>
                    )}
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-security">
            <span className="security-dot" aria-hidden="true" />
            <div>
              <p className="sidebar-security-title">Session verified</p>
              <p className="sidebar-security-copy">HttpOnly · CSRF protected</p>
            </div>
          </div>
          <div
            className="user-card"
            title={sidebarCollapsed ? `${user.full_name} · ${roleLabel(user.role)}` : undefined}
          >
            <span className="avatar" aria-hidden="true">
              {getInitials(user.full_name)}
            </span>
            <span className="user-card-copy">
              <span className="user-card-name">{user.full_name}</span>
              <span className="user-card-role">{roleLabel(user.role)}</span>
            </span>
          </div>
          <button
            type="button"
            className="btn btn-ghost btn-full sidebar-logout"
            aria-label={loggingOut ? 'Signing out' : 'Logout'}
            onClick={signOut}
            disabled={loggingOut}
            title={sidebarCollapsed ? 'Logout' : undefined}
          >
            <LogOutIcon width={17} height={17} />
            <span className="sidebar-logout-label">
              {loggingOut ? 'Signing out…' : 'Logout'}
            </span>
          </button>
        </div>
      </aside>

      {drawerVisible && (
        <button
          type="button"
          className="sidebar-backdrop"
          aria-label="Close navigation overlay"
          onClick={closeDrawer}
        />
      )}

      <div className="app-main">
        <header className="topbar">
          {isMobile && (
            <IconButton
              ref={menuButtonRef}
              label="Open navigation"
              className="sidebar-toggle"
              aria-expanded={drawerVisible}
              aria-controls="app-sidebar"
              onClick={toggleNavigation}
            >
              <MenuIcon />
            </IconButton>
          )}

          <Link to="/" className="brand topbar-brand" aria-label="TrustVault overview">
            <span className="brand-mark">
              <ShieldIcon width={19} height={19} />
            </span>
            <span className="brand-copy topbar-brand-copy">
              <span className="brand-name">TrustVault</span>
              <span className="brand-tagline">Private document workspace</span>
            </span>
          </Link>

          <nav className="breadcrumbs" aria-label="Breadcrumb">
            <Link to="/" className="breadcrumb-root">
              Workspace
            </Link>
            <span aria-hidden="true" className="breadcrumb-separator">
              /
            </span>
            <span aria-current="page">{pageTitle}</span>
          </nav>

          <span className="topbar-status">Session verified</span>

          <div className="topbar-actions">
            <button
              type="button"
              className="command-trigger"
              aria-label="Open command palette"
              aria-keyshortcuts="Control+K Meta+K"
              title="Open command palette (Ctrl or Cmd + K)"
              onClick={() => setPaletteOpen(true)}
            >
              <SearchIcon />
              <span className="command-trigger-label">Search or jump to</span>
              <kbd className="command-kbd">Ctrl K</kbd>
            </button>
            <NotificationBell />
            <span className="topbar-divider" aria-hidden="true" />
            <Menu
              label="Account menu"
              triggerLabel={`Account menu for ${user.full_name}`}
              trigger={
                <>
                  <span className="avatar" aria-hidden="true">
                    {getInitials(user.full_name)}
                  </span>
                  <span className="account-trigger-copy">
                    <span className="account-trigger-name">{user.full_name}</span>
                    <span className="account-trigger-role">{roleLabel(user.role)}</span>
                  </span>
                </>
              }
              items={[
                {
                  id: 'documents',
                  label: 'My documents',
                  icon: FileIcon,
                  to: '/documents',
                },
                {
                  id: 'settings',
                  label: 'Account settings',
                  icon: SettingsIcon,
                  to: '/settings',
                },
                {
                  id: 'sign-out',
                  label: 'Sign out',
                  icon: LogOutIcon,
                  onSelect: signOut,
                  danger: true,
                },
              ]}
            />
          </div>
        </header>

        {logoutError && (
          <div className="alert alert-error shell-alert" role="alert">
            {logoutError}
          </div>
        )}

        <main id="main-content" className="page-content">
          <PageTransition>{children}</PageTransition>
        </main>
      </div>

      {paletteOpen && (
        <CommandPalette role={user.role} onClose={() => setPaletteOpen(false)} />
      )}
    </div>
  );
}
