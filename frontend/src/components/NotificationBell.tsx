import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  listNotifications,
  markAllNotificationsRead,
  markNotificationRead,
} from '../api';
import type { NotificationResponse } from '../types';
import IconButton from './IconButton';
import { BellIcon } from './Icons';

const POLL_INTERVAL_MS = 60_000;
const VISIBLE_LIMIT = 10;

function timeAgo(value: string): string {
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) {
    return '';
  }
  const minutes = Math.floor(Math.max(0, Date.now() - then) / 60_000);
  if (minutes < 1) {
    return 'Just now';
  }
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }
  const days = Math.floor(hours / 24);
  if (days < 7) {
    return `${days}d ago`;
  }
  return new Date(value).toLocaleDateString();
}

export default function NotificationBell() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [notifications, setNotifications] = useState<NotificationResponse[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [markingAll, setMarkingAll] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const load = useCallback(async () => {
    try {
      const data = await listNotifications(VISIBLE_LIMIT);
      setNotifications(data.notifications);
      setUnreadCount(data.unread_count);
      setError(null);
    } catch {
      setError('Could not load notifications.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react/set-state-in-effect -- initial inbox fetch reflects server state on mount
    void load();
    const timer = window.setInterval(() => {
      void load();
    }, POLL_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const onPointerDown = (event: MouseEvent | TouchEvent) => {
      const target = event.target;
      if (target instanceof Node && !containerRef.current?.contains(target)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('touchstart', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('touchstart', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  const toggle = () => {
    setOpen((wasOpen) => {
      if (!wasOpen) {
        void load();
      }
      return !wasOpen;
    });
  };

  const handleSelect = async (notification: NotificationResponse) => {
    setOpen(false);
    if (!notification.is_read) {
      setNotifications((current) =>
        current.map((item) =>
          item.id === notification.id ? { ...item, is_read: true } : item,
        ),
      );
      setUnreadCount((count) => Math.max(0, count - 1));
      try {
        await markNotificationRead(notification.id);
      } catch {
        void load();
      }
    }
    if (notification.link) {
      navigate(notification.link);
    }
  };

  const handleMarkAll = async () => {
    if (unreadCount === 0 || markingAll) {
      return;
    }
    setMarkingAll(true);
    try {
      await markAllNotificationsRead();
      setNotifications((current) =>
        current.map((item) => ({ ...item, is_read: true })),
      );
      setUnreadCount(0);
      setError(null);
    } catch {
      setError('Could not mark notifications as read.');
    } finally {
      setMarkingAll(false);
    }
  };

  const label =
    unreadCount > 0 ? `Notifications (${unreadCount} unread)` : 'Notifications';

  return (
    <div className="notification-bell" ref={containerRef}>
      <IconButton
        ref={triggerRef}
        label={label}
        className="notification-trigger"
        aria-haspopup="true"
        aria-expanded={open}
        onClick={toggle}
      >
        <BellIcon />
        {unreadCount > 0 && (
          <span className="notification-count" aria-hidden="true">
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </IconButton>

      {open && (
        <div className="notification-panel" role="dialog" aria-label="Notifications">
          <div className="notification-head">
            <div>
              <p className="notification-title">Notifications</p>
              <p className="notification-subtitle">
                {unreadCount > 0 ? `${unreadCount} unread` : 'All caught up'}
              </p>
            </div>
            <button
              type="button"
              className="notification-mark-all"
              onClick={() => void handleMarkAll()}
              disabled={unreadCount === 0 || markingAll}
            >
              {markingAll ? 'Updating…' : 'Mark all read'}
            </button>
          </div>

          {error && (
            <p role="alert" className="notification-error">
              {error}
            </p>
          )}

          {loading && notifications.length === 0 && (
            <p className="notification-empty">Loading notifications…</p>
          )}

          {!loading && !error && notifications.length === 0 && (
            <p className="notification-empty">Nothing needs your attention.</p>
          )}

          {notifications.length > 0 && (
            <ul className="notification-list">
              {notifications.map((notification) => (
                <li key={notification.id}>
                  <button
                    type="button"
                    className={`notification-item${notification.is_read ? '' : ' is-unread'}`}
                    onClick={() => void handleSelect(notification)}
                  >
                    <span className="notification-dot" aria-hidden="true" />
                    <span className="notification-copy">
                      <span className="notification-item-title">
                        {notification.title}
                      </span>
                      <span className="notification-message">
                        {notification.message}
                      </span>
                      <span className="notification-time">
                        {timeAgo(notification.created_at)}
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
