/** Notification bell behaviour with mocked API calls. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import NotificationBell from '../components/NotificationBell';
import type { NotificationResponse } from '../types';

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api');
  return {
    ...actual,
    listNotifications: vi.fn(),
    markNotificationRead: vi.fn(),
    markAllNotificationsRead: vi.fn(),
  };
});

import * as api from '../api';

const mockListNotifications = vi.mocked(api.listNotifications);
const mockMarkNotificationRead = vi.mocked(api.markNotificationRead);
const mockMarkAllNotificationsRead = vi.mocked(api.markAllNotificationsRead);

const NOTIFICATIONS: NotificationResponse[] = [
  {
    id: 'ntf_1',
    title: 'New permission request',
    message: 'Bob Viewer requested download activity access to "Board minutes".',
    link: '/documents/doc_1',
    is_read: false,
    created_at: new Date(Date.now() - 5 * 60_000).toISOString(),
  },
  {
    id: 'ntf_2',
    title: 'Permission request approved',
    message: 'Your request for "Board minutes" was approved.',
    link: '/documents/doc_1',
    is_read: false,
    created_at: new Date(Date.now() - 90 * 60_000).toISOString(),
  },
];

function renderBell() {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <Routes>
        <Route path="/" element={<NotificationBell />} />
        <Route path="/documents/:id" element={<div>Document destination</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockListNotifications.mockResolvedValue({
    notifications: NOTIFICATIONS,
    unread_count: 2,
  });
  mockMarkNotificationRead.mockResolvedValue({
    ...NOTIFICATIONS[0],
    is_read: true,
  });
  mockMarkAllNotificationsRead.mockResolvedValue(2);
});

describe('NotificationBell', () => {
  it('shows the unread badge and marks every notification as read', async () => {
    const user = userEvent.setup();
    renderBell();

    const trigger = await screen.findByRole('button', {
      name: 'Notifications (2 unread)',
    });
    expect(trigger).toHaveTextContent('2');

    await user.click(trigger);
    expect(screen.getByRole('dialog', { name: 'Notifications' })).toBeInTheDocument();
    expect(screen.getByText('New permission request')).toBeInTheDocument();
    expect(screen.getByText('Permission request approved')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Mark all read' }));

    await waitFor(() => expect(mockMarkAllNotificationsRead).toHaveBeenCalledTimes(1));
    expect(
      await screen.findByRole('button', { name: 'Notifications' }),
    ).toBeInTheDocument();
    expect(screen.getByText('All caught up')).toBeInTheDocument();
  });

  it('marks a selected notification as read and opens its destination', async () => {
    const user = userEvent.setup();
    renderBell();

    await user.click(
      await screen.findByRole('button', { name: 'Notifications (2 unread)' }),
    );
    await user.click(
      screen.getByRole('button', { name: /New permission request/ }),
    );

    await waitFor(() =>
      expect(mockMarkNotificationRead).toHaveBeenCalledWith('ntf_1'),
    );
    expect(await screen.findByText('Document destination')).toBeInTheDocument();
  });
});
