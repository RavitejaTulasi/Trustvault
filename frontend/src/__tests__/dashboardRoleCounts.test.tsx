import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import Dashboard from '../pages/Dashboard';
import type { UserResponse } from '../types';

vi.mock('../auth', () => ({
  getMe: vi.fn(),
}));

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api');
  return {
    ...actual,
    getUserRoleCounts: vi.fn(),
    listPendingPermissionRequests: vi.fn(),
    updatePermissionRequestStatus: vi.fn(),
  };
});

import * as api from '../api';

const mockGetUserRoleCounts = vi.mocked(api.getUserRoleCounts);
const mockListPendingPermissionRequests = vi.mocked(api.listPendingPermissionRequests);

const ADMIN: UserResponse = {
  id: 'usr_admin',
  email: 'admin@example.com',
  full_name: 'Admin User',
  role: 'admin',
  is_active: true,
  must_change_password: false,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

const VIEWER: UserResponse = {
  ...ADMIN,
  id: 'usr_viewer',
  email: 'viewer@example.com',
  full_name: 'Viewer User',
  role: 'viewer',
};

beforeEach(() => {
  mockGetUserRoleCounts.mockReset();
  mockListPendingPermissionRequests.mockReset();
  mockGetUserRoleCounts.mockResolvedValue({ admin: 2, owner: 3, viewer: 5 });
  mockListPendingPermissionRequests.mockResolvedValue([]);
});

describe('Dashboard role counts', () => {
  it('shows the role-count card to administrators', async () => {
    render(
      <MemoryRouter>
        <Dashboard initialUser={ADMIN} />
      </MemoryRouter>,
    );

    const card = await screen.findByRole('region', { name: 'Accounts by role' });
    expect(await within(card).findByText('2')).toBeInTheDocument();
    expect(within(card).getByText('3')).toBeInTheDocument();
    expect(within(card).getByText('5')).toBeInTheDocument();
    expect(mockGetUserRoleCounts).toHaveBeenCalledTimes(1);
  });

  it('does not show the role-count card to non-administrators', async () => {
    render(
      <MemoryRouter>
        <Dashboard initialUser={VIEWER} />
      </MemoryRouter>,
    );

    expect(await screen.findByText(/Welcome, Viewer User/)).toBeInTheDocument();
    expect(screen.queryByRole('region', { name: 'Accounts by role' })).not.toBeInTheDocument();
    expect(mockGetUserRoleCounts).not.toHaveBeenCalled();
  });
});
