/**
 * COMPONENT tests for administrator user management. The auth and api modules
 * are mocked so no backend runs.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { ToastProvider } from '../components/Toast';
import AdminUsers from '../pages/AdminUsers';
import type { UserListResponse, UserResponse } from '../types';

vi.mock('../auth', () => ({
  getMe: vi.fn(),
  logout: vi.fn(),
}));

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api');
  return {
    ...actual,
    listUsers: vi.fn(),
    createUser: vi.fn(),
    resetUserPassword: vi.fn(),
    updateUser: vi.fn(),
    revokeUserSessions: vi.fn(),
  };
});

import * as auth from '../auth';
import * as api from '../api';

const mockGetMe = vi.mocked(auth.getMe);
const mockListUsers = vi.mocked(api.listUsers);
const mockCreateUser = vi.mocked(api.createUser);
const mockResetUserPassword = vi.mocked(api.resetUserPassword);
const mockUpdateUser = vi.mocked(api.updateUser);
const mockRevokeUserSessions = vi.mocked(api.revokeUserSessions);

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

const OWNER: UserResponse = {
  id: 'usr_owner',
  email: 'ada@example.com',
  full_name: 'Ada Lovelace',
  role: 'owner',
  is_active: true,
  must_change_password: false,
  created_at: '2026-01-02T00:00:00Z',
  updated_at: '2026-01-02T00:00:00Z',
};

function listResponse(overrides: Partial<UserListResponse> = {}): UserListResponse {
  return {
    users: [OWNER],
    total: 1,
    page: 1,
    page_size: 25,
    ...overrides,
  };
}

function renderPage() {
  return render(
    <ToastProvider>
      <MemoryRouter initialEntries={['/admin/users']}>
        <Routes>
          <Route path="/admin/users" element={<AdminUsers />} />
        </Routes>
      </MemoryRouter>
    </ToastProvider>,
  );
}

describe('AdminUsers (component)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('blocks non-administrators without requesting account data', async () => {
    mockGetMe.mockResolvedValue({ ...OWNER, role: 'owner' });
    renderPage();

    expect(await screen.findByText('Administrator access required')).toBeInTheDocument();
    expect(mockListUsers).not.toHaveBeenCalled();
  });

  it('lists accounts and paginates through the server response', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListUsers
      .mockResolvedValueOnce(listResponse({ total: 30 }))
      .mockResolvedValueOnce(
        listResponse({
          users: [{ ...OWNER, id: 'usr_2', full_name: 'Bob Viewer', role: 'viewer' }],
          total: 30,
          page: 2,
        }),
      );

    renderPage();

    expect(await screen.findByText('Ada Lovelace')).toBeInTheDocument();
    expect(screen.getByText('30 registered accounts')).toBeInTheDocument();
    expect(mockListUsers).toHaveBeenCalledWith({ page: 1, page_size: 25 });

    await user.click(screen.getByRole('button', { name: 'Next' }));

    expect(await screen.findByText('Bob Viewer')).toBeInTheDocument();
    expect(mockListUsers).toHaveBeenCalledWith({ page: 2, page_size: 25 });
    expect(screen.getByText('Page 2 of 2')).toBeInTheDocument();
  });

  it('updates a role and reports the result', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListUsers.mockResolvedValue(listResponse());
    mockUpdateUser.mockResolvedValue({ ...OWNER, role: 'admin' });

    renderPage();

    const roleSelect = await screen.findByLabelText('Role for Ada Lovelace');
    await user.selectOptions(roleSelect, 'admin');

    await waitFor(() => {
      expect(mockUpdateUser).toHaveBeenCalledWith('usr_owner', { role: 'admin' });
    });
    expect(await screen.findByText('Role updated')).toBeInTheDocument();
  });

  it('creates an account with an initial password and role', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListUsers.mockResolvedValue(listResponse());
    mockCreateUser.mockResolvedValue({
      ...OWNER,
      id: 'usr_new',
      email: 'new.owner@example.com',
      full_name: 'New Owner',
      role: 'owner',
    });

    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Create user' }));
    const dialog = screen.getByRole('dialog', { name: 'Create user' });
    await user.type(screen.getByLabelText('Full name'), 'New Owner');
    await user.type(screen.getByLabelText('Email'), 'new.owner@example.com');
    await user.selectOptions(screen.getByLabelText('Initial role'), 'owner');
    await user.type(screen.getByLabelText('Initial password'), 'Initial!Secure#Pass2');
    await user.type(screen.getByLabelText('Confirm password'), 'Initial!Secure#Pass2');
    await user.click(screen.getByRole('button', { name: 'Create account' }));

    await waitFor(() => {
      expect(mockCreateUser).toHaveBeenCalledWith({
        full_name: 'New Owner',
        email: 'new.owner@example.com',
        password: 'Initial!Secure#Pass2',
        role: 'owner',
        is_active: true,
      });
    });
    expect(await screen.findByText('Account created')).toBeInTheDocument();
    expect(dialog).not.toBeInTheDocument();
    expect(mockListUsers).toHaveBeenLastCalledWith({ page: 1, page_size: 25 });
  });

  it('requires explicit confirmation before creating an administrator', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListUsers.mockResolvedValue(listResponse());
    mockCreateUser.mockResolvedValue({
      ...OWNER,
      id: 'usr_new_admin',
      email: 'new.admin@example.com',
      full_name: 'New Admin',
      role: 'admin',
    });

    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Create user' }));
    await user.type(screen.getByLabelText('Full name'), 'New Admin');
    await user.type(screen.getByLabelText('Email'), 'new.admin@example.com');
    await user.selectOptions(screen.getByLabelText('Initial role'), 'admin');
    await user.type(screen.getByLabelText('Initial password'), 'Initial!Secure#Pass2');
    await user.type(screen.getByLabelText('Confirm password'), 'Initial!Secure#Pass2');
    await user.click(screen.getByRole('button', { name: 'Create account' }));

    expect(
      await screen.findByText('Confirm the administrator access before creating this account.'),
    ).toBeInTheDocument();
    expect(mockCreateUser).not.toHaveBeenCalled();

    await user.click(
      screen.getByRole('checkbox', {
        name: 'I confirm this account should have full administrator access.',
      }),
    );
    await user.click(screen.getByRole('button', { name: 'Create account' }));

    await waitFor(() => {
      expect(mockCreateUser).toHaveBeenCalledWith({
        full_name: 'New Admin',
        email: 'new.admin@example.com',
        password: 'Initial!Secure#Pass2',
        role: 'admin',
        is_active: true,
      });
    });
  });

  it('resets another account password and reports revoked sessions', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListUsers.mockResolvedValue(listResponse());
    mockResetUserPassword.mockResolvedValue({ user_id: 'usr_owner', sessions_revoked: 2 });

    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Reset password' }));
    const dialog = screen.getByRole('dialog', { name: 'Reset password' });
    expect(dialog).toHaveTextContent('Ada Lovelace');
    expect(dialog).toHaveTextContent('ada@example.com');

    await user.type(screen.getByLabelText('New password'), 'Reset!Secure#Pass3');
    await user.type(screen.getByLabelText('Confirm new password'), 'Reset!Secure#Pass3');
    await user.click(within(dialog).getByRole('button', { name: 'Reset password' }));

    await waitFor(() => {
      expect(mockResetUserPassword).toHaveBeenCalledWith('usr_owner', 'Reset!Secure#Pass3');
    });
    expect(await screen.findByText('Password reset')).toBeInTheDocument();
    expect(screen.getByText(/2 active sessions were signed out/)).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: 'Reset password' })).not.toBeInTheDocument();
  });

  it('keeps the reset dialog open when the new passwords differ', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListUsers.mockResolvedValue(listResponse());

    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Reset password' }));
    const dialog = screen.getByRole('dialog', { name: 'Reset password' });
    await user.type(screen.getByLabelText('New password'), 'Reset!Secure#Pass3');
    await user.type(screen.getByLabelText('Confirm new password'), 'Different!Secure#Pass4');
    await user.click(within(dialog).getByRole('button', { name: 'Reset password' }));

    expect(await screen.findByText('The passwords do not match.')).toBeInTheDocument();
    expect(mockResetUserPassword).not.toHaveBeenCalled();
  });

  it('keeps the create dialog open and reports duplicate emails', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListUsers.mockResolvedValue(listResponse());
    mockCreateUser.mockRejectedValue(
      new api.ApiError(409, 'An account with this email already exists'),
    );

    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Create user' }));
    await user.type(screen.getByLabelText('Full name'), 'New Owner');
    await user.type(screen.getByLabelText('Email'), 'new.owner@example.com');
    await user.type(screen.getByLabelText('Initial password'), 'Initial!Secure#Pass2');
    await user.type(screen.getByLabelText('Confirm password'), 'Initial!Secure#Pass2');
    await user.click(screen.getByRole('button', { name: 'Create account' }));

    expect(
      await screen.findByText('An account with this email already exists'),
    ).toBeInTheDocument();
    expect(screen.getByRole('dialog', { name: 'Create user' })).toBeInTheDocument();
  });

  it('requires confirmation before deactivating an account', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListUsers.mockResolvedValue(listResponse());
    mockUpdateUser.mockResolvedValue({ ...OWNER, is_active: false });

    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Deactivate' }));
    expect(mockUpdateUser).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Confirm deactivate' }));

    await waitFor(() => {
      expect(mockUpdateUser).toHaveBeenCalledWith('usr_owner', { is_active: false });
    });
    expect(await screen.findByText('Account deactivated')).toBeInTheDocument();
  });

  it('revokes sessions only after confirmation and reports the count', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListUsers.mockResolvedValue(listResponse());
    mockRevokeUserSessions.mockResolvedValue({ user_id: 'usr_owner', sessions_revoked: 3 });

    renderPage();

    await user.click(await screen.findByRole('button', { name: 'Revoke sessions' }));
    expect(mockRevokeUserSessions).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Confirm revoke' }));

    await waitFor(() => {
      expect(mockRevokeUserSessions).toHaveBeenCalledWith('usr_owner');
    });
    expect(await screen.findByText('Sessions revoked')).toBeInTheDocument();
    expect(
      screen.getByText('3 active sessions of Ada Lovelace were invalidated.'),
    ).toBeInTheDocument();
  });

  it('disables the role control on the administrator’s own row', async () => {
    mockGetMe.mockResolvedValue(ADMIN);
    mockListUsers.mockResolvedValue(
      listResponse({ users: [OWNER, ADMIN], total: 2 }),
    );

    renderPage();

    expect(await screen.findByLabelText('Role for Admin User')).toBeDisabled();
    expect(screen.getByLabelText('Role for Ada Lovelace')).toBeEnabled();
  });
});
