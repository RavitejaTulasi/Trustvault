/** Mandatory password-change page tests with mocked auth. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import ChangePasswordPage from '../pages/ChangePassword';
import { ApiError } from '../api';
import type { UserResponse } from '../types';

vi.mock('../auth', () => ({
  getMe: vi.fn(),
  changePassword: vi.fn(),
  logout: vi.fn(),
}));

import * as auth from '../auth';

const mockGetMe = vi.mocked(auth.getMe);
const mockChangePassword = vi.mocked(auth.changePassword);
const mockLogout = vi.mocked(auth.logout);

const FLAGGED_USER: UserResponse = {
  id: 'usr_temp',
  email: 'new.member@example.com',
  full_name: 'New Member',
  role: 'viewer',
  is_active: true,
  must_change_password: true,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/change-password']}>
      <Routes>
        <Route path="/change-password" element={<ChangePasswordPage />} />
        <Route path="/" element={<div>Workspace home</div>} />
        <Route path="/login" element={<div>Login destination</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mockGetMe.mockReset();
  mockChangePassword.mockReset();
  mockLogout.mockReset();
  mockGetMe.mockResolvedValue(FLAGGED_USER);
});

describe('ChangePasswordPage', () => {
  it('requires a temporary password, a new password, and confirmation', async () => {
    renderPage();

    expect(await screen.findByLabelText('Temporary password')).toBeInTheDocument();
    expect(screen.getByLabelText('New password')).toBeInTheDocument();
    expect(screen.getByLabelText('Confirm new password')).toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: 'Update password and continue' }),
    ).toBeInTheDocument();
  });

  it('rejects a mismatched confirmation before calling the API', async () => {
    const user = userEvent.setup();
    renderPage();

    await user.type(
      await screen.findByLabelText('Temporary password'),
      'Temporary!Pass1',
    );
    await user.type(screen.getByLabelText('New password'), 'Changed!Pass2');
    await user.type(screen.getByLabelText('Confirm new password'), 'Different!Pass3');
    await user.click(screen.getByRole('button', { name: 'Update password and continue' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The new passwords do not match.',
    );
    expect(mockChangePassword).not.toHaveBeenCalled();
  });

  it('shows the backend error when the temporary password is rejected', async () => {
    const user = userEvent.setup();
    mockChangePassword.mockRejectedValue(
      new ApiError(400, 'Current password is incorrect'),
    );
    renderPage();

    await user.type(await screen.findByLabelText('Temporary password'), 'Wrong!Pass1');
    await user.type(screen.getByLabelText('New password'), 'Changed!Pass2');
    await user.type(screen.getByLabelText('Confirm new password'), 'Changed!Pass2');
    await user.click(screen.getByRole('button', { name: 'Update password and continue' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Current password is incorrect',
    );
  });

  it('changes the password and enters the workspace', async () => {
    const user = userEvent.setup();
    mockChangePassword.mockResolvedValue({
      ...FLAGGED_USER,
      must_change_password: false,
    });
    renderPage();

    await user.type(
      await screen.findByLabelText('Temporary password'),
      'Temporary!Pass1',
    );
    await user.type(screen.getByLabelText('New password'), 'Changed!Pass2');
    await user.type(screen.getByLabelText('Confirm new password'), 'Changed!Pass2');
    await user.click(screen.getByRole('button', { name: 'Update password and continue' }));

    await expect(mockChangePassword).toHaveBeenCalledWith(
      'Temporary!Pass1',
      'Changed!Pass2',
    );
    expect(await screen.findByText('Workspace home')).toBeInTheDocument();
  });

  it('redirects users who are not flagged back into the workspace', async () => {
    mockGetMe.mockResolvedValue({ ...FLAGGED_USER, must_change_password: false });
    renderPage();

    expect(await screen.findByText('Workspace home')).toBeInTheDocument();
  });

  it('redirects an expired session to sign in', async () => {
    mockGetMe.mockResolvedValue(null);
    renderPage();

    expect(await screen.findByText('Login destination')).toBeInTheDocument();
  });
});
