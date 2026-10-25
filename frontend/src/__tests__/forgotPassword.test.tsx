/** Login-page OTP password reset tests with mocked auth. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import ForgotPasswordPage from '../pages/ForgotPassword';
import type { UserResponse } from '../types';

vi.mock('../auth', () => ({
  getMe: vi.fn(),
  requestPasswordReset: vi.fn(),
  verifyPasswordResetOtp: vi.fn(),
  confirmPasswordReset: vi.fn(),
}));

import * as auth from '../auth';

const mockGetMe = vi.mocked(auth.getMe);
const mockRequestPasswordReset = vi.mocked(auth.requestPasswordReset);
const mockVerifyPasswordResetOtp = vi.mocked(auth.verifyPasswordResetOtp);
const mockConfirmPasswordReset = vi.mocked(auth.confirmPasswordReset);

const SIGNED_IN_USER: UserResponse = {
  id: 'usr_1',
  email: 'ada@example.com',
  full_name: 'Ada Lovelace',
  role: 'owner',
  is_active: true,
  must_change_password: false,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/forgot-password']}>
      <Routes>
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/" element={<div>Workspace home</div>} />
        <Route path="/login" element={<div>Login destination</div>} />
        <Route path="/change-password" element={<div>Change password destination</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockGetMe.mockResolvedValue(null);
});

describe('ForgotPasswordPage', () => {
  it('walks through email, code, and new password in order', async () => {
    const user = userEvent.setup();
    mockRequestPasswordReset.mockResolvedValue(
      'If an account exists, a code has been sent.',
    );
    mockVerifyPasswordResetOtp.mockResolvedValue();
    mockConfirmPasswordReset.mockResolvedValue('Password successfully reset.');
    renderPage();

    await user.type(await screen.findByLabelText('Email'), 'Ada@Example.com');
    await user.click(screen.getByRole('button', { name: 'Send one-time code' }));

    expect(mockRequestPasswordReset).toHaveBeenCalledWith('ada@example.com');
    await user.type(await screen.findByLabelText('One-time code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Verify code' }));

    expect(mockVerifyPasswordResetOtp).toHaveBeenCalledWith(
      'ada@example.com',
      '123456',
    );
    await user.type(await screen.findByLabelText('New password'), 'New!SecurePass99');
    await user.type(screen.getByLabelText('Confirm new password'), 'New!SecurePass99');
    await user.click(screen.getByRole('button', { name: 'Reset password' }));

    expect(mockConfirmPasswordReset).toHaveBeenCalledWith(
      'ada@example.com',
      '123456',
      'New!SecurePass99',
    );
    expect(await screen.findByText('Password updated')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Go to sign in' })).toBeInTheDocument();
  });

  it('rejects a mismatched confirmation without calling the API', async () => {
    const user = userEvent.setup();
    mockRequestPasswordReset.mockResolvedValue('Sent.');
    mockVerifyPasswordResetOtp.mockResolvedValue();
    renderPage();

    await user.type(await screen.findByLabelText('Email'), 'ada@example.com');
    await user.click(screen.getByRole('button', { name: 'Send one-time code' }));
    await user.type(await screen.findByLabelText('One-time code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Verify code' }));
    await user.type(await screen.findByLabelText('New password'), 'New!SecurePass99');
    await user.type(screen.getByLabelText('Confirm new password'), 'Other!SecurePass99');
    await user.click(screen.getByRole('button', { name: 'Reset password' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The passwords do not match.',
    );
    expect(mockConfirmPasswordReset).not.toHaveBeenCalled();
  });

  it('sends signed-in users to the workspace instead of showing recovery', async () => {
    mockGetMe.mockResolvedValue(SIGNED_IN_USER);
    renderPage();

    expect(await screen.findByText('Workspace home')).toBeInTheDocument();
  });
});
