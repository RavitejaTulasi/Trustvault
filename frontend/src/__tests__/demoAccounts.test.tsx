import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import LoginPage from '../pages/Login';
import { ApiError, NetworkError } from '../api';
import type { DemoAccount, UserResponse } from '../types';

vi.mock('../auth', () => ({
  login: vi.fn(),
  getMe: vi.fn(),
  getDemoAccounts: vi.fn(),
  logout: vi.fn(),
}));

import * as auth from '../auth';

const mockLogin = vi.mocked(auth.login);
const mockGetMe = vi.mocked(auth.getMe);
const mockGetDemoAccounts = vi.mocked(auth.getDemoAccounts);

const DEMO_ACCOUNTS: DemoAccount[] = [
  {
    role: 'admin',
    email: 'demo.admin@example.com',
    password: 'DemoAdminPassword123!',
  },
  {
    role: 'owner',
    email: 'demo.owner@example.com',
    password: 'DemoOwnerPassword123!',
  },
  {
    role: 'viewer',
    email: 'demo.viewer@example.com',
    password: 'DemoViewerPassword123!',
  },
];

const SAMPLE_USER: UserResponse = {
  id: 'usr_1',
  email: DEMO_ACCOUNTS[0].email,
  full_name: 'Demo Administrator',
  role: 'admin',
  is_active: true,
  must_change_password: false,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

function renderLogin() {
  return render(
    <MemoryRouter initialEntries={['/login']}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<div>Dashboard region</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mockLogin.mockReset();
  mockGetMe.mockReset();
  mockGetDemoAccounts.mockReset();
  mockGetMe.mockResolvedValue(null);
});

describe('LoginPage demo accounts', () => {
  it('renders the three role buttons supplied by the server', async () => {
    mockGetDemoAccounts.mockResolvedValue(DEMO_ACCOUNTS);

    renderLogin();

    expect(await screen.findAllByText('Explore TrustVault')).toHaveLength(2);
    expect(screen.getAllByText('Administrator').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Document owner').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Viewer').length).toBeGreaterThan(0);
  });

  it('fills the existing form without submitting or displaying the password', async () => {
    const user = userEvent.setup();
    mockGetDemoAccounts.mockResolvedValue(DEMO_ACCOUNTS);

    renderLogin();

    const adminButtons = await screen.findAllByRole('button', {
      name: /Use Administrator demo account/i,
    });
    expect(adminButtons.length).toBeGreaterThan(0);
    expect(adminButtons[0]).toHaveAttribute('type', 'button');

    await user.click(adminButtons[0]);

    expect(screen.getByLabelText('Email')).toHaveValue(DEMO_ACCOUNTS[0].email);
    expect(screen.getByLabelText('Password')).toHaveValue(DEMO_ACCOUNTS[0].password);
    expect(mockLogin).not.toHaveBeenCalled();
    expect(screen.getByRole('status')).toHaveTextContent('Demo credentials filled');
    expect(screen.queryByText(DEMO_ACCOUNTS[0].password)).toBeNull();
    expect(screen.getByRole('button', { name: 'Sign in' })).toHaveFocus();
  });

  it('uses normal login after a demo account is selected', async () => {
    const user = userEvent.setup();
    mockGetDemoAccounts.mockResolvedValue(DEMO_ACCOUNTS);
    mockLogin.mockResolvedValue(SAMPLE_USER);

    renderLogin();

    const adminButtons = await screen.findAllByRole('button', {
      name: /Use Administrator demo account/i,
    });
    await user.click(adminButtons[0]);
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(mockLogin).toHaveBeenCalledWith(
      DEMO_ACCOUNTS[0].email,
      DEMO_ACCOUNTS[0].password,
    );
    expect(await screen.findByText('Dashboard region')).toBeInTheDocument();
  });

  it('clears the demo notice when the user edits the form', async () => {
    const user = userEvent.setup();
    mockGetDemoAccounts.mockResolvedValue(DEMO_ACCOUNTS);

    renderLogin();

    const adminButtons = await screen.findAllByRole('button', {
      name: /Use Administrator demo account/i,
    });
    await user.click(adminButtons[0]);
    expect(screen.getByRole('status')).toBeInTheDocument();

    await user.type(screen.getByLabelText('Email'), 'x');

    expect(screen.queryByRole('status')).toBeNull();
  });

  it('does not render in production or when the feature is disabled (404)', async () => {
    mockGetDemoAccounts.mockRejectedValue(new ApiError(404, 'Not Found'));

    renderLogin();

    await waitFor(() => expect(mockGetDemoAccounts).toHaveBeenCalledTimes(1));
    expect(screen.queryByText('Explore TrustVault')).toBeNull();
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument();
  });

  it('does not render when no demo account is provisioned', async () => {
    mockGetDemoAccounts.mockResolvedValue([]);

    renderLogin();

    await waitFor(() => expect(mockGetDemoAccounts).toHaveBeenCalledTimes(1));
    expect(screen.queryByText('Explore TrustVault')).toBeNull();
  });

  it('hides the section on a network failure without blocking login', async () => {
    mockGetDemoAccounts.mockRejectedValue(new NetworkError(new TypeError('fetch failed')));

    renderLogin();

    await waitFor(() => expect(mockGetDemoAccounts).toHaveBeenCalledTimes(1));
    expect(screen.queryByText('Explore TrustVault')).toBeNull();
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled();
  });
});
