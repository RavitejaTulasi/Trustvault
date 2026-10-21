/**
 * COMPONENT tests (isolated). The auth module is mocked so no backend runs.
 * Covers: login rendering/validation, error feedback, navigation on success,
 * and the priority rule that only 401 ends a Dashboard session.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import LoginPage from '../pages/Login';
import Dashboard from '../pages/Dashboard';
import { ApiError, NetworkError } from '../api';
import type { UserResponse } from '../types';

vi.mock('../auth', () => ({
  login: vi.fn(),
  getMe: vi.fn(),
  logout: vi.fn(),
}));

import * as auth from '../auth';

const mockLogin = vi.mocked(auth.login);
const mockGetMe = vi.mocked(auth.getMe);
const mockLogout = vi.mocked(auth.logout);

const SAMPLE_USER: UserResponse = {
  id: 'usr_1',
  email: 'ada@example.com',
  full_name: 'Ada Lovelace',
  role: 'Viewer',
  is_active: true,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

function renderLoginRoutes(initialEntry: string) {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/dashboard" element={<div>Dashboard region</div>} />
        <Route path="*" element={<div>Unknown route</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

function renderDashboardRoutes(initialEntry: string) {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/login" element={<div>Login landing zone</div>} />
        <Route path="*" element={<div>Unknown route</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mockLogin.mockReset();
  mockGetMe.mockReset();
  mockLogout.mockReset();
  // Login./(Dashboard) components call getMe() on mount; give every test a
  // sane default (unauthenticated) unless it overrides this explicitly.
  mockGetMe.mockResolvedValue(null);
});

describe('LoginPage (component)', () => {
  it('renders labelled email and password fields', () => {
    renderLoginRoutes('/login');
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
  });

  it('submits credentials and navigates to the dashboard on success', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(null);
    mockLogin.mockResolvedValue(SAMPLE_USER);

    renderLoginRoutes('/login');
    await user.type(screen.getByLabelText('Email'), 'ada@example.com');
    await user.type(screen.getByLabelText('Password'), 'correct horse');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    await expect(mockLogin).toHaveBeenCalledWith('ada@example.com', 'correct horse');
    expect(await screen.findByText('Dashboard region')).toBeInTheDocument();
  }, 10000);

  it('shows the backend error detail for invalid credentials', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(null);
    mockLogin.mockRejectedValue(new ApiError(401, 'Incorrect email or password'));

    renderLoginRoutes('/login');
    await user.type(screen.getByLabelText('Email'), 'ada@example.com');
    await user.type(screen.getByLabelText('Password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Incorrect email or password');
  }, 10000);

  it('shows a network failure distinctly from a rejected password', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(null);
    mockLogin.mockRejectedValue(new NetworkError(new TypeError('fetch failed')));

    renderLoginRoutes('/login');
    await user.type(screen.getByLabelText('Email'), 'ada@example.com');
    await user.type(screen.getByLabelText('Password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/Network request failed/i);
  }, 10000);
});

describe('Dashboard (component)', () => {
  it('shows the signed-in user', async () => {
    mockGetMe.mockResolvedValue(SAMPLE_USER);
    renderDashboardRoutes('/dashboard');
    expect(await screen.findByText(/Welcome, Ada Lovelace/)).toBeInTheDocument();
  });

  it('redirects to login when the session is gone (401 → null)', async () => {
    mockGetMe.mockResolvedValue(null);
    renderDashboardRoutes('/dashboard');
    expect(await screen.findByText('Login landing zone')).toBeInTheDocument();
  });

  it('stays on the dashboard with a retry option for server errors', async () => {
    mockGetMe.mockRejectedValue(new ApiError(503, 'Database unavailable'));
    renderDashboardRoutes('/dashboard');
    expect(await screen.findByRole('alert')).toHaveTextContent('Database unavailable');
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });

  it('notifies the user without faking success when logout fails', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(SAMPLE_USER);
    mockLogout.mockRejectedValue(new ApiError(403, 'CSRF token missing or invalid'));
    renderDashboardRoutes('/dashboard');

    await user.click(await screen.findByRole('button', { name: 'Logout' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('CSRF token missing or invalid');
    expect(mockLogout).toHaveBeenCalledTimes(1);
    expect(mockGetMe).toHaveBeenCalledTimes(1);
  }, 10000);
});

describe('LoginPage session restoration', () => {
  it('shows the plain login form and no banner for an ordinary logged-out session', () => {
    // getMe resolves null for HTTP 401; that is a logged-out session, not a
    // service failure, so no availability banner may appear.
    mockGetMe.mockResolvedValue(null);

    renderLoginRoutes('/login');

    expect(mockGetMe).toHaveBeenCalledTimes(1);
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument();
    expect(screen.queryByRole('status')).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('surfaces the temporary-unavailability detail when the session check gets a 503', async () => {
    mockGetMe.mockRejectedValue(new ApiError(503, 'Authentication temporarily unavailable'));

    renderLoginRoutes('/login');

    expect(await screen.findByRole('status')).toHaveTextContent(
      'Authentication temporarily unavailable',
    );
    // The banner is contextual: the form stays visible and enabled for a retry.
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled();
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
  });

  it('still allows signing in after a failed session check', async () => {
    const user = userEvent.setup();
    mockGetMe.mockRejectedValue(new ApiError(503, 'Authentication temporarily unavailable'));
    mockLogin.mockResolvedValue(SAMPLE_USER);

    renderLoginRoutes('/login');
    await screen.findByRole('status');
    await user.type(screen.getByLabelText('Email'), 'ada@example.com');
    await user.type(screen.getByLabelText('Password'), 'correct horse');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(mockLogin).toHaveBeenCalledWith('ada@example.com', 'correct horse');
    expect(await screen.findByText('Dashboard region')).toBeInTheDocument();
  }, 10000);

  it('shows a useful network-failure message when the session check cannot connect', async () => {
    mockGetMe.mockRejectedValue(new NetworkError(new TypeError('fetch failed')));

    renderLoginRoutes('/login');

    expect(await screen.findByRole('status')).toHaveTextContent(
      'Network request failed. Check your connection and try again.',
    );
  });

  it('does not fake a success banner: the sign-in error stays an alert', async () => {
    // Restoration failure and sign-in failure are different events with
    // different roles; a submit error must keep its alert semantics.
    const user = userEvent.setup();
    mockGetMe.mockRejectedValue(new ApiError(503, 'Authentication temporarily unavailable'));
    mockLogin.mockRejectedValue(new ApiError(401, 'Invalid email or password'));

    renderLoginRoutes('/login');
    await screen.findByRole('status');
    await user.type(screen.getByLabelText('Email'), 'ada@example.com');
    await user.type(screen.getByLabelText('Password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password');
    expect(screen.getByRole('status')).toBeInTheDocument();
  }, 10000);
});
