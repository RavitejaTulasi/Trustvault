/**
 * ROUTING tests (isolated). Renders the real router with client-side URL
 * spoofing via history.pushState; no backend involved. Pages are lazy-loaded,
 * so every route assertion waits for the resolved module.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import Root from '../router';
import type { UserResponse } from '../types';

vi.mock('../auth', () => ({ getMe: vi.fn() }));

import * as auth from '../auth';

const mockGetMe = vi.mocked(auth.getMe);

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

vi.mock('../pages/AccessSharing', () => ({ default: () => <div>Access page render</div> }));
vi.mock('../pages/Activity', () => ({ default: () => <div>Activity page render</div> }));
vi.mock('../pages/AdminUsers', () => ({ default: () => <div>Admin users page render</div> }));
vi.mock('../pages/ChangePassword', () => ({ default: () => <div>Change password page render</div> }));
vi.mock('../pages/Dashboard', () => ({ default: () => <div>Dashboard page render</div> }));
vi.mock('../pages/DocumentDetail', () => ({ default: () => <div>Document detail render</div> }));
vi.mock('../pages/Documents', () => ({ default: () => <div>Documents page render</div> }));
vi.mock('../pages/Landing', () => ({ default: () => <div>Landing page render</div> }));
vi.mock('../pages/Login', () => ({ default: () => <div>Login page render</div> }));
vi.mock('../pages/Register', () => ({ default: () => <div>Register page render</div> }));
vi.mock('../pages/Settings', () => ({ default: () => <div>Settings page render</div> }));
vi.mock('../pages/SharedWithMe', () => ({ default: () => <div>Shared page render</div> }));

describe('router', () => {
  beforeEach(() => {
    mockGetMe.mockReset();
    mockGetMe.mockResolvedValue(null);
  });

  afterEach(() => {
    window.history.pushState(null, '', '/login');
  });

  it('maps /login to the login page', async () => {
    window.history.pushState(null, '', '/login');
    render(<Root />);
    expect(await screen.findByText('Login page render')).toBeInTheDocument();
  });

  it('maps /dashboard to the dashboard page', async () => {
    window.history.pushState(null, '', '/dashboard');
    render(<Root />);
    expect(await screen.findByText('Dashboard page render')).toBeInTheDocument();
  });

  it('maps /documents to the documents page', async () => {
    window.history.pushState(null, '', '/documents');
    render(<Root />);
    expect(await screen.findByText('Documents page render')).toBeInTheDocument();
  });

  it('maps /documents/:id to the document detail page', async () => {
    window.history.pushState(null, '', '/documents/doc_1');
    render(<Root />);
    expect(await screen.findByText('Document detail render')).toBeInTheDocument();
  });

  it('maps / to the landing page for anonymous visitors', async () => {
    window.history.pushState(null, '', '/');
    render(<Root />);
    expect(await screen.findByText('Landing page render')).toBeInTheDocument();
  });

  it('maps / to the overview for a signed-in session', async () => {
    mockGetMe.mockResolvedValue(SIGNED_IN_USER);
    window.history.pushState(null, '', '/');
    render(<Root />);
    expect(await screen.findByText('Dashboard page render')).toBeInTheDocument();
  });

  it('maps /register to the registration page', async () => {
    window.history.pushState(null, '', '/register');
    render(<Root />);
    expect(await screen.findByText('Register page render')).toBeInTheDocument();
  });

  it('maps /change-password to the mandatory password page', async () => {
    window.history.pushState(null, '', '/change-password');
    render(<Root />);
    expect(await screen.findByText('Change password page render')).toBeInTheDocument();
  });

  it('redirects a flagged signed-in session away from the overview', async () => {
    mockGetMe.mockResolvedValue({
      ...SIGNED_IN_USER,
      must_change_password: true,
    });
    window.history.pushState(null, '', '/');
    render(<Root />);
    expect(await screen.findByText('Change password page render')).toBeInTheDocument();
    expect(window.location.pathname).toBe('/change-password');
  });

  it('maps /shared to the shared documents page', async () => {
    window.history.pushState(null, '', '/shared');
    render(<Root />);
    expect(await screen.findByText('Shared page render')).toBeInTheDocument();
  });

  it('maps /access to the access and sharing page', async () => {
    window.history.pushState(null, '', '/access');
    render(<Root />);
    expect(await screen.findByText('Access page render')).toBeInTheDocument();
  });

  it('maps /admin/audit to the audit page', async () => {
    window.history.pushState(null, '', '/admin/audit');
    render(<Root />);
    expect(await screen.findByText('Activity page render')).toBeInTheDocument();
  });

  it('keeps /activity as a compatibility route for the audit page', async () => {
    window.history.pushState(null, '', '/activity');
    render(<Root />);
    expect(await screen.findByText('Activity page render')).toBeInTheDocument();
  });

  it('maps /admin/users to the admin user management page', async () => {
    window.history.pushState(null, '', '/admin/users');
    render(<Root />);
    expect(await screen.findByText('Admin users page render')).toBeInTheDocument();
  });

  it('maps /settings to the account settings page', async () => {
    window.history.pushState(null, '', '/settings');
    render(<Root />);
    expect(await screen.findByText('Settings page render')).toBeInTheDocument();
  });

  it('renders a 404 page with a link home for unknown routes', async () => {
    window.history.pushState(null, '', '/definitely/not/here');
    render(<Root />);
    expect(await screen.findByText('404 — Page not found')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Go to sign in' })).toBeInTheDocument();
  });
});
