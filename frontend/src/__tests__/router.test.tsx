/**
 * ROUTING tests (isolated). Renders the real router with client-side URL
 * spoofing via history.pushState; no backend involved.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import Root from '../router';

vi.mock('../pages/Login', () => ({ default: () => <div>Login page render</div> }));
vi.mock('../pages/Dashboard', () => ({ default: () => <div>Dashboard page render</div> }));
vi.mock('../pages/Documents', () => ({ default: () => <div>Documents page render</div> }));
vi.mock('../pages/DocumentDetail', () => ({ default: () => <div>Document detail render</div> }));

describe('router', () => {
  afterEach(() => {
    window.history.pushState(null, '', '/login');
  });

  it('maps /login to the login page', () => {
    window.history.pushState(null, '', '/login');
    render(<Root />);
    expect(screen.getByText('Login page render')).toBeInTheDocument();
  });

  it('maps /dashboard to the dashboard page', () => {
    window.history.pushState(null, '', '/dashboard');
    render(<Root />);
    expect(screen.getByText('Dashboard page render')).toBeInTheDocument();
  });

  it('maps /documents to the documents page', () => {
    window.history.pushState(null, '', '/documents');
    render(<Root />);
    expect(screen.getByText('Documents page render')).toBeInTheDocument();
  });

  it('maps /documents/:id to the document detail page', () => {
    window.history.pushState(null, '', '/documents/doc_1');
    render(<Root />);
    expect(screen.getByText('Document detail render')).toBeInTheDocument();
  });

  it('redirects / to /login', async () => {
    window.history.pushState(null, '', '/');
    render(<Root />);
    await waitFor(() => expect(screen.getByText('Login page render')).toBeInTheDocument());
    expect(window.location.pathname).toBe('/login');
  });

  it('renders a 404 page with a link home for unknown routes', () => {
    window.history.pushState(null, '', '/definitely/not/here');
    render(<Root />);
    expect(screen.getByText('404 — Page not found')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Go to sign in' })).toBeInTheDocument();
  });
});
