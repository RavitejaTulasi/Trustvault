import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import AppShell from '../components/AppShell';
import type { UserResponse } from '../types';

const OWNER: UserResponse = {
  id: 'usr_1',
  email: 'ada@example.com',
  full_name: 'Ada Lovelace',
  role: 'owner',
  is_active: true,
  must_change_password: false,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

const VIEWER: UserResponse = {
  ...OWNER,
  id: 'usr_2',
  email: 'bob@example.com',
  full_name: 'Bob Viewer',
  role: 'viewer',
};

const ADMIN: UserResponse = {
  ...OWNER,
  id: 'usr_admin',
  email: 'admin@example.com',
  full_name: 'Admin User',
  role: 'admin',
};

function renderShell(user: UserResponse) {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Routes>
        <Route
          path="/dashboard"
          element={
            <AppShell user={user}>
              <div>Shell content</div>
            </AppShell>
          }
        />
        <Route path="/documents" element={<div>Documents destination</div>} />
        <Route path="*" element={<div>Other route</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe('AppShell navigation', () => {
  it('shows the administrator audit link only to administrators', () => {
    const { unmount } = renderShell(VIEWER);
    expect(screen.queryByRole('link', { name: 'Audit' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'User management' })).not.toBeInTheDocument();
    unmount();

    renderShell(ADMIN);
    expect(screen.getByRole('link', { name: 'Audit' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'User management' })).toBeInTheDocument();
  });

  it('opens the command palette with Ctrl+K and restores trigger focus on Escape', async () => {
    const user = userEvent.setup();
    renderShell(OWNER);

    const trigger = screen.getByRole('button', { name: 'Open command palette' });
    await user.click(trigger);
    expect(screen.getByRole('dialog', { name: 'Command palette' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Search pages and actions' })).toHaveFocus();

    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: 'Command palette' })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();

    await user.keyboard('{Control>}k{/Control}');
    expect(screen.getByRole('dialog', { name: 'Command palette' })).toBeInTheDocument();
  });

  it('filters and opens the role-gated upload action', async () => {
    const user = userEvent.setup();
    renderShell(OWNER);

    await user.click(screen.getByRole('button', { name: 'Open command palette' }));
    const input = screen.getByRole('combobox', { name: 'Search pages and actions' });
    await user.type(input, 'upload');

    expect(screen.getByRole('option', { name: /Upload a document/ })).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: /Overview/ })).not.toBeInTheDocument();

    await user.keyboard('{Enter}');
    expect(await screen.findByText('Documents destination')).toBeInTheDocument();
  });

  it('starts as an icon rail, expands from the sidebar toggle, and persists the preference', async () => {
    const user = userEvent.setup();
    const { unmount } = renderShell(OWNER);

    const sidebar = document.getElementById('app-sidebar');
    const topbar = document.querySelector('.topbar');
    expect(sidebar).not.toBeNull();
    expect(topbar).not.toBeNull();
    expect(within(topbar as HTMLElement).getByRole('link', { name: 'TrustVault overview' })).toBeInTheDocument();
    expect(within(sidebar as HTMLElement).getByRole('button', { name: 'Expand navigation' })).toHaveAttribute(
      'aria-expanded',
      'false',
    );
    expect(sidebar).toHaveAttribute('data-collapsed', 'true');
    expect(screen.getByRole('link', { name: 'My documents' })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Expand navigation' }));

    expect(screen.getByRole('button', { name: 'Collapse navigation' })).toHaveAttribute(
      'aria-expanded',
      'true',
    );
    expect(sidebar).not.toHaveAttribute('data-collapsed');
    expect(window.localStorage.getItem('trustvault.sidebar.collapsed')).toBe('false');

    await user.click(screen.getByRole('button', { name: 'Collapse navigation' }));
    expect(sidebar).toHaveAttribute('data-collapsed', 'true');
    expect(window.localStorage.getItem('trustvault.sidebar.collapsed')).toBe('true');

    unmount();
    renderShell(OWNER);
    expect(screen.getByRole('button', { name: 'Expand navigation' })).toBeInTheDocument();
  });

  it('does not offer the upload action to viewers', async () => {
    const user = userEvent.setup();
    renderShell(VIEWER);

    await user.click(screen.getByRole('button', { name: 'Open command palette' }));
    const input = screen.getByRole('combobox', { name: 'Search pages and actions' });
    await user.type(input, 'upload');

    expect(screen.queryByText('Upload a document')).not.toBeInTheDocument();
    expect(screen.queryByText('Actions')).not.toBeInTheDocument();
    expect(screen.getByRole('option', { name: /My documents/ })).toBeInTheDocument();
  });
});

describe('AppShell mobile drawer', () => {
  it('traps the drawer open state, locks scroll, and closes on Escape', async () => {
    vi.stubGlobal(
      'matchMedia',
      vi.fn().mockImplementation((query: string) => ({
        matches: query === '(max-width: 960px)',
        media: query,
        onchange: null,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    );

    const user = userEvent.setup();
    renderShell(OWNER);

    const openButton = screen.getByRole('button', { name: 'Open navigation' });
    await user.click(openButton);

    const closeButton = screen.getByRole('button', { name: 'Close navigation' });
    await waitFor(() => expect(closeButton).toHaveFocus());
    expect(document.body.style.overflow).toBe('hidden');

    const logoutButton = screen.getByRole('button', { name: 'Logout' });
    await user.tab({ shift: true });
    expect(logoutButton).toHaveFocus();
    await user.tab();
    expect(closeButton).toHaveFocus();

    closeButton.focus();
    await user.keyboard('{Escape}');
    expect(document.body.style.overflow).toBe('');
    expect(openButton).toHaveFocus();
  });
});
