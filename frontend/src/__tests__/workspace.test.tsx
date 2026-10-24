/**
 * COMPONENT tests for the account, sharing, and audit surfaces added in the
 * redesign. The auth module is mocked so no backend runs.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import LoginPage from '../pages/Login';
import RegisterPage from '../pages/Register';
import Settings from '../pages/Settings';
import SharedWithMe from '../pages/SharedWithMe';
import AccessSharing from '../pages/AccessSharing';
import Activity from '../pages/Activity';
import type {
  AuditCheckpointInfoResponse,
  AuditEventResponse,
  DocumentListItem,
  GrantResponse,
  HealthResponse,
  UserResponse,
} from '../types';

vi.mock('../auth', () => ({
  getMe: vi.fn(),
  getDemoAccounts: vi.fn(() => Promise.resolve([])),
  logout: vi.fn(),
  register: vi.fn(),
  updateMe: vi.fn(),
  listDocuments: vi.fn(),
  listGrants: vi.fn(),
  revokeGrant: vi.fn(),
  downloadDocument: vi.fn(),
}));

vi.mock('../api', async () => {
  const actual = await vi.importActual<typeof import('../api')>('../api');
  return {
    ...actual,
    listAuditEvents: vi.fn(),
    listDocumentActivity: vi.fn(),
    verifyAuditChain: vi.fn(),
    getAuditCheckpoint: vi.fn(),
    createAuditCheckpoint: vi.fn(),
    verifyAuditCheckpoint: vi.fn(),
    getHealth: vi.fn(),
  };
});

import * as auth from '../auth';
import * as api from '../api';

const mockGetMe = vi.mocked(auth.getMe);
const mockRegister = vi.mocked(auth.register);
const mockUpdateMe = vi.mocked(auth.updateMe);
const mockListDocuments = vi.mocked(auth.listDocuments);
const mockListAuditEvents = vi.mocked(api.listAuditEvents);
const mockListDocumentActivity = vi.mocked(api.listDocumentActivity);
const mockVerifyAuditChain = vi.mocked(api.verifyAuditChain);
const mockGetAuditCheckpoint = vi.mocked(api.getAuditCheckpoint);
const mockCreateAuditCheckpoint = vi.mocked(api.createAuditCheckpoint);
const mockVerifyAuditCheckpoint = vi.mocked(api.verifyAuditCheckpoint);
const mockGetHealth = vi.mocked(api.getHealth);
const mockListGrants = vi.mocked(auth.listGrants);
const mockRevokeGrant = vi.mocked(auth.revokeGrant);

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

const READER_ID = 'usr_2';

function makeDocument(overrides: Partial<DocumentListItem> = {}): DocumentListItem {
  return {
    id: 'doc_1',
    title: 'Shared report',
    original_filename: 'report.pdf',
    file_size_bytes: 2048,
    mime_type: 'application/pdf',
    category: 'Reports',
    owner_id: 'usr_1',
    is_deleted: false,
    created_at: '2026-01-02T00:00:00Z',
    updated_at: '2026-01-02T00:00:00Z',
    effective_permission: 'read',
    ...overrides,
  };
}

const GRANT: GrantResponse = {
  id: 'gr_1',
  document_id: 'doc_1',
  user_id: READER_ID,
  permission: 'read',
  granted_by_id: 'usr_1',
  is_revoked: false,
  created_at: '2026-01-02T00:00:00Z',
  updated_at: '2026-01-02T00:00:00Z',
};

const AUDIT_EVENT: AuditEventResponse = {
  id: 'evt_1',
  sequence_number: 12,
  timestamp: '2026-01-02T00:00:00Z',
  actor_id: 'usr_1',
  action: 'document.upload',
  resource_type: 'document',
  resource_id: 'doc_1',
  outcome: 'SUCCESS',
  request_id: 'req_1',
  ip_address: '127.0.0.1',
  user_agent: 'vitest',
  details: { category: 'Reports' },
};

const NO_CHECKPOINT: AuditCheckpointInfoResponse = {
  anchor_mode: 'disabled',
  available: false,
  stream_id: null,
  sequence_number: null,
  created_at: null,
  format_version: null,
};

const DISABLED_HEALTH: HealthResponse = {
  status: 'healthy',
  app: 'TrustVault',
  environment: 'test',
  version: '0.1.0',
  timestamp: '2026-01-03T00:00:00Z',
  database: 'connected',
  storage: 'available',
  components: {
    audit_anchor: {
      status: 'not_configured',
      mode: 'disabled',
      independent: false,
      external_adapter: false,
      independence_verified: false,
      available: false,
      last_checkpoint_at: null,
      checkpoint_sequence: null,
      checkpoint_age_seconds: null,
      max_age_seconds: 3600,
      overdue: false,
      failure_reason: null,
    },
  },
};

const LOCAL_FILE_HEALTH: HealthResponse = {
  ...DISABLED_HEALTH,
  status: 'degraded',
  components: {
    audit_anchor: {
      status: 'local_only',
      mode: 'local_file',
      independent: false,
      external_adapter: false,
      independence_verified: false,
      available: true,
      last_checkpoint_at: '2026-01-02T00:00:00Z',
      checkpoint_sequence: 12,
      checkpoint_age_seconds: 12,
      max_age_seconds: 3600,
      overdue: false,
      failure_reason: null,
    },
  },
};

function renderRoute(path: string, element: ReactNode) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path={path} element={element} />
        <Route path="/" element={<div>Dashboard region</div>} />
        <Route path="/login" element={<div>Login landing zone</div>} />
        <Route path="*" element={<div>Unknown route</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockGetMe.mockResolvedValue(null);
  mockListDocuments.mockResolvedValue({
    documents: [],
    total: 0,
    page: 1,
    page_size: 100,
  });
  mockListGrants.mockResolvedValue({ grants: [] });
  mockGetHealth.mockResolvedValue(DISABLED_HEALTH);
  mockGetAuditCheckpoint.mockResolvedValue(NO_CHECKPOINT);
});

describe('Auth home navigation', () => {
  it('links sign-in back to the public home page', async () => {
    renderRoute('/login', <LoginPage />);

    const homeLinks = await screen.findAllByRole('link', { name: /home/i });
    expect(homeLinks.length).toBeGreaterThanOrEqual(2);
    for (const link of homeLinks) {
      expect(link).toHaveAttribute('href', '/');
    }
  });

  it('links registration back to the public home page', async () => {
    renderRoute('/register', <RegisterPage />);

    const homeLinks = await screen.findAllByRole('link', { name: /home/i });
    expect(homeLinks.length).toBeGreaterThanOrEqual(2);
    for (const link of homeLinks) {
      expect(link).toHaveAttribute('href', '/');
    }
  });
});

describe('Registration (component)', () => {
  it('registers with a valid form and never sends a role', async () => {
    const user = userEvent.setup();
    mockRegister.mockResolvedValue(VIEWER);

    renderRoute('/register', <RegisterPage />);

    await user.type(screen.getByLabelText('Full name'), 'Bob Viewer');
    await user.type(screen.getByLabelText('Email'), 'bob@example.com');
    await user.type(screen.getByLabelText('Password'), 'CorrectHorse1!');
    await user.type(screen.getByLabelText('Confirm password'), 'CorrectHorse1!');
    await user.click(screen.getByRole('button', { name: 'Create account' }));

    expect(mockRegister).toHaveBeenCalledWith(
      'Bob Viewer',
      'bob@example.com',
      'CorrectHorse1!',
    );
    expect(await screen.findByText('Dashboard region')).toBeInTheDocument();
  }, 15000);

  it('blocks a weak password before calling the backend', async () => {
    const user = userEvent.setup();

    renderRoute('/register', <RegisterPage />);

    await user.type(screen.getByLabelText('Full name'), 'Bob Viewer');
    await user.type(screen.getByLabelText('Email'), 'bob@example.com');
    await user.type(screen.getByLabelText('Password'), 'shortshortshort');
    await user.type(screen.getByLabelText('Confirm password'), 'shortshortshort');
    await user.click(screen.getByRole('button', { name: 'Create account' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Choose a password that meets every requirement',
    );
    expect(mockRegister).not.toHaveBeenCalled();
  });
});

describe('Settings (component)', () => {
  it('saves a display name through PATCH and reflects the response', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockUpdateMe.mockResolvedValue({ ...OWNER, full_name: 'Ada King' });

    renderRoute('/settings', <Settings />);

    const name = await screen.findByLabelText('Full name');
    expect(name).toHaveValue('Ada Lovelace');
    await user.clear(name);
    await user.type(name, 'Ada King');
    await user.click(screen.getByRole('button', { name: 'Save profile' }));

    expect(mockUpdateMe).toHaveBeenCalledWith({ full_name: 'Ada King' });
    expect(await screen.findByText('Profile updated.')).toBeInTheDocument();
  }, 15000);

  it('explains that a password change revokes every session', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockUpdateMe.mockResolvedValue(OWNER);

    renderRoute('/settings', <Settings />);

    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Account' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Security' })).toBeInTheDocument();
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument();

    await user.type(await screen.findByLabelText('New password'), 'NewSecurePass1!');
    await user.type(screen.getByLabelText('Confirm new password'), 'NewSecurePass1!');
    await user.click(screen.getByRole('button', { name: 'Change password' }));

    expect(mockUpdateMe).toHaveBeenCalledWith({ password: 'NewSecurePass1!' });
    expect(await screen.findByText('Password updated')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Go to sign in' })).toBeInTheDocument();
    expect(screen.getByText(/managed by the deployment environment/)).toBeInTheDocument();
  }, 15000);
});

describe('Shared With Me (component)', () => {
  it('lists only documents the caller does not own', async () => {
    mockGetMe.mockResolvedValue(VIEWER);
    mockListDocuments.mockResolvedValue({
      documents: [
        makeDocument({ id: 'doc_1', title: 'Shared report', effective_permission: 'read' }),
        makeDocument({
          id: 'doc_2',
          title: 'Editable plan',
          effective_permission: 'edit',
          owner_id: 'usr_3',
        }),
        makeDocument({
          id: 'doc_3',
          title: 'Owned draft',
          effective_permission: 'owner',
          owner_id: VIEWER.id,
        }),
      ],
      total: 3,
      page: 1,
      page_size: 100,
    });

    renderRoute('/shared', <SharedWithMe />);

    expect(await screen.findByText('Shared report')).toBeInTheDocument();
    expect(screen.getByText('Editable plan')).toBeInTheDocument();
    expect(screen.queryByText('Owned draft')).not.toBeInTheDocument();
    expect(screen.getByText('read')).toBeInTheDocument();
    expect(screen.getByText('edit')).toBeInTheDocument();
  }, 15000);

  it('loads every page of the visible document set', async () => {
    mockGetMe.mockResolvedValue(VIEWER);
    mockListDocuments
      .mockResolvedValueOnce({
        documents: [makeDocument({ id: 'doc_1', title: 'First page report' })],
        total: 2,
        page: 1,
        page_size: 100,
      })
      .mockResolvedValueOnce({
        documents: [
          makeDocument({
            id: 'doc_2',
            title: 'Second page report',
            owner_id: 'usr_3',
            effective_permission: 'edit',
          }),
        ],
        total: 2,
        page: 2,
        page_size: 100,
      });

    renderRoute('/shared', <SharedWithMe />);

    expect(await screen.findByText('First page report')).toBeInTheDocument();
    expect(await screen.findByText('Second page report')).toBeInTheDocument();
    expect(mockListDocuments).toHaveBeenNthCalledWith(1, {
      page: 1,
      page_size: 100,
      owner_id: undefined,
    });
    expect(mockListDocuments).toHaveBeenNthCalledWith(2, {
      page: 2,
      page_size: 100,
      owner_id: undefined,
    });
  }, 15000);
});

describe('Access & Sharing (component)', () => {
  it('loads grants on demand and only revokes after confirmation', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue({
      documents: [makeDocument({ effective_permission: 'owner', owner_id: OWNER.id })],
      total: 1,
      page: 1,
      page_size: 100,
    });
    mockListGrants
      .mockResolvedValueOnce({ grants: [GRANT] })
      .mockResolvedValueOnce({ grants: [{ ...GRANT, is_revoked: true }] });
    mockRevokeGrant.mockResolvedValue(undefined);

    renderRoute('/access', <AccessSharing />);

    await screen.findByText('Shared report');
    await user.click(screen.getByRole('button', { name: 'View access' }));
    expect(await screen.findByText(READER_ID)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Revoke' }));
    expect(mockRevokeGrant).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Confirm revoke?' }));
    expect(mockRevokeGrant).toHaveBeenCalledWith('doc_1', READER_ID);
    expect(await screen.findByText(/Access revoked for/)).toBeInTheDocument();
    expect(await screen.findByText('Revoked grant')).toBeInTheDocument();
  }, 15000);

  it('separates documents shared with the caller from documents they manage', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue({
      documents: [
        makeDocument({ effective_permission: 'owner', owner_id: OWNER.id, title: 'Owned draft' }),
        makeDocument({
          id: 'doc_2',
          title: 'Incoming brief',
          owner_id: 'usr_9',
          effective_permission: 'read',
        }),
      ],
      total: 2,
      page: 1,
      page_size: 100,
    });

    renderRoute('/access', <AccessSharing />);

    expect(await screen.findByText('Owned draft')).toBeInTheDocument();
    expect(screen.queryByText('Incoming brief')).not.toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'My access' }));

    expect(await screen.findByText('Incoming brief')).toBeInTheDocument();
    expect(screen.queryByText('Owned draft')).not.toBeInTheDocument();
  }, 15000);
});

describe('Activity (component)', () => {
  it('does not request audit data for non-administrators', async () => {
    mockGetMe.mockResolvedValue(VIEWER);

    renderRoute('/activity', <Activity />);

    expect(await screen.findByText('Administrator access required')).toBeInTheDocument();
    expect(mockListAuditEvents).not.toHaveBeenCalled();
  });

  it('renders audit events and verifies the chain for administrators', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListAuditEvents.mockResolvedValue({
      events: [AUDIT_EVENT],
      total: 1,
      page: 1,
      page_size: 25,
    });
    mockVerifyAuditChain.mockResolvedValue({
      status: 'VALID',
      is_valid: true,
      records_verified: 3,
      failure_reason: null,
    });

    renderRoute('/activity', <Activity />);

    expect(await screen.findByText('document.upload')).toBeInTheDocument();
    expect(screen.getByText('Success')).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'Verification' }));
    await user.click(screen.getByRole('button', { name: 'Verify chain' }));
    expect(await screen.findByText(/3 records verified/)).toBeInTheDocument();
  }, 15000);

  it('loads document activity in its own audit tab', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListAuditEvents.mockResolvedValue({
      events: [AUDIT_EVENT],
      total: 1,
      page: 1,
      page_size: 25,
    });
    mockListDocumentActivity.mockResolvedValue({
      events: [{ ...AUDIT_EVENT, resource_type: 'document_grant' }],
      total: 1,
      page: 1,
      page_size: 25,
    });

    renderRoute('/activity', <Activity />);

    await screen.findByText('document.upload');
    await user.click(screen.getByRole('tab', { name: 'Document activity' }));

    await waitFor(() => {
      expect(mockListDocumentActivity).toHaveBeenCalledWith({
        page: 1,
        page_size: 25,
        document_id: undefined,
        actor_id: undefined,
        action: undefined,
        outcome: undefined,
      });
    });
    expect(await screen.findByText('1 document events')).toBeInTheDocument();
  }, 15000);

  it('applies bounded filters and resets them', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListAuditEvents.mockResolvedValue({
      events: [AUDIT_EVENT],
      total: 1,
      page: 1,
      page_size: 25,
    });

    renderRoute('/activity', <Activity />);

    expect(await screen.findByText('document.upload')).toBeInTheDocument();

    await user.type(screen.getByLabelText('Actor ID'), 'usr_1');
    await user.click(screen.getByRole('button', { name: 'Apply filters' }));

    expect(mockListAuditEvents).toHaveBeenLastCalledWith(
      expect.objectContaining({ actor_id: 'usr_1', page: 1, outcome: undefined }),
    );

    await user.click(screen.getByRole('button', { name: 'Reset' }));

    expect(mockListAuditEvents).toHaveBeenLastCalledWith(
      expect.objectContaining({ actor_id: undefined, outcome: undefined, page: 1 }),
    );
  }, 15000);

  it('hides checkpoint controls when independent anchoring is not configured', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListAuditEvents.mockResolvedValue({
      events: [AUDIT_EVENT],
      total: 1,
      page: 1,
      page_size: 25,
    });
    mockGetHealth.mockResolvedValue(DISABLED_HEALTH);

    renderRoute('/activity', <Activity />);

    await user.click(await screen.findByRole('tab', { name: 'Verification' }));

    expect(
      await screen.findByText(/not configured for this deployment/),
    ).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /Checkpoint anchor/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create checkpoint' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Verify against checkpoint' }),
    ).not.toBeInTheDocument();
    expect(mockGetAuditCheckpoint).not.toHaveBeenCalled();
  }, 15000);

  it('hides independent checkpoint controls for local-file anchoring', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(ADMIN);
    mockListAuditEvents.mockResolvedValue({
      events: [AUDIT_EVENT],
      total: 1,
      page: 1,
      page_size: 25,
    });
    mockGetHealth.mockResolvedValue(LOCAL_FILE_HEALTH);

    renderRoute('/activity', <Activity />);

    await user.click(await screen.findByRole('tab', { name: 'Verification' }));

    expect(
      await screen.findByText(/not configured for this deployment/),
    ).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /Checkpoint anchor/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create checkpoint' })).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Verify against checkpoint' }),
    ).not.toBeInTheDocument();
    expect(mockGetAuditCheckpoint).not.toHaveBeenCalled();
    expect(mockCreateAuditCheckpoint).not.toHaveBeenCalled();
    expect(mockVerifyAuditCheckpoint).not.toHaveBeenCalled();
  }, 15000);
});
