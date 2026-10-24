/**
 * COMPONENT tests for the documents pages (isolated). The auth module is
 * mocked so no backend runs. Covers visibility scoping, upload gating,
 * search, pagination, and the two-step delete confirm.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import Documents from '../pages/Documents';
import DocumentDetail from '../pages/DocumentDetail';
import { ApiError } from '../api';
import type { DocumentListResponse, UserResponse } from '../types';

vi.mock('../auth', () => ({
  getMe: vi.fn(),
  listDocuments: vi.fn(),
  uploadDocument: vi.fn(),
  deleteDocument: vi.fn(),
  downloadDocument: vi.fn(),
  getDocument: vi.fn(),
  updateDocument: vi.fn(),
  listGrants: vi.fn(),
  resolveGrantRecipient: vi.fn(),
  createGrant: vi.fn(),
  revokeGrant: vi.fn(),
}));

import * as auth from '../auth';

const mockGetMe = vi.mocked(auth.getMe);
const mockListDocuments = vi.mocked(auth.listDocuments);
const mockUploadDocument = vi.mocked(auth.uploadDocument);
const mockDeleteDocument = vi.mocked(auth.deleteDocument);
const mockGetDocument = vi.mocked(auth.getDocument);
const mockUpdateDocument = vi.mocked(auth.updateDocument);
const mockListGrants = vi.mocked(auth.listGrants);
const mockResolveGrantRecipient = vi.mocked(auth.resolveGrantRecipient);
const mockCreateGrant = vi.mocked(auth.createGrant);
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
  id: 'usr_2',
  email: 'bob@example.com',
  full_name: 'Bob Viewer',
  role: 'viewer',
  is_active: true,
  must_change_password: false,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

const DOC_A = {
  id: 'doc_1',
  title: 'Quarterly Financial Audit',
  original_filename: 'q3_audit.pdf',
  file_size_bytes: 1048576,
  mime_type: 'application/pdf',
  category: 'Financial',
  owner_id: 'usr_1',
  is_deleted: false,
  created_at: '2026-10-19T10:00:00.000000Z',
  updated_at: '2026-10-19T10:00:00.000000Z',
};

const DOC_B = {
  ...DOC_A,
  id: 'doc_2',
  title: 'Shared notes',
  owner_id: 'usr_3',
};

function listResponse(total = 1, page = 1, documents = [DOC_A]): DocumentListResponse {
  return {
    documents: documents.map((doc) => ({
      ...doc,
      effective_permission: doc.owner_id === 'usr_1' ? ('owner' as const) : ('read' as const),
    })),
    total,
    page,
    page_size: 25,
  };
}

function renderDocumentsPage(initialEntry = '/documents') {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/documents" element={<Documents />} />
        <Route path="/documents/:id" element={<DocumentDetail />} />
        <Route path="/login" element={<div>Login landing zone</div>} />
        <Route path="*" element={<div>Unknown route</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  window.sessionStorage.clear();
  vi.mocked(auth.downloadDocument).mockReset();
  mockGetMe.mockReset();
  mockListDocuments.mockReset();
  mockUploadDocument.mockReset();
  mockDeleteDocument.mockReset();
  mockGetDocument.mockReset();
  mockUpdateDocument.mockReset();
  mockListGrants.mockReset();
  mockResolveGrantRecipient.mockReset();
  mockCreateGrant.mockReset();
  mockRevokeGrant.mockReset();
});

describe('Documents page (component)', () => {
  it('lists visible documents with their server-derived access level', async () => {
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse(1, 1, [DOC_A, DOC_B]));

    renderDocumentsPage();

    expect(await screen.findByText('Quarterly Financial Audit')).toBeInTheDocument();
    expect(screen.getByText('Shared notes')).toBeInTheDocument();
    const ownerBadges = screen.getAllByText('owner');
    expect(ownerBadges.length).toBe(1);
    expect(screen.getByText('read')).toBeInTheDocument();
  });

  it('redirects to login when the session is gone (401 → null)', async () => {
    mockGetMe.mockResolvedValue(null);

    renderDocumentsPage();

    expect(await screen.findByText('Login landing zone')).toBeInTheDocument();
    expect(mockListDocuments).not.toHaveBeenCalled();
  });

  it('stays on the page with a retry option for server errors', async () => {
    mockGetMe.mockRejectedValue(new ApiError(503, 'Database unavailable'));

    renderDocumentsPage();

    expect(await screen.findByRole('alert')).toHaveTextContent('Database unavailable');
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });

  it('hides the upload form from viewers', async () => {
    mockGetMe.mockResolvedValue(VIEWER);
    mockListDocuments.mockResolvedValue(listResponse(0, 1, []));

    renderDocumentsPage();
    expect(await screen.findByText('No documents found.')).toBeInTheDocument();
    expect(screen.queryByText('Upload a document')).not.toBeInTheDocument();
  });

  it('shows the upload form to owners', async () => {
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse());

    renderDocumentsPage();
    expect(await screen.findByText('Upload a document')).toBeInTheDocument();
    expect(screen.getByLabelText('File')).toBeInTheDocument();
  });

  it('reviews an upload before sending the selected file, title, and category', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse());
    mockUploadDocument.mockResolvedValue(DOC_A);

    renderDocumentsPage();
    await screen.findByText('Upload a document');

    const file = new File(['pdf-bytes'], 'q3_audit.pdf', { type: 'application/pdf' });
    await user.upload(screen.getByLabelText('File'), file);
    await user.type(screen.getByLabelText('Title'), 'Quarterly Financial Audit');
    await user.type(screen.getByLabelText('Category (optional)'), 'Financial');
    await user.click(screen.getByRole('button', { name: 'Review upload' }));

    expect(mockUploadDocument).not.toHaveBeenCalled();
    expect(screen.getByRole('group', { name: 'Review upload' })).toHaveTextContent(
      'Quarterly Financial Audit',
    );

    await user.click(screen.getByRole('button', { name: 'Confirm upload' }));

    await waitFor(() => expect(mockUploadDocument).toHaveBeenCalledTimes(1));
    const [sentFile, sentTitle, , sentCategory] = mockUploadDocument.mock.calls[0];
    expect(sentFile?.name).toBe('q3_audit.pdf');
    expect(sentTitle).toBe('Quarterly Financial Audit');
    expect(sentCategory).toBe('Financial');
    expect(mockListDocuments.mock.lastCall?.[0]).toMatchObject({ page: 1 });
    expect(screen.getByRole('button', { name: 'Review upload' })).toBeEnabled();
  });

  it('reuses a pending idempotency key after an ambiguous upload failure', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse());
    mockUploadDocument
      .mockRejectedValueOnce(new Error('network interrupted'))
      .mockResolvedValueOnce(DOC_A);

    renderDocumentsPage();
    await screen.findByText('Upload a document');
    await user.upload(
      screen.getByLabelText('File'),
      new File(['pdf-bytes'], 'q3_audit.pdf', { type: 'application/pdf' }),
    );
    await user.type(screen.getByLabelText('Title'), 'Quarterly Financial Audit');
    await user.click(screen.getByRole('button', { name: 'Review upload' }));

    await user.click(screen.getByRole('button', { name: 'Confirm upload' }));
    await screen.findByRole('alert');
    expect(screen.queryByText('Document uploaded')).not.toBeInTheDocument();
    const firstKey = mockUploadDocument.mock.calls[0][2];
    expect(firstKey).toBeTruthy();
    const storedPendingUpload = window.sessionStorage.getItem(
      'trustvault.pending-upload-idempotency-key',
    );
    expect(storedPendingUpload).not.toContain('Quarterly Financial Audit');
    expect(storedPendingUpload).not.toContain('q3_audit.pdf');
    expect(
      JSON.parse(
        storedPendingUpload ?? '{}',
      ),
    ).toEqual({ fingerprint: expect.any(String), key: firstKey });

    await user.click(screen.getByRole('button', { name: 'Confirm upload' }));
    await waitFor(() => expect(mockUploadDocument).toHaveBeenCalledTimes(2));
    expect(mockUploadDocument.mock.calls[1][2]).toBe(firstKey);
    expect(window.sessionStorage.getItem('trustvault.pending-upload-idempotency-key')).toBeNull();
  });

  it('uses a new idempotency key when the upload payload changes after a failure', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse());
    mockUploadDocument
      .mockRejectedValueOnce(new Error('network interrupted'))
      .mockResolvedValueOnce(DOC_A);

    renderDocumentsPage();
    await screen.findByText('Upload a document');
    await user.upload(
      screen.getByLabelText('File'),
      new File(['pdf-bytes'], 'q3_audit.pdf', { type: 'application/pdf' }),
    );
    await user.type(screen.getByLabelText('Title'), 'Quarterly Financial Audit');
    await user.click(screen.getByRole('button', { name: 'Review upload' }));

    await user.click(screen.getByRole('button', { name: 'Confirm upload' }));
    await screen.findByRole('alert');
    const firstKey = mockUploadDocument.mock.calls[0][2];

    await user.click(screen.getByRole('button', { name: 'Back' }));
    await user.clear(screen.getByLabelText('Title'));
    await user.type(screen.getByLabelText('Title'), 'Updated Financial Audit');
    await user.click(screen.getByRole('button', { name: 'Review upload' }));
    await user.click(screen.getByRole('button', { name: 'Confirm upload' }));

    await waitFor(() => expect(mockUploadDocument).toHaveBeenCalledTimes(2));
    expect(mockUploadDocument.mock.calls[1][2]).not.toBe(firstKey);
    expect(window.sessionStorage.getItem('trustvault.pending-upload-idempotency-key')).toBeNull();
  });

  it('uses a new idempotency key when the selected file changes after a failure', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse());
    mockUploadDocument
      .mockRejectedValueOnce(new Error('network interrupted'))
      .mockResolvedValueOnce(DOC_A);

    renderDocumentsPage();
    await screen.findByText('Upload a document');
    await user.upload(
      screen.getByLabelText('File'),
      new File(['pdf-bytes'], 'q3_audit.pdf', { type: 'application/pdf' }),
    );
    await user.type(screen.getByLabelText('Title'), 'Quarterly Financial Audit');
    await user.click(screen.getByRole('button', { name: 'Review upload' }));

    await user.click(screen.getByRole('button', { name: 'Confirm upload' }));
    await screen.findByRole('alert');
    const firstKey = mockUploadDocument.mock.calls[0][2];

    await user.click(screen.getByRole('button', { name: 'Back' }));
    await user.upload(
      screen.getByLabelText('File'),
      new File(['revised-pdf-bytes'], 'q3_audit_revised.pdf', {
        type: 'application/pdf',
      }),
    );
    await user.click(screen.getByRole('button', { name: 'Review upload' }));
    await user.click(screen.getByRole('button', { name: 'Confirm upload' }));

    await waitFor(() => expect(mockUploadDocument).toHaveBeenCalledTimes(2));
    expect(mockUploadDocument.mock.calls[1][0]?.name).toBe('q3_audit_revised.pdf');
    expect(mockUploadDocument.mock.calls[1][2]).not.toBe(firstKey);
    expect(window.sessionStorage.getItem('trustvault.pending-upload-idempotency-key')).toBeNull();
  });

  it('shows the backend rejection detail when an upload fails', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse());
    mockUploadDocument.mockRejectedValue(new ApiError(413, 'Storage quota exceeded'));

    renderDocumentsPage();
    await screen.findByText('Upload a document');

    await user.upload(
      screen.getByLabelText('File'),
      new File(['x'], 'big.bin', { type: 'application/octet-stream' }),
    );
    await user.type(screen.getByLabelText('Title'), 'Big file');
    await user.click(screen.getByRole('button', { name: 'Review upload' }));
    await user.click(screen.getByRole('button', { name: 'Confirm upload' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Storage quota exceeded');
  });

  it('applies search and category filters from the search form', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse());

    renderDocumentsPage();
    await screen.findByText('Upload a document');

    await user.type(screen.getByLabelText('Search'), 'aud');
    await user.type(screen.getByLabelText('Category'), 'Financial');
    await user.click(screen.getByRole('button', { name: 'Search' }));

    await waitFor(() => {
      expect(mockListDocuments).toHaveBeenLastCalledWith(
        expect.objectContaining({ page: 1, q: 'aud', category: 'Financial' }),
      );
    });
  });

  it('deletes only after confirming twice, then reloads the list', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse());
    mockDeleteDocument.mockResolvedValue(undefined);

    renderDocumentsPage();
    await screen.findByText('Quarterly Financial Audit');

    const deleteButton = screen.getByRole('button', { name: 'Delete' });
    await user.click(deleteButton);
    // First click only arms the confirmation.
    expect(mockDeleteDocument).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Confirm delete?' }));
    await waitFor(() => expect(mockDeleteDocument).toHaveBeenCalledWith('doc_1'));
    expect(mockListDocuments).toHaveBeenCalledTimes(2);
  });

  it('offers delete only on documents the caller owns', async () => {
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse(2, 1, [DOC_A, DOC_B]));

    renderDocumentsPage();
    expect(await screen.findByText('Shared notes')).toBeInTheDocument();

    const rows = screen.getAllByRole('row');
    const ownedRow = rows.find((row) => row.textContent?.includes('Quarterly Financial Audit'));
    const sharedRow = rows.find((row) => row.textContent?.includes('Shared notes'));
    expect(ownedRow?.textContent).toContain('Delete');
    expect(sharedRow?.textContent).not.toContain('Delete');
  });

  it('disables pagination Next when the last page is shown', async () => {
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse(25, 1));

    renderDocumentsPage();
    expect(await screen.findByText('Page 1 of 1')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();
  });

  it('fetches the next page when Next is clicked', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockListDocuments.mockResolvedValue(listResponse(50, 1));

    renderDocumentsPage();
    await screen.findByText('Page 1 of 2');

    await user.click(screen.getByRole('button', { name: 'Next' }));

    await waitFor(() =>
      expect(mockListDocuments).toHaveBeenLastCalledWith(expect.objectContaining({ page: 2 })),
    );
  });
});

describe('DocumentDetail page (component)', () => {
  function renderDetail(id = '/documents/doc_1') {
    return render(
      <MemoryRouter initialEntries={[id]}>
        <Routes>
          <Route path="/documents" element={<div>Documents list zone</div>} />
          <Route path="/documents/:id" element={<DocumentDetail />} />
          <Route path="/login" element={<div>Login landing zone</div>} />
        </Routes>
      </MemoryRouter>,
    );
  }

  it('shows metadata plus owner-only edit/delete/sharing controls', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockGetDocument.mockResolvedValue(DOC_A);
    mockListGrants.mockResolvedValue({ grants: [] });

    renderDetail();

    expect(await screen.findByText('Quarterly Financial Audit')).toBeInTheDocument();
    expect(screen.getByText('q3_audit.pdf')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Edit title / category' })).toBeInTheDocument();

    await user.click(screen.getByRole('tab', { name: 'Access' }));
    expect(
      screen.getByRole('heading', { name: 'Sharing', level: 2 }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        'Share with an existing, active TrustVault account by email.',
      ),
    ).toBeInTheDocument();
  });

  it('shows the deliberate 404 message when the caller has no access', async () => {
    mockGetMe.mockResolvedValue(VIEWER);
    mockGetDocument.mockRejectedValue(new ApiError(404, 'Document not found'));

    renderDetail('/documents/doc_missing');

    expect(await screen.findByText('Document not found')).toBeInTheDocument();
    expect(
      screen.getByText(/does not exist, or you do not have permission/i),
    ).toBeInTheDocument();
  });

  it('saves metadata edits through PATCH and reflects the response', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockGetDocument.mockResolvedValue(DOC_A);
    mockListGrants.mockResolvedValue({ grants: [] });
    mockUpdateDocument.mockResolvedValue({ ...DOC_A, title: 'Renamed audit' });

    renderDetail();
    await user.click(await screen.findByRole('button', { name: 'Edit title / category' }));

    const titleInput = screen.getByLabelText('Title');
    await user.clear(titleInput);
    await user.type(titleInput, 'Renamed audit');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() =>
      expect(mockUpdateDocument).toHaveBeenCalledWith('doc_1', {
        title: 'Renamed audit',
        category: 'Financial',
      }),
    );
    expect(await screen.findByRole('heading', { name: 'Renamed audit' })).toBeInTheDocument();
  });

  it('resolves an active recipient email before granting access', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockGetDocument.mockResolvedValue(DOC_A);
    mockResolveGrantRecipient.mockResolvedValue({ user_id: 'usr_2' });
    mockListGrants
      .mockResolvedValueOnce({ grants: [] })
      .mockResolvedValueOnce({
        grants: [
          {
            id: 'gr_1',
            document_id: 'doc_1',
            user_id: 'usr_2',
            permission: 'read',
            granted_by_id: 'usr_1',
            is_revoked: false,
            created_at: '2026-10-19T10:00:00Z',
            updated_at: '2026-10-19T10:00:00Z',
          },
        ],
      });
    mockCreateGrant.mockResolvedValue({
      id: 'gr_1',
      document_id: 'doc_1',
      user_id: 'usr_2',
      permission: 'read',
      granted_by_id: 'usr_1',
      is_revoked: false,
      created_at: '2026-10-19T10:00:00Z',
      updated_at: '2026-10-19T10:00:00Z',
    });

    renderDetail();
    await user.click(await screen.findByRole('tab', { name: 'Access' }));
    await screen.findByText('No permission grants for this document yet.');

    await user.type(screen.getByLabelText('Recipient email'), 'bob@example.com');
    await user.click(screen.getByRole('button', { name: 'Review grant' }));
    await waitFor(() =>
      expect(mockResolveGrantRecipient).toHaveBeenCalledWith(
        'doc_1',
        'bob@example.com',
      ),
    );
    expect(mockCreateGrant).not.toHaveBeenCalled();
    expect(await screen.findByText('bob@example.com')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Confirm grant access' }));

    await waitFor(() => expect(mockCreateGrant).toHaveBeenCalledWith('doc_1', 'usr_2', 'read'));
    expect(await screen.findByText('usr_2')).toBeInTheDocument();
  });

  it('does not grant access when the recipient email cannot be resolved', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockGetDocument.mockResolvedValue(DOC_A);
    mockListGrants.mockResolvedValue({ grants: [] });
    mockResolveGrantRecipient.mockRejectedValue(
      new ApiError(404, 'Recipient user not found or inactive'),
    );

    renderDetail();
    await user.click(await screen.findByRole('tab', { name: 'Access' }));
    await screen.findByText('No permission grants for this document yet.');

    await user.type(
      screen.getByLabelText('Recipient email'),
      'missing@example.com',
    );
    await user.click(screen.getByRole('button', { name: 'Review grant' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Recipient user not found or inactive',
    );
    expect(mockCreateGrant).not.toHaveBeenCalled();
  });

  it('revokes an active grant only after confirming twice', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockGetDocument.mockResolvedValue(DOC_A);
    const grant = {
      id: 'gr_1',
      document_id: 'doc_1',
      user_id: 'usr_2',
      permission: 'read' as const,
      granted_by_id: 'usr_1',
      is_revoked: false,
      created_at: '2026-10-19T10:00:00Z',
      updated_at: '2026-10-19T10:00:00Z',
    };
    mockListGrants.mockResolvedValue({ grants: [grant] });
    mockRevokeGrant.mockResolvedValue(undefined);

    renderDetail();
    await user.click(await screen.findByRole('tab', { name: 'Access' }));
    await screen.findByText('usr_2');

    await user.click(screen.getByRole('button', { name: 'Revoke' }));
    expect(mockRevokeGrant).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Confirm revoke?' }));
    await waitFor(() => expect(mockRevokeGrant).toHaveBeenCalledWith('doc_1', 'usr_2'));
    expect(mockListGrants).toHaveBeenCalledTimes(2);
  });

  it('shows the backend conflict detail when a revoke races a concurrent change', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockGetDocument.mockResolvedValue(DOC_A);
    mockListGrants.mockResolvedValue({
      grants: [
        {
          id: 'gr_1',
          document_id: 'doc_1',
          user_id: 'usr_2',
          permission: 'read',
          granted_by_id: 'usr_1',
          is_revoked: false,
          created_at: '2026-10-19T10:00:00Z',
          updated_at: '2026-10-19T10:00:00Z',
        },
      ],
    });
    mockRevokeGrant.mockRejectedValue(new ApiError(404, 'No active grant for that recipient'));

    renderDetail();
    await user.click(await screen.findByRole('tab', { name: 'Access' }));
    await screen.findByText('usr_2');

    await user.click(screen.getByRole('button', { name: 'Revoke' }));
    await user.click(screen.getByRole('button', { name: 'Confirm revoke?' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'No active grant for that recipient',
    );
  });

  it('navigates back to the list after a confirmed delete', async () => {
    const user = userEvent.setup();
    mockGetMe.mockResolvedValue(OWNER);
    mockGetDocument.mockResolvedValue(DOC_A);
    mockListGrants.mockResolvedValue({ grants: [] });
    mockDeleteDocument.mockResolvedValue(undefined);

    renderDetail();
    await screen.findByRole('button', { name: 'Delete' });

    await user.click(screen.getByRole('button', { name: 'Delete' }));
    await user.click(screen.getByRole('button', { name: 'Confirm delete?' }));

    expect(await screen.findByText('Documents list zone')).toBeInTheDocument();
    expect(mockDeleteDocument).toHaveBeenCalledWith('doc_1');
  });
});
