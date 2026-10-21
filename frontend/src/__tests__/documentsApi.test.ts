/**
 * UNIT tests for the documents/grants API client. The global `fetch` is
 * stubbed; no backend runs. Covers request construction (query strings,
 * multipart bodies, CSRF headers), download plumbing, and error mapping.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ApiError,
  createGrant,
  deleteDocument,
  downloadDocument,
  getDocument,
  listDocuments,
  listGrants,
  parseContentDispositionFilename,
  revokeGrant,
  uploadDocument,
} from '../api';
import type { DocumentListResponse } from '../types';

const SAMPLE_DOCUMENT = {
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

function jsonResponse(status: number, body: unknown | undefined): Response {
  if (body === undefined) {
    return new Response(undefined, { status });
  }
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const fetchMock = vi.fn();

function clearCookie(name: string): void {
  document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
  document.cookie = 'trustvault_csrf=tok-123; path=/';
});

afterEach(() => {
  vi.unstubAllGlobals();
  clearCookie('trustvault_csrf');
  fetchMock.mockReset();
});

describe('listDocuments', () => {
  it('requests the documents endpoint and maps the response', async () => {
    const listResponse: DocumentListResponse = {
      documents: [{ ...SAMPLE_DOCUMENT, effective_permission: 'owner' }],
      total: 1,
      page: 1,
      page_size: 25,
    };
    fetchMock.mockResolvedValueOnce(jsonResponse(200, listResponse));

    const result = await listDocuments();

    expect(result).toEqual(listResponse);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/documents');
    expect(init.method).toBe('GET');
  });

  it('encodes search filters as query parameters', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { documents: [], total: 0, page: 1, page_size: 25 }),
    );

    await listDocuments({ page: 2, page_size: 50, q: 'aud it%', category: 'Fin youre' });

    const url = (fetchMock.mock.calls[0] as [string, RequestInit])[0];
    expect(url).toBe(
      '/api/v1/documents?page=2&page_size=50&q=aud+it%25&category=Fin+youre',
    );
  });

  it('omits blank and absent optional filters', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { documents: [], total: 0, page: 3, page_size: 25 }),
    );

    await listDocuments({ page: 3, q: '  ', category: '' });

    const url = (fetchMock.mock.calls[0] as [string, RequestInit])[0];
    expect(url).toBe('/api/v1/documents?page=3');
  });

  it('surfaces 422 validation details from the backend', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(422, { detail: 'created_from > created_to' }));

    await expect(listDocuments({ created_from: '2026-12-01', created_to: '2026-01-01' })).rejects.toMatchObject(
      { status: 422, detail: 'created_from > created_to' },
    );
  });
});

describe('uploadDocument', () => {
  it('sends multipart form data without forcing a Content-Type header', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(201, SAMPLE_DOCUMENT));
    const file = new File(['pdf-bytes'], 'q3_audit.pdf', { type: 'application/pdf' });

    const result = await uploadDocument(file, 'Quarterly Financial Audit', 'Financial');

    expect(result).toEqual(SAMPLE_DOCUMENT);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/documents');
    expect(init.method).toBe('POST');
    expect(init.body).toBeInstanceOf(FormData);
    const form = init.body as FormData;
    expect(form.get('file')).toBe(file);
    expect(form.get('title')).toBe('Quarterly Financial Audit');
    expect(form.get('category')).toBe('Financial');
    const headers = init.headers as Headers;
    // Content-Type must be left to the browser so the multipart boundary is valid.
    expect(headers.has('Content-Type')).toBe(false);
    expect(headers.get('X-CSRF-Token')).toBe('tok-123');
  });

  it('omits the category field when none is provided', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(201, SAMPLE_DOCUMENT));

    await uploadDocument(new File(['bytes'], 'a.txt', { type: 'text/plain' }), 'Note');

    const form = (fetchMock.mock.calls[0] as [string, RequestInit])[1].body as FormData;
    expect(form.get('category')).toBeNull();
  });
});

describe('getDocument / deleteDocument', () => {
  it('GETs the document metadata by id', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SAMPLE_DOCUMENT));

    const result = await getDocument('doc_1');

    expect(result).toEqual(SAMPLE_DOCUMENT);
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/documents/doc_1');
  });

  it('maps the deliberate 404 to an ApiError with the backend detail', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(404, { detail: 'Document not found' }));

    await expect(getDocument('doc_missing')).rejects.toMatchObject({
      status: 404,
      detail: 'Document not found',
    });
  });

  it('DELETEs the document and resolves on 204', async () => {
    fetchMock.mockResolvedValueOnce(new Response(undefined, { status: 204 }));

    await expect(deleteDocument('doc_1')).resolves.toBeUndefined();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/documents/doc_1');
    expect(init.method).toBe('DELETE');
  });
});

describe('downloadDocument', () => {
  const originalCreateObjectURL = URL.createObjectURL;
  const originalRevokeObjectURL = URL.revokeObjectURL;

  afterEach(() => {
    URL.createObjectURL = originalCreateObjectURL;
    URL.revokeObjectURL = originalRevokeObjectURL;
  });

  it('fetches the bytes and triggers a browser download with the server filename', async () => {
    const revokeSpy = vi.fn();
    URL.createObjectURL = vi.fn(() => 'blob:fake');
    URL.revokeObjectURL = revokeSpy;
    const anchorClick = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(
      () => undefined,
    );
    fetchMock.mockResolvedValueOnce(
      new Response(new Blob(['pdf-bytes'], { type: 'application/pdf' }), {
        status: 200,
        headers: {
          'content-disposition': 'attachment; filename="q3_audit.pdf"',
        },
      }),
    );

    await downloadDocument('doc_1', 'fallback.pdf');

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/documents/doc_1/download');
    expect(init.method).toBe('GET');
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(anchorClick).toHaveBeenCalledTimes(1);
    expect(revokeSpy).toHaveBeenCalledWith('blob:fake');
    anchorClick.mockRestore();
  });

  it('surfaces authorization failures instead of writing partial data', async () => {
    const createSpy = vi.fn();
    URL.createObjectURL = createSpy;
    URL.revokeObjectURL = vi.fn();
    fetchMock.mockResolvedValueOnce(jsonResponse(404, { detail: 'Document not found' }));

    await expect(downloadDocument('doc_1')).rejects.toBeInstanceOf(ApiError);
    expect(createSpy).not.toHaveBeenCalled();
  });
});

describe('permission grants', () => {
  it('GETs the grant list for the owner', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { grants: [] }));

    await expect(listGrants('doc_1')).resolves.toEqual({ grants: [] });
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/documents/doc_1/permissions');
  });

  it('sends the recipient and permission level as JSON', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(201, {
        id: 'gr_1',
        document_id: 'doc_1',
        user_id: 'usr_2',
        permission: 'edit',
        granted_by_id: 'usr_1',
        is_revoked: false,
        created_at: '2026-10-19T10:00:00Z',
        updated_at: '2026-10-19T10:00:00Z',
      }),
    );

    const grant = await createGrant('doc_1', 'usr_2', 'edit');

    expect(grant).toMatchObject({ id: 'gr_1', permission: 'edit' });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/documents/doc_1/permissions');
    expect(init.method).toBe('POST');
    expect(init.body).toBe(JSON.stringify({ user_id: 'usr_2', permission: 'edit' }));
    expect((init.headers as Headers).get('Content-Type')).toBe('application/json');
  });

  it('maps self-grant and inactive-recipient 400s to the backend detail', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(400, { detail: 'Cannot grant to the document owner' }));

    await expect(createGrant('doc_1', 'usr_1', 'read')).rejects.toMatchObject({
      status: 400,
      detail: 'Cannot grant to the document owner',
    });
  });
});

describe('revokeGrant', () => {
  it('DELETEs the recipient grant and resolves on 200', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { detail: 'Permission successfully revoked' }));

    await expect(revokeGrant('doc_1', 'usr_2')).resolves.toBeUndefined();
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/documents/doc_1/permissions/usr_2');
    expect(init.method).toBe('DELETE');
    expect((init.headers as Headers).get('X-CSRF-Token')).toBe('tok-123');
  });

  it('maps a concurrent revoke race 409 through to the caller', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(409, { detail: 'Permission grant was revoked concurrently' }),
    );

    await expect(revokeGrant('doc_1', 'usr_2')).rejects.toMatchObject({
      status: 409,
      detail: 'Permission grant was revoked concurrently',
    });
  });
});

describe('parseContentDispositionFilename', () => {
  it('prefers the RFC 5987 UTF-8 extended parameter', () => {
    expect(
      parseContentDispositionFilename("attachment; filename*=UTF-8''a%20b.txt"),
    ).toBe('a b.txt');
  });

  it('reads the quoted plain filename', () => {
    expect(
      parseContentDispositionFilename('attachment; filename="q3_audit.pdf"'),
    ).toBe('q3_audit.pdf');
  });

  it('returns undefined without a header', () => {
    expect(parseContentDispositionFilename(null)).toBeUndefined();
  });
});
