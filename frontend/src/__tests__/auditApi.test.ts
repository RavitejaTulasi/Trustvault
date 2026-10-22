import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createAuditCheckpoint,
  getAuditCheckpoint,
  listAuditEvents,
  verifyAuditChain,
  verifyAuditCheckpoint,
} from '../api';
import type {
  AuditCheckpointCreateResponse,
  AuditCheckpointInfoResponse,
  AuditCheckpointVerificationResponse,
  AuditEventListResponse,
  AuditVerificationResponse,
} from '../types';

const SAMPLE_EVENT = {
  id: 'evt_1',
  sequence_number: 42,
  timestamp: '2026-10-19T10:00:00Z',
  actor_id: 'usr_1',
  action: 'document.download',
  resource_type: 'document',
  resource_id: 'doc_1',
  outcome: 'SUCCESS' as const,
  request_id: 'req_1',
  ip_address: '203.0.113.10',
  user_agent: 'Test Agent',
  details: { bytes: 1024 },
};

const SAMPLE_LIST: AuditEventListResponse = {
  events: [SAMPLE_EVENT],
  total: 1,
  page: 2,
  page_size: 50,
};

const SAMPLE_VERIFICATION: AuditVerificationResponse = {
  status: 'VALID',
  is_valid: true,
  records_verified: 42,
  failure_reason: null,
};

const SAMPLE_CHECKPOINT_INFO: AuditCheckpointInfoResponse = {
  anchor_mode: 'filesystem',
  available: true,
  stream_id: 'audit',
  sequence_number: 42,
  created_at: '2026-10-19T10:00:00Z',
  format_version: 1,
};

const SAMPLE_CHECKPOINT_CREATE: AuditCheckpointCreateResponse = {
  status: 'CREATED',
  anchor_mode: 'filesystem',
  stream_id: 'audit',
  sequence_number: 43,
  created_at: '2026-10-20T10:00:00Z',
};

const SAMPLE_CHECKPOINT_VERIFICATION: AuditCheckpointVerificationResponse = {
  status: 'VALID',
  is_valid: true,
  records_verified: 43,
  checkpoint_sequence: 43,
  chain_head_sequence: 43,
  failure_reason: null,
  anchor_mode: 'filesystem',
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

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  fetchMock.mockReset();
});

describe('listAuditEvents', () => {
  it('encodes bounded filters and returns the audit page', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SAMPLE_LIST));

    const result = await listAuditEvents({
      page: 2,
      page_size: 50,
      actor_id: ' usr_1 ',
      action: 'document.download',
      resource_type: 'document',
      resource_id: 'doc_1',
      outcome: 'SUCCESS',
      timestamp_from: '2026-10-01T00:00:00Z',
      timestamp_to: '2026-10-31T00:00:00Z',
    });

    expect(result).toEqual(SAMPLE_LIST);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(
      '/api/v1/admin/audit?page=2&page_size=50&actor_id=usr_1&action=document.download&resource_type=document&resource_id=doc_1&outcome=SUCCESS&timestamp_from=2026-10-01T00%3A00%3A00Z&timestamp_to=2026-10-31T00%3A00%3A00Z',
    );
    expect(init.method).toBe('GET');
  });

  it('omits blank filters', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { events: [], total: 0, page: 1, page_size: 25 }),
    );

    await listAuditEvents({
      actor_id: '  ',
      action: '',
      resource_type: ' ',
      resource_id: '',
      timestamp_from: '',
      timestamp_to: '',
    });

    const url = (fetchMock.mock.calls[0] as [string, RequestInit])[0];
    expect(url).toBe('/api/v1/admin/audit');
  });

  it('surfaces admin authorization failures', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(403, { detail: 'Admin privileges required' }));

    await expect(listAuditEvents()).rejects.toMatchObject({
      status: 403,
      detail: 'Admin privileges required',
    });
  });
});

describe('verifyAuditChain', () => {
  it('requests verification and returns the backend verdict', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SAMPLE_VERIFICATION));

    await expect(verifyAuditChain()).resolves.toEqual(SAMPLE_VERIFICATION);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/admin/audit/verify');
    expect(init.method).toBe('GET');
  });

  it('surfaces verification failures instead of assuming validity', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(503, { detail: 'Audit backend unavailable' }));

    await expect(verifyAuditChain()).rejects.toMatchObject({
      status: 503,
      detail: 'Audit backend unavailable',
    });
  });
});

describe('audit checkpoints', () => {
  it('reads the latest checkpoint metadata without raw hashes', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SAMPLE_CHECKPOINT_INFO));

    await expect(getAuditCheckpoint()).resolves.toEqual(SAMPLE_CHECKPOINT_INFO);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/admin/audit/checkpoints');
    expect(init.method).toBe('GET');
  });

  it('creates a checkpoint with a CSRF-protected POST', async () => {
    document.cookie = 'trustvault_csrf=tok-123; path=/';
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SAMPLE_CHECKPOINT_CREATE));

    await expect(createAuditCheckpoint()).resolves.toEqual(SAMPLE_CHECKPOINT_CREATE);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/admin/audit/checkpoints');
    expect(init.method).toBe('POST');
    expect((init.headers as Headers).get('X-CSRF-Token')).toBe('tok-123');
  });

  it('surfaces refused checkpoint creation without assuming success', async () => {
    document.cookie = 'trustvault_csrf=tok-123; path=/';
    fetchMock.mockResolvedValueOnce(
      jsonResponse(409, {
        detail: 'Checkpoint creation refused: a conflicting checkpoint already exists',
      }),
    );

    await expect(createAuditCheckpoint()).rejects.toMatchObject({
      status: 409,
      detail: 'Checkpoint creation refused: a conflicting checkpoint already exists',
    });
  });

  it('requests checkpoint verification and returns the verdict', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SAMPLE_CHECKPOINT_VERIFICATION));

    await expect(verifyAuditCheckpoint()).resolves.toEqual(SAMPLE_CHECKPOINT_VERIFICATION);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/admin/audit/checkpoints/verify');
    expect(init.method).toBe('GET');
  });
});
