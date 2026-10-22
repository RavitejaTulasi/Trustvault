import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ApiError,
  createUser,
  listUsers,
  resetUserPassword,
  revokeUserSessions,
  updateUser,
} from '../api';
import type { UserListResponse, UserResponse } from '../types';

const SAMPLE_USER: UserResponse = {
  id: 'usr_1',
  email: 'ada@example.com',
  full_name: 'Ada Lovelace',
  role: 'owner',
  is_active: true,
  must_change_password: false,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

const SAMPLE_LIST: UserListResponse = {
  users: [SAMPLE_USER],
  total: 40,
  page: 2,
  page_size: 25,
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
  document.cookie = 'trustvault_csrf=tok-123; path=/';
});

afterEach(() => {
  vi.unstubAllGlobals();
  fetchMock.mockReset();
  document.cookie = 'trustvault_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
});

describe('listUsers', () => {
  it('encodes pagination and returns the account page', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SAMPLE_LIST));

    const result = await listUsers({ page: 2, page_size: 25 });

    expect(result).toEqual(SAMPLE_LIST);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/admin/users?page=2&page_size=25');
  });

  it('omits the query string when no pagination is requested', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SAMPLE_LIST));

    await listUsers();

    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/v1/admin/users');
  });

  it('surfaces the server detail when the request is forbidden', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(403, { detail: 'Admin privileges required' }),
    );

    await expect(listUsers()).rejects.toMatchObject({
      status: 403,
      detail: 'Admin privileges required',
    });
  });
});

describe('createUser', () => {
  it('posts the complete account payload with CSRF protection', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(201, SAMPLE_USER));

    const account = {
      email: 'ada@example.com',
      password: 'Initial!Secure#Pass2',
      full_name: 'Ada Lovelace',
      role: 'owner' as const,
      is_active: true,
    };
    const result = await createUser(account);

    expect(result).toEqual(SAMPLE_USER);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/admin/users');
    expect(init.method).toBe('POST');
    expect(init.body).toBe(JSON.stringify(account));
    const headers = init.headers as Headers;
    expect(headers.get('X-CSRF-Token')).toBe('tok-123');
  });

  it('surfaces duplicate-email conflicts', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(409, { detail: 'An account with this email already exists' }),
    );

    await expect(
      createUser({
        email: 'ada@example.com',
        password: 'Initial!Secure#Pass2',
        full_name: 'Ada Lovelace',
        role: 'owner',
        is_active: true,
      }),
    ).rejects.toMatchObject({
      status: 409,
      detail: 'An account with this email already exists',
    });
  });
});

describe('updateUser', () => {
  it('patches the role with a CSRF-protected JSON body', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, { ...SAMPLE_USER, role: 'admin' }));

    const result = await updateUser('usr_1', { role: 'admin' });

    expect(result.role).toBe('admin');
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/admin/users/usr_1');
    expect(init.method).toBe('PATCH');
    expect(init.body).toBe(JSON.stringify({ role: 'admin' }));
    const headers = init.headers as Headers;
    expect(headers.get('X-CSRF-Token')).toBe('tok-123');
  });

  it('throws an ApiError for a rejected self-demotion', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(400, { detail: 'Administrators cannot remove their own admin role' }),
    );

    await expect(updateUser('usr_1', { role: 'viewer' })).rejects.toBeInstanceOf(ApiError);
  });
});

describe('resetUserPassword', () => {
  it('posts the replacement password with CSRF protection and returns the session count', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { user_id: 'usr_1', sessions_revoked: 2 }),
    );

    const result = await resetUserPassword('usr_1', 'Reset!Secure#Pass3');

    expect(result).toEqual({ user_id: 'usr_1', sessions_revoked: 2 });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/admin/users/usr_1/reset-password');
    expect(init.method).toBe('POST');
    expect(init.body).toBe(JSON.stringify({ password: 'Reset!Secure#Pass3' }));
    const headers = init.headers as Headers;
    expect(headers.get('X-CSRF-Token')).toBe('tok-123');
  });

  it('surfaces an authorization failure', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(400, { detail: 'Use account settings to change your own password' }),
    );

    await expect(
      resetUserPassword('usr_1', 'Reset!Secure#Pass3'),
    ).rejects.toMatchObject({
      status: 400,
      detail: 'Use account settings to change your own password',
    });
  });
});

describe('revokeUserSessions', () => {
  it('posts to the revoke endpoint and returns the count', async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(200, { user_id: 'usr_1', sessions_revoked: 4 }),
    );

    const result = await revokeUserSessions('usr_1');

    expect(result).toEqual({ user_id: 'usr_1', sessions_revoked: 4 });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/admin/users/usr_1/revoke-sessions');
    expect(init.method).toBe('POST');
  });
});
