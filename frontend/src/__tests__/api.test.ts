/**
 * UNIT tests for the API client. The global `fetch` is stubbed; no backend runs.
 * Covers: request construction, cookie reading + CSRF header injection,
 * login success/failure, session restoration (401 vs server error),
 * logout success/failure, and non-JSON error bodies.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ApiError,
  NetworkError,
  apiFetch,
  changePassword,
  confirmPasswordReset,
  getCookie,
  getDemoAccounts,
  getMe,
  login,
  logout,
  register,
  requestPasswordReset,
  updateMe,
  verifyPasswordResetOtp,
} from '../api';
import type { UserResponse } from '../types';

const SAMPLE_USER: UserResponse = {
  id: 'usr_1',
  email: 'ada@example.com',
  full_name: 'Ada Lovelace',
  role: 'Viewer',
  is_active: true,
  must_change_password: false,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
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

/**
 * jsdom's cookie jar ignores `document.cookie = ''`; the only reliable way to
 * reset state between tests is to expire the exact cookie by name.
 */
function clearCookie(name: string): void {
  document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
  clearCookie('trustvault_csrf');
});

afterEach(() => {
  vi.unstubAllGlobals();
  clearCookie('trustvault_csrf');
  fetchMock.mockReset();
});

describe('getCookie', () => {
  it('reads a simple browser cookie value', () => {
    document.cookie = 'trustvault_csrf=tok-123; path=/';
    expect(getCookie('trustvault_csrf')).toBe('tok-123');
  });

  it('returns undefined for an absent cookie', () => {
    expect(getCookie('trustvault_csrf')).toBeUndefined();
  });

  it('does not confuse names with a shared prefix', () => {
    document.cookie = 'trustvault_csrf_backup=tok-999';
    expect(getCookie('trustvault_csrf')).toBeUndefined();
  });
});

describe('apiFetch request construction', () => {
  it('builds the URL from the base URL and injects CSRF token for mutating requests', async () => {
    document.cookie = 'trustvault_csrf=tok-123; path=/';
    fetchMock.mockResolvedValueOnce(new Response(undefined, { status: 204 }));

    await apiFetch('/api/v1/auth/logout', { method: 'POST' });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/auth/logout');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('include');
    const headers = init.headers as Headers;
    expect(headers.get('X-CSRF-Token')).toBe('tok-123');
    expect(headers.get('X-Request-ID')).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    // logout sends no body, so no Content-Type is attached
    expect(headers.has('Content-Type')).toBe(false);
  });

  it('keeps a caller-supplied request ID on mutations', async () => {
    document.cookie = 'trustvault_csrf=tok-123; path=/';
    fetchMock.mockResolvedValueOnce(new Response(undefined, { status: 204 }));

    await apiFetch('/api/v1/auth/logout', {
      method: 'POST',
      headers: { 'X-Request-ID': 'ui-test-123' },
    });

    const headers = (fetchMock.mock.calls[0] as [string, RequestInit])[1].headers as Headers;
    expect(headers.get('X-Request-ID')).toBe('ui-test-123');
  });

  it('does not inject a CSRF or request ID header for GET requests', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Not authenticated' }));

    await apiFetch('/api/v1/auth/me');

    const headers = (fetchMock.mock.calls[0] as [string, RequestInit])[1].headers as Headers;
    expect(headers.get('X-CSRF-Token')).toBeNull();
    expect(headers.get('X-Request-ID')).toBeNull();
  });

  it('bootstraps the CSRF cookie with a GET before the first mutating request', async () => {
    // The document has no csrf cookie yet; the bootstrap GET must run first.
    fetchMock.mockImplementation(async (_input: string | URL, init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'GET') {
        // simulate the backend middleware setting the cookie on any response
        document.cookie = 'trustvault_csrf=tok-bootstrapped; path=/';
        return jsonResponse(401, { detail: 'Not authenticated' });
      }
      return new Response(undefined, { status: 204 });
    });

    await apiFetch('/api/v1/auth/logout', { method: 'POST' });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const bootstrapCall = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(bootstrapCall[0]).toBe('/api/v1/auth/me');
    expect(bootstrapCall[1].method).toBe('GET');
    const mutatingCall = fetchMock.mock.calls[1] as [string, RequestInit];
    expect((mutatingCall[1].headers as Headers).get('X-CSRF-Token')).toBe('tok-bootstrapped');
  });

  it('wraps network failures in NetworkError', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('fetch failed'));
    await expect(apiFetch('/api/v1/auth/me')).rejects.toBeInstanceOf(NetworkError);
  });
});

describe('login', () => {
  it('posts credentials as JSON and returns UserResponse', async () => {
    document.cookie = 'trustvault_csrf=tok-123; path=/';
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SAMPLE_USER));

    const user = await login('ada@example.com', 'correct horse');

    expect(user).toEqual(SAMPLE_USER);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/auth/login');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('include');
    expect(init.body).toBe(
      JSON.stringify({ email: 'ada@example.com', password: 'correct horse' }),
    );
    expect((init.headers as Headers).get('X-CSRF-Token')).toBe('tok-123');
  });

  it('throws ApiError with the backend detail on 401', async () => {
    document.cookie = 'trustvault_csrf=tok-123; path=/';
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Incorrect email or password' }));

    const error = await login('ada@example.com', 'wrong').catch((err: unknown) => err);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      status: 401,
      detail: 'Incorrect email or password',
    });
  });

  it('surfaces rate-limit detail on 429', async () => {
    document.cookie = 'trustvault_csrf=tok-123; path=/';
    fetchMock.mockResolvedValueOnce(jsonResponse(429, { detail: 'Too many attempts' }));

    await expect(login('ada@example.com', 'x')).rejects.toMatchObject({
      status: 429,
      detail: 'Too many attempts',
    });
  });

  it('falls back to a generic message when the error body is not JSON', async () => {
    document.cookie = 'trustvault_csrf=tok-123; path=/';
    fetchMock.mockResolvedValueOnce(
      new Response('<html>502 Bad Gateway</html>', {
        status: 502,
        headers: { 'content-type': 'text/html' },
      }),
    );

    await expect(login('ada@example.com', 'x')).rejects.toMatchObject({
      status: 502,
      detail: 'Request failed (HTTP 502)',
    });
  });
});

describe('register / updateMe', () => {
  beforeEach(() => {
    document.cookie = 'trustvault_csrf=tok-123; path=/';
  });

  it('posts registration fields and returns the created user', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(201, SAMPLE_USER));

    const user = await register('Ada Lovelace', 'ada@example.com', 'correct horse');

    expect(user).toEqual(SAMPLE_USER);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/auth/register');
    expect(init.method).toBe('POST');
    expect(init.body).toBe(
      JSON.stringify({
        full_name: 'Ada Lovelace',
        email: 'ada@example.com',
        password: 'correct horse',
      }),
    );
  });

  it('PATCHes only the supplied profile changes', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SAMPLE_USER));

    await updateMe({ full_name: 'Ada Byron' });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/auth/me');
    expect(init.method).toBe('PATCH');
    expect(init.body).toBe(JSON.stringify({ full_name: 'Ada Byron' }));
  });

  it('posts the current and replacement passwords for a mandatory change', async () => {
    const changed = { ...SAMPLE_USER, must_change_password: false };
    fetchMock.mockResolvedValueOnce(jsonResponse(200, changed));

    const user = await changePassword('Temporary!Pass1', 'Changed!Pass2');

    expect(user).toEqual(changed);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/auth/change-password');
    expect(init.method).toBe('POST');
    expect(init.body).toBe(
      JSON.stringify({
        current_password: 'Temporary!Pass1',
        new_password: 'Changed!Pass2',
      }),
    );
  });

  it('drives the OTP reset flow through request, verify, and confirm', async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse(200, { message: 'If an account exists, a code has been sent.' }),
      )
      .mockResolvedValueOnce(jsonResponse(200, { valid: true }))
      .mockResolvedValueOnce(
        jsonResponse(200, { message: 'Password successfully reset.' }),
      );

    const sent = await requestPasswordReset('ada@example.com');
    await verifyPasswordResetOtp('ada@example.com', '123456');
    const confirmed = await confirmPasswordReset(
      'ada@example.com',
      '123456',
      'New!SecurePass99',
    );

    expect(sent).toContain('code has been sent');
    expect(confirmed).toContain('successfully reset');

    const calls = fetchMock.mock.calls as [string, RequestInit][];
    expect(calls.map(([url]) => url)).toEqual([
      '/api/v1/auth/request-reset',
      '/api/v1/auth/verify-otp',
      '/api/v1/auth/confirm-reset',
    ]);
    expect(calls[0][1].body).toBe(JSON.stringify({ email: 'ada@example.com' }));
    expect(calls[1][1].body).toBe(
      JSON.stringify({ email: 'ada@example.com', otp_code: '123456' }),
    );
    expect(calls[2][1].body).toBe(
      JSON.stringify({
        email: 'ada@example.com',
        otp_code: '123456',
        new_password: 'New!SecurePass99',
      }),
    );
  });

  it('surfaces registration conflicts', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(409, { detail: 'Email already registered' }));

    await expect(register('Ada', 'ada@example.com', 'correct horse')).rejects.toMatchObject({
      status: 409,
      detail: 'Email already registered',
    });
  });
});

describe('getMe', () => {
  it('returns the user for an authenticated session', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(200, SAMPLE_USER));
    await expect(getMe()).resolves.toEqual(SAMPLE_USER);
  });

  it('resolves null on 401 instead of throwing', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(401, { detail: 'Not authenticated' }));
    await expect(getMe()).resolves.toBeNull();
  });

  it('throws on server errors so they stay distinguishable from 401', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(503, { detail: 'Database unavailable' }));
    await expect(getMe()).rejects.toMatchObject({ status: 503 });
  });
});

describe('getDemoAccounts', () => {
  it('returns parsed demo accounts on success', async () => {
    const accounts = [
      { role: 'admin', email: 'demo.admin@example.com', password: 'secret' },
    ];
    fetchMock.mockResolvedValueOnce(jsonResponse(200, accounts));

    await expect(getDemoAccounts()).resolves.toEqual(accounts);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/auth/demo-accounts'),
      expect.objectContaining({ method: 'GET' }),
    );
  });

  it('returns an empty list on 404 (production or disabled)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(404, { detail: 'Not Found' }));

    await expect(getDemoAccounts()).resolves.toEqual([]);
  });

  it('surfaces other API errors', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(500, { detail: 'boom' }));

    await expect(getDemoAccounts()).rejects.toBeInstanceOf(ApiError);
  });
});

describe('logout', () => {
  beforeEach(() => {
    document.cookie = 'trustvault_csrf=tok-123; path=/';
  });

  it('posts to the logout endpoint and resolves on 204', async () => {
    fetchMock.mockResolvedValueOnce(new Response(undefined, { status: 204 }));
    await expect(logout()).resolves.toBeUndefined();
  });

  it('throws an ApiError when logout fails instead of faking success', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(403, { detail: 'CSRF token missing or invalid' }));
    await expect(logout()).rejects.toMatchObject({
      status: 403,
      detail: 'CSRF token missing or invalid',
    });
  });
});
